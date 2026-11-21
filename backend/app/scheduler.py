"""In-process scheduler for deferred switch jobs (table ``jobs``).

``run_scheduler`` runs as a task of the application lifespan. Every ``POLL_SECONDS`` it claims
due ``pending`` jobs (at most ``MAX_PARALLEL`` running at once), runs their handler from
``JOB_HANDLERS`` in a thread pool and stores ``done``/``failed`` with ``result`` = JSON
``{ok, message}``; every outcome is audited as ``job-<kind>`` by user ``system``. The tick also
deletes expired transfer tokens. ``recover_jobs`` runs at startup: jobs that were running when
the server stopped fail, and pending jobs that are more than ``MISSED_AFTER`` overdue fail too.
"""

import asyncio
import contextvars
import json
import logging
import sqlite3
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import timedelta

from starlette.concurrency import run_in_threadpool

from . import audit
from . import database as db
from .auth.sessions import now, timestamp
from .i18n import t

logger = logging.getLogger("switchsteward.scheduler")

# kind → handler(job) -> {"ok": bool, "message": str}; ``job`` = {id, kind, switch_id, run_at, params, created_by}.
JOB_HANDLERS: dict[str, Callable[[dict], dict]] = {}

POLL_SECONDS = 30
MAX_PARALLEL = 4
MISSED_AFTER = timedelta(minutes=15)
STATUSES = ("pending", "running", "done", "failed", "cancelled")
_ACTOR = "system"


def create_job(
    kind: str, switch_id: int | None, run_at: str, params: dict, created_by: str,
    *, conn: sqlite3.Connection | None = None,
) -> int:
    """Insert a ``pending`` job; ``run_at`` is UTC in ``sessions.timestamp()`` format. Returns the id."""
    values = (kind, switch_id, run_at, json.dumps(params, separators=(",", ":")), created_by, timestamp(), timestamp())
    sql = (
        "INSERT INTO jobs (kind, switch_id, run_at, params, status, created_by, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)"
    )
    if conn is not None:
        return conn.execute(sql, values).lastrowid
    with db.get_conn() as own:
        return own.execute(sql, values).lastrowid


def _loads(value: str | None):
    if not value:
        return None
    try:
        return json.loads(value)
    except ValueError:
        return None


def job_view(row) -> dict:
    return {
        "id": row["id"],
        "kind": row["kind"],
        "switch_id": row["switch_id"],
        "switch_name": row["switch_name"],
        "run_at": row["run_at"],
        "params": _loads(row["params"]) or {},
        "status": row["status"],
        "result": _loads(row["result"]),
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


_VIEW_SQL = "SELECT j.*, s.name AS switch_name FROM jobs AS j LEFT JOIN switches AS s ON s.id = j.switch_id"


def list_switch_jobs(switch_id: int, limit: int = 50) -> list[dict]:
    with db.get_conn() as conn:
        rows = conn.execute(
            f"{_VIEW_SQL} WHERE j.switch_id = ? ORDER BY j.run_at DESC, j.id DESC LIMIT ?", (switch_id, limit),
        ).fetchall()
    return [job_view(row) for row in rows]


def list_jobs(finished_limit: int = 100) -> list[dict]:
    """All pending/running jobs (next first) plus the most recently finished ones."""
    with db.get_conn() as conn:
        active = conn.execute(
            f"{_VIEW_SQL} WHERE j.status IN ('pending', 'running') ORDER BY j.run_at, j.id",
        ).fetchall()
        finished = conn.execute(
            f"{_VIEW_SQL} WHERE j.status IN ('done', 'failed', 'cancelled') "
            "ORDER BY j.updated_at DESC, j.id DESC LIMIT ?",
            (finished_limit,),
        ).fetchall()
    return [job_view(row) for row in (*active, *finished)]


def get_job(job_id: int) -> dict | None:
    with db.get_conn() as conn:
        row = conn.execute(f"{_VIEW_SQL} WHERE j.id = ?", (job_id,)).fetchone()
    return job_view(row) if row else None


def cancel_job(job_id: int) -> bool:
    """Set a ``pending`` job to ``cancelled``; False when the job is not pending (anymore)."""
    with db.get_conn() as conn:
        cursor = conn.execute(
            "UPDATE jobs SET status = 'cancelled', updated_at = ? WHERE id = ? AND status = 'pending'",
            (timestamp(), job_id),
        )
        return cursor.rowcount == 1


def _audit(job: dict, ok: bool, message: str) -> None:
    try:
        audit.record(
            f"job-{job['kind']}", username=_ACTOR, target=job.get("switch_name"),
            detail=f"job={job['id']} {message}", status="ok" if ok else "error",
        )
    except Exception:
        logger.exception("Job %s could not be audited", job["id"])


def _finish(job: dict, ok: bool, message: str) -> None:
    result = json.dumps({"ok": ok, "message": message}, ensure_ascii=False)
    with db.get_conn() as conn:
        conn.execute(
            "UPDATE jobs SET status = ?, result = ?, updated_at = ? WHERE id = ?",
            ("done" if ok else "failed", result, timestamp(), job["id"]),
        )
    _audit(job, ok, message)


def claim_due_jobs(limit: int = MAX_PARALLEL) -> list[dict]:
    """Atomically mark up to ``limit`` due pending jobs as running and return them."""
    if limit <= 0:
        return []
    with db.get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            f"{_VIEW_SQL} WHERE j.status = 'pending' AND j.run_at <= ? ORDER BY j.run_at, j.id LIMIT ?",
            (timestamp(), limit),
        ).fetchall()
        conn.executemany(
            "UPDATE jobs SET status = 'running', updated_at = ? WHERE id = ?",
            [(timestamp(), row["id"]) for row in rows],
        )
    return [job_view(row) for row in rows]


def run_job(job: dict) -> None:
    """Run the handler of a claimed job and store its outcome; never raises."""
    handler = JOB_HANDLERS.get(job["kind"])
    try:
        if handler is None:
            ok, message = False, t("Unbekannte Aufgabe: {kind}", kind=job["kind"])
        else:
            result = handler(job)
            ok, message = bool(result.get("ok")), str(result.get("message") or "")
    except Exception as exc:
        logger.exception("Job %s (%s) failed", job["id"], job["kind"])
        ok, message = False, str(exc) or type(exc).__name__
    try:
        _finish(job, ok, message)
    except Exception:
        logger.exception("Result of job %s could not be stored", job["id"])


def purge_expired_transfer_tokens() -> int:
    with db.get_conn() as conn:
        return conn.execute("DELETE FROM transfer_tokens WHERE expires_at < ?", (timestamp(),)).rowcount


def recover_jobs() -> int:
    """At startup: fail jobs interrupted by a server stop and pending jobs missed by more than 15 min."""
    interrupted = t("Server-Neustart während der Ausführung.")
    missed = t("Termin verpasst (Server war nicht erreichbar).")
    with db.get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            f"{_VIEW_SQL} WHERE j.status = 'running' OR (j.status = 'pending' AND j.run_at < ?)",
            (timestamp(now() - MISSED_AFTER),),
        ).fetchall()
        jobs = [(job_view(row), interrupted if row["status"] == "running" else missed) for row in rows]
        conn.executemany(
            "UPDATE jobs SET status = 'failed', result = ?, updated_at = ? WHERE id = ?",
            [(json.dumps({"ok": False, "message": message}, ensure_ascii=False), timestamp(), job["id"])
             for job, message in jobs],
        )
    for job, message in jobs:
        logger.warning("Job %s (%s) failed: %s", job["id"], job["kind"], message)
        _audit(job, False, message)
    return len(jobs)


class _Runner:
    """Claims due jobs and keeps at most ``MAX_PARALLEL`` of them running in the pool."""

    def __init__(self, executor: ThreadPoolExecutor):
        self.executor = executor
        self.running: set[Future] = set()

    def tick(self) -> None:
        self.running = {future for future in self.running if not future.done()}
        try:
            purge_expired_transfer_tokens()
        except Exception:
            logger.exception("Expired transfer tokens could not be deleted")
        for job in claim_due_jobs(MAX_PARALLEL - len(self.running)):
            self.running.add(self.executor.submit(contextvars.copy_context().run, run_job, job))


async def run_scheduler(stop: asyncio.Event) -> None:
    """Lifespan task: tick every ``POLL_SECONDS`` until ``stop`` is set."""
    executor = ThreadPoolExecutor(max_workers=MAX_PARALLEL, thread_name_prefix="switchsteward-job")
    runner = _Runner(executor)
    try:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=POLL_SECONDS)
                break
            except asyncio.TimeoutError:
                pass
            try:
                await run_in_threadpool(runner.tick)
            except Exception:
                logger.exception("Scheduler tick failed")
    finally:
        # Running jobs are not awaited (a firmware transfer can take an hour); recover_jobs marks
        # them failed at the next start if the process ends before they finish.
        executor.shutdown(wait=False, cancel_futures=True)
