"""Scheduled jobs: per-switch list, overview for administrators and cancelling pending jobs."""

from fastapi import APIRouter, HTTPException

from . import database as db
from . import scheduler
from .audit import audit_action, record
from .auth import AdminPrincipal, CurrentPrincipal
from .i18n import t

router = APIRouter(prefix="/api", tags=["jobs"])


@router.get("/switches/{switch_id}/jobs")
def list_switch_jobs(switch_id: int, _: CurrentPrincipal):
    if db.get_switch(switch_id) is None:
        raise HTTPException(404, t("Switch nicht gefunden"))
    return scheduler.list_switch_jobs(switch_id)


@router.get("/jobs")
def list_jobs(_: AdminPrincipal):
    return scheduler.list_jobs()


@router.delete("/jobs/{job_id}")
@audit_action("job-cancel")
def cancel_job(job_id: int, _: AdminPrincipal):
    job = scheduler.get_job(job_id)
    if job is None:
        raise HTTPException(404, t("Aufgabe nicht gefunden."))
    if not scheduler.cancel_job(job_id):
        raise HTTPException(409, t("Nur geplante Aufgaben, die noch nicht laufen, können abgebrochen werden."))
    record("job-cancel", target=job["switch_name"], detail=f"job={job_id} kind={job['kind']} run_at={job['run_at']}")
    return scheduler.get_job(job_id)
