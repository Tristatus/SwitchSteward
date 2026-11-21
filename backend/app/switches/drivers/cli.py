"""CLI helpers shared by SSH drivers: configuration sequences and output parsing."""

import logging
import re
import time
from collections.abc import Callable, Iterable, Sequence

from netmiko.exceptions import ReadTimeout

from ... import config
from ...i18n import t
from ..errors import SwitchConnectionError
from .plans import redact

logger = logging.getLogger("switchsteward.switches.cli")

_SEPARATOR_LINE = re.compile(r"^[\s\-=+|]+$")


def error_lines(output: str | None, error_markers: Iterable[str | re.Pattern]) -> list[str]:
    """Stripped output lines matching any marker (regular expressions, searched case-insensitively)."""
    patterns = [
        marker if isinstance(marker, re.Pattern) else re.compile(marker, re.IGNORECASE) for marker in error_markers
    ]
    return [
        line.strip()
        for line in (output or "").splitlines()
        if line.strip() and any(pattern.search(line.strip()) for pattern in patterns)
    ]


def run_config_lines(
    conn,
    lines: Sequence[str],
    error_markers: Iterable[str | re.Pattern],
    *,
    enter: bool = True,
    exit: bool = True,
    check: Callable[[str, str, list[str]], list[str]] | None = None,
    config_mode_command: str | None = None,
    secrets: Sequence[str] = (),
) -> tuple[str, list[str]]:
    """Send configuration lines one by one and stop at the first rejected line.

    ``enter``: enter configuration mode before the first line; ``exit``: leave it
    afterwards (also after a rejected line). ``check(line, output, errors)`` may
    adjust the detected error lines of one line (e.g. tolerate an optional command).
    ``secrets`` are removed from the log lines. Returns the combined output and the
    error lines of the rejected line ([] = success).
    """
    markers = list(error_markers)
    outputs = []
    errors: list[str] = []
    for index, line in enumerate(lines):
        logger.info("Config command on %s: %s", getattr(conn, "host", "-"), redact(line, secrets))
        try:
            output = conn.send_config_set(
                [line],
                enter_config_mode=enter and index == 0,
                exit_config_mode=False,
                read_timeout=config.settings.ssh_timeout_seconds,
                **({"config_mode_command": config_mode_command} if config_mode_command and enter and index == 0 else {}),
            )
        except ValueError:
            raise SwitchConnectionError(t("Der Konfigurationsmodus konnte nicht sicher aktiviert werden.")) from None
        if not isinstance(output, str) or not output.strip():
            raise SwitchConnectionError(t("Der Switch hat die Konfigurationsaenderung nicht bestaetigt."))
        outputs.append(output)
        errors = error_lines(output, markers)
        if check is not None:
            errors = check(line, output, errors)
        if errors:
            break
    if exit:
        try:
            conn.exit_config_mode()
        except ValueError:
            raise SwitchConnectionError(t("Der Konfigurationsmodus konnte nicht sicher verlassen werden.")) from None
    return "\n".join(outputs), errors


MAX_PROMPT_ROUNDS = 10
# Explicit question shapes only: "(y/n)?", "[y/n/^C]?", "[confirm]", "[yes/no]:", "Password:", "...?".
# Progress lines such as "Loading x.bin from 10.0.0.1 (via Vlan10): " are no questions.
_QUESTION_TAIL = re.compile(
    r"\[(?:y/n|yes/no|confirm)[^\]]*\]\s*[:?]?\s*$|\(y/n\)\s*\??\s*$|(?i:password)\s*:\s*$|\?\s*$",
    re.IGNORECASE,
)


def _device_prompt_reached(conn, text: str) -> bool:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return False
    last = lines[-1]
    base = (getattr(conn, "base_prompt", "") or "").strip()
    return bool(base) and last.startswith(base) and last.endswith(("#", ">"))


def run_exec(
    conn,
    command: str,
    prompts: Sequence[tuple[str, str]] = (),
    *,
    timeout: int = 30,
    expect_disconnect: bool = False,
    secrets: Sequence[str] = (),
) -> tuple[bool, str, str | None]:
    """Run an exec-mode command and answer its interactive questions.

    Each question line is matched against ``prompts`` (regex, answer; "" = Enter).
    Returns ``(finished, output, unanswered_question)``: ``finished`` is True once the
    device prompt returns (or, with ``expect_disconnect``, when the session drops).
    An unknown question is never answered; it is aborted with Ctrl-C after at most
    ``MAX_PROMPT_ROUNDS`` answers or as soon as no prompt regex matches. ``secrets``
    are removed from the log line (answers are never logged).
    """
    compiled = [(re.compile(pattern), answer) for pattern, answer in prompts]
    logger.info("Exec command on %s: %s", getattr(conn, "host", "-"), redact(command, secrets))
    # Netmiko's read_timeout_override would replace every read_timeout below (and with
    # it the deadline handling); a longer configured SSH timeout still extends the step.
    previous_override = getattr(conn, "read_timeout_override", None)
    timeout = max(timeout, previous_override or 0)
    if previous_override is not None:
        conn.read_timeout_override = None
    try:
        return _run_exec(conn, command, compiled, timeout, expect_disconnect)
    finally:
        if previous_override is not None:
            conn.read_timeout_override = previous_override


def _run_exec(conn, command, compiled, timeout, expect_disconnect) -> tuple[bool, str, str | None]:
    outputs: list[str] = []
    disconnect_errors = (EOFError, OSError, ReadTimeout)
    deadline = time.monotonic() + max(timeout, 1)
    try:
        output = conn.send_command_timing(
            command, read_timeout=timeout, strip_prompt=False, strip_command=False, cmd_verify=False,
        )
        outputs.append(output)
        rounds = 0
        while True:
            text = "\n".join(outputs)
            if _device_prompt_reached(conn, output):
                return True, text, None
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            tail = lines[-1] if lines else ""
            answer = next((answer for regex, answer in compiled if tail and regex.search(tail)), None)
            if answer is not None:
                rounds += 1
                if rounds > MAX_PROMPT_ROUNDS:
                    _abort(conn)
                    return False, text, tail
                output = conn.send_command_timing(
                    answer, read_timeout=timeout, strip_prompt=False, strip_command=False, cmd_verify=False,
                )
                outputs.append(output)
                continue
            if tail and _QUESTION_TAIL.search(tail):
                _abort(conn)
                return False, text, tail
            if time.monotonic() >= deadline:
                if expect_disconnect:
                    return True, text, None
                return False, text, None
            # Still running (progress output or silence): keep reading until the deadline.
            try:
                output = conn.read_channel_timing(read_timeout=max(1, int(deadline - time.monotonic())))
            except ReadTimeout:
                output = ""
            outputs.append(output)
    except disconnect_errors:
        if expect_disconnect:
            return True, "\n".join(outputs), None
        raise


def _abort(conn) -> None:
    """Cancel a pending question (Ctrl-C) and drop whatever the device prints afterwards."""
    try:
        conn.write_channel("\x03")
        conn.read_channel_timing(read_timeout=5)
    except Exception as exc:  # best effort: the session ends with the plan anyway
        logger.warning("Could not cancel a pending question (%s)", type(exc).__name__)



def parse_fixed_table(output: str, header_pattern: str, columns: Sequence[str]) -> list[dict[str, str]] | None:
    """Split a fixed-width table at the column starts found in its header line.

    ``header_pattern`` identifies the header line (regex, case-insensitive);
    ``columns`` are the header words in order. The last column runs to the line end.
    Returns ``None`` when no header is found; separator and empty lines are skipped.
    """
    lines = (output or "").splitlines()
    header_index = next(
        (index for index, line in enumerate(lines) if re.search(header_pattern, line, re.IGNORECASE)), None,
    )
    if header_index is None:
        return None
    header = lines[header_index]
    starts = []
    position = 0
    for column in columns:
        match = re.compile(rf"(?<!\S){re.escape(column)}(?!\S)", re.IGNORECASE).search(header, position)
        if match is None:
            return None
        starts.append(match.start())
        position = match.end()
    rows = []
    for line in lines[header_index + 1 :]:
        if not line.strip() or _SEPARATOR_LINE.match(line):
            continue
        row = {}
        for index, column in enumerate(columns):
            end = starts[index + 1] if index + 1 < len(starts) else None
            row[column] = line[starts[index] : end].strip() if len(line) > starts[index] else ""
        rows.append(row)
    return rows


def parse_key_values(output: str) -> dict[str, str]:
    """``Key : Value`` and ``Key......... Value`` lines; the first occurrence of a key wins."""
    values: dict[str, str] = {}
    for line in (output or "").splitlines():
        match = re.match(r"^\s*([^:]+?)\s*(?:\.{2,}\s*:?|:)\s*(.*?)\s*$", line)
        if match and match.group(1) and match.group(1) not in values:
            values[match.group(1)] = match.group(2)
    return values


def parse_multiline_field(output: str, field_label: str) -> str | None:
    """Read a ``Label: value`` field whose value may wrap onto indented follow-up lines.

    Reading only the first line would silently cut e.g. long VLAN lists; writing
    them back would then lose VLANs. Follow-up lines are appended until a new
    ``Field: value`` pair, an unindented line or an empty line.
    """
    lines = output.splitlines()
    for i, line in enumerate(lines):
        m = re.match(rf"^\s*{re.escape(field_label)}\s*:\s*(.*)$", line, re.IGNORECASE)
        if not m:
            continue
        parts = [m.group(1).strip()]
        for follow in lines[i + 1 :]:
            if not follow.strip():
                break
            if not follow.startswith((" ", "\t")):
                break
            if re.match(r"^\s*[A-Za-z][A-Za-z0-9 /\-()]*:\s", follow, re.IGNORECASE):
                break
            parts.append(follow.strip())
        return "".join(parts).strip() if len(parts) > 1 else parts[0]
    return None


_PORT_ITEM = re.compile(r"^(.*?)(\d+)$")
MAX_EXPANDED_PORTS = 4096


def expand_port_list(text: str) -> list[str]:
    """Expand port lists such as ``1-4,7``, ``A1-A4``, ``1/1-1/4`` or ``Trk1-Trk2``.

    A range end without prefix inherits the start prefix (``A1-4``). Raises
    ``ValueError`` for malformed ranges.
    """
    ports: list[str] = []
    for item in (text or "").split(","):
        item = item.strip()
        if not item:
            continue
        if "-" not in item:
            ports.append(item)
            continue
        start, end = (part.strip() for part in item.split("-", 1))
        start_match, end_match = _PORT_ITEM.match(start), _PORT_ITEM.match(end)
        if not start_match or not end_match:
            raise ValueError(f"Invalid port range {item!r}")
        prefix, first = start_match.group(1), int(start_match.group(2))
        end_prefix, last = end_match.group(1) or prefix, int(end_match.group(2))
        if end_prefix != prefix or last < first or len(ports) + last - first >= MAX_EXPANDED_PORTS:
            raise ValueError(f"Invalid port range {item!r}")
        ports.extend(f"{prefix}{number}" for number in range(first, last + 1))
    return ports
