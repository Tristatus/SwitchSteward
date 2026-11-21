"""HTTP download of transfer tickets by switches (no session; the ticket is the credential)."""

import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, Response
from starlette.concurrency import run_in_threadpool

from . import transfer

logger = logging.getLogger("switchsteward.transfer")

router = APIRouter(tags=["transfer"])


def _download(token: str, filename: str, client_ip: str | None):
    token_id, _, secret = token.partition(".")
    grant = transfer.redeem(token_id, secret, filename)
    if grant is None:
        logger.warning("Transfer download refused (client %s)", client_ip or "-")
        return None
    try:
        payload = transfer.open_payload(grant.kind, grant.ref_id)
    except (LookupError, ValueError, OSError) as exc:
        logger.error("Transfer payload %s %s unavailable: %s", grant.kind, grant.ref_id, exc)
        transfer.audit_download(grant, "http", client_ip, status="error")
        return None
    transfer.audit_download(grant, "http", client_ip)
    return payload


@router.get("/transfer/{token}/{filename}", include_in_schema=False)
async def download(token: str, filename: str, request: Request):
    client_ip = request.client.host if request.client else None
    payload = await run_in_threadpool(_download, token, filename, client_ip)
    if payload is None:
        # No detail: an invalid, used-up or expired ticket looks like a missing file.
        raise HTTPException(404)
    if isinstance(payload, bytes):
        return Response(payload, media_type="text/plain; charset=utf-8")
    return FileResponse(payload, media_type="application/octet-stream", filename=filename)
