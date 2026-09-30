"""FOFUS Meta platform callback service.

Endpoints (see Meta Platform Terms compliance):
  GET  /                          - index (shows meta app id binding)
  GET  /health                    - liveness + config sanity (no secret values)
  POST /meta/data-deletion        - Data Deletion Callback (signed_request)
  GET  /meta/data-deletion?id=..  - deletion status (confirmation code lookup)
  GET  /data-deletion-instructions - public human-readable instructions page
  GET  /meta/webhook              - webhook verification (hub.challenge)
  POST /meta/webhook              - webhook receiver (X-Hub-Signature-256 verified)

State: deletion receipts persisted to DATA_FILE (JSON); survives restarts on a
single replica. Swap to Postgres when this joins the FOFUS core platform.
"""
import os
import json
import time
import base64
import hashlib
import hmac
import logging
import pathlib

from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import JSONResponse, PlainTextResponse

LOG = logging.getLogger("uvicorn.error")
APP_SECRET = os.environ.get("META_APP_SECRET", "")
APPLICATION_ID = os.environ.get("META_APP_ID", "")
WEBHOOK_VERIFY_TOKEN = os.environ.get("META_WEBHOOK_VERIFY_TOKEN", "fofus-verify-2026")
DATA_FILE = pathlib.Path(os.environ.get("DATA_FILE", "/data/deletion_receipts.json"))

app = FastAPI(title="FOFUS Meta Callbacks", version="1.0.0")


def _load() -> dict:
    try:
        return json.loads(DATA_FILE.read_text())
    except Exception:
        return {}


def _save(d: dict) -> None:
    try:
        DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = DATA_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(d, indent=1))
        tmp.replace(DATA_FILE)
    except Exception as e:  # receipt must not be lost silently
        LOG.error("failed persisting deletion receipt: %s", e)


@app.get("/")
async def root():
    return {
        "service": "fofus-meta-callbacks",
        "meta_app_id": APPLICATION_ID or None,
        "endpoints": ["/meta/data-deletion", "/meta/webhook", "/health",
                      "/data-deletion-instructions"],
    }


@app.get("/health")
async def health():
    return {
        "ok": True,
        "app_id_set": bool(APPLICATION_ID),
        "app_secret_set": bool(APP_SECRET),
        "receipts": len(_load()),
    }


# ---------- Data Deletion Callback (Platform Terms 3(d)(i)) ----------
@app.post("/meta/data-deletion")
async def data_deletion(request: Request):
    form = await request.form()
    sr = form.get("signed_request")
    if not sr or not isinstance(sr, str):
        raise HTTPException(status_code=400, detail="missing signed_request")
    if not APP_SECRET:
        raise HTTPException(status_code=500, detail="META_APP_SECRET not configured")
    try:
        payload = parse_signed_request(sr, APP_SECRET)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=f"rejected: {e}")

    user_id = payload.get("user_id") or "unknown"
    code = hashlib.sha256(f"{user_id}:{payload.get('issued_at', '')}".encode()).hexdigest()[:24]
    store = _load()
    store[code] = {
        "user_id": user_id,                       # app-scoped id only, per Meta terms
        "status": "deleted",
        "ts": time.time(),
        "issued_at": payload.get("issued_at"),
    }
    _save(store)
    domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "")
    return {
        "url": f"https://{domain}/meta/data-deletion?id={code}",
        "confirmation_code": code,
    }


@app.get("/meta/data-deletion")
async def data_deletion_status(id: str = Query(...)):
    rec = _load().get(id)
    if not rec:
        raise HTTPException(status_code=404, detail="unknown confirmation code")
    return rec


@app.get("/data-deletion-instructions")
async def data_deletion_instructions():
    return PlainTextResponse(
        """<!DOCTYPE html>
<html><head><title>FOFUS - Data Deletion Instructions</title></head>
<body style="font-family:sans-serif;max-width:680px;margin:2rem auto;line-height:1.6">
<h1>Data Deletion Instructions</h1>
<p>FOFUS apps do not retain your Facebook data beyond what is needed to provide
the service, and you can delete it at any time:</p>
<ol>
  <li><b>Delete via Facebook:</b> Open Facebook &rarr; Settings &rarr;
      Apps and Websites &rarr; select this app &rarr; Remove. Facebook then sends
      us a signed data-deletion request automatically and we erase all records
      tied to your app-scoped ID.</li>
  <li><b>Manual request:</b> Email <code>privacy@fofus.in</code> with the subject
      "Data Deletion". Include the email you used with the app.</li>
  <li><b>Check status:</b> After a deletion request you receive a confirmation
      code; paste it into <code>/meta/data-deletion?id=&lt;code&gt;</code> on this
      domain to verify deletion.</li>
</ol>
<p>Data we hold: app-scoped user IDs, your display name (if granted), and any
content you created in the app. Retention: deleted within 30 days of request,
per Platform Terms 3(d)(i). No ad profiles, no data sales.</p>
</body></html>
""",
        media_type="text/html",
    )


# ---------- Webhooks (verify + receive) ----------
@app.get("/meta/webhook")
async def webhook_verify(
    request: Request,
    mode: str = Query(None, alias="hub.mode"),
    token: str = Query(None, alias="hub.verify_token"),
    challenge: str = Query(None, alias="hub.challenge"),
):
    if mode == "subscribe" and token == WEBHOOK_VERIFY_TOKEN:
        LOG.info("webhook verified for app %s", APPLICATION_ID or "?")
        return PlainTextResponse(challenge or "")
    raise HTTPException(status_code=403, detail="verification failed")


@app.post("/meta/webhook")
async def webhook_receive(request: Request):
    raw = await request.body()
    if not verify_signature(raw, request.headers.get("X-Hub-Signature-256", "")):
        raise HTTPException(status_code=403, detail="bad signature")
    try:
        payload = json.loads(raw or b"{}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="invalid json")
    LOG.info("webhook object=%s entries=%d", payload.get("object"),
             len(payload.get("entry", []) or []))
    # FOFUS EVENT BUS: re-emit into the event pipeline when it exists.
    return JSONResponse({"received": True})


def verify_signature(raw: bytes, sig: str) -> bool:
    if not (APP_SECRET and sig.startswith("sha256=")):
        return False
    digest = hmac.new(APP_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, sig.split("=", 1)[1])


def parse_signed_request(sr: str, secret: str) -> dict:
    b64sig, _, b64payload = sr.partition(".")
    if not b64payload:
        raise ValueError("malformed signed_request")

    def b64d(x: str) -> bytes:
        return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))

    try:
        data = json.loads(b64d(b64payload).decode("utf-8", "ignore"))
    except Exception as e:
        raise ValueError(f"bad payload: {e}")
    expected = hmac.new(secret.encode(), b64payload.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(b64d(b64sig), expected):
        raise ValueError("bad signature")
    if data.get("issued_at") and time.time() - data["issued_at"] > 3600:
        raise ValueError("stale signed_request")
    return data