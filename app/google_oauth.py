"""User-authorized Gmail access through OAuth 2.0.

No Gmail password or app password is collected. Tokens are held only in this
server process for the active browser session; production must use encrypted,
tenant-isolated token storage and a real user-authentication system.
"""
from __future__ import annotations

import base64
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow

# Google returns the OpenID scope with the user email profile.  Request it
# explicitly so oauthlib does not reject an otherwise valid token response
# as a changed scope.
SCOPES = ["openid", "https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/userinfo.email"]
_connections: dict[str, dict] = {}
_pending_authorizations: dict[str, dict] = {}
_lock = threading.Lock()


def configured() -> bool:
    return bool(os.getenv("CIPHERX_GOOGLE_CLIENT_ID") and os.getenv("CIPHERX_GOOGLE_CLIENT_SECRET") and os.getenv("CIPHERX_GOOGLE_REDIRECT_URI"))


def _client_config() -> dict:
    return {"web": {"client_id": os.environ["CIPHERX_GOOGLE_CLIENT_ID"], "client_secret": os.environ["CIPHERX_GOOGLE_CLIENT_SECRET"], "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token", "redirect_uris": [os.environ["CIPHERX_GOOGLE_REDIRECT_URI"]]}}


def authorization_url() -> tuple[str, str, str]:
    if not configured():
        raise RuntimeError("Google OAuth is not configured. Add CIPHERX_GOOGLE_CLIENT_ID, CIPHERX_GOOGLE_CLIENT_SECRET and CIPHERX_GOOGLE_REDIRECT_URI on the backend host.")
    flow = Flow.from_client_config(_client_config(), scopes=SCOPES, redirect_uri=os.environ["CIPHERX_GOOGLE_REDIRECT_URI"])
    url, state = flow.authorization_url(access_type="offline", include_granted_scopes="true", prompt="consent")
    # Google uses PKCE for this web flow.  The verifier is created by the
    # library before the authorization URL is generated and must be supplied
    # again when exchanging the returned one-time authorization code.
    if not flow.code_verifier:
        raise RuntimeError("Google OAuth could not create a PKCE code verifier.")
    return url, state, flow.code_verifier


def remember_authorization(state: str, code_verifier: str) -> None:
    """Keep a short-lived PKCE verifier server-side as a cookie-safe fallback.

    The browser session remains the primary CSRF binding. This record handles
    restrictive cross-site-cookie settings during the Google → Render callback.
    It expires after ten minutes and is consumed exactly once.
    """
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    with _lock:
        now = datetime.now(timezone.utc)
        for key in [key for key, value in _pending_authorizations.items() if value["expires_at"] <= now]:
            _pending_authorizations.pop(key, None)
        _pending_authorizations[state] = {"code_verifier": code_verifier, "expires_at": expires_at}


def take_pending_authorization(state: str) -> str | None:
    with _lock:
        value = _pending_authorizations.pop(state, None)
    if not value or value["expires_at"] <= datetime.now(timezone.utc):
        return None
    return value["code_verifier"]


def complete_authorization(code: str, code_verifier: str) -> str:
    flow = Flow.from_client_config(_client_config(), scopes=SCOPES, redirect_uri=os.environ["CIPHERX_GOOGLE_REDIRECT_URI"])
    if not code_verifier:
        raise RuntimeError("The Google OAuth PKCE verifier is missing. Start the Gmail connection again from CIPHER-X.")
    flow.code_verifier = code_verifier
    flow.fetch_token(code=code)
    credentials = flow.credentials
    token = credentials.token
    request = Request("https://www.googleapis.com/oauth2/v2/userinfo", headers={"Authorization": f"Bearer {token}"})
    with urlopen(request, timeout=10) as response:
        profile = __import__("json").loads(response.read().decode("utf-8"))
    connection_id = uuid.uuid4().hex
    with _lock:
        _connections[connection_id] = {
            "email": profile.get("email", "Authorized Gmail account"),
            "credentials": {"token": credentials.token, "refresh_token": credentials.refresh_token, "token_uri": credentials.token_uri, "client_id": credentials.client_id, "client_secret": credentials.client_secret, "scopes": credentials.scopes},
            "scanner": {"running": False, "watching": False, "poll_seconds": None, "processed": 0, "requested": 0, "failed": 0, "sources": [], "last_error": None, "finished_at": None, "last_polled_at": None},
            "watch_stop": threading.Event(),
        }
    return connection_id


def status(connection_id: str | None) -> dict:
    with _lock:
        record = _connections.get(connection_id or "")
        if not record:
            return {"configured": configured(), "connected": False, "email": None, "scanner": None, "token_storage": "No token is stored for this browser session."}
        return {"configured": configured(), "connected": True, "email": record["email"], "scanner": dict(record["scanner"]), "token_storage": "Temporary server-side session storage; tokens are removed when disconnected or when this prototype server restarts."}


def disconnect(connection_id: str | None) -> None:
    with _lock:
        record = _connections.pop(connection_id or "", None)
        if record:
            record["watch_stop"].set()


def _access_token(connection_id: str) -> str:
    with _lock:
        record = _connections.get(connection_id)
        if not record:
            raise RuntimeError("No Gmail account is connected for this browser session.")
        values = dict(record["credentials"])
    credentials = Credentials(**values)
    if not credentials.valid:
        if not credentials.refresh_token:
            raise RuntimeError("Gmail authorization expired. Connect Gmail again.")
        credentials.refresh(GoogleRequest())
        with _lock:
            record["credentials"]["token"] = credentials.token
    return credentials.token


def _gmail_json(connection_id: str, endpoint: str) -> dict:
    token = _access_token(connection_id)
    request = Request(f"https://gmail.googleapis.com/gmail/v1/users/me/{endpoint}", headers={"Authorization": f"Bearer {token}"})
    with urlopen(request, timeout=20) as response:
        return __import__("json").loads(response.read().decode("utf-8"))


def start_scan(connection_id: str, limit: int, analyze: Callable[[bytes, str], dict], persist: Callable[[dict], object]) -> dict:
    if not status(connection_id)["connected"]:
        raise RuntimeError("Connect a Gmail account first.")
    limit = max(1, min(int(limit), 1000))
    with _lock:
        scanner = _connections[connection_id]["scanner"]
        if scanner["running"]:
            return status(connection_id)
        scanner.update({"running": True, "processed": 0, "requested": 0, "failed": 0, "sources": ["Unread Inbox", "Spam"], "last_error": None, "finished_at": None})
    threading.Thread(target=_scan, args=(connection_id, limit, analyze, persist), daemon=True, name="cipherx-google-oauth-scan").start()
    return status(connection_id)


def start_watch(connection_id: str, poll_seconds: int, analyze: Callable[[bytes, str], dict], persist: Callable[[dict], object]) -> dict:
    """Continuously re-check authorized unread Inbox and Spam, without mutating Gmail."""
    if not status(connection_id)["connected"]:
        raise RuntimeError("Connect a Gmail account first.")
    poll_seconds = max(30, min(int(poll_seconds), 3600))
    with _lock:
        record = _connections[connection_id]
        scanner = record["scanner"]
        if scanner["watching"]:
            return status(connection_id)
        record["watch_stop"].clear()
        scanner.update({"watching": True, "poll_seconds": poll_seconds, "last_error": None, "sources": ["Unread Inbox", "Spam"]})
    threading.Thread(target=_watch, args=(connection_id, poll_seconds, analyze, persist), daemon=True, name="cipherx-google-oauth-watch").start()
    return status(connection_id)


def stop_watch(connection_id: str) -> dict:
    with _lock:
        record = _connections.get(connection_id)
        if not record:
            raise RuntimeError("No Gmail account is connected for this browser session.")
        record["watch_stop"].set()
        record["scanner"]["watching"] = False
    return status(connection_id)


def _watch(connection_id: str, poll_seconds: int, analyze: Callable[[bytes, str], dict], persist: Callable[[dict], object]) -> None:
    while True:
        with _lock:
            record = _connections.get(connection_id)
            if not record or record["watch_stop"].is_set():
                return
        _scan(connection_id, 100, analyze, persist)
        with _lock:
            record = _connections.get(connection_id)
            if not record:
                return
            record["scanner"]["last_polled_at"] = datetime.now(timezone.utc).isoformat()
            stop_event = record["watch_stop"]
        if stop_event.wait(poll_seconds):
            return


def _scan(connection_id: str, limit: int, analyze: Callable[[bytes, str], dict], persist: Callable[[dict], object]) -> None:
    try:
        for source, query in (("gmail_oauth_unread_inbox", "is:unread in:inbox"), ("gmail_oauth_spam", "in:spam")):
            listing = _gmail_json(connection_id, f"messages?{urlencode({'q': query, 'maxResults': limit})}")
            messages = listing.get("messages", [])
            with _lock: _connections[connection_id]["scanner"]["requested"] += len(messages)
            for item in messages:
                try:
                    payload = _gmail_json(connection_id, f"messages/{item['id']}?format=raw")
                    raw = base64.urlsafe_b64decode(payload["raw"] + "===")
                    result = analyze(raw, f"gmail-api-{item['id']}.eml")
                    result["ingestion_source"] = source
                    persist(result)
                    with _lock: _connections[connection_id]["scanner"]["processed"] += 1
                except Exception:
                    with _lock: _connections[connection_id]["scanner"]["failed"] += 1
    except Exception as error:
        with _lock: _connections[connection_id]["scanner"]["last_error"] = f"{type(error).__name__}: {error}"
    finally:
        with _lock:
            scanner = _connections.get(connection_id, {}).get("scanner")
            if scanner:
                scanner["running"] = False; scanner["finished_at"] = datetime.now(timezone.utc).isoformat()
