"""Read-only OAuth connectors for Outlook/Microsoft 365 and Yahoo Mail.

Provider credentials stay in environment variables. Tokens are temporary,
in-memory prototype state and are never returned through the API.
"""
from __future__ import annotations

import base64, hashlib, imaplib, json, os, secrets, threading, uuid
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlencode
from urllib.request import Request, urlopen

PROVIDERS = {
    "outlook": {
        "label": "Outlook / Microsoft 365", "prefix": "CIPHERX_MICROSOFT",
        "authorize": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "scopes": ["openid", "profile", "email", "offline_access", "https://graph.microsoft.com/User.Read", "https://graph.microsoft.com/Mail.Read"],
    },
    "yahoo": {
        "label": "Yahoo Mail", "prefix": "CIPHERX_YAHOO",
        "authorize": "https://api.login.yahoo.com/oauth2/request_auth",
        "token": "https://api.login.yahoo.com/oauth2/get_token", "scopes": ["openid", "mail-r"],
    },
}
_connections: dict[str, dict] = {}
_lock = threading.Lock()

def _settings(provider: str) -> tuple[str, str, str]:
    item = PROVIDERS[provider]; prefix = item["prefix"]
    return os.getenv(f"{prefix}_CLIENT_ID", ""), os.getenv(f"{prefix}_CLIENT_SECRET", ""), os.getenv(f"{prefix}_REDIRECT_URI", "")

def configured(provider: str) -> bool:
    try: return bool(all(_settings(provider)))
    except KeyError: return False

def provider_catalog() -> dict:
    return {key: {"label": item["label"], "configured": configured(key), "connection_mode": "OAuth 2.0 read-only"} for key, item in PROVIDERS.items()}

def authorization_url(provider: str) -> tuple[str, str, str]:
    if provider not in PROVIDERS or not configured(provider):
        raise RuntimeError(f"{PROVIDERS.get(provider, {}).get('label', provider)} OAuth is not configured. Add its client ID, client secret and redirect URI to .env.")
    client_id, _, redirect_uri = _settings(provider)
    state = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    params = {"client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code", "state": state, "scope": " ".join(PROVIDERS[provider]["scopes"])}
    if provider == "outlook": params.update({"response_mode": "query", "code_challenge": challenge, "code_challenge_method": "S256"})
    return f"{PROVIDERS[provider]['authorize']}?{urlencode(params)}", state, verifier

def _json(url: str, token: str | None = None, form: dict | None = None) -> dict:
    headers = {"Accept": "application/json"}; body = None
    if token: headers["Authorization"] = f"Bearer {token}"
    if form is not None: headers["Content-Type"] = "application/x-www-form-urlencoded"; body = urlencode(form).encode()
    with urlopen(Request(url, data=body, headers=headers), timeout=25) as response:
        return json.loads(response.read().decode())

def complete_authorization(provider: str, code: str, verifier: str) -> str:
    client_id, client_secret, redirect_uri = _settings(provider)
    if not verifier: raise RuntimeError("The secure OAuth verifier is missing. Start the connection again from CIPHER-X.")
    form = {"client_id": client_id, "client_secret": client_secret, "code": code, "redirect_uri": redirect_uri, "grant_type": "authorization_code"}
    if provider == "outlook": form["code_verifier"] = verifier
    token_data = _json(PROVIDERS[provider]["token"], form=form)
    token = token_data.get("access_token")
    if not token: raise RuntimeError("The provider did not return an access token.")
    if provider == "outlook": profile = _json("https://graph.microsoft.com/v1.0/me?$select=mail,userPrincipalName", token); email = profile.get("mail") or profile.get("userPrincipalName")
    else: profile = _json("https://api.login.yahoo.com/openid/v1/userinfo", token); email = profile.get("email") or profile.get("preferred_username")
    connection_id = uuid.uuid4().hex
    with _lock:
        _connections[connection_id] = {"provider": provider, "email": email or f"Authorized {PROVIDERS[provider]['label']} account", "token": token, "scanner": {"running": False, "processed": 0, "requested": 0, "failed": 0, "sources": [], "last_error": None, "finished_at": None}}
    return connection_id

def status(provider: str, connection_id: str | None) -> dict:
    with _lock:
        item = _connections.get(connection_id or "")
        label = PROVIDERS[provider]["label"]
        if not item or item["provider"] != provider: return {"label": label, "configured": configured(provider), "connected": False, "email": None, "scanner": None, "token_storage": "No token is stored for this browser session."}
        return {"label": label, "configured": configured(provider), "connected": True, "email": item["email"], "scanner": dict(item["scanner"]), "token_storage": "Temporary server-side session storage; removed when disconnected or this prototype server restarts."}

def disconnect(provider: str, connection_id: str | None) -> None:
    with _lock:
        if connection_id in _connections and _connections[connection_id]["provider"] == provider: _connections.pop(connection_id, None)

def start_scan(provider: str, connection_id: str, limit: int, analyze: Callable[[bytes, str], dict], persist: Callable[[dict], object]) -> dict:
    if not status(provider, connection_id)["connected"]: raise RuntimeError(f"Connect a {PROVIDERS[provider]['label']} account first.")
    limit = max(1, min(int(limit), 1000))
    with _lock:
        scanner = _connections[connection_id]["scanner"]
        if scanner["running"]: return status(provider, connection_id)
        scanner.update({"running": True, "processed": 0, "requested": 0, "failed": 0, "sources": ["Unread Inbox", "Spam / Junk"], "last_error": None, "finished_at": None})
    threading.Thread(target=_scan, args=(provider, connection_id, limit, analyze, persist), daemon=True, name=f"cipherx-{provider}-scan").start()
    return status(provider, connection_id)

def _record(connection_id: str) -> dict:
    with _lock:
        if connection_id not in _connections: raise RuntimeError("Mailbox session ended.")
        return _connections[connection_id]

def _outlook_messages(record: dict, limit: int):
    token = record["token"]
    for source, folder in (("outlook_unread_inbox", "inbox"), ("outlook_junk", "junkemail")):
        query = urlencode({"$filter": "isRead eq false", "$top": limit, "$select": "id"})
        listing = _json(f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder}/messages?{query}", token)
        for message in listing.get("value", []):
            request = Request(f"https://graph.microsoft.com/v1.0/me/messages/{message['id']}/$value", headers={"Authorization": f"Bearer {token}", "Accept": "message/rfc822"})
            with urlopen(request, timeout=25) as response: yield source, f"outlook-{message['id']}.eml", response.read()

def _yahoo_messages(record: dict, limit: int):
    mail = imaplib.IMAP4_SSL("imap.mail.yahoo.com", 993)
    try:
        auth = f"user={record['email']}\x01auth=Bearer {record['token']}\x01\x01".encode()
        mail.authenticate("XOAUTH2", lambda _: auth)
        status, boxes = mail.list()
        names = b" ".join(boxes or []).decode(errors="ignore")
        spam = "Bulk Mail" if "Bulk Mail" in names else "Spam"
        for source, folder in (("yahoo_unread_inbox", "INBOX"), ("yahoo_spam", spam)):
            if mail.select(f'"{folder}"', readonly=True)[0] != "OK": continue
            _, values = mail.search(None, "UNSEEN")
            for message_id in (values[0].split()[-limit:] if values and values[0] else []):
                _, payload = mail.fetch(message_id, "(RFC822)")
                raw = next((part[1] for part in payload if isinstance(part, tuple) and isinstance(part[1], bytes)), b"")
                if raw: yield source, f"yahoo-{message_id.decode()}.eml", raw
    finally:
        try: mail.logout()
        except Exception: pass

def _scan(provider: str, connection_id: str, limit: int, analyze: Callable[[bytes, str], dict], persist: Callable[[dict], object]) -> None:
    try:
        record = _record(connection_id); iterator = _outlook_messages(record, limit) if provider == "outlook" else _yahoo_messages(record, limit)
        for source, filename, raw in iterator:
            with _lock: _connections[connection_id]["scanner"]["requested"] += 1
            try:
                result = analyze(raw, filename); result["ingestion_source"] = source; persist(result)
                with _lock: _connections[connection_id]["scanner"]["processed"] += 1
            except Exception:
                with _lock: _connections[connection_id]["scanner"]["failed"] += 1
    except Exception as error:
        with _lock: _connections[connection_id]["scanner"]["last_error"] = f"{type(error).__name__}: {error}"
    finally:
        with _lock:
            record = _connections.get(connection_id)
            if record: record["scanner"].update({"running": False, "finished_at": datetime.now(timezone.utc).isoformat()})
