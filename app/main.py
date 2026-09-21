from __future__ import annotations

import hashlib
import html
import json
import ipaddress
import re
import uuid
import os
import logging
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request as URLRequest, urlopen
from urllib.error import URLError
from functools import lru_cache

from fastapi import FastAPI, File, HTTPException, UploadFile, Request
from pydantic import BaseModel
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
from .realtime_monitor import ImapMonitor
from .mailbox_scanner import MailboxScanner
from .mailbox_store import save as save_case, dashboard as mailbox_dashboard
from .ml_engine import predict_phishing, model_status
from .forensics import protocol_evidence, domain_intelligence, behavioral_evidence
from .live_intelligence import authentication_intelligence
from .blockchain import status as blockchain_status, anchor as anchor_evidence, verify as verify_anchor
from .mailbox_store import case_hash, save_anchor, get_case, intelligence, clear_cases
from . import google_oauth
from . import external_mail_oauth

ROOT = Path(__file__).resolve().parent.parent
# Local development reads private configuration from .env.  Deployed hosts
# provide the same names as protected environment variables; those always win.
load_dotenv(ROOT / ".env", override=False)
ORGANIZATION_PROFILES = json.loads((ROOT / "data" / "organization_profiles.json").read_text(encoding="utf-8"))
app = FastAPI(title="CIPHER-X", version="1.0.0")
logger = logging.getLogger("cipherx.oauth")
frontend_url = os.getenv("CIPHERX_FRONTEND_URL", "").rstrip("/")
external_frontend = bool(frontend_url and frontend_url not in {"http://127.0.0.1:8000", "http://localhost:8000"})
app.add_middleware(SessionMiddleware, secret_key=os.getenv("CIPHERX_SESSION_SECRET", "cipherx-local-prototype-change-this"), https_only=external_frontend or os.getenv("CIPHERX_COOKIE_SECURE", "false").lower() == "true", same_site="none" if external_frontend else "lax")
app.add_middleware(CORSMiddleware, allow_origins=[origin for origin in {frontend_url, "http://127.0.0.1:8000", "http://localhost:8000"} if origin], allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
IP_RE = re.compile(r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])")
DOMAIN_RE = re.compile(r"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])", re.I)
SUSPICIOUS_WORDS = {
    "urgent": 5, "immediately": 4, "verify your account": 10, "password": 7,
    "credential": 10, "click here": 7, "suspended": 8, "wire transfer": 12,
    "gift card": 12, "invoice": 4, "payment": 5, "bitcoin": 8,
}
BRANDS = ("paypal", "microsoft", "google", "amazon", "bank", "apple", "netflix")
SENSITIVE_REQUESTS = {
    "otp": "One-time-password (OTP) reference",
    "one time password": "One-time-password reference",
    "verification code": "Verification-code reference",
    "transaction": "Financial or account transaction reference",
    "bank account": "Bank-account reference",
    "card number": "Payment-card reference",
}


def body_text(message) -> str:
    chunks = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart" or part.get_filename():
            continue
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        try:
            value = part.get_content()
            if isinstance(value, str):
                chunks.append(re.sub(r"<[^>]+>", " ", value))
        except Exception:
            continue
    return "\n".join(chunks)


def domain_of(value: str) -> str:
    value = value.lower().strip().strip(".")
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    return value


def email_domain(value: str) -> str:
    match = re.search(r"@([\w.-]+)", value or "")
    return domain_of(match.group(1)) if match else ""


def organization_context(sender_domain: str) -> dict | None:
    """Return a separately verified organisation profile, when one exists.

    This must never be inferred from a mail relay's IP. Profiles are curated
    from an organisation's own public contact information and may be absent.
    """
    profile = ORGANIZATION_PROFILES.get(sender_domain)
    if not profile:
        return None
    return {"domain": sender_domain, **profile}


def public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except ValueError:
        return False


def auth_status(headers: str, name: str) -> str:
    # This is evidence extracted from the receiver's Authentication-Results header.
    match = re.search(rf"\b{name}=([a-z]+)", headers, re.I)
    return match.group(1).upper() if match else "NOT PRESENT"


def received_ip_context(received_headers: list[str], all_ips: list[str]) -> dict[str, dict]:
    """Classify where an IP was observed without claiming it is the sender.

    `Received` fields are prepended by each mail relay. Therefore they document
    a delivery chain, not a user's GPS location. An IP in the earliest hop may
    be closer to the sending system, but remains unverified header evidence.
    """
    context: dict[str, dict] = {}
    for index, header in enumerate(received_headers):
        for ip in IP_RE.findall(header):
            if ip in context:
                continue
            if index == 0:
                role = "most recent observed upstream relay"
                trust = "higher"
            elif index == len(received_headers) - 1:
                role = "earliest observed mail relay"
                trust = "unverified"
            else:
                role = "intermediate mail relay"
                trust = "contextual"
            context[ip] = {"role": role, "header_position": index + 1, "routing_confidence": trust}
    for ip in all_ips:
        context.setdefault(ip, {"role": "indicator referenced outside Received headers", "header_position": None, "routing_confidence": "unverified"})
    return context


@lru_cache(maxsize=256)
def enrich_ip(ip: str) -> dict:
    """Return source-labelled IP infrastructure data.

    ipwho.is is used only for globally routable IPs. The service does not require
    an API key, making it appropriate for a hackathon demo.  Production should
    replace this adapter with an approved, contract-backed provider or local
    GeoIP database, and cache results outside process memory.
    """
    if not public_ip(ip):
        return {"ip": ip, "scope": "private/reserved", "country": "Not applicable", "region": "Not applicable", "city": "Not applicable", "latitude": None, "longitude": None, "asn": "N/A", "isp": "Not applicable", "organization": "Not applicable", "timezone": "N/A", "confidence": "high", "source": "RFC 1918 / reserved-address classification", "lookup_status": "not_applicable", "looked_up_at": datetime.now(timezone.utc).isoformat()}
    try:
        request = URLRequest(f"https://ipwho.is/{ip}", headers={"User-Agent": "CIPHER-X-SIH-MVP/1.0", "Accept": "application/json"})
        with urlopen(request, timeout=4) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not payload.get("success", True):
            raise ValueError(payload.get("message", "Provider returned no location"))
        connection = payload.get("connection") or {}
        lat, lon = payload.get("latitude"), payload.get("longitude")
        return {"ip": ip, "scope": "public", "country": payload.get("country") or "Unknown", "country_code": payload.get("country_code") or "", "region": payload.get("region") or "Unknown", "city": payload.get("city") or "Unknown", "latitude": lat if isinstance(lat, (int, float)) else None, "longitude": lon if isinstance(lon, (int, float)) else None, "asn": connection.get("asn") or "Unknown", "isp": connection.get("isp") or "Unknown", "organization": connection.get("org") or "Unknown", "timezone": (payload.get("timezone") or {}).get("id", "Unknown"), "confidence": "medium", "source": "ipwho.is live GeoIP lookup", "lookup_status": "enriched", "looked_up_at": datetime.now(timezone.utc).isoformat()}
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError, OSError) as exc:
        # Do not manufacture location data when the enrichment service is unavailable.
        return {"ip": ip, "scope": "public", "country": "Unknown", "region": "Unknown", "city": "Unknown", "latitude": None, "longitude": None, "asn": "Unknown", "isp": "Unknown", "organization": "Unknown", "timezone": "Unknown", "confidence": "low", "source": "Live GeoIP lookup unavailable", "lookup_status": "unavailable", "lookup_error": type(exc).__name__, "looked_up_at": datetime.now(timezone.utc).isoformat()}


def risk_level(score: int) -> str:
    return "CRITICAL" if score >= 81 else "HIGH" if score >= 61 else "MEDIUM" if score >= 31 else "LOW"


def intelligence_signals(text: str, sender_domain: str, domains: set[str]) -> list[dict]:
    """Return transparent content and domain-consistency signals.

    Signals are triage prompts, not proof that an email is malicious. This
    makes the output useful to analysts without presenting a hidden ML verdict.
    """
    lowered = text.lower()
    signals = []
    for phrase, label in SENSITIVE_REQUESTS.items():
        if phrase in lowered:
            signals.append({"type": "sensitive_request", "severity": "review", "label": label, "detail": "Treat requests for codes, credentials or transaction approval as sensitive. Verify through a trusted channel before responding."})
    external_domains = sorted(domain for domain in domains if domain and domain != sender_domain)
    if external_domains:
        signals.append({"type": "domain_consistency", "severity": "review", "label": "External domain observed", "detail": f"Sender domain is {sender_domain or 'unavailable'}; embedded or referenced domains include {', '.join(external_domains[:3])}. Check whether this relationship is expected."})
    if not signals:
        signals.append({"type": "content_triage", "severity": "info", "label": "No sensitive-request cue observed", "detail": "No configured OTP, credential, payment or transaction phrase was found. This does not prove the email is safe."})
    return signals


def analyze(raw: bytes, filename: str) -> dict:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    headers = "\n".join(f"{k}: {v}" for k, v in message.items())
    body = body_text(message)
    text = f"{message.get('Subject', '')}\n{body}"
    urls = sorted(set(URL_RE.findall(text)))
    domains = {domain_of(urlparse(u).hostname or "") for u in urls}
    sender = str(message.get("From", ""))
    sender_domain = email_domain(sender)
    protocol = protocol_evidence(message, sender_domain, urls)
    if sender_domain:
        domains.add(sender_domain)
    received = message.get_all("Received", [])
    ips = sorted(set(IP_RE.findall(headers + "\n" + text)))
    ip_context = received_ip_context(received, ips)
    evidence, score = [], 0

    def add(points: int, title: str, detail: str):
        nonlocal score
        score += points
        evidence.append({"points": points, "title": title, "detail": detail})

    auth = {kind.upper(): auth_status(headers, kind) for kind in ("spf", "dkim", "dmarc")}
    live_auth = authentication_intelligence(sender_domain, str(message.get("DKIM-Signature", "")))
    for kind, points in (("SPF", 18), ("DKIM", 14), ("DMARC", 16)):
        if auth[kind] in ("FAIL", "SOFTFAIL", "PERMERROR", "TEMPERROR"):
            add(points, f"{kind} authentication {auth[kind]}", "Receiver authentication evidence indicates a policy or signature failure.")
    for anomaly in protocol["anomalies"]:
        add(12, f"Identity anomaly: {anomaly['kind'].replace('_', ' ')}", anomaly["detail"])
    for finding in protocol["link_findings"]:
        add(7, f"Link analysis: {finding['kind']}", finding["detail"])
    behavior = behavioral_evidence(text, sender_domain, urls)
    for finding in behavior:
        add(finding["points"], f"Behavioral pattern: {finding['kind'].replace('_', ' ')}", finding["detail"])
    low_text = text.lower()
    pressure_context = any(cue in low_text for cue in ("urgent", "immediately", "click here", "suspended", "verify your account", "credential", "otp", "wire transfer"))
    for phrase, points in SUSPICIOUS_WORDS.items():
        if phrase in low_text:
            if phrase in ("password", "invoice", "payment") and not pressure_context:
                evidence.append({"points": 0, "title": f"Contextual term: '{phrase}'", "detail": "This common transactional term needs surrounding pressure or technical evidence before increasing risk."})
            else:
                add(points, f"Social-engineering cue: '{phrase}'", "Content contains a common phishing or BEC pressure signal.")
    ml_analysis = predict_phishing(text)
    if ml_analysis["phishing_probability"] >= 0.80:
        add(10, "ML triage: high phishing likelihood", f"Local explainable ML probability: {ml_analysis['phishing_probability']:.0%}. Review this alongside technical evidence.")
    elif ml_analysis["phishing_probability"] >= 0.50:
        evidence.append({"points": 0, "title": "ML triage: review signal", "detail": f"Local explainable ML probability: {ml_analysis['phishing_probability']:.0%}. The baseline model alone does not increase the forensic score."})
    domain_intel = [domain_intelligence(domain) for domain in sorted(domains)]
    for record in domain_intel:
        for finding in record["findings"]:
            if finding["type"] == "brand_similarity":
                add(12, f"Possible brand lookalike: {record['domain']}", finding["detail"])
            elif finding["type"] == "uncommon_tld":
                add(4, f"Uncommon phishing-abuse TLD: .{finding['tld']}", finding["detail"])
    if urls:
        evidence.append({"points": 0, "title": "Embedded URL(s) found", "detail": "URLs are preserved as investigation indicators. They do not increase risk unless a specific deceptive-link signal is observed."})
    if len(received) < 1:
        add(5, "No Received routing header", "Routing evidence is missing or stripped, reducing traceability.")
    attachments = []
    for part in message.walk():
        if part.get_filename():
            payload = part.get_payload(decode=True) or b""
            attachments.append({"name": part.get_filename(), "content_type": part.get_content_type(), "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
            if part.get_content_type() in ("application/x-msdownload", "application/x-dosexec") or part.get_filename().lower().endswith((".exe", ".js", ".vbs", ".scr")):
                add(18, f"Executable attachment: {part.get_filename()}", "Executable attachments should be handled as high-risk evidence.")
    if score == 0:
        evidence.append({"points": 0, "title": "No high-confidence risk signals found", "detail": "This is not proof of safety; investigate external reputation and mail-server logs if needed."})
    score = min(100, score)
    investigation_id = f"CX-{datetime.now():%Y%m%d}-{uuid.uuid4().hex[:6].upper()}"
    nodes = [{"id": "email", "label": "Email", "type": "email"}]
    edges = []
    for d in sorted(domains):
        node = f"domain:{d}"; nodes.append({"id": node, "label": d, "type": "domain"}); edges.append({"from": "email", "to": node, "label": "references"})
    for ip in ips:
        node = f"ip:{ip}"; nodes.append({"id": node, "label": ip, "type": "ip"}); edges.append({"from": "email", "to": node, "label": "observed in routing"})
    infrastructure = []
    for ip in ips:
        record = enrich_ip(ip).copy()
        record.update(ip_context[ip])
        # A public GeoIP result describes the registered/service location of
        # this relay. It cannot identify the organization named in From.
        record["location_interpretation"] = "Approximate location of the observed mail/network infrastructure, not the sender organization or a person."
        infrastructure.append(record)
    return {
        "investigation_id": investigation_id, "analyzed_at": datetime.now(timezone.utc).isoformat(), "evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "file": filename, "verdict": "SUSPICIOUS" if score >= 31 else "NO HIGH-RISK SIGNALS", "risk_score": score, "risk_level": risk_level(score),
        "confidence": min(95, 45 + len(evidence) * 7), "email": {"from": sender, "to": str(message.get("To", "")), "subject": str(message.get("Subject", "")), "date": str(message.get("Date", "")), "message_id": str(message.get("Message-ID", ""))}, "ml_analysis": ml_analysis,
        "authentication": auth, "live_authentication_intelligence": live_auth, "protocol_analysis": protocol, "behavioral_analysis": behavior, "domain_intelligence": domain_intel, "received_chain": received, "iocs": {"urls": urls, "domains": sorted(domains), "ips": ips, "attachments": attachments}, "organization_context": organization_context(sender_domain), "intelligence_signals": intelligence_signals(text, sender_domain, domains),
        "infrastructure": infrastructure, "evidence": sorted(evidence, key=lambda x: x["points"], reverse=True), "graph": {"nodes": nodes, "edges": edges},
        "limitations": ["CIPHER-X performs live SPF/DMARC/DKIM DNS policy lookup. Message-level SPF/DKIM/DMARC pass/fail values are receiver-provided header evidence; full cryptographic validation requires the original raw mail and a production verifier.", "GeoIP describes approximate network infrastructure from third-party IP intelligence. It does not identify the physical location of the organisation in From, an attacker, or a person.", "Received headers describe a relay chain. CIPHER-X labels each observed hop by its position and confidence instead of treating any IP as a confirmed source."],
    }


def analyze_and_store(raw: bytes, filename: str, ingestion_source: str = "authorized_mailbox") -> dict:
    result = analyze(raw, filename)
    result["ingestion_source"] = ingestion_source
    save_case(result)
    return result


monitor = ImapMonitor(analyze_and_store)
mailbox_scanner = MailboxScanner(analyze, save_case)


@app.get("/", response_class=HTMLResponse)
def home():
    return (ROOT / "static" / "index.html").read_text(encoding="utf-8")


@app.post("/api/analyze")
async def upload(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(400, "Upload an RFC 822 .eml file.")
    raw = await file.read()
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(413, "Maximum upload size is 10 MB.")
    try:
        return JSONResponse(analyze_and_store(raw, file.filename, "eml_upload"))
    except Exception as exc:
        raise HTTPException(422, f"Could not parse email: {exc}")


class PasteEmail(BaseModel):
    content: str
    filename: str = "pasted-email.eml"


@app.post("/api/analyze/paste")
def analyze_pasted_email(request: PasteEmail):
    if not request.content.strip():
        raise HTTPException(400, "Paste an email message or RFC 822 headers before analysis.")
    raw = request.content.encode("utf-8", errors="replace")
    try:
        return JSONResponse(analyze_and_store(raw, request.filename, "pasted_message"))
    except Exception as exc:
        raise HTTPException(422, f"Could not parse pasted email: {exc}")


@app.post("/api/demo/phishing")
def run_phishing_demo():
    """Analyze the bundled, clearly labelled test message for demonstrations."""
    sample = ROOT / "samples" / "phishing-demo.eml"
    if not sample.exists():
        raise HTTPException(404, "The bundled phishing demonstration file is unavailable.")
    result = analyze(sample.read_bytes(), sample.name)
    result["ingestion_source"] = "bundled_test_file"
    save_case(result)
    return JSONResponse(result)


@app.get("/api/monitor/status")
def monitor_status():
    """Safe status endpoint. It never exposes IMAP hostnames or credentials."""
    return monitor.status()


@app.get("/api/monitor/events")
def monitor_events():
    return {"events": monitor.events()}


@app.post("/api/monitor/start")
def start_monitor():
    try:
        monitor.start()
        return monitor.status()
    except RuntimeError as error:
        raise HTTPException(400, str(error))


@app.post("/api/monitor/stop")
def stop_monitor():
    monitor.stop()
    return monitor.status()


def gmail_connection_status(request: Request) -> dict:
    """Return browser-session OAuth state without exposing any token material."""
    result = google_oauth.status(request.session.get("gmail_connection_id"))
    result["last_error"] = request.session.get("gmail_oauth_error")
    return result


@app.get("/api/mailbox/dashboard")
def get_mailbox_dashboard(request: Request):
    providers = {name: external_mail_oauth.status(name, request.session.get(f"{name}_connection_id")) for name in external_mail_oauth.PROVIDERS}
    return {"scanner": mailbox_scanner.status(), "google": gmail_connection_status(request), "providers": providers, "monitor": monitor.status(), "ml": model_status(), "dashboard": mailbox_dashboard()}


@app.get("/api/gmail/oauth/status")
def gmail_oauth_status(request: Request):
    return gmail_connection_status(request)


@app.get("/api/gmail/oauth/start")
def gmail_oauth_start(request: Request):
    try:
        url, state, code_verifier = google_oauth.authorization_url()
        request.session.pop("gmail_oauth_error", None)
        request.session["gmail_oauth_state"] = state
        request.session["gmail_oauth_code_verifier"] = code_verifier
        return RedirectResponse(url)
    except RuntimeError as error:
        raise HTTPException(503, str(error))


@app.get("/api/gmail/oauth/callback")
def gmail_oauth_callback(request: Request, state: str = "", code: str = "", error: str = ""):
    # A local installation normally has no CIPHERX_FRONTEND_URL.  Do not build
    # URLs as "//?…" in that case: browsers treat that as a scheme-relative
    # URL and may send the OAuth callback into a redirect loop.
    configured_frontend = os.getenv("CIPHERX_FRONTEND_URL", "").strip().rstrip("/")
    frontend_url = configured_frontend or ""
    def dashboard_redirect(query: str) -> RedirectResponse:
        destination = f"{frontend_url}/?{query}" if frontend_url else f"/?{query}"
        return RedirectResponse(destination, status_code=303)
    if error:
        logger.warning("Google OAuth returned error: %s", error)
        request.session["gmail_oauth_error"] = f"Google declined authorization: {error}. Confirm that this Gmail address is listed as a Google Cloud test user."
        return dashboard_redirect(f"gmail_error={error}")
    if not code or state != request.session.get("gmail_oauth_state"):
        logger.warning("Google OAuth state validation failed.")
        request.session["gmail_oauth_error"] = "The secure Google login session did not match this browser. Start the Gmail connection again from the CIPHER-X dashboard."
        return dashboard_redirect("gmail_error=invalid_oauth_state")
    try:
        request.session["gmail_connection_id"] = google_oauth.complete_authorization(code, request.session.get("gmail_oauth_code_verifier", ""))
        request.session.pop("gmail_oauth_state", None)
        request.session.pop("gmail_oauth_code_verifier", None)
        request.session.pop("gmail_oauth_error", None)
        return dashboard_redirect("gmail_connected=1")
    except Exception as exc:
        logger.exception("Google OAuth token exchange failed")
        request.session["gmail_oauth_error"] = "Google approved access, but CIPHER-X could not complete the secure token exchange. See the server terminal for the exact technical error, then reconnect."
        return dashboard_redirect("gmail_error=authorization_failed")


@app.post("/api/gmail/oauth/disconnect")
def gmail_oauth_disconnect(request: Request):
    google_oauth.disconnect(request.session.get("gmail_connection_id"))
    request.session.pop("gmail_connection_id", None)
    request.session.pop("gmail_oauth_error", None)
    return {"connected": False, "message": "Gmail access was disconnected for this browser session."}


@app.post("/api/gmail/oauth/scan")
def gmail_oauth_scan(request: Request, limit: int = 250):
    try:
        return google_oauth.start_scan(request.session.get("gmail_connection_id", ""), limit, analyze, save_case)
    except RuntimeError as error:
        raise HTTPException(400, str(error))


@app.post("/api/gmail/oauth/watch/start")
def gmail_oauth_watch_start(request: Request, poll_seconds: int = 60):
    try:
        return google_oauth.start_watch(request.session.get("gmail_connection_id", ""), poll_seconds, analyze, save_case)
    except RuntimeError as error:
        raise HTTPException(400, str(error))


@app.post("/api/gmail/oauth/watch/stop")
def gmail_oauth_watch_stop(request: Request):
    try:
        return google_oauth.stop_watch(request.session.get("gmail_connection_id", ""))
    except RuntimeError as error:
        raise HTTPException(400, str(error))


@app.get("/api/mail/oauth/{provider}/start")
def external_oauth_start(provider: str, request: Request):
    try:
        url, state, verifier = external_mail_oauth.authorization_url(provider)
        request.session[f"{provider}_oauth_state"] = state
        request.session[f"{provider}_oauth_verifier"] = verifier
        return RedirectResponse(url)
    except (RuntimeError, KeyError) as error:
        raise HTTPException(503, str(error))


@app.get("/api/mail/oauth/{provider}/callback")
def external_oauth_callback(provider: str, request: Request, state: str = "", code: str = "", error: str = ""):
    configured_frontend = os.getenv("CIPHERX_FRONTEND_URL", "").strip().rstrip("/")
    def redirect(query: str): return RedirectResponse(f"{configured_frontend}/?{query}" if configured_frontend else f"/?{query}", status_code=303)
    if error or not code or state != request.session.get(f"{provider}_oauth_state"):
        return redirect(f"mail_error={provider}")
    try:
        request.session[f"{provider}_connection_id"] = external_mail_oauth.complete_authorization(provider, code, request.session.get(f"{provider}_oauth_verifier", ""))
        request.session.pop(f"{provider}_oauth_state", None); request.session.pop(f"{provider}_oauth_verifier", None)
        return redirect(f"mail_connected={provider}")
    except Exception:
        logger.exception("%s OAuth token exchange failed", provider)
        return redirect(f"mail_error={provider}")


@app.post("/api/mail/oauth/{provider}/scan")
def external_oauth_scan(provider: str, request: Request, limit: int = 250):
    try: return external_mail_oauth.start_scan(provider, request.session.get(f"{provider}_connection_id", ""), limit, analyze, save_case)
    except (RuntimeError, KeyError) as error: raise HTTPException(400, str(error))


@app.post("/api/mail/oauth/{provider}/disconnect")
def external_oauth_disconnect(provider: str, request: Request):
    try:
        external_mail_oauth.disconnect(provider, request.session.get(f"{provider}_connection_id")); request.session.pop(f"{provider}_connection_id", None)
        return {"connected": False}
    except KeyError: raise HTTPException(404, "Unsupported mail provider.")


@app.get("/api/investigations")
def investigations():
    return mailbox_dashboard()


@app.post("/api/investigations/clear")
def clear_investigations():
    removed = clear_cases()
    return {"removed_cases": removed, "message": "Local CIPHER-X investigation data cleared. Gmail messages were not changed."}


@app.get("/api/investigations/{case_id}")
def investigation(case_id: str):
    item = get_case(case_id)
    if not item:
        raise HTTPException(404, "Investigation not found.")
    return item


@app.get("/api/intelligence")
def threat_intelligence():
    return intelligence()


@app.get("/api/system/capabilities")
def system_capabilities():
    """An auditable feature inventory for demos and deployment reviews.

    This route deliberately separates working evidence sources from optional
    production integrations.  It prevents the dashboard or a report from
    implying that an unavailable threat feed or antivirus engine ran.
    """
    return {
        "implemented": [
            "RFC 822 (.eml) parsing and Gmail IMAP mailbox scanning in read-only mode",
            "header, Received-chain, sender/Reply-To/Return-Path and URL structure analysis",
            "receiver-provided SPF/DKIM/DMARC result parsing plus live public DNS policy lookup",
            "passive IP infrastructure enrichment, routing-hop labelling and IOC extraction",
            "explainable local TF-IDF + Logistic Regression language triage",
            "attachment hashing, executable-file flagging, evidence hashing and local chain-of-custody cases",
            "HTML forensic report, case archive, evidence anchoring adapter and real-time IMAP polling",
        ],
        "optional_not_enabled": [
            "VirusTotal, AbuseIPDB and URLhaus reputation queries require a configured API key and approved data-sharing policy.",
            "ClamAV attachment scanning requires a locally installed and updated ClamAV service.",
            "Full cryptographic DKIM verification and SMTP-context SPF evaluation require a production mail-authentication verifier.",
            "DistilBERT requires a reviewed, trained model artifact; it is not represented as active by this prototype.",
        ],
        "data_handling": "Gmail access is IMAP read-only. Public DNS lookups contain only a sender domain; IP enrichment contains only observed public IP addresses.",
        "model": model_status(),
    }


@app.post("/api/mailbox/scan")
def scan_mailbox(limit: int = 250):
    try:
        mailbox_scanner.start(limit)
        return mailbox_scanner.status()
    except RuntimeError as error:
        raise HTTPException(400, str(error))


@app.get("/api/blockchain/status")
def get_blockchain_status():
    return blockchain_status()


@app.post("/api/cases/{case_id}/anchor")
def anchor_case(case_id: str):
    evidence_hash = case_hash(case_id)
    if not evidence_hash:
        raise HTTPException(404, "Case not found in the local evidence index.")
    try:
        anchored = anchor_evidence(case_id, evidence_hash)
        save_anchor(anchored)
        return anchored
    except RuntimeError as error:
        raise HTTPException(400, str(error))


@app.get("/api/evidence/{evidence_hash}/blockchain")
def verify_evidence_anchor(evidence_hash: str):
    try:
        return verify_anchor(evidence_hash)
    except RuntimeError as error:
        raise HTTPException(400, str(error))


def report_page(result: dict) -> str:
    safe = lambda value: html.escape(str(value if value is not None else ""))
    evidence = result.get("evidence", [])
    rows = "".join(f"<tr><td>{safe(e.get('title'))}</td><td>{int(e.get('points', 0)):+d}</td><td>{safe(e.get('detail'))}</td></tr>" for e in evidence) or "<tr><td colspan='3'>No scored evidence was retained.</td></tr>"
    ioc_data = result.get("iocs", {})
    iocs = "<br>".join(safe(x) for x in ioc_data.get("urls", []) + ioc_data.get("domains", []) + ioc_data.get("ips", [])) or "None observed"
    infra_rows = "".join(f"<tr><td>{safe(i.get('ip'))}</td><td>{safe(i.get('role'))}</td><td>{safe(i.get('country'))}</td><td>{safe(i.get('city'))}, {safe(i.get('region'))}</td><td>{safe(i.get('asn'))} / {safe(i.get('isp'))}</td></tr>" for i in result.get("infrastructure", [])) or "<tr><td colspan='5'>No public routing IP was observed.</td></tr>"
    auth = result.get("authentication", {})
    auth_rows = "".join(f"<tr><td>{safe(kind)}</td><td>{safe(value)}</td></tr>" for kind, value in auth.items()) or "<tr><td colspan='2'>No receiver authentication values were present.</td></tr>"
    live_auth = result.get("live_authentication_intelligence", {})
    policy_rows = "".join(f"<tr><td>{safe(label.replace('_', ' ').title())}</td><td>{safe(value)}</td></tr>" for label, value in live_auth.items() if label not in {"spf_records", "dmarc_records", "dkim_records"}) or "<tr><td colspan='2'>Live DNS policy lookup was unavailable.</td></tr>"
    protocol = result.get("protocol_analysis", {})
    protocol_rows = "".join(f"<tr><td>{safe(item.get('kind'))}</td><td>{safe(item.get('detail'))}</td></tr>" for item in protocol.get("anomalies", [])) or "<tr><td colspan='2'>No configured identity anomaly observed.</td></tr>"
    domains = result.get("domain_intelligence", [])
    domain_rows = "".join(f"<tr><td>{safe(record.get('domain'))}</td><td>{safe('; '.join(str(f.get('detail', '')) for f in record.get('findings', [])) or 'No configured lookalike/TLD signal')}</td></tr>" for record in domains) or "<tr><td colspan='2'>No domains observed.</td></tr>"
    ml = result.get("ml_analysis", {})
    cues = ", ".join(safe(cue.get("term")) for cue in ml.get("top_text_cues", [])) or "No positive text cue"
    cue_rows = "".join(f"<tr><td>{safe(cue.get('term'))}</td><td>{safe(cue.get('contribution'))}</td><td>Relative local-model feature influence; not a standalone maliciousness finding.</td></tr>" for cue in ml.get("top_text_cues", [])) or "<tr><td colspan='3'>No positive phishing-language feature was extracted.</td></tr>"
    attachment_rows = "".join(f"<tr><td>{safe(item.get('name'))}</td><td>{safe(item.get('content_type'))}</td><td>{safe(item.get('size'))}</td><td>{safe(item.get('sha256'))}</td></tr>" for item in ioc_data.get("attachments", [])) or "<tr><td colspan='4'>No attachment observed.</td></tr>"
    header_data = protocol.get("headers", {})
    header_rows = "".join(f"<tr><td>{safe(label)}</td><td>{safe(value)}</td></tr>" for label, value in (
        ("From", result.get("email", {}).get("from")), ("To", result.get("email", {}).get("to")), ("Subject", result.get("email", {}).get("subject")),
        ("Date", result.get("email", {}).get("date")), ("Message-ID", header_data.get("message_id")), ("Reply-To", header_data.get("reply_to")),
        ("Return-Path", header_data.get("return_path")), ("Received header count", header_data.get("received_hops")), ("DKIM-Signature present", header_data.get("dkim_signature_present")),
    ))
    received_rows = "".join(f"<tr><td>{index + 1}</td><td>{safe(value)}</td></tr>" for index, value in enumerate(result.get("received_chain", []))) or "<tr><td colspan='2'>No Received routing header was available.</td></tr>"
    behavior_rows = "".join(f"<tr><td>{safe(item.get('kind', '').replace('_', ' ').title())}</td><td>+{safe(item.get('points'))}</td><td>{safe(item.get('detail'))}</td></tr>" for item in result.get("behavioral_analysis", [])) or "<tr><td colspan='3'>No concrete credential-harvesting or BEC combination was observed.</td></tr>"
    email_addresses = [result.get("email", {}).get("from"), result.get("email", {}).get("to"), header_data.get("reply_to"), header_data.get("return_path")]
    email_addresses = [value for value in email_addresses if value]
    ioc_inventory = f"<b>URLs:</b> {safe(', '.join(ioc_data.get('urls', [])) or 'None')}<br><b>Domains:</b> {safe(', '.join(ioc_data.get('domains', [])) or 'None')}<br><b>Observed IPs:</b> {safe(', '.join(ioc_data.get('ips', [])) or 'None')}<br><b>Email fields:</b> {safe(' | '.join(email_addresses) or 'None')}<br><b>Attachment SHA-256:</b> {safe(', '.join(item.get('sha256', '') for item in ioc_data.get('attachments', [])) or 'None')}"
    module_rows = "".join((
        "<tr><td>Evidence ingestion and SHA-256 preservation</td><td>Complete</td><td>Source file, analysis time and evidence hash recorded; raw email is not retained by default.</td></tr>",
        "<tr><td>MIME, header, identity and routing analysis</td><td>Complete</td><td>Parsed fields, MIME attachment metadata and Received headers are included in this report.</td></tr>",
        "<tr><td>SPF / DKIM / DMARC</td><td>Header evidence + live DNS policy lookup</td><td>Receiver-reported outcomes and public sender-domain policy records are shown above.</td></tr>",
        "<tr><td>Domain, URL, BEC and impersonation analysis</td><td>Complete for observable signals</td><td>Only detected signals are scored; absence of a signal is not proof of safety.</td></tr>",
        "<tr><td>IP / GeoIP infrastructure context</td><td>Complete where public IPs are observed</td><td>Each result identifies its network-location provider and routing confidence.</td></tr>",
        f"<tr><td>Explainable ML</td><td>{safe(ml.get('model', 'Unavailable'))}</td><td>Local text triage is displayed with feature influence and is never the sole final verdict.</td></tr>",
        "<tr><td>External reputation / malware scanning</td><td>Not run unless explicitly configured</td><td>No VirusTotal, AbuseIPDB, URLhaus or ClamAV result is claimed in this report.</td></tr>",
        "<tr><td>Blockchain anchoring</td><td>Optional analyst action</td><td>Only the evidence hash can be anchored after case review; raw mail is never put on-chain.</td></tr>",
    ))
    limitations = "<br>".join(safe(item) for item in result.get("limitations", [])) or "None recorded."
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>CIPHER-X Forensic Report</title><style>body{{font:15px Arial;margin:38px;color:#15243a;line-height:1.45}}h1{{color:#0f766e;margin-bottom:2px}}h2{{margin-top:28px;color:#0f5265}}table{{border-collapse:collapse;width:100%;margin:8px 0 16px}}td,th{{border:1px solid #cbd5e1;padding:8px;text-align:left;vertical-align:top}}th{{background:#edf7f7}}.score{{font-size:32px;color:#b91c1c;font-weight:bold}}.note{{border-left:4px solid #e09c22;padding:10px;background:#fff8e7}}.meta{{color:#526477}}.status{{font-weight:bold;color:#0f766e}}</style></head><body><h1>CIPHER-X Final Mail Investigation Report</h1><p class='meta'>Evidence-oriented email triage report — every module records a finding, evidence source, or explicit unavailable status.</p><p><b>Investigation:</b> {safe(result.get('investigation_id'))}<br><b>Evidence SHA-256:</b> {safe(result.get('evidence_sha256'))}<br><b>Generated:</b> {safe(result.get('analyzed_at'))}<br><b>Ingestion:</b> {safe(result.get('ingestion_source', 'authorized_mailbox'))}<br><b>Source file:</b> {safe(result.get('file'))}</p><p class='score'>{safe(result.get('risk_score'))}/100 — {safe(result.get('risk_level'))}</p><h2>1. Evidence preservation and message headers</h2><p><span class='status'>Preserved evidence metadata:</span> SHA-256 is recorded before analysis. The local case index stores the result and chain-of-custody entry; it does not retain raw email by default.</p><table><tr><th>Header / field</th><th>Observed value</th></tr>{header_rows}</table><h2>2. Header forensics and authentication</h2><table><tr><th>Mechanism</th><th>Receiver-reported result</th></tr>{auth_rows}</table><p>Live public DNS sender-policy lookup:</p><table><tr><th>Field</th><th>Observed value</th></tr>{policy_rows}</table><table><tr><th>Identity check</th><th>Finding</th></tr>{protocol_rows}</table><h2>3. Relay path and network-origin context</h2><table><tr><th>Received position</th><th>Raw relay evidence</th></tr>{received_rows}</table><table><tr><th>IP</th><th>Routing role</th><th>Network country</th><th>Service city / region</th><th>ASN / operator</th></tr>{infra_rows}</table><p class='note'>Received headers can be incomplete or forged. GeoIP is approximate network-infrastructure context; it does not establish a person's or organisation's physical location.</p><h2>4. Domain, URL, attachment and IOC inventory</h2><table><tr><th>Domain</th><th>Configured lookalike / TLD findings</th></tr>{domain_rows}</table><table><tr><th>Name</th><th>Declared type</th><th>Bytes</th><th>SHA-256</th></tr>{attachment_rows}</table><p>{ioc_inventory}</p><h2>5. Behavioural fraud and BEC analysis</h2><table><tr><th>Pattern</th><th>Points</th><th>Evidence-based interpretation</th></tr>{behavior_rows}</table><h2>6. Explainable AI evidence</h2><p><b>Model:</b> {safe(ml.get('model'))}<br><b>Phishing-language probability:</b> {safe(ml.get('phishing_probability'))}<br><b>Label:</b> {safe(ml.get('label'))}<br><b>Model limitation:</b> {safe(ml.get('limitations'))}</p><table><tr><th>Extracted text feature</th><th>Relative influence</th><th>Interpretation</th></tr>{cue_rows}</table><h2>7. Evidence-fusion risk assessment</h2><table><tr><th>Finding</th><th>Points</th><th>Explanation</th></tr>{rows}</table><p class='note'>The final risk score is a transparent sum of shown forensic evidence. The ML probability alone never creates a high-risk verdict.</p><h2>8. Module execution ledger</h2><table><tr><th>Module</th><th>Status</th><th>What this report proves</th></tr>{module_rows}</table><h2>9. Limitations and analyst hand-off</h2><p>{limitations}</p><p class='note'>This report supports triage, forensic preservation and investigator hand-off. It is not conclusive attribution; verify material findings with mail-server logs, approved reputation services and a qualified analyst.</p><script>print()</script></body></html>"""


@app.get("/api/investigations/{case_id}/report")
def saved_case_report(case_id: str):
    result = get_case(case_id)
    if not result:
        raise HTTPException(404, "Investigation not found.")
    return HTMLResponse(report_page(result), headers={"Content-Disposition": f"inline; filename={case_id}-forensic-report.html"})


@app.get("/api/investigations/{case_id}/report/download")
def download_saved_case_report(case_id: str):
    """Download a locally generated forensic report without reopening the dashboard."""
    result = get_case(case_id)
    if not result:
        raise HTTPException(404, "Investigation not found.")
    return HTMLResponse(report_page(result), headers={"Content-Disposition": f'attachment; filename="{case_id}-forensic-report.html"'})


@app.post("/api/report/html")
async def report(file: UploadFile = File(...)):
    raw = await file.read()
    return HTMLResponse(report_page(analyze(raw, file.filename or "email.eml")), headers={"Content-Disposition": "inline; filename=forensic-report.html"})
