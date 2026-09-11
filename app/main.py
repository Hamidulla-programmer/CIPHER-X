from __future__ import annotations

import hashlib
import html
import json
import ipaddress
import re
import uuid
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError
from functools import lru_cache

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent.parent
ORGANIZATION_PROFILES = json.loads((ROOT / "data" / "organization_profiles.json").read_text(encoding="utf-8"))
app = FastAPI(title="CIPHER-X", version="1.0.0")
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
        request = Request(f"https://ipwho.is/{ip}", headers={"User-Agent": "CIPHER-X-SIH-MVP/1.0", "Accept": "application/json"})
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
    for kind, points in (("SPF", 18), ("DKIM", 14), ("DMARC", 16)):
        if auth[kind] in ("FAIL", "SOFTFAIL", "PERMERROR", "TEMPERROR"):
            add(points, f"{kind} authentication {auth[kind]}", "Receiver authentication evidence indicates a policy or signature failure.")
    low_text = text.lower()
    for phrase, points in SUSPICIOUS_WORDS.items():
        if phrase in low_text:
            add(points, f"Social-engineering cue: '{phrase}'", "Content contains a common phishing or BEC pressure signal.")
    for domain in sorted(domains):
        compact = domain.replace("-", "").replace("0", "o").replace("1", "l")
        if any(brand in compact and domain != f"{brand}.com" for brand in BRANDS):
            add(15, f"Possible brand lookalike: {domain}", "Domain resembles a frequently impersonated brand and needs analyst verification.")
    if urls:
        add(min(10, len(urls) * 4), "Embedded URL(s) found", "URLs are preserved as investigation indicators. This MVP does not claim a live URL-reputation verdict.")
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
        "confidence": min(95, 45 + len(evidence) * 7), "email": {"from": sender, "to": str(message.get("To", "")), "subject": str(message.get("Subject", "")), "date": str(message.get("Date", "")), "message_id": str(message.get("Message-ID", ""))},
        "authentication": auth, "received_chain": received, "iocs": {"urls": urls, "domains": sorted(domains), "ips": ips, "attachments": attachments}, "organization_context": organization_context(sender_domain), "intelligence_signals": intelligence_signals(text, sender_domain, domains),
        "infrastructure": infrastructure, "evidence": sorted(evidence, key=lambda x: x["points"], reverse=True), "graph": {"nodes": nodes, "edges": edges},
        "limitations": ["Authentication values are parsed from message headers; this prototype does not perform live SPF/DKIM/DMARC validation.", "GeoIP describes approximate network infrastructure from a third-party source. It does not identify the physical location of the organisation named in From, an attacker, or a person.", "Received headers describe a relay chain. CIPHER-X labels each observed hop by its position and confidence instead of treating any IP as a confirmed source."],
    }


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
        return JSONResponse(analyze(raw, file.filename))
    except Exception as exc:
        raise HTTPException(422, f"Could not parse email: {exc}")


@app.post("/api/report/html")
async def report(file: UploadFile = File(...)):
    raw = await file.read(); result = analyze(raw, file.filename or "email.eml")
    rows = "".join(f"<tr><td>{html.escape(e['title'])}</td><td>+{e['points']}</td><td>{html.escape(e['detail'])}</td></tr>" for e in result['evidence'])
    iocs = "<br>".join(html.escape(x) for x in result['iocs']['urls'] + result['iocs']['domains'] + result['iocs']['ips']) or "None"
    infra_rows = "".join(f"<tr><td>{html.escape(i['ip'])}</td><td>{html.escape(i['role'])}</td><td>{html.escape(i['country'])}</td><td>{html.escape(i['city'])}, {html.escape(i['region'])}</td><td>{html.escape(i['asn'])} / {html.escape(i['isp'])}</td></tr>" for i in result["infrastructure"]) or "<tr><td colspan='5'>No public routing IP was observed.</td></tr>"
    page = f"""<!doctype html><title>CIPHER-X Forensic Report</title><style>body{{font:14px Arial;margin:40px;color:#16213e}}h1{{color:#0f766e}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:8px;text-align:left}}.score{{font-size:42px;color:#b91c1c}}.note{{border-left:4px solid #e09c22;padding:10px;background:#fff8e7}}</style><h1>CIPHER-X Forensic Investigation Report</h1><p><b>Investigation:</b> {result['investigation_id']}<br><b>Evidence SHA-256:</b> {result['evidence_sha256']}<br><b>Generated:</b> {result['analyzed_at']}</p><p class='score'>{result['risk_score']}/100 — {result['risk_level']}</p><h2>Email</h2><p><b>From:</b> {html.escape(result['email']['from'])}<br><b>Subject:</b> {html.escape(result['email']['subject'])}</p><h2>Authentication evidence</h2><p>{html.escape(str(result['authentication']))}</p><h2>Risk evidence</h2><table><tr><th>Finding</th><th>Points</th><th>Explanation</th></tr>{rows}</table><h2>Observed mail infrastructure</h2><table><tr><th>IP</th><th>Routing role</th><th>Network country</th><th>Service city / region</th><th>ASN / operator</th></tr>{infra_rows}</table><p class='note'>GeoIP indicates approximate mail or network infrastructure. It does not identify the physical location of the organisation in the From address, an attacker, or a person.</p><h2>Indicators of compromise</h2><p>{iocs}</p><h2>Limitations</h2><p>{'<br>'.join(html.escape(x) for x in result['limitations'])}</p><script>print()</script>"""
    return HTMLResponse(page, headers={"Content-Disposition": "inline; filename=forensic-report.html"})
