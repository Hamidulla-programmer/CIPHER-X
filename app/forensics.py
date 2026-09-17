"""Protocol, spoofing and link evidence. Findings are prompts for review, not proof."""
from __future__ import annotations
import re
from difflib import SequenceMatcher
from email.utils import parseaddr
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "cutt.ly"}
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "work", "gq", "tk", "ml", "cf"}
BRAND_DOMAINS = {"google": "google.com", "microsoft": "microsoft.com", "paypal": "paypal.com", "amazon": "amazon.com", "apple": "apple.com", "netflix": "netflix.com"}

def _domain(value: str) -> str:
    address = parseaddr(value or "")[1]
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""

def _base_domain(value: str) -> str:
    """Conservative organisation-domain comparison for legitimate relay aliases."""
    parts = (value or "").lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else value

def domain_intelligence(domain: str) -> dict:
    """Offline, explainable lookalike and TLD signals; no reputation claim."""
    base = _base_domain(domain); label = base.split(".")[0] if base else ""
    normalized = re.sub(r"(?:[-_]?)(login|secure|security|support|verify|account)$", "", label.lower())
    findings = []
    for brand, legitimate in BRAND_DOMAINS.items():
        if base == legitimate or base.endswith("." + legitimate):
            continue
        similarity = SequenceMatcher(None, normalized.replace("0", "o").replace("1", "l"), brand).ratio()
        if similarity >= 0.80:
            findings.append({"type":"brand_similarity", "brand":brand, "similarity":round(similarity,2), "detail":f"Domain label resembles {legitimate}; analyst verification required."})
    tld = base.rsplit(".", 1)[-1] if "." in base else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append({"type":"uncommon_tld", "tld":tld, "detail":"This TLD is commonly abused in phishing campaigns, but is not proof of maliciousness."})
    return {"domain":domain,"base_domain":base,"findings":findings,"limitations":"No live reputation or WHOIS age claim is made without an approved reputation/WHOIS provider."}

def protocol_evidence(message, sender_domain: str, urls: list[str]) -> dict:
    reply_to, return_path = str(message.get("Reply-To", "")), str(message.get("Return-Path", ""))
    message_id = str(message.get("Message-ID", "")); match = re.search(r"@([^>\s]+)", message_id)
    message_id_domain = match.group(1).lower() if match else ""
    reply_domain, return_domain = _domain(reply_to), _domain(return_path)
    anomalies = []
    for kind, observed, label in (("reply_to_mismatch", reply_domain, "Reply-To"), ("return_path_mismatch", return_domain, "Return-Path"), ("message_id_mismatch", message_id_domain, "Message-ID host")):
        if observed and sender_domain and _base_domain(observed) != _base_domain(sender_domain):
            anomalies.append({"kind": kind, "detail": f"{label} domain ({observed}) differs from From domain ({sender_domain})."})
    link_findings = []
    for url in urls:
        parsed = urlparse(url); host = (parsed.hostname or "").lower()
        if "@" in parsed.netloc: link_findings.append({"url":url,"kind":"credential-style URL","detail":"The URL contains @, which can obscure its actual destination."})
        if host.startswith("xn--"): link_findings.append({"url":url,"kind":"punycode domain","detail":"The destination uses internationalized-domain encoding; verify its intended brand."})
        if host in SHORTENERS: link_findings.append({"url":url,"kind":"shortened URL","detail":"The destination is shortened and cannot be assessed from the visible host alone."})
        if parsed.scheme != "https": link_findings.append({"url":url,"kind":"non-HTTPS link","detail":"The URL does not use HTTPS."})
    return {"headers":{"return_path":return_path,"reply_to":reply_to,"message_id":message_id,"dkim_signature_present":bool(message.get("DKIM-Signature")),"received_hops":len(message.get_all("Received",[]))},"identity_domains":{"from":sender_domain,"reply_to":reply_domain,"return_path":return_domain,"message_id":message_id_domain},"anomalies":anomalies,"link_findings":link_findings}


def behavioral_evidence(text: str, sender_domain: str, urls: list[str]) -> list[dict]:
    """Evidence rules for credential-harvesting and BEC patterns.

    A real Gmail sender can pass all mail-authentication checks. These rules
    therefore only score concrete combinations found in the message; they do
    not treat a sender's IP, display name, or generic ML probability as proof.
    """
    lowered = (text or "").lower()
    sender_base = _base_domain(sender_domain)
    link_domains = {_base_domain(urlparse(url).hostname or "") for url in urls}
    external_link = bool(link_domains and any(domain and domain != sender_base for domain in link_domains))
    has_credential = any(term in lowered for term in ("password", "credential", "otp", "one time password", "verification code", "login", "sign in"))
    has_account_pressure = any(term in lowered for term in ("verify your account", "account is suspended", "account suspended", "confirm your account", "unlock your account", "validate your account"))
    has_payment = any(term in lowered for term in ("wire transfer", "bank account", "bank details", "beneficiary", "payment instruction", "invoice"))
    has_money_request = any(term in lowered for term in ("gift card", "send money", "transfer funds", "payment today", "new bank account"))
    has_urgency = any(term in lowered for term in ("urgent", "immediately", "asap", "today", "confidential"))
    findings = []
    if has_credential and (has_account_pressure or external_link):
        points = 32 if external_link else 20
        findings.append({"points": points, "kind": "credential_harvesting_pattern", "detail": "Credential/OTP language is combined with account pressure or a destination outside the sender's organisation domain." if external_link else "Credential/OTP language is combined with account-pressure language; verify through an independent channel."})
    if has_payment and (has_money_request or has_urgency):
        findings.append({"points": 28, "kind": "business_email_compromise_pattern", "detail": "Payment or banking instruction is combined with a money-request or urgency cue. Verify the request using a known contact channel."})
    elif has_money_request and has_urgency:
        findings.append({"points": 24, "kind": "financial_social_engineering_pattern", "detail": "A money/gift-card request is combined with urgency. This is a common fraud pattern requiring independent verification."})
    if external_link and has_account_pressure:
        findings.append({"points": 12, "kind": "off_domain_account_action", "detail": "An account-action request leads to a domain different from the sender's organisation domain."})
    return findings
