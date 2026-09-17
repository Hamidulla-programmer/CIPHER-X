"""Bounded live DNS intelligence for sender domains.

This uses Google's public DNS-over-HTTPS API only for public domain records.
It does not upload email bodies, headers, addresses, or attachments.
"""
from __future__ import annotations
import json
from functools import lru_cache
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def _base_domain(domain: str) -> str:
    parts = (domain or "").strip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


@lru_cache(maxsize=512)
def dns_records(name: str, record_type: str) -> list[str]:
    try:
        query = urlencode({"name": name, "type": record_type})
        request = Request(f"https://dns.google/resolve?{query}", headers={"Accept": "application/dns-json", "User-Agent": "CIPHER-X/1.0"})
        with urlopen(request, timeout=3) as response:
            data = json.loads(response.read().decode("utf-8"))
        return [str(item.get("data", "")).strip('"') for item in data.get("Answer", [])]
    except Exception:
        return []


def authentication_intelligence(sender_domain: str, dkim_header: str) -> dict:
    """Live policy lookup, clearly distinct from message authentication validation."""
    domain = _base_domain(sender_domain)
    if not domain:
        return {"source": "Google DNS-over-HTTPS", "status": "unavailable", "reason": "Sender domain unavailable."}
    spf = [record for record in dns_records(domain, "TXT") if record.lower().startswith("v=spf1")]
    dmarc = [record for record in dns_records(f"_dmarc.{domain}", "TXT") if record.lower().startswith("v=dmarc1")]
    selector = ""
    for piece in (dkim_header or "").split(";"):
        if piece.strip().lower().startswith("s="):
            selector = piece.split("=", 1)[1].strip(); break
    dkim = dns_records(f"{selector}._domainkey.{sender_domain}", "TXT") if selector and sender_domain else []
    return {"source": "Google DNS-over-HTTPS live lookup", "status": "enriched", "domain": domain, "spf_policy_found": bool(spf), "spf_records": spf[:2], "dmarc_policy_found": bool(dmarc), "dmarc_records": dmarc[:2], "dkim_selector": selector or "not present", "dkim_public_key_found": bool(dkim), "dkim_records": dkim[:1], "interpretation": "These are live sender-domain policy records. They support investigation but do not by themselves prove that this individual email passed SPF, DKIM, or DMARC."}
