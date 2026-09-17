"""Local SQLite case index. Raw mail is not retained by default."""
from __future__ import annotations
import json
import os
import hashlib
import sqlite3
from pathlib import Path

DB = Path(__file__).resolve().parent.parent / "data" / "cipherx_cases.sqlite3"


def connect():
    DB.parent.mkdir(exist_ok=True)
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    db.execute("""CREATE TABLE IF NOT EXISTS cases (
      id TEXT PRIMARY KEY, analyzed_at TEXT, sender TEXT, subject TEXT,
      risk_score INTEGER, risk_level TEXT, verdict TEXT, evidence_hash TEXT,
      ml_probability REAL, payload TEXT)""")
    db.execute("""CREATE TABLE IF NOT EXISTS custody_log (
      sequence INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, recorded_at TEXT,
      evidence_hash TEXT, previous_hash TEXT, entry_hash TEXT)""")
    db.execute("""CREATE TABLE IF NOT EXISTS blockchain_anchors (
      case_id TEXT PRIMARY KEY, network TEXT, transaction_hash TEXT, block_number INTEGER, anchored_at TEXT)""")
    return db


def save(result: dict) -> bool:
    ml = result.get("ml_analysis", {})
    masking = os.getenv("CIPHERX_MASK_PERSONAL_DATA", "true").lower() != "false"
    payload = dict(result)
    if masking:
        payload["email"] = {**result["email"], "from": _mask(result["email"]["from"]), "to": _mask(result["email"]["to"])}
    with connect() as db:
        existing = db.execute("SELECT id FROM cases WHERE evidence_hash = ? LIMIT 1", (result["evidence_sha256"],)).fetchone()
        if existing:
            return False
        db.execute("INSERT OR REPLACE INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
          result["investigation_id"], result["analyzed_at"], result["email"]["from"],
          result["email"]["subject"], result["risk_score"], result["risk_level"],
          result["verdict"], result["evidence_sha256"], ml.get("phishing_probability", 0), json.dumps(payload)))
        last = db.execute("SELECT entry_hash FROM custody_log ORDER BY sequence DESC LIMIT 1").fetchone()
        previous = last[0] if last else "GENESIS"
        entry_hash = hashlib.sha256(f"{previous}|{result['investigation_id']}|{result['evidence_sha256']}|{result['analyzed_at']}".encode()).hexdigest()
        db.execute("INSERT INTO custody_log(case_id,recorded_at,evidence_hash,previous_hash,entry_hash) VALUES (?,?,?,?,?)", (result["investigation_id"], result["analyzed_at"], result["evidence_sha256"], previous, entry_hash))
    return True


def _mask(value: str) -> str:
    if "@" not in (value or ""):
        return value
    local, domain = value.rsplit("@", 1)
    return (local[:1] + "***@" + domain) if local else "***@" + domain


def case_hash(case_id: str) -> str | None:
    with connect() as db:
        row = db.execute("SELECT evidence_hash FROM cases WHERE id = ?", (case_id,)).fetchone()
    return row[0] if row else None


def save_anchor(anchor: dict) -> None:
    with connect() as db:
        db.execute("INSERT OR REPLACE INTO blockchain_anchors VALUES (?, ?, ?, ?, datetime('now'))", (anchor["case_id"], anchor["network"], anchor["transaction_hash"], anchor["block_number"]))


def clear_cases() -> int:
    """Remove only CIPHER-X's local case index; never touches the mailbox."""
    with connect() as db:
        count = db.execute("SELECT count(*) FROM cases").fetchone()[0]
        db.execute("DELETE FROM blockchain_anchors")
        db.execute("DELETE FROM custody_log")
        db.execute("DELETE FROM cases")
    return count


def get_case(case_id: str) -> dict | None:
    with connect() as db:
        row = db.execute("SELECT payload FROM cases WHERE id = ?", (case_id,)).fetchone()
    return json.loads(row[0]) if row else None


def intelligence() -> dict:
    """Create a local threat-intelligence index from previously authorized cases."""
    domains: dict[str, int] = {}; ips: dict[str, int] = {}; urls: dict[str, int] = {}
    with connect() as db:
        rows = db.execute("SELECT payload FROM cases ORDER BY analyzed_at DESC LIMIT 500").fetchall()
    for row in rows:
        item = json.loads(row[0]); score = item.get("risk_score", 0)
        for value in item.get("iocs", {}).get("domains", []): domains[value] = max(domains.get(value, 0), score)
        for value in item.get("iocs", {}).get("ips", []): ips[value] = max(ips.get(value, 0), score)
        for value in item.get("iocs", {}).get("urls", []): urls[value] = max(urls.get(value, 0), score)
    pack = lambda values: [{"indicator": key, "max_risk": value} for key, value in sorted(values.items(), key=lambda item: item[1], reverse=True)]
    return {"domains": pack(domains), "ips": pack(ips), "urls": pack(urls)}


def dashboard() -> dict:
    with connect() as db:
        total = db.execute("SELECT count(*) FROM cases").fetchone()[0]
        critical = db.execute("SELECT count(*) FROM cases WHERE risk_score >= 61").fetchone()[0]
        avg = db.execute("SELECT round(coalesce(avg(risk_score), 0),1) FROM cases").fetchone()[0]
        rows = db.execute("SELECT id, analyzed_at, sender, subject, risk_score, risk_level, verdict, ml_probability, payload FROM cases ORDER BY analyzed_at DESC LIMIT 100").fetchall()
        campaigns = db.execute("SELECT sender, count(*) AS count, max(risk_score) AS max_risk FROM cases GROUP BY sender HAVING count(*) > 1 ORDER BY max_risk DESC, count DESC LIMIT 10").fetchall()
        custody_count = db.execute("SELECT count(*) FROM custody_log").fetchone()[0]
    cases = []
    for row in rows:
        item = dict(row); payload = json.loads(item.pop("payload"))
        ml = payload.get("ml_analysis", {})
        item["ml_label"] = ml.get("label", "unavailable")
        item["ml_model"] = ml.get("model", "unavailable")
        item["ml_cues"] = ml.get("top_text_cues", [])[:3]
        item["ingestion_source"] = payload.get("ingestion_source", "authorized_mailbox")
        item["evidence_summary"] = payload.get("evidence", [])[:5]
        item["file"] = payload.get("file", "email.eml")
        cases.append(item)
    return {"total_scanned": total, "high_risk": critical, "average_risk": avg, "cases": cases, "campaign_candidates": [dict(row) for row in campaigns], "chain_of_custody_entries": custody_count, "privacy": {"raw_email_retained": False, "masking_enabled": os.getenv("CIPHERX_MASK_PERSONAL_DATA", "true").lower() != "false"}}
