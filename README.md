# CIPHER-X — runnable SIH MVP

CIPHER-X turns an uploaded `.eml` email into an explainable, analyst-oriented investigation: evidence hash, parsed headers and routing, SPF/DKIM/DMARC header evidence, IOC extraction, transparent risk scoring, live source-labelled GeoIP enrichment, a relationship graph, printable report and JSON export.

## Run it

Prerequisite: Python 3.10 or later.

```powershell
cd C:\Users\hloha\Documents\Codex\2026-09-10\i-x20\outputs\cipher-x
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`, then upload `samples\phishing-demo.eml`.

## Demo workflow

1. Upload the provided phishing sample.
2. Lead with the score and evidence list—not just a phishing label.
3. Open authentication and routing evidence.
4. Show IOCs and the relationship graph.
5. Click **Print / Save report** and choose “Save as PDF”; or download the JSON evidence file.

## What is real in this MVP

- RFC 822 email parsing, multipart body parsing and attachment SHA-256 hashes.
- Header, `Received` chain, URL/domain/IP extraction.
- Authentication results *as claimed by the receiving mail server* are parsed from headers.
- Deterministic, transparent scoring; all assigned points are visible.
- Public IPs are enriched through `https://ipwho.is` with country, region, city, coordinates, ASN and network data. The result identifies the lookup source and timestamp. If the provider is unavailable, the app continues with an explicit unavailable result.

## Deliberate boundaries

This prototype does not claim live SPF/DKIM/DMARC verification or reputation scoring. GeoIP is approximate infrastructure context from a third-party lookup, not proof of a human attacker or physical location. For production, use an approved provider or local GeoIP database, cache results, record source/time, and keep provider failures non-blocking.

## Production extension plan

1. Persist raw evidence encrypted, with object retention and audit logs.
2. Add `dnspython` SPF/DMARC lookups and a bounded DKIM verifier; retain verification inputs.
3. Add a consented GeoIP/ASN/reputation adapter with API keys in environment variables—not source code.
4. Train/evaluate an NLP classifier against held-out phishing and legitimate samples; treat it as one scored signal.
5. Move investigations into PostgreSQL and relationships/campaign correlation into Neo4j.
6. Add role-based access, upload malware scanning, rate limits, tests, and a chain-of-custody ledger (hash + timestamp) before deployment.

## Suggested five-day implementation plan

| Day | Deliverable |
|---|---|
| 1 | Stabilize `.eml` ingestion and collect 10–20 consented test samples. |
| 2 | Add verified authentication and an offline/local enrichment adapter. |
| 3 | Train and evaluate a content classifier; plug its calibrated result into scoring. |
| 4 | Persist investigations, polish graph/report, rehearse the demo. |
| 5 | Test failure modes, privacy handling and the exact demo narrative—no scope expansion. |
