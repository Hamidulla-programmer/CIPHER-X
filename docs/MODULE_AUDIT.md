# CIPHER-X module audit

This is the implementation inventory for the SIH prototype. A module is only
called **implemented** when the running application produces evidence for it.

| Module | Status | Evidence produced |
| --- | --- | --- |
| Gmail mailbox ingestion and live watch | Implemented, configuration required | Read-only IMAP scan/poll status and locally stored cases |
| `.eml` parsing | Implemented | Parsed message identity, body, headers and MIME attachments |
| Header and routing forensics | Implemented | SPF/DKIM/DMARC header outcomes, Received chain and labelled observed relay IPs |
| Live sender-domain policy intelligence | Implemented | Public DNS SPF, DMARC and selected DKIM public-key records |
| Sender impersonation and link structure checks | Implemented | From/Reply-To/Return-Path mismatches, lookalike-domain and deceptive-link signals |
| IP/GeoIP intelligence | Implemented for public IPs | Provider, lookup time, ASN/operator and approximate network location |
| Attachment evidence | Implemented | Filename, declared MIME type, byte count and SHA-256; executables are flagged |
| Explainable ML triage | Implemented baseline | Local TF-IDF + Logistic Regression probability, label and positive text cues |
| Risk fusion and analyst review | Implemented | Explainable scored evidence; ML is not allowed to make a final verdict alone |
| Cases, integrity and reports | Implemented | SQLite case archive, evidence SHA-256, local custody records and printable HTML report |
| Blockchain anchoring | Implemented adapter, optional configuration | Polygon/EVM testnet anchor for a case hash only; no raw email is sent on-chain |
| VirusTotal, AbuseIPDB, URLhaus | Not enabled | Requires organisation-approved accounts/API keys and an explicit policy for sharing IOCs |
| ClamAV attachment scanning | Not enabled | Requires an updated local ClamAV service |
| Full message-level SPF/DKIM/DMARC cryptographic validation | Not enabled | Requires a production mail-authentication verifier and complete SMTP context |
| DistilBERT / production-trained ML | Not enabled | Requires a reviewed training dataset, model artifact, calibration and evaluation |

## Correct interpretation

The risk score is evidence-based triage, not proof that a person or organisation
sent an email. GeoIP identifies approximate network infrastructure, not a
person's location. The final report preserves the source hash and each check's
result or limitation so an analyst can reproduce and validate material findings.
