# CIPHER-X — runnable SIH MVP

CIPHER-X is an authorized-mailbox forensic intelligence platform. It batch-scans a mailbox in read-only mode, indexes each email as an explainable investigation, persists local evidence metadata, and keeps a separate near-real-time unread-email watch.

## Run it

Prerequisite: Python 3.10 or later.

```powershell
cd C:\Users\hloha\Documents\Codex\2026-09-10\i-x20\outputs\cipher-x
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`. The React/Tailwind command-center UI supports draggable dashboard panels, a full-mailbox scan and a live watch. The old single `.eml` workflow remains available through the API for evidence testing.

## Full Gmail mailbox scan

Use only a Gmail mailbox that you own or are explicitly authorized to monitor. Create a Gmail App Password locally; never place it in Git or share it in chat. In the same terminal, before starting Uvicorn:

```powershell
$env:CIPHERX_IMAP_HOST="imap.gmail.com"
$env:CIPHERX_IMAP_PORT="993"
$env:CIPHERX_IMAP_USERNAME="your-authorized-mailbox@gmail.com"
$secure = Read-Host "Paste Gmail App Password" -AsSecureString
$env:CIPHERX_IMAP_PASSWORD = [System.Net.NetworkCredential]::new("", $secure).Password
uvicorn app.main:app --reload
```

Choose a batch size in the dashboard and select **Start full scan**. It fetches the most recent 100–1,000 emails from `INBOX`, in read-only IMAP mode, and records only analysis metadata, case results and evidence hashes in `data/cipherx_cases.sqlite3`. It does not persist raw email by default.

## ML signal

The local classifier is a scikit-learn TF-IDF + Logistic Regression baseline and returns probability, label and contributing text cues. It runs alongside—not instead of—mail headers, authentication results, routing and attachment evidence. The pinned dependency is compatible with modern Python; run `pip install -r requirements.txt` after pulling the update. A DistilBERT adapter is a planned deployment option after the team selects a reviewed model and evaluation data; it should never be claimed as trained or accurate until it has been evaluated on a held-out, consented dataset.

## SIH forensic-intelligence coverage

- **Header and protocol evidence:** From, Reply-To, Return-Path, Message-ID host, DKIM-signature presence, Received-hop count, plus claimed SPF/DKIM/DMARC results.
- **Spoofing and link detection:** identity-domain mismatches, shortened links, punycode domains, `@` URL deception, non-HTTPS links, executable attachments, lookalikes and social-engineering language.
- **Origin traceability:** Received-chain role labels, public-IP GeoIP/ASN/ISP enrichment and explicit confidence/limitations. Infrastructure location is never presented as a person's location.
- **Campaign support:** searchable local cases can be grouped by recurring sender identity and risk level; the dashboard exposes campaign candidates.
- **Privacy and evidence:** raw email is processed in memory and is not persisted by default. Stored email identities are masked by default (`CIPHERX_MASK_PERSONAL_DATA=true`). A hash-linked `custody_log` records every stored investigation.

## Optional blockchain evidence anchoring

The local chain-of-custody ledger is not blockchain. CIPHER-X now also includes an optional Solidity contract for **Polygon Amoy testnet** or another Ethereum-compatible network. It anchors only an existing SHA-256 evidence hash and CIPHER-X case ID; it never puts raw mail, names, addresses, subject lines or credentials on-chain.

1. Deploy [`contracts/EvidenceAnchor.sol`](contracts/EvidenceAnchor.sol) with a team-owned testnet wallet using Remix, Hardhat or Foundry.
2. Obtain an RPC URL from a provider such as Alchemy, Infura or a Polygon RPC provider. Store the URL and the dedicated testnet wallet key locally, never in source code or Git.
3. Configure the environment before launching CIPHER-X:

```powershell
$env:CIPHERX_BLOCKCHAIN_PLATFORM="Polygon Amoy testnet"
$env:CIPHERX_BLOCKCHAIN_RPC_URL="https://your-provider-rpc-url"
$env:CIPHERX_BLOCKCHAIN_CONTRACT="0xYourDeployedContractAddress"
$env:CIPHERX_BLOCKCHAIN_PRIVATE_KEY="your-dedicated-testnet-wallet-private-key"
```

`GET /api/blockchain/status` reports configuration without exposing secrets. `POST /api/cases/{case_id}/anchor` creates an on-chain anchor; that action requires testnet gas and should only be called after analyst review. `GET /api/evidence/{sha256}/blockchain` verifies a hash against the deployed contract.

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

## Near-real-time monitoring

CIPHER-X includes an authorized-mailbox monitor. It checks unread messages from a configured IMAP inbox every 30 seconds by default, analyzes each new message in read-only mode, and shows the latest events in the dashboard.

Set these environment variables on the machine or deployment platform that owns the mailbox connection. Use a provider-issued app password or service account, never a personal password in source code:

```powershell
$env:CIPHERX_IMAP_HOST="imap.example.org"
$env:CIPHERX_IMAP_USERNAME="security-monitor@example.org"
$env:CIPHERX_IMAP_PASSWORD="provider-app-password"
$env:CIPHERX_IMAP_FOLDER="INBOX"
$env:CIPHERX_IMAP_POLL_SECONDS="30"
uvicorn app.main:app --reload
```

After upload analysis, open **Near-real-time mailbox monitor** and select **Start monitor**. The monitor never deletes, forwards, sends, or marks email as read. If credentials are not configured, the dashboard clearly shows that live monitoring is unavailable while normal `.eml` investigation continues.

## Suggested five-day implementation plan

| Day | Deliverable |
|---|---|
| 1 | Stabilize `.eml` ingestion and collect 10–20 consented test samples. |
| 2 | Add verified authentication and an offline/local enrichment adapter. |
| 3 | Train and evaluate a content classifier; plug its calibrated result into scoring. |
| 4 | Persist investigations, polish graph/report, rehearse the demo. |
| 5 | Test failure modes, privacy handling and the exact demo narrative—no scope expansion. |
