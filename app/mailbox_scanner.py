"""Read-only bulk scanning for Gmail Spam and unread Inbox messages only."""
from __future__ import annotations

import hashlib
import imaplib
import os
import re
import threading
from datetime import datetime, timezone
from typing import Callable

from dotenv import load_dotenv

load_dotenv(override=True)


def _decode_mailbox(line: bytes | str) -> tuple[str, str]:
    """Return IMAP LIST flags and mailbox name without assuming Gmail labels."""
    value = line.decode("utf-8", errors="replace") if isinstance(line, bytes) else line
    flags = value[value.find("(") + 1:value.find(")")] if "(" in value and ")" in value else ""
    quoted = re.findall(r'"((?:[^"\\]|\\.)*)"', value)
    name = quoted[-1] if quoted else value.rsplit(" ", 1)[-1].strip('"')
    return flags.lower(), name


class MailboxScanner:
    def __init__(self, analyze: Callable[[bytes, str], dict], persist: Callable[[dict], None]):
        self.analyze, self.persist = analyze, persist
        self._lock = threading.Lock(); self._thread = None
        self._state = {"running": False, "configured": False, "processed": 0, "requested": 0, "failed": 0, "folders": [], "last_error": None, "started_at": None, "finished_at": None}

    @property
    def configured(self):
        return all(os.getenv(key) for key in ("CIPHERX_IMAP_HOST", "CIPHERX_IMAP_USERNAME", "CIPHERX_IMAP_PASSWORD"))

    def status(self):
        with self._lock:
            return {**self._state, "configured": self.configured, "mode": "Read-only Gmail bulk scan: unread Inbox + Spam only"}

    def start(self, limit: int = 250):
        if not self.configured:
            raise RuntimeError("IMAP setup is missing. Configure Gmail before starting a mailbox scan.")
        if self._thread and self._thread.is_alive():
            return
        limit = max(1, min(int(limit), 2000))
        with self._lock:
            self._state.update({"running": True, "processed": 0, "requested": 0, "failed": 0, "folders": [], "last_error": None, "started_at": datetime.now(timezone.utc).isoformat(), "finished_at": None})
        self._thread = threading.Thread(target=self._run, args=(limit,), daemon=True, name="cipherx-mailbox-scan")
        self._thread.start()

    def _folders(self, client: imaplib.IMAP4_SSL) -> list[str]:
        configured = [value.strip() for value in os.getenv("CIPHERX_IMAP_FOLDERS", "").split(";") if value.strip()]
        if configured:
            return configured
        status, listing = client.list()
        if status != "OK":
            return [os.getenv("CIPHERX_IMAP_FOLDER", "INBOX")]
        spam = None
        for line in listing or []:
            flags, name = _decode_mailbox(line)
            if "\\junk" in flags:
                spam = name
        folders = [os.getenv("CIPHERX_IMAP_FOLDER", "INBOX")]
        if spam and spam not in folders:
            folders.append(spam)
        return folders

    def _run(self, limit: int):
        seen_hashes: set[str] = set()
        try:
            with imaplib.IMAP4_SSL(os.environ["CIPHERX_IMAP_HOST"], int(os.getenv("CIPHERX_IMAP_PORT", "993"))) as client:
                client.login(os.environ["CIPHERX_IMAP_USERNAME"], os.environ["CIPHERX_IMAP_PASSWORD"])
                folders = self._folders(client)
                with self._lock:
                    self._state["folders"] = folders
                for folder_index, folder in enumerate(folders):
                    status, _ = client.select(folder, readonly=True)
                    if status != "OK":
                        with self._lock: self._state["failed"] += 1
                        continue
                    # The Inbox branch intentionally reads only unread messages.
                    # Spam is scanned in full because Gmail may mark spam as read.
                    query = "UNSEEN" if folder_index == 0 else "ALL"
                    status, data = client.uid("search", None, query)
                    if status != "OK":
                        with self._lock: self._state["failed"] += 1
                        continue
                    ids = data[0].split()[-limit:]
                    with self._lock: self._state["requested"] += len(ids)
                    for uid in ids:
                        try:
                            status, mail = client.uid("fetch", uid, "(RFC822)")
                            if status != "OK" or not mail or not isinstance(mail[0], tuple):
                                raise RuntimeError("Could not fetch email")
                            raw = mail[0][1]
                            digest = hashlib.sha256(raw).hexdigest()
                            if digest in seen_hashes:
                                continue
                            seen_hashes.add(digest)
                            result = self.analyze(raw, f"gmail-{uid.decode(errors='replace')}.eml")
                            result["ingestion_source"] = "gmail_spam" if folder_index else "authorized_mailbox"
                            self.persist(result)
                            with self._lock: self._state["processed"] += 1
                        except Exception:
                            with self._lock: self._state["failed"] += 1
        except Exception as error:
            with self._lock: self._state["last_error"] = f"{type(error).__name__}: {error}"
        finally:
            with self._lock:
                self._state["running"] = False; self._state["finished_at"] = datetime.now(timezone.utc).isoformat()
