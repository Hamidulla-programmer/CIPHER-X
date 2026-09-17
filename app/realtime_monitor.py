"""Near-real-time IMAP ingestion for an authorized mailbox.

The monitor polls a mailbox at a bounded interval and analyzes only unseen
messages.  It intentionally does not delete, forward, move or modify emails.
"""
from __future__ import annotations

import imaplib
import os
import threading
from dotenv import load_dotenv

load_dotenv(override=True)
from collections import deque
from datetime import datetime, timezone
from typing import Callable


class ImapMonitor:
    def __init__(self, analyze: Callable[[bytes, str], dict]):
        self._analyze = analyze
        self._events: deque[dict] = deque(maxlen=50)
        self._seen: set[bytes] = set()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._last_error: str | None = None
        self._last_poll: str | None = None

    @property
    def configured(self) -> bool:
        return all(os.getenv(key) for key in ("CIPHERX_IMAP_HOST", "CIPHERX_IMAP_USERNAME", "CIPHERX_IMAP_PASSWORD"))

    def status(self) -> dict:
        return {"configured": self.configured, "running": bool(self._thread and self._thread.is_alive()), "poll_interval_seconds": int(os.getenv("CIPHERX_IMAP_POLL_SECONDS", "30")), "last_poll": self._last_poll, "last_error": self._last_error, "event_count": len(self._events), "mode": "IMAP unread-message polling"}

    def events(self) -> list[dict]:
        return list(self._events)

    def start(self) -> None:
        if not self.configured:
            raise RuntimeError("IMAP settings are missing. Add CIPHERX_IMAP_HOST, CIPHERX_IMAP_USERNAME and CIPHERX_IMAP_PASSWORD as environment variables.")
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="cipherx-imap-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        interval = max(10, int(os.getenv("CIPHERX_IMAP_POLL_SECONDS", "30")))
        while not self._stop.is_set():
            try:
                self._poll_once()
                self._last_error = None
            except Exception as error:  # A monitor must survive a temporary mail/network failure.
                self._last_error = f"{type(error).__name__}: {error}"
            self._stop.wait(interval)

    def _poll_once(self) -> None:
        host = os.environ["CIPHERX_IMAP_HOST"]
        port = int(os.getenv("CIPHERX_IMAP_PORT", "993"))
        folder = os.getenv("CIPHERX_IMAP_FOLDER", "INBOX")
        with imaplib.IMAP4_SSL(host, port) as client:
            client.login(os.environ["CIPHERX_IMAP_USERNAME"], os.environ["CIPHERX_IMAP_PASSWORD"])
            client.select(folder, readonly=True)
            status, payload = client.uid("search", None, "UNSEEN")
            if status != "OK":
                raise RuntimeError("Mailbox search failed")
            for uid in payload[0].split()[-10:]:
                if uid in self._seen:
                    continue
                status, email_data = client.uid("fetch", uid, "(RFC822)")
                if status != "OK" or not email_data or not isinstance(email_data[0], tuple):
                    continue
                result = self._analyze(email_data[0][1], f"imap-{uid.decode(errors='replace')}.eml")
                event = {"uid": uid.decode(errors="replace"), "received_at": datetime.now(timezone.utc).isoformat(), "investigation_id": result["investigation_id"], "subject": result["email"]["subject"], "sender": result["email"]["from"], "risk_score": result["risk_score"], "risk_level": result["risk_level"], "verdict": result["verdict"]}
                with self._lock:
                    self._events.appendleft(event)
                self._seen.add(uid)
        self._last_poll = datetime.now(timezone.utc).isoformat()
