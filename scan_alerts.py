"""Discord webhook alerting for SIC scan lifecycle events."""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any

import requests

logger = logging.getLogger(__name__)

# Embed colors (decimal)
_COLORS: dict[str, int] = {
    "scan_started": 3447003,          # blue
    "scan_completed": 3066993,        # green
    "scan_failed": 15158332,          # red
    "scan_killed": 15105570,          # yellow
    "critical_finding": 15158332,     # red
    "unauthorized_attempt": 10038562, # dark red
}

_TITLES: dict[str, str] = {
    "scan_started": "Scan Started",
    "scan_completed": "Scan Completed",
    "scan_failed": "Scan Failed",
    "scan_killed": "Scan Killed",
    "critical_finding": "Critical Finding",
    "unauthorized_attempt": "Unauthorized Scan Attempt",
}

_WEBHOOK_URL: str | None = None
_url_checked: bool = False
_url_lock = threading.Lock()


def _get_webhook_url() -> str | None:
    """Return the webhook URL, logging a warning once if unset."""
    global _WEBHOOK_URL, _url_checked
    with _url_lock:
        if not _url_checked:
            _url_checked = True
            _WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL") or None
            if not _WEBHOOK_URL:
                logger.warning(
                    "DISCORD_WEBHOOK_URL is not set — Discord scan alerts are disabled"
                )
    return _WEBHOOK_URL


def _build_fields(details: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a flat details dict into Discord embed fields."""
    label_map = {
        "scan_type": "Scan Type",
        "target": "Target",
        "duration": "Duration",
        "findings_count": "Findings",
        "error": "Error",
        "severity": "Severity",
        "finding": "Finding",
        "reason": "Reason",
        "ip": "IP Address",
    }
    fields: list[dict[str, Any]] = []
    for key, value in details.items():
        label = label_map.get(key, key.replace("_", " ").title())
        fields.append({"name": label, "value": str(value), "inline": True})
    return fields


def _fire_webhook(event: str, details: dict[str, Any]) -> None:
    """Send the Discord webhook request (runs in a daemon thread)."""
    url = _get_webhook_url()
    if not url:
        return
    try:
        payload = {
            "embeds": [
                {
                    "title": _TITLES.get(event, event),
                    "description": details.pop("description", f"SIC event: {event}"),
                    "color": _COLORS.get(event, 0),
                    "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                    "fields": _build_fields(details),
                    "footer": {"text": "SIC Scanner \u2022 HexStrike AI"},
                }
            ]
        }
        requests.post(url, json=payload, timeout=5)
    except Exception:
        logger.debug("Discord alert delivery failed for event '%s'", event, exc_info=True)


def send_scan_alert(event: str, details: dict[str, Any] | None = None) -> None:
    """Fire a Discord alert for a scan lifecycle event (non-blocking).

    Args:
        event: One of scan_started, scan_completed, scan_failed, scan_killed,
               critical_finding, unauthorized_attempt.
        details: Optional flat dict of key/value pairs to render as embed fields.
                 Special key ``description`` becomes the embed description text.
    """
    if not _get_webhook_url():
        return
    try:
        payload = dict(details) if details else {}
        t = threading.Thread(target=_fire_webhook, args=(event, payload), daemon=True)
        t.start()
    except Exception:
        logger.debug("Failed to dispatch Discord alert thread for event '%s'", event, exc_info=True)
