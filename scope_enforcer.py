"""
Scope Enforcer — application-level target allowlist for HexStrike AI.
Reads ALLOWED_TARGETS, DRY_RUN_DEFAULT, MAX_REQUESTS_PER_SCAN, SCAN_TIMEOUT_SECONDS from env.
"""

import os
import logging
import threading
from urllib.parse import urlparse
from typing import Tuple, Optional
import requests as _requests

logger = logging.getLogger(__name__)


class ScopeViolationError(Exception):
    """Raised when a request violates the scope enforcer rules."""
    pass


class ScopeEnforcer:
    # Hard-blocked path prefixes — never configurable
    HARD_BLOCKED_PATHS = ["/api/admin/", "/api/auth/delete-account"]
    # Methods never allowed against non-staging targets
    MUTATION_METHODS = {"DELETE", "PUT"}

    def __init__(self) -> None:
        raw = os.environ.get("ALLOWED_TARGETS", "")
        self.allowed_targets: set[str] = set(t.strip() for t in raw.split(",") if t.strip())
        self.dry_run: bool = os.environ.get("DRY_RUN_DEFAULT", "true").lower() == "true"
        self.max_requests: int = int(os.environ.get("MAX_REQUESTS_PER_SCAN", "500"))
        self.timeout_seconds: int = int(os.environ.get("SCAN_TIMEOUT_SECONDS", "300"))
        self._request_count: int = 0
        self._lock = threading.Lock()
        logger.info(
            "ScopeEnforcer initialized: targets=%s, dry_run=%s, max_requests=%s",
            self.allowed_targets,
            self.dry_run,
            self.max_requests,
        )

    def is_target_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        # Check hostname:port and hostname alone
        hostport = f"{hostname}:{parsed.port}" if parsed.port else hostname
        return hostname in self.allowed_targets or hostport in self.allowed_targets

    def check_request(self, method: str, url: str) -> Tuple[bool, str]:
        parsed = urlparse(url)
        path = parsed.path or ""

        # Hard blocks
        for blocked in self.HARD_BLOCKED_PATHS:
            if path.startswith(blocked):
                return False, f"hard-blocked path: {blocked}"

        # Target allowlist
        if not self.is_target_allowed(url):
            return False, f"target not in allowlist: {parsed.hostname}"

        # Mutation method block on prod
        if method.upper() in self.MUTATION_METHODS:
            return False, f"{method} not allowed (mutation blocked)"

        # Request count limit
        with self._lock:
            if self._request_count >= self.max_requests:
                return False, f"request limit reached ({self.max_requests})"
            self._request_count += 1

        return True, "allowed"

    def reset_count(self) -> None:
        with self._lock:
            self._request_count = 0

    @property
    def request_count(self) -> int:
        return self._request_count

    def status(self) -> dict:
        return {
            "allowed_targets": sorted(self.allowed_targets),
            "dry_run": self.dry_run,
            "max_requests": self.max_requests,
            "timeout_seconds": self.timeout_seconds,
            "request_count": self._request_count,
            "hard_blocked_paths": self.HARD_BLOCKED_PATHS,
        }


# Singleton
_enforcer: Optional[ScopeEnforcer] = None
_enforcer_lock = threading.Lock()


def get_enforcer() -> ScopeEnforcer:
    global _enforcer
    if _enforcer is None:
        with _enforcer_lock:
            if _enforcer is None:
                _enforcer = ScopeEnforcer()
    return _enforcer


class DryRunResponse:
    """Mock response returned during dry-run mode."""

    def __init__(self, method: str, url: str) -> None:
        self.status_code = 200
        self.text = f'{{"dry_run": true, "method": "{method}", "url": "{url}"}}'
        self.headers = {"Content-Type": "application/json"}
        self.ok = True

    def json(self) -> dict:
        import json
        return json.loads(self.text)


def safe_request(method: str, url: str, **kwargs):
    """Drop-in wrapper for requests.request() with scope enforcement."""
    enforcer = get_enforcer()
    allowed, reason = enforcer.check_request(method, url)
    if not allowed:
        logger.warning("SCOPE BLOCKED: %s %s — %s", method, url, reason)
        raise ScopeViolationError(f"Blocked: {reason}")
    if enforcer.dry_run:
        logger.info("DRY RUN: would %s %s", method, url)
        return DryRunResponse(method, url)
    # Set timeout from enforcer if not already specified
    if "timeout" not in kwargs:
        kwargs["timeout"] = enforcer.timeout_seconds
    return _requests.request(method, url, **kwargs)
