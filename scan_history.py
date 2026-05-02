"""
scan_history.py — Flask Blueprint for SQLite-backed scan history persistence.

Provides:
  - record_scan_start / record_scan_complete — write helpers for scan runners
  - get_scan / list_scans — read helpers
  - Blueprint routes: GET /api/scans, /api/scans/<id>, /api/export/<id>

Retention gating: list_scans_route enforces scan_history_days per tier via
feature_gates.get_tier_limit / feature_gates.current_user_tier.  list_scans()
itself is ungated so internal callers are unaffected.
"""

import csv
import io
import json
import logging
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Blueprint, Response, abort, jsonify, request

scan_history_bp = Blueprint("sic_scan_history", __name__, url_prefix="/api")

_DB_PATH = Path.home() / ".sic" / "state.db"
_db_init_done: bool = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def nanoid() -> str:
    """Return a URL-safe 20-character random ID."""
    return secrets.token_urlsafe(15)[:20]


def _iso_now() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat()


def _db_path() -> Path:
    """Ensure DB parent directory exists and return the DB path."""
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return _DB_PATH


def _connect() -> sqlite3.Connection:
    """Return a sqlite3 connection with Row factory enabled."""
    conn = sqlite3.connect(str(_db_path()))
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    """Create scan_runs table and indexes if not already done (idempotent)."""
    global _db_init_done
    if _db_init_done:
        return
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_runs (
                id TEXT PRIMARY KEY,
                scan_type TEXT NOT NULL,
                target TEXT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                duration_s INTEGER,
                status TEXT NOT NULL,
                findings_count INTEGER DEFAULT 0,
                findings_json TEXT,
                error TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_started ON scan_runs(started_at DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_type ON scan_runs(scan_type)"
        )
        conn.commit()
    _db_init_done = True


# ---------------------------------------------------------------------------
# Public write helpers
# ---------------------------------------------------------------------------


def record_scan_start(scan_type: str, target: str | None = None) -> str:
    """Insert a new scan_runs row with status='running'. Return scan_id."""
    _init_db()
    sid = nanoid()
    started = _iso_now()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO scan_runs (id, scan_type, target, started_at, status) VALUES (?, ?, ?, ?, 'running')",
            (sid, scan_type, target, started),
        )
        conn.commit()
    logger.debug("scan started: id=%s type=%s target=%s", sid, scan_type, target)
    return sid


def record_scan_complete(
    scan_id: str,
    findings: list,
    status: str = "completed",
    error: str | None = None,
) -> None:
    """Update scan_runs row with completion data."""
    _init_db()
    finished = _iso_now()
    findings_json = json.dumps(findings) if findings is not None else None
    findings_count = len(findings) if findings else 0
    with _connect() as conn:
        row = conn.execute(
            "SELECT started_at FROM scan_runs WHERE id = ?", (scan_id,)
        ).fetchone()
        duration: int | None = None
        if row:
            try:
                started_dt = datetime.fromisoformat(row["started_at"])
                finished_dt = datetime.fromisoformat(finished)
                duration = int((finished_dt - started_dt).total_seconds())
            except Exception:  # noqa: BLE001
                duration = None
        conn.execute(
            "UPDATE scan_runs SET finished_at=?, duration_s=?, status=?, findings_count=?, findings_json=?, error=? WHERE id=?",
            (finished, duration, status, findings_count, findings_json, error, scan_id),
        )
        conn.commit()
    logger.debug(
        "scan complete: id=%s status=%s findings=%d", scan_id, status, findings_count
    )


# ---------------------------------------------------------------------------
# Public read helpers
# ---------------------------------------------------------------------------


def get_scan(scan_id: str) -> dict | None:
    """Return scan dict or None. Parses findings_json into findings list."""
    _init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scan_runs WHERE id = ?", (scan_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    raw = d.pop("findings_json", None)
    if raw:
        try:
            d["findings"] = json.loads(raw)
        except Exception:  # noqa: BLE001
            d["findings"] = []
    else:
        d["findings"] = []
    return d


def list_scans(
    cursor: str | None,
    scan_type: str | None,
    status: str | None,
    limit: int,
    oldest_allowed: str | None = None,
) -> tuple[list[dict], str | None]:
    """Cursor-paginated scan list.

    Cursor is a started_at ISO string (exclusive lower bound for DESC order).
    oldest_allowed, when provided, is an ISO string acting as an inclusive lower
    bound — scans older than this value are excluded (retention gate).
    Returns (rows, next_cursor).
    """
    _init_db()
    limit = max(1, min(100, int(limit or 20)))
    where: list[str] = []
    params: list = []
    if cursor:
        where.append("started_at < ?")
        params.append(cursor)
    if oldest_allowed:
        where.append("started_at >= ?")
        params.append(oldest_allowed)
    if scan_type:
        where.append("scan_type = ?")
        params.append(scan_type)
    if status:
        where.append("status = ?")
        params.append(status)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    sql = (
        f"SELECT id, scan_type, target, started_at, finished_at, duration_s, status, findings_count"
        f" FROM scan_runs {where_sql}"
        f" ORDER BY started_at DESC, id DESC LIMIT ?"
    )
    params.append(limit + 1)
    with _connect() as conn:
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = page[-1]["started_at"] if (has_more and page) else None
    return page, next_cursor


# ---------------------------------------------------------------------------
# Auth gate (lazy import — auth module may be created in parallel)
# ---------------------------------------------------------------------------


def _require_auth():
    """Abort 401 if no authenticated session. Fails open if auth module absent."""
    try:
        from auth import get_session_email  # noqa: PLC0415
    except ImportError:
        return None  # auth module not loaded — fail open in dev
    email = get_session_email()
    if not email:
        abort(401)
    return email


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@scan_history_bp.get("/scans")
def list_scans_route():
    """GET /api/scans — paginated scan history (retention-gated by tier)."""
    _require_auth()
    cursor = request.args.get("cursor")
    scan_type = request.args.get("type")
    status = request.args.get("status")
    try:
        limit = int(request.args.get("limit", 20))
    except (TypeError, ValueError):
        limit = 20

    # Tier-based retention gate: clamp cursor to the oldest allowed scan date.
    try:
        from feature_gates import current_user_tier, get_tier_limit  # noqa: PLC0415
        retention_days: int = get_tier_limit(current_user_tier(), "scan_history_days")
    except ImportError:
        retention_days = 7  # fail-safe: community default

    retention_cutoff: str | None = None
    if retention_days != -1:  # -1 = unlimited (studio)
        cutoff_dt = datetime.now(timezone.utc) - timedelta(days=retention_days)
        retention_cutoff = cutoff_dt.isoformat()
        # If the caller's cursor is older than the cutoff, clamp it.
        if cursor and cursor < retention_cutoff:
            cursor = None

    rows, next_cursor = list_scans(cursor, scan_type, status, limit, oldest_allowed=retention_cutoff)
    return jsonify({"scans": rows, "next_cursor": next_cursor})


@scan_history_bp.get("/scans/<scan_id>")
def get_scan_route(scan_id: str):
    """GET /api/scans/<scan_id> — single scan detail."""
    _require_auth()
    scan = get_scan(scan_id)
    if scan is None:
        abort(404)
    return jsonify(scan)


@scan_history_bp.get("/export/<scan_id>")
def export_scan_route(scan_id: str):
    """GET /api/export/<scan_id>?format=json|csv — download scan data."""
    _require_auth()
    scan = get_scan(scan_id)
    if scan is None:
        abort(404)

    fmt = request.args.get("format", "json").lower()

    if fmt == "csv":
        findings: list = scan.get("findings") or []
        buf = io.StringIO()
        if not findings:
            writer = csv.writer(buf)
            writer.writerow(["index"])
        else:
            # Build union of all keys across finding dicts, sorted for stability
            all_keys: list[str] = sorted(
                {k for f in findings if isinstance(f, dict) for k in f.keys()}
            )
            if not all_keys:
                # findings are non-dict scalars — wrap as {"value": ...}
                all_keys = ["value"]
                findings = [{"value": f} for f in findings]
            writer = csv.DictWriter(
                buf,
                fieldnames=all_keys,
                extrasaction="ignore",
                lineterminator="\r\n",
            )
            writer.writeheader()
            for finding in findings:
                if not isinstance(finding, dict):
                    finding = {"value": finding}
                row: dict = {}
                for k in all_keys:
                    v = finding.get(k, "")
                    if isinstance(v, (dict, list)):
                        row[k] = json.dumps(v)
                    else:
                        row[k] = str(v) if v is not None else ""
                writer.writerow(row)
        csv_text = buf.getvalue()
        return Response(
            csv_text,
            mimetype="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="scan-{scan_id}.csv"'
            },
        )

    # Default: JSON
    body = json.dumps(scan, indent=2, default=str)
    return Response(
        body,
        mimetype="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="scan-{scan_id}.json"'
        },
    )


# ---------------------------------------------------------------------------
# App registration
# ---------------------------------------------------------------------------


def init_app(app) -> None:
    """Register the scan_history blueprint on a Flask app."""
    app.register_blueprint(scan_history_bp)
