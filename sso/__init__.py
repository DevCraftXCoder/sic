"""SSO package — SAML 2.0 + OIDC single-sign-on for SIC workspaces.

Exports:
    sso_bp   — Flask Blueprint (register on the Flask app)
    init_db  — create the sso_configs table (idempotent; called automatically on first use)
"""

from __future__ import annotations

from .db import init_db
from .routes import sso_bp

__all__ = ["sso_bp", "init_db"]
