"""OIDC client helpers — wraps authlib with lazy import.

Public API:
    build_authorize_url(idp_config, sp_config, state, nonce) -> url: str
    exchange_code(code, idp_config, sp_config) -> id_token_claims: dict
    validate_id_token(id_token, idp_config, sp_config) -> claims: dict
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

import requests as _requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy import guard
# ---------------------------------------------------------------------------

_authlib_available: bool | None = None
_jwt_decode: Any = None


def _check_authlib() -> bool:
    global _authlib_available, _jwt_decode
    if _authlib_available is not None:
        return _authlib_available
    try:
        from authlib.jose import JsonWebToken, KeySet, OctKey  # noqa: PLC0415, F401
        from authlib.jose.errors import JoseError  # noqa: PLC0415, F401

        _authlib_available = True
        logger.debug("authlib loaded successfully")
    except ImportError:
        _authlib_available = False
        logger.warning(
            "authlib not installed — OIDC SSO unavailable. "
            "Install with: pip install authlib>=1.3.0"
        )
    return _authlib_available


# ---------------------------------------------------------------------------
# Discovery document cache (in-memory, 5-minute TTL)
# ---------------------------------------------------------------------------

_discovery_cache: dict[str, tuple[dict[str, Any], float]] = {}
_DISCOVERY_TTL = 300.0


def _fetch_discovery(discovery_url: str) -> dict[str, Any]:
    """Fetch and cache the OIDC discovery document."""
    now = time.monotonic()
    cached = _discovery_cache.get(discovery_url)
    if cached and (now - cached[1]) < _DISCOVERY_TTL:
        return cached[0]
    resp = _requests.get(discovery_url, timeout=10)
    resp.raise_for_status()
    doc: dict[str, Any] = resp.json()
    _discovery_cache[discovery_url] = (doc, now)
    return doc


def _fetch_jwks(jwks_uri: str) -> Any:
    """Fetch JWKS from the IdP for token signature verification."""
    from authlib.jose import JsonWebKeySet  # noqa: PLC0415

    resp = _requests.get(jwks_uri, timeout=10)
    resp.raise_for_status()
    return JsonWebKeySet.import_key_set(resp.json())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_authorize_url(
    idp_config: dict[str, Any],
    sp_config: dict[str, Any],
    state: str,
    nonce: str,
) -> str:
    """Build the OIDC authorization URL. Returns the full redirect URL.

    Raises RuntimeError if authlib is not installed.
    """
    if not _check_authlib():
        raise RuntimeError(
            "authlib is not installed. Run: pip install authlib>=1.3.0"
        )

    discovery_url = idp_config["oidc_discovery_url"]
    doc = _fetch_discovery(discovery_url)
    auth_endpoint = doc["authorization_endpoint"]

    base_url = sp_config["base_url"].rstrip("/")
    workspace_id = sp_config["workspace_id"]
    redirect_uri = f"{base_url}/auth/sso/callback/oidc/{workspace_id}"

    from urllib.parse import urlencode  # noqa: PLC0415

    params = {
        "response_type": "code",
        "client_id": idp_config["oidc_client_id"],
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
    }
    url = f"{auth_endpoint}?{urlencode(params)}"
    logger.debug("OIDC authorize URL built for workspace=%s", workspace_id)
    return url


def exchange_code(
    code: str,
    idp_config: dict[str, Any],
    sp_config: dict[str, Any],
    nonce: str,
) -> dict[str, Any]:
    """Exchange authorization code for tokens, validate ID token. Returns claims dict.

    Raises RuntimeError if authlib is not installed.
    Raises ValueError on token validation failure.
    """
    if not _check_authlib():
        raise RuntimeError(
            "authlib is not installed. Run: pip install authlib>=1.3.0"
        )

    discovery_url = idp_config["oidc_discovery_url"]
    doc = _fetch_discovery(discovery_url)
    token_endpoint = doc["token_endpoint"]
    jwks_uri = doc["jwks_uri"]

    base_url = sp_config["base_url"].rstrip("/")
    workspace_id = sp_config["workspace_id"]
    redirect_uri = f"{base_url}/auth/sso/callback/oidc/{workspace_id}"

    # POST to token endpoint using client credentials
    token_resp = _requests.post(
        token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": idp_config["oidc_client_id"],
            "client_secret": idp_config["oidc_client_secret"],
        },
        timeout=15,
    )
    if not token_resp.ok:
        logger.warning(
            "OIDC token exchange failed workspace=%s status=%s",
            workspace_id,
            token_resp.status_code,
        )
        raise ValueError(f"Token exchange failed: HTTP {token_resp.status_code}")

    token_data: dict[str, Any] = token_resp.json()
    id_token_str = token_data.get("id_token")
    if not id_token_str:
        raise ValueError("Token response missing id_token")

    claims = validate_id_token(id_token_str, idp_config, sp_config, jwks_uri=jwks_uri, nonce=nonce)
    return claims


def validate_id_token(
    id_token: str,
    idp_config: dict[str, Any],
    sp_config: dict[str, Any],
    *,
    jwks_uri: str | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Validate an OIDC ID token. Returns the validated claims dict.

    Validates: signature (JWS), iss, aud, exp, iat, nonce (if provided),
    email_verified.

    Raises ValueError on any validation failure.
    Raises RuntimeError if authlib is not installed.
    """
    if not _check_authlib():
        raise RuntimeError(
            "authlib is not installed. Run: pip install authlib>=1.3.0"
        )

    from authlib.jose import JsonWebToken  # noqa: PLC0415
    from authlib.jose.errors import JoseError  # noqa: PLC0415

    discovery_url = idp_config["oidc_discovery_url"]
    workspace_id = sp_config["workspace_id"]
    client_id = idp_config["oidc_client_id"]

    # Resolve JWKS URI from discovery if not pre-fetched
    if not jwks_uri:
        doc = _fetch_discovery(discovery_url)
        jwks_uri = doc["jwks_uri"]
        expected_issuer = doc["issuer"]
    else:
        doc = _fetch_discovery(discovery_url)
        expected_issuer = doc["issuer"]

    key_set = _fetch_jwks(jwks_uri)

    jwt = JsonWebToken(["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"])
    try:
        claims_obj = jwt.decode(id_token, key_set)
    except JoseError as exc:
        raise ValueError(f"ID token JWS validation failed: {exc}") from exc

    claims: dict[str, Any] = dict(claims_obj)

    # ----- iss validation -----
    iss = claims.get("iss")
    if not iss or iss != expected_issuer:
        raise ValueError(
            f"ID token issuer mismatch: expected {expected_issuer!r}, got {iss!r}"
        )

    # ----- aud validation -----
    aud = claims.get("aud")
    if isinstance(aud, str):
        aud = [aud]
    if not aud or client_id not in aud:
        raise ValueError(
            f"ID token audience mismatch: client_id {client_id!r} not in aud {aud!r}"
        )

    # ----- exp / iat validation -----
    now = int(time.time())
    exp = claims.get("exp")
    if exp is None or now > int(exp):
        raise ValueError("ID token has expired")
    iat = claims.get("iat")
    if iat is not None and now < int(iat) - 60:
        raise ValueError("ID token issued in the future (clock skew too large)")

    # ----- nonce validation (replay protection) -----
    if nonce is not None:
        token_nonce = claims.get("nonce")
        if not token_nonce:
            raise ValueError("ID token missing nonce claim")
        # Compare nonce hashes to avoid timing oracle
        if not _safe_compare(token_nonce, nonce):
            raise ValueError("ID token nonce mismatch — possible replay attack")

    # ----- email_verified -----
    email_verified = claims.get("email_verified")
    # Treat missing as False only if the IdP supports the claim
    # Some IdPs (e.g. Azure AD) omit it but always verify — allow via env override
    strict = not (
        idp_config.get("skip_email_verified_check") is True
        or str(idp_config.get("skip_email_verified_check", "")).lower() == "true"
    )
    if strict and email_verified is False:
        raise ValueError("ID token email_verified=false — email not verified by IdP")

    # ----- email extraction -----
    email: str | None = claims.get("email")
    if not email or "@" not in email:
        raise ValueError("ID token missing or invalid email claim")
    email = email.strip().lower()
    claims["email"] = email

    # ----- allowed_email_domains -----
    domains_raw = idp_config.get("allowed_email_domains")
    if domains_raw:
        _check_email_domain(email, domains_raw)

    logger.info(
        "OIDC ID token validated workspace=%s email_domain=%s",
        workspace_id,
        email.split("@")[1],
    )
    return claims


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_compare(a: str, b: str) -> bool:
    """Timing-safe string comparison via SHA-256 digests."""
    ha = hashlib.sha256(a.encode()).digest()
    hb = hashlib.sha256(b.encode()).digest()
    # Use built-in hmac.compare_digest on the hashed values
    import hmac as _hmac  # noqa: PLC0415

    return _hmac.compare_digest(ha, hb)


def _check_email_domain(email: str, domains_raw: str) -> None:
    """Raise ValueError if email's domain is not in the allowed list."""
    allowed = {d.strip().lower() for d in domains_raw.split(",") if d.strip()}
    if not allowed:
        return
    domain = email.split("@", 1)[1]
    if domain not in allowed:
        raise ValueError(
            f"Email domain {domain!r} not in allowed domains for this workspace"
        )
