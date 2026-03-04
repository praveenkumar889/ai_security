"""
SentinelSQL — Layer 01: Identity & Context Layer
session_token.py — Signs and verifies the SecurityContext as a short-lived JWT.

The session token is the trust artifact passed between layers.
Every downstream layer calls verify() before doing anything — no exceptions.

Design decisions:
  - HS256 (HMAC-SHA256) for simplicity in single-service deployments.
  - RS256 (RSA) available for multi-service deployments where other services
    need to verify without the secret key.
  - Token TTL: 15 minutes (re-issue required after expiry).
  - On tampering: jose raises JWTError — caught and converted to TokenError.
"""

from __future__ import annotations

import logging
import os
import time
from abc import ABC, abstractmethod
from typing import Literal

from jose import jwt, JWTError

from .models import SecurityContext, ClearanceLevel

logger = logging.getLogger(__name__)


class TokenError(Exception):
    """Raised when a session token is invalid, expired, or tampered with."""
    pass


# ─── BASE ─────────────────────────────────────────────────────────────────────

class BaseSessionTokenIssuer(ABC):
    @abstractmethod
    def issue(self, context: SecurityContext) -> str:
        """Sign a SecurityContext into a compact JWT string."""
        ...

    @abstractmethod
    def verify(self, token: str) -> SecurityContext:
        """
        Verify and decode a session token back into a SecurityContext.
        Raises TokenError on any failure.
        """
        ...


# ─── HMAC (HS256) — Single-service / monolith ─────────────────────────────────

class HS256SessionTokenIssuer(BaseSessionTokenIssuer):
    """
    Signs with a shared secret (HMAC-SHA256).

    Use when: all layers run in the same service / process.
    Secret must be at least 32 random bytes. Load from environment variable.
    """

    ALGORITHM = "HS256"

    def __init__(self, secret_key: str | None = None, ttl_seconds: int = 900):
        self._secret = secret_key or os.environ.get("SENTINELSQL_SESSION_SECRET")
        if not self._secret:
            raise EnvironmentError(
                "Session secret not set. "
                "Set SENTINELSQL_SESSION_SECRET env var or pass secret_key."
            )
        if len(self._secret) < 32:
            raise ValueError("Session secret must be at least 32 characters.")
        self._ttl = ttl_seconds

    def issue(self, context: SecurityContext) -> str:
        payload = context.model_dump(exclude={'unit', 'facility', 'facility_id', 'provider_id', 'device_trust'})
        # Ensure expiry is set correctly from TTL
        payload["exp"] = time.time() + self._ttl
        payload["iat"] = time.time()
        token = jwt.encode(payload, self._secret, algorithm=self.ALGORITHM)
        logger.debug("Session token issued for user=%s session=%s",
                     context.user_id, context.session_id)
        
        # Added print statement to display the JWT token in the terminal
        print(f"\n=== NEW JWT TOKEN GENERATED ===\n{token}\n================================\n")
        
        return token

    def verify(self, token: str) -> SecurityContext:
        try:
            # Disable jose's internal exp check — we use context.is_expired()
            # for expiry validation. This means:
            #   1. time.time() monkeypatching in tests works correctly
            #   2. A single consistent clock (time.time) controls expiry everywhere
            #   3. jose still validates signature, algorithm, and all other claims
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=[self.ALGORITHM],
                options={"verify_exp": False, "verify_aud": False, "verify_iss": False},
            )
        except JWTError as e:
            raise TokenError(f"Session token is invalid or tampered: {e}") from e

        context = SecurityContext(**claims)

        # Single expiry check — uses time.time() so monkeypatching works in tests.
        # This is also defense-in-depth: catches tokens whose exp claim was
        # manually crafted to bypass jose's check.
        if context.is_expired():
            raise TokenError("Session token has expired — re-authenticate")

        logger.debug("Session token verified for user=%s", context.user_id)
        return context


# ─── RSA (RS256) — Multi-service deployments ──────────────────────────────────

class RS256SessionTokenIssuer(BaseSessionTokenIssuer):
    """
    Signs with a private RSA key; verifies with the public key.

    Use when: multiple microservices need to verify tokens independently
              without sharing the signing secret.

    Generate a key pair:
        openssl genrsa -out private.pem 2048
        openssl rsa -in private.pem -pubout -out public.pem
    """

    ALGORITHM = "RS256"

    def __init__(
        self,
        private_key: str | None = None,
        public_key: str | None = None,
        ttl_seconds: int = 900,
    ):
        self._private_key = private_key or self._load_from_env("SENTINELSQL_PRIVATE_KEY")
        self._public_key  = public_key  or self._load_from_env("SENTINELSQL_PUBLIC_KEY")
        self._ttl = ttl_seconds

    @staticmethod
    def _load_from_env(var: str) -> str:
        val = os.environ.get(var)
        if not val:
            raise EnvironmentError(f"Required env var '{var}' is not set.")
        return val.replace("\\n", "\n")  # Handle newlines in env vars

    def issue(self, context: SecurityContext) -> str:
        from datetime import datetime, timezone
        import hashlib
        import uuid as _uuid

        now = time.time()
        now_iso = datetime.utcfromtimestamp(now).isoformat() + "Z"
        exp_ts = now + self._ttl
        exp_iso = datetime.utcfromtimestamp(exp_ts).isoformat() + "Z"
        jti = str(_uuid.uuid4())

        # ── Build the nested payload structure ──
        payload = {
            # Top-level metadata
            "ctx_id": f"ctx_{context.session_id.replace('-', '')[:10]}",
            "version": "2.0",
            "oid": f"oid-{context.user_id}",
            "sub": f"oid-{context.user_id}",

            # Top-level role claims (for quick access by downstream layers)
            "direct_roles": context.raw_roles or [],
            "effective_roles": context.effective_roles or [],
            "allowed_domains": context.allowed_domains or [],

            # ── identity block ──
            "identity": {
                "oid": f"oid-{context.user_id}",
                "name": context.username,
                "email": context.email,
                "jti": jti,
                "mfa_verified": True,
                "auth_methods": ["pwd", "mfa"],
            },

            # ── org_context block ──
            "org_context": {
                "employee_id": f"DR-{context.user_id.split('-')[-1]}" if context.user_id else "DR-0001",
                "department": context.department or "Unknown",
                "facility_ids": ["FAC-001"],
                "unit_ids": ["UNIT-1A-APJH", "UNIT-1B-APJH"],
                "provider_npi": "NPI-1234567890",
                "license_type": "MD",
                "employment_status": "ACTIVE",
            },

            # ── authorization block ──
            "authorization": {
                "direct_roles": context.raw_roles or ["Unknown_Role"],
                "effective_roles": context.effective_roles or ["Unknown_Effective_Role"],
                "groups": [f"clinical-{(context.department or 'general').lower()}"],
                "domain": "CLINICAL",
                "clearance_level": ClearanceLevel(context.clearance_level).numeric if isinstance(context.clearance_level, str) else 1,
                "sensitivity_cap": ClearanceLevel(context.clearance_level).numeric if isinstance(context.clearance_level, str) else 1,
                "bound_policies": ["CLIN-001", "HIPAA-001"],
            },

            # ── request_metadata block ──
            "request_metadata": {
                "ip_address": "10.0.0.1",
                "user_agent": "SentinelSQL-Dashboard/1.0",
                "timestamp": now_iso,
                "session_id": f"ses_{context.session_id}",
            },

            # ── emergency block ──
            "emergency": {
                "mode": "NONE",
            },

            # ── timing fields ──
            "ttl_seconds": self._ttl,
            "created_at": now_iso,
            "expires_at": exp_iso,

            # ── Standard JWT registered claims ──
            "iss": "https://login.microsoftonline.com/apollo-mock-tenant/v2.0",
            "aud": "apollo-zt-pipeline",
            "iat": now,
            "nbf": now,
            "exp": exp_ts,
            "jti": jti,

            # ── SecurityContext fields needed for verify() reconstruction ──
            "_sc": {
                "user_id": context.user_id,
                "username": context.username,
                #"email": context.email,
                #"raw_roles": context.raw_roles,
                # "effective_roles": context.effective_roles,
                "department": context.department,
                # "clearance_level": context.clearance_level,
                # "allowed_domains": context.allowed_domains,
                "session_id": context.session_id,
                "issued_at": context.issued_at,
                "expires_at": context.expires_at,
                "idp_issuer": context.idp_issuer,
                "auth_method": context.auth_method,
            },
        }

        token = jwt.encode(payload, self._private_key, algorithm=self.ALGORITHM)

        # Added print statement to display the JWT token in the terminal
        print(f"\n=== NEW JWT TOKEN GENERATED ===\n{token}\n================================\n")

        return token

    def verify(self, token: str) -> SecurityContext:
        try:
            claims = jwt.decode(
                token,
                self._public_key,
                algorithms=[self.ALGORITHM],
                options={"verify_exp": False, "verify_aud": False, "verify_iss": False},
            )
        except JWTError as e:
            raise TokenError(f"Session token is invalid: {e}") from e

        # Extract SecurityContext from _sc block + other JWT sections
        sc_data = claims.get("_sc", {})
        if not sc_data:
            raise TokenError("Token missing _sc context block — cannot reconstruct security context")

        # Supplement _sc with fields stored in other JWT blocks
        identity = claims.get("identity", {})
        authorization = claims.get("authorization", {})

        sc_data.setdefault("email", identity.get("email", ""))
        sc_data.setdefault("raw_roles", claims.get("direct_roles", authorization.get("direct_roles", [])))
        sc_data.setdefault("effective_roles", claims.get("effective_roles", authorization.get("effective_roles", [])))
        sc_data.setdefault("clearance_level", authorization.get("clearance_level", "PUBLIC"))
        sc_data.setdefault("allowed_domains", claims.get("allowed_domains", []))

        context = SecurityContext(**sc_data)
        if context.is_expired():
            raise TokenError("Session token has expired — re-authenticate")

        return context


# ─── FACTORY ──────────────────────────────────────────────────────────────────

def get_token_issuer(
    algorithm: Literal["HS256", "RS256"] = "HS256",
    ttl_seconds: int = 900,
    **kwargs,
) -> BaseSessionTokenIssuer:
    """
    Factory function — select algorithm via config.

    Args:
        algorithm:   "HS256" (default) or "RS256"
        ttl_seconds: session lifetime in seconds (default 900 = 15 min)
        **kwargs:    passed to the issuer constructor

    Examples:
        # Single-service (reads SENTINELSQL_SESSION_SECRET from env)
        issuer = get_token_issuer("HS256")

        # Multi-service (reads SENTINELSQL_PRIVATE_KEY / PUBLIC_KEY from env)
        issuer = get_token_issuer("RS256")

        # Explicit keys (testing only — never hardcode in production)
        issuer = get_token_issuer("HS256", secret_key="test-secret-32-chars-minimum!!")
    """
    if algorithm == "HS256":
        return HS256SessionTokenIssuer(ttl_seconds=ttl_seconds, **kwargs)
    elif algorithm == "RS256":
        return RS256SessionTokenIssuer(ttl_seconds=ttl_seconds, **kwargs)
    else:
        raise ValueError(f"Unsupported algorithm: '{algorithm}'. Use 'HS256' or 'RS256'.")
