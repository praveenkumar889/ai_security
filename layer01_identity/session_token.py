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

from jose import jwt, JWTError, ExpiredSignatureError

from .models import SecurityContext

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
        payload = context.model_dump()
        # Ensure expiry is set correctly from TTL
        payload["exp"] = time.time() + self._ttl
        payload["iat"] = time.time()
        token = jwt.encode(payload, self._secret, algorithm=self.ALGORITHM)
        logger.debug("Session token issued for user=%s session=%s",
                     context.user_id, context.session_id)
        return token

    def verify(self, token: str) -> SecurityContext:
        try:
            claims = jwt.decode(token, self._secret, algorithms=[self.ALGORITHM])
        except ExpiredSignatureError:
            raise TokenError("Session token has expired — re-authenticate")
        except JWTError as e:
            raise TokenError(f"Session token is invalid or tampered: {e}") from e

        context = SecurityContext(**claims)

        # Double-check expiry (defense in depth against clock skew)
        if context.is_expired():
            raise TokenError("Session token is expired (clock check)")

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
        payload = context.model_dump()
        payload["exp"] = time.time() + self._ttl
        payload["iat"] = time.time()
        return jwt.encode(payload, self._private_key, algorithm=self.ALGORITHM)

    def verify(self, token: str) -> SecurityContext:
        try:
            claims = jwt.decode(token, self._public_key, algorithms=[self.ALGORITHM])
        except ExpiredSignatureError:
            raise TokenError("Session token has expired — re-authenticate")
        except JWTError as e:
            raise TokenError(f"Session token is invalid: {e}") from e
        return SecurityContext(**claims)


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
