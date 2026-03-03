"""
SentinelSQL — Layer 01: Identity & Context Layer
context_builder.py — Builds the full SecurityContext from IdP claims + internal profile.

The SecurityContextBuilder merges:
  1. IdPClaims  — from the validated token (identity source of truth)
  2. UserProfile — from your internal DB (department, clearance, facility, etc.)
  3. Device assessment — from the request fingerprint header

Zero Trust rule: clearance_level ALWAYS defaults DOWN (to PUBLIC) on any ambiguity.
Never assume a higher clearance; always require explicit evidence.
"""

from __future__ import annotations

import logging
import time
import uuid
from abc import ABC, abstractmethod
from typing import Optional

from .models import (
    ClearanceLevel,
    DeviceTrust,
    IdPClaims,
    SecurityContext,
    UserProfile,
)

logger = logging.getLogger(__name__)

# Session TTL in seconds (15 minutes — short-lived by design)
SESSION_TTL_SECONDS = 900


# ─── USER PROFILE STORE (abstract) ────────────────────────────────────────────

class BaseUserProfileStore(ABC):
    """
    Interface for fetching internal user profiles.
    Implement this for your DB of choice (PostgreSQL, DynamoDB, etc.)
    """

    @abstractmethod
    async def get(self, user_id: str) -> Optional[UserProfile]:
        """Return the internal profile for user_id, or None if not found."""
        ...

    @abstractmethod
    async def is_active(self, user_id: str) -> bool:
        """Return False if the account is suspended or deprovisioned."""
        ...


class InMemoryUserProfileStore(BaseUserProfileStore):
    """
    In-memory store for development / testing.
    Replace with PostgresUserProfileStore or DynamoUserProfileStore in production.
    """

    def __init__(self, profiles: dict[str, UserProfile] | None = None):
        self._profiles: dict[str, UserProfile] = profiles or {}

    def add(self, profile: UserProfile) -> None:
        self._profiles[profile.user_id] = profile

    async def get(self, user_id: str) -> Optional[UserProfile]:
        return self._profiles.get(user_id)

    async def is_active(self, user_id: str) -> bool:
        profile = self._profiles.get(user_id)
        return profile.is_active if profile else True  # unknown = allow, log


# ─── DEVICE TRUST REGISTRY (abstract) ────────────────────────────────────────

class BaseDeviceTrustRegistry(ABC):
    @abstractmethod
    async def assess(self, fingerprint: str) -> DeviceTrust:
        ...


class InMemoryDeviceTrustRegistry(BaseDeviceTrustRegistry):
    """
    Simple allowlist of MDM-enrolled device fingerprints.
    In production, integrate with your MDM (Jamf, Intune, etc.) via their API.
    """

    def __init__(self, managed_fingerprints: set[str] | None = None):
        self._managed: set[str] = managed_fingerprints or set()

    def register(self, fingerprint: str) -> None:
        self._managed.add(fingerprint)

    async def assess(self, fingerprint: str) -> DeviceTrust:
        if not fingerprint or fingerprint == "unknown":
            return DeviceTrust.UNKNOWN
        if fingerprint in self._managed:
            return DeviceTrust.MANAGED
        return DeviceTrust.UNMANAGED


# ─── SECURITY CONTEXT BUILDER ─────────────────────────────────────────────────

class SecurityContextBuilder:
    """
    Assembles a SecurityContext from three inputs:
      - IdPClaims (already validated by IdentityProvider)
      - UserProfile (from internal directory)
      - Device fingerprint (from request header)

    Merge priority for conflicting fields:
      clearance_level → minimum(idp_claim, internal_profile)  [always safer]
      department      → internal_profile wins over IdP claim
      groups/roles    → IdP is source of truth
    """

    def __init__(
        self,
        profile_store: BaseUserProfileStore,
        device_registry: BaseDeviceTrustRegistry,
        session_ttl: int = SESSION_TTL_SECONDS,
        auth_method: str = "oauth2",
    ):
        self._profiles = profile_store
        self._devices  = device_registry
        self._ttl      = session_ttl
        self._auth_method = auth_method

    async def build(
        self,
        idp_claims: IdPClaims,
        device_fingerprint: str = "unknown",
    ) -> SecurityContext:
        """
        Main entry point. Returns a fully-populated SecurityContext.

        Raises:
            ValueError: if the account is deprovisioned (is_active = False)
        """
        # ── 1. Check account is still active ──────────────────────────────
        if not await self._profiles.is_active(idp_claims.sub):
            logger.warning("Deprovisioned account attempted access: %s", idp_claims.sub)
            raise ValueError(f"Account '{idp_claims.sub}' is deprovisioned or suspended")

        # ── 2. Fetch internal profile (may be None for new users) ──────────
        profile = await self._profiles.get(idp_claims.sub)
        if profile is None:
            logger.info("No internal profile for user '%s' — applying minimum defaults", idp_claims.sub)

        # ── 3. Resolve clearance (take the LOWER of IdP vs internal) ──────
        clearance = self._resolve_clearance(idp_claims, profile)

        # ── 4. Assess device trust ─────────────────────────────────────────
        device_trust = await self._devices.assess(device_fingerprint)
        if device_trust == DeviceTrust.UNMANAGED:
            logger.warning(
                "Unmanaged device for user %s (fingerprint: %s). "
                "Consider restricting clearance or requiring MFA.",
                idp_claims.sub, device_fingerprint,
            )

        # ── 5. Assemble context ────────────────────────────────────────────
        now = time.time()
        context = SecurityContext(
            user_id=idp_claims.sub,
            username=idp_claims.preferred_username or idp_claims.sub,
            email=idp_claims.email,

            raw_roles=profile.roles if profile and profile.roles else idp_claims.groups,
            effective_roles=[],

            department=profile.department if profile else idp_claims.department,
            unit=profile.unit if profile else None,
            facility=profile.facility if profile else idp_claims.facility,
            provider_id=profile.provider_id if profile else idp_claims.provider_id,

            clearance_level=clearance,
            session_id=str(uuid.uuid4()),
            device_trust=device_trust,
            issued_at=now,
            expires_at=now + self._ttl,
            idp_issuer=idp_claims.iss,
            auth_method=self._auth_method,
        )

        logger.info(
            "SecurityContext built | user=%s session=%s clearance=%s device=%s roles=%s",
            context.user_id,
            context.session_id,
            context.clearance_level,
            context.device_trust,
            context.raw_roles,
        )

        return context

    # ── helpers ────────────────────────────────────────────────────────────────

    def _resolve_clearance(
        self,
        idp_claims: IdPClaims,
        profile: Optional[UserProfile],
    ) -> ClearanceLevel:
        """
        Zero Trust clearance resolution:
        - If BOTH IdP and profile specify a level, take the LOWER (more restrictive).
        - If only one specifies, use that.
        - Default: PUBLIC.
        """
        levels: list[ClearanceLevel] = []

        if idp_claims.clearance_level:
            try:
                levels.append(ClearanceLevel(idp_claims.clearance_level.upper()))
            except ValueError:
                logger.warning(
                    "Unknown clearance level in IdP claims: '%s' — defaulting to PUBLIC",
                    idp_claims.clearance_level,
                )

        if profile and profile.clearance_level:
            levels.append(profile.clearance_level)

        if not levels:
            return ClearanceLevel.PUBLIC

        # Return the least privileged level (minimum numeric value)
        return min(levels, key=lambda c: c.numeric)
