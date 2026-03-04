"""
SentinelSQL — Layer 01: Identity & Context Layer
models.py — Core data contracts for the security context pipeline.

The SecurityContext is the central object that travels (as a signed JWT)
through every subsequent layer. Nothing downstream is trusted without it.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict
import time
import uuid


# ─── ENUMS ────────────────────────────────────────────────────────────────────

class ClearanceLevel(str, Enum):
    PUBLIC       = "PUBLIC"
    INTERNAL     = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET       = "SECRET"
    TOP_SECRET   = "TOP_SECRET"

    @property
    def numeric(self) -> int:
        """Numeric rank for comparison (higher = more privileged)."""
        return {
            "PUBLIC": 0,
            "INTERNAL": 1,
            "CONFIDENTIAL": 2,
            "SECRET": 3,
            "TOP_SECRET": 4,
        }[self.value]

    def can_access(self, required: "ClearanceLevel") -> bool:
        return self.numeric >= required.numeric


class DeviceTrust(str, Enum):
    MANAGED   = "managed"    # MDM-enrolled, corp device
    UNMANAGED = "unmanaged"  # personal / unknown device
    UNKNOWN   = "unknown"    # fingerprint absent


# ─── SECURITY CONTEXT ─────────────────────────────────────────────────────────

class SecurityContext(BaseModel):
    """
    The fully-resolved security identity for one request.
    Issued once at Layer 01 and verified (never re-built) by every downstream layer.
    """

    # Identity
    user_id:     str = Field(..., description="Stable unique identifier from IdP (sub claim)")
    username:    str = Field(..., description="Human-readable login name")
    email:       str = Field(..., description="Verified email from IdP")

    # Roles
    raw_roles:      list[str] = Field(default_factory=list, description="Roles exactly as received from IdP")
    effective_roles: list[str] = Field(default_factory=list, description="All roles after hierarchy flattening")

    # Organizational attributes
    department:    Optional[str] = None
    unit:          Optional[str] = None
    facility:      Optional[str] = None
    facility_id:   Optional[str] = None   # internal DB FK, set by context_builder
    provider_id:   Optional[str] = None   # Healthcare: treating-provider ID for row-level filters

    # Security classification
    clearance_level: ClearanceLevel = Field(
        default=ClearanceLevel.PUBLIC,
        description="Max data sensitivity this user may see"
    )

    # Domain access
    allowed_domains: list[str] = Field(default_factory=list, description="Data domains this user may query")

    # Session metadata
    session_id:    str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_trust:  DeviceTrust = DeviceTrust.UNKNOWN
    issued_at:     float = Field(default_factory=time.time)
    expires_at:    float = Field(default=0.0)

    # Audit trail
    idp_issuer:    Optional[str] = None   # Which IdP issued the original token
    auth_method:   str = "unknown"        # "oauth2", "saml", "ldap"

    model_config = ConfigDict(use_enum_values=True)

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def has_role(self, role: str) -> bool:
        return role in self.effective_roles

    def has_any_role(self, *roles: str) -> bool:
        return any(r in self.effective_roles for r in roles)

    def can_see_clearance(self, level: ClearanceLevel) -> bool:
        return ClearanceLevel(self.clearance_level).can_access(level)

    def to_audit_dict(self) -> dict:
        """Minimal representation safe to write to audit logs."""
        return {
            "user_id":        self.user_id,
            "session_id":     self.session_id,
            "effective_roles": self.effective_roles,
            "clearance_level": self.clearance_level,
            "device_trust":   self.device_trust,
            "issued_at":      self.issued_at,
        }


# ─── TOKEN PAYLOADS ───────────────────────────────────────────────────────────

class IdPClaims(BaseModel):
    """
    Normalized claims extracted from an IdP token (OAuth2 JWT or SAML assertion).
    Field names map to OIDC standard claims where possible.
    """
    sub:                 str                    # Unique user ID
    email:               str = ""
    preferred_username:  str = ""
    groups:              list[str] = Field(default_factory=list)
    iss:                 Optional[str] = None   # Issuer
    aud:                 Optional[str] = None   # Audience
    exp:                 Optional[float] = None
    iat:                 Optional[float] = None

    # Non-standard claims your IdP may include
    department:          Optional[str] = None
    clearance_level:     Optional[str] = None
    facility:            Optional[str] = None
    provider_id:         Optional[str] = None


class UserProfile(BaseModel):
    """
    Internal user profile (from HR/directory DB), merged with IdP claims.
    These fields are NOT in the IdP token — they come from your own store.
    """
    user_id:         str
    department:      Optional[str] = None
    unit:            Optional[str] = None
    facility:        Optional[str] = None
    provider_id:     Optional[str] = None
    clearance_level: ClearanceLevel = ClearanceLevel.PUBLIC
    is_active:       bool = True
    roles:           list[str] = Field(default_factory=list)


# ─── API REQUEST / RESPONSE ───────────────────────────────────────────────────

class QueryRequest(BaseModel):
    question: str = Field(..., min_length=3, max_length=2000)


class AuthenticatedQueryRequest(BaseModel):
    question:      str
    session_token: str   # Signed SecurityContext JWT from Layer 01


class Layer01Response(BaseModel):
    session_token:   str
    user_id:         str
    effective_roles: list[str]
    clearance_level: str
    device_trust:    str
    expires_at:      float
    status:          str = "authenticated"
