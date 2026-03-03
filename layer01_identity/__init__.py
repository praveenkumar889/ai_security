"""
SentinelSQL — Layer 01: Identity & Context Layer
__init__.py — Public API for authentication and identity management.

This module exports all core classes for building a production-grade
identity and authentication system with support for multiple identity providers
and Neo4j-backed user/role management.
"""

from __future__ import annotations

# ── Context Building ──────────────────────────────────────────────────────
from .context_builder import (
    BaseUserProfileStore,
    BaseDeviceTrustRegistry,
    InMemoryUserProfileStore,
    InMemoryDeviceTrustRegistry,
    SecurityContextBuilder,
)

# ── Identity Providers ────────────────────────────────────────────────────
from .identity_provider import (
    BaseIdentityProvider,
    OAuth2Provider,
    SAMLProvider,
    LDAPProvider,
    AuthenticationError,
)

# ── Data Models ───────────────────────────────────────────────────────────
from .models import (
    SecurityContext,
    IdPClaims,
    UserProfile,
    ClearanceLevel,
    DeviceTrust,
    QueryRequest,
    AuthenticatedQueryRequest,
    Layer01Response,
)

# ── Role Resolution ───────────────────────────────────────────────────────
from .role_resolver import (
    BaseRoleResolver,
    DictRoleResolver,
)

# ── Session Token Management ──────────────────────────────────────────────
from .session_token import (
    BaseSessionTokenIssuer,
    HS256SessionTokenIssuer,
    RS256SessionTokenIssuer,
    TokenError,
)

# ── Neo4j Profile Store ───────────────────────────────────────────────────
from .neo4j_profile_store import Neo4jUserProfileStore

# ── Neo4j Role Resolver ───────────────────────────────────────────────────
from .neo4j_role_resolver import Neo4jRoleResolver

__all__ = [
    # Context Building
    "BaseUserProfileStore",
    "BaseDeviceTrustRegistry",
    "InMemoryUserProfileStore",
    "InMemoryDeviceTrustRegistry",
    "SecurityContextBuilder",
    # Identity Providers
    "BaseIdentityProvider",
    "OAuth2Provider",
    "SAMLProvider",
    "LDAPProvider",
    "AuthenticationError",
    # Data Models
    "SecurityContext",
    "IdPClaims",
    "UserProfile",
    "ClearanceLevel",
    "DeviceTrust",
    "QueryRequest",
    "AuthenticatedQueryRequest",
    "Layer01Response",
    # Role Resolution
    "BaseRoleResolver",
    "DictRoleResolver",
    "Neo4jRoleResolver",
    # Session Tokens
    "BaseSessionTokenIssuer",
    "HS256SessionTokenIssuer",
    "RS256SessionTokenIssuer",
    "TokenError",
    # Neo4j Integration
    "Neo4jUserProfileStore",
]
