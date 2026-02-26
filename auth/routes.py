"""
SentinelSQL — Auth Layer
routes.py — FastAPI router for /auth endpoints.

Endpoints:
  POST /auth/login   → validate credentials → build SecurityContext → issue JWT
  POST /auth/logout  → client-side only (returns instruction to clear token)
  GET  /auth/me      → decode current session token → return user + role UI data
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel

from layer01_identity.context_builder import SecurityContextBuilder
from layer01_identity.models import IdPClaims, SecurityContext
from layer01_identity.role_resolver import BaseRoleResolver
from layer01_identity.session_token import TokenError
from .mock_users import ROLE_UI_META, MockUser, authenticate, get_user

logger = logging.getLogger("sentinelsql.auth")

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ─── REQUEST / RESPONSE SCHEMAS ───────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    session_token:    str
    user_id:          str
    display_name:     str
    role:             str
    effective_roles:  list[str]
    clearance_level:  str
    device_trust:     str
    department_label: str
    avatar_initials:  str
    avatar_color:     str
    expires_at:       float
    status:           str = "authenticated"


class MeResponse(BaseModel):
    user_id:          str
    display_name:     str
    username:         str
    role:             str
    effective_roles:  list[str]
    clearance_level:  str
    device_trust:     str
    department:       Optional[str]
    facility:         Optional[str]
    department_label: str
    avatar_initials:  str
    avatar_color:     str
    session_id:       str
    expires_at:       float
    permissions:      list[dict]
    badge_color:      str


# ─── DEPENDENCY: GET CURRENT USER FROM SESSION TOKEN ─────────────────────────

async def get_current_context(
    request: Request,
    authorization: str = Header(...),
) -> SecurityContext:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization must be 'Bearer <token>'")
    token = authorization[7:]
    try:
        return request.app.state.token_issuer.verify(token)
    except TokenError as e:
        raise HTTPException(status_code=401, detail=str(e))


# ─── ENDPOINTS ────────────────────────────────────────────────────────────────

@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    request: Request,
    x_device_fingerprint: str = Header(default="unknown"),
):
    """
    Authenticate with username + password.
    Returns a signed SecurityContext JWT on success.
    """

    # ── 1. Validate credentials against mock store ─────────────────────────
    mock_user: Optional[MockUser] = authenticate(body.username, body.password)
    if mock_user is None:
        # Check if user exists but is suspended
        existing = get_user(body.username)
        if existing and not existing.is_active:
            raise HTTPException(status_code=403, detail="Account is suspended. Contact your administrator.")
        logger.warning("Failed login attempt for username='%s'", body.username)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # ── 2. Build IdPClaims from mock user (simulates what OAuth2Provider would return) ─
    idp_claims = IdPClaims(
        sub=mock_user.username,
        email=f"{mock_user.username}@apollohospitals.com",
        preferred_username=mock_user.display_name,
        groups=[mock_user.role],
        iss="mock-apollo-idp",
    )

    # ── 3. Build SecurityContext via Layer 01 pipeline ─────────────────────
    context_builder: SecurityContextBuilder = request.app.state.context_builder
    try:
        context = await context_builder.build(
            idp_claims=idp_claims,
            device_fingerprint=x_device_fingerprint,
        )
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

    # ── 4. Resolve role hierarchy ──────────────────────────────────────────
    role_resolver: BaseRoleResolver = request.app.state.role_resolver
    context.effective_roles = role_resolver.resolve(context.raw_roles)

    # ── 5. Issue signed session token ─────────────────────────────────────
    session_token = request.app.state.token_issuer.issue(context)

    logger.info(
        "Login successful | user=%s role=%s clearance=%s effective_roles=%s",
        mock_user.username,
        mock_user.role,
        context.clearance_level,
        context.effective_roles,
    )

    return LoginResponse(
        session_token=session_token,
        user_id=context.user_id,
        display_name=mock_user.display_name,
        role=mock_user.role,
        effective_roles=context.effective_roles,
        clearance_level=context.clearance_level,
        device_trust=context.device_trust,
        department_label=mock_user.department_label,
        avatar_initials=mock_user.avatar_initials,
        avatar_color=mock_user.avatar_color,
        expires_at=context.expires_at,
    )


@router.post("/logout")
async def logout():
    """
    Logout — stateless JWT design means the token is cleared client-side.
    In production: add the token to a server-side denylist (Redis TTL).
    """
    return {
        "status": "logged_out",
        "message": "Session token cleared. Please remove it from client storage.",
    }


@router.get("/me", response_model=MeResponse)
async def get_me(
    request: Request,
    context: SecurityContext = Depends(get_current_context),
):
    """
    Returns full user context + role-specific permission UI data.
    Called by the dashboard after login to render the role cards.
    """
    mock_user = get_user(context.user_id)
    if mock_user is None:
        raise HTTPException(status_code=404, detail="User profile not found")

    # Get the primary role (first raw role = the role they logged in with)
    primary_role = context.raw_roles[0] if context.raw_roles else "BASE_USER"
    ui_meta = ROLE_UI_META.get(primary_role, ROLE_UI_META.get("DATA_ANALYST", {}))

    return MeResponse(
        user_id=context.user_id,
        display_name=mock_user.display_name,
        username=mock_user.username,
        role=primary_role,
        effective_roles=context.effective_roles,
        clearance_level=context.clearance_level,
        device_trust=context.device_trust,
        department=context.department,
        facility=context.facility,
        department_label=mock_user.department_label,
        avatar_initials=mock_user.avatar_initials,
        avatar_color=mock_user.avatar_color,
        session_id=context.session_id,
        expires_at=context.expires_at,
        permissions=ui_meta.get("permissions", []),
        badge_color=ui_meta.get("badge_color", "#64748B"),
    )


import os

@router.get("/users", include_in_schema=False)
async def list_demo_users():
    """
    Returns all available demo accounts.
    REMOVE THIS ENDPOINT IN PRODUCTION.
    """
    if os.environ.get("APP_ENV", "development") != "development":
        raise HTTPException(status_code=404)
        
    from .mock_users import MOCK_USERS
    return {
        "note": "Development mode — remove /auth/users in production",
        "password_for_all": "Apollo@123",
        "users": [
            {
                "username": u.username,
                "display_name": u.display_name,
                "role": u.role,
                "department": u.department_label,
                "clearance": u.profile.clearance_level,
            }
            for u in MOCK_USERS.values()
        ],
    }
