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
import os
import time
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel

from layer01_identity.context_builder import SecurityContextBuilder
from layer01_identity.models import IdPClaims, SecurityContext, ClearanceLevel
from layer01_identity.role_resolver import BaseRoleResolver
from layer01_identity.session_token import TokenError
from .mock_users import ROLE_UI_META, MockUser, authenticate, get_user

logger = logging.getLogger("sentinelsql.auth.routes")

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
    allowed_domains:  list[str]
    max_clearance_level: Optional[int] = None


# ─── DEPENDENCY: GET CURRENT USER FROM SESSION TOKEN ──────────────────────────

async def get_current_context(
    request: Request,
    authorization: str = Header(...),
) -> SecurityContext:
    logger.debug(">>> [TOKEN] Verifying session token from Authorization header...")

    if not authorization.startswith("Bearer "):
        logger.warning(">>> [TOKEN] FAILED — Authorization header missing 'Bearer ' prefix")
        raise HTTPException(status_code=401, detail="Authorization must be 'Bearer <token>'")

    token = authorization[7:]
    logger.debug(">>> [TOKEN] JWT received: %s...%s (%d chars)", token[:20], token[-10:], len(token))

    try:
        context = request.app.state.token_issuer.verify(token)
        logger.debug(
            ">>> [TOKEN] Verified ✓ | user=%s | session=%s | expires_in=%.0fs",
            context.user_id,
            context.session_id,
            context.expires_at - time.time(),
        )
        return context
    except TokenError as e:
        logger.warning(">>> [TOKEN] INVALID — %s", e)
        raise HTTPException(status_code=401, detail=str(e))


# ─── ENDPOINTS ────────────────────────────────────────────────────────────────

@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    request: Request,
    x_device_fingerprint: str = Header(default="unknown"),
):
    logger.info("")
    logger.info("━" * 65)
    logger.info(">>> [LOGIN] ══════════ LOGIN ATTEMPT ══════════")
    logger.info(">>> [LOGIN] Username      : %s", body.username)
    logger.info(">>> [LOGIN] Password      : %s", "*" * len(body.password))
    logger.info(">>> [LOGIN] Device FP     : %s", x_device_fingerprint)
    logger.info(">>> [LOGIN] Client IP     : %s", request.client.host if request.client else "unknown")
    logger.info("━" * 65)

    # ── Step 1: Validate credentials ──────────────────────────────────────
    logger.info(">>> [LOGIN] Step 1/5 — Validating credentials against mock store...")
    mock_user: Optional[MockUser] = authenticate(body.username, body.password)

    if mock_user is None:
        existing = get_user(body.username)
        if existing and not existing.is_active:
            logger.warning(">>> [LOGIN] ✗ BLOCKED — Account '%s' is suspended", body.username)
            raise HTTPException(status_code=403, detail="Account is suspended. Contact your administrator.")
        logger.warning(">>> [LOGIN] ✗ FAILED — Invalid credentials for username='%s'", body.username)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    logger.info(">>> [LOGIN] ✓ Credentials valid")
    logger.info("            display_name  = %s", mock_user.display_name)
    logger.info("            role          = %s", mock_user.role)
    logger.info("            is_active     = %s", mock_user.is_active)

    # ── Step 2: Build IdPClaims ────────────────────────────────────────────
    logger.info("")
    logger.info(">>> [LOGIN] Step 2/5 — Building IdPClaims (simulates OAuth2 IdP response)...")
    idp_claims = IdPClaims(
        sub=mock_user.username,
        email=f"{mock_user.username}@apollohospitals.com",
        preferred_username=mock_user.display_name,
        groups=[mock_user.role],  # ← Pass role from mock_users!
        department=mock_user.department,
        iss="mock-apollo-idp",
    )
    logger.info(">>> [LOGIN] ✓ IdPClaims built")
    logger.info("            sub               = %s", idp_claims.sub)
    logger.info("            email             = %s", idp_claims.email)
    logger.info("            preferred_username = %s", idp_claims.preferred_username)
    logger.info("            issuer            = %s", idp_claims.iss)

    # ── Step 3: Build SecurityContext ─────────────────────────────────────
    logger.info("")
    logger.info(">>> [LOGIN] Step 3/5 — Building SecurityContext (context_builder.py)...")
    context_builder: SecurityContextBuilder = request.app.state.context_builder
    try:
        context = await context_builder.build(
            idp_claims=idp_claims,
            device_fingerprint=x_device_fingerprint,
        )
    except ValueError as e:
        logger.error(">>> [LOGIN] ✗ SecurityContext build FAILED — %s", e)
        raise HTTPException(status_code=403, detail=str(e))

    logger.info(">>> [LOGIN] ✓ SecurityContext assembled")
    logger.info("            user_id          = %s", context.user_id)
    logger.info("            session_id       = %s", context.session_id)
    logger.info("            department       = %s", context.department)
    logger.info("            unit             = %s", context.unit)
    logger.info("            facility         = %s", context.facility)
    logger.info("            clearance_level  = %s", context.clearance_level)
    logger.info("            device_trust     = %s", context.device_trust)
    logger.info("            raw_roles        = %s", context.raw_roles)
    logger.info("            issued_at        = %.0f", context.issued_at)
    logger.info("            expires_at       = %.0f  (+3600s)", context.expires_at)

    # ── Step 4: Resolve role hierarchy ────────────────────────────────────
    logger.info("")
    logger.info(">>> [LOGIN] Step 4/5 — Resolving role hierarchy (role_resolver.py)...")
    logger.info(">>> [LOGIN] Input  : %s", context.raw_roles)
    role_resolver: BaseRoleResolver = request.app.state.role_resolver
    context.effective_roles = role_resolver.resolve(context.raw_roles)
    logger.info(">>> [LOGIN] ✓ BFS traversal complete — effective roles:")
    for r in context.effective_roles:
        logger.info("            + %s", r)
        
    # Apply clearance from Role Graph since Staff nodes don't exist yet
    metadata = role_resolver.get_role_metadata(context.effective_roles)
    max_lvl = metadata.get("max_clearance_level")
    if max_lvl is not None:
        level_map = {
            0: ClearanceLevel.PUBLIC,
            1: ClearanceLevel.INTERNAL,
            2: ClearanceLevel.CONFIDENTIAL,
            3: ClearanceLevel.SECRET,
            4: ClearanceLevel.TOP_SECRET,
        }
        context.clearance_level = level_map.get(max_lvl, ClearanceLevel.PUBLIC)
        logger.info(">>> [LOGIN] ✓ Neo4j Roles dictate Clearance Level: %s", context.clearance_level.value)

    # ── Step 5: Issue JWT session token ───────────────────────────────────
    logger.info("")
    logger.info(">>> [LOGIN] Step 5/5 — Signing JWT session token (session_token.py)...")
    session_token = request.app.state.token_issuer.issue(context)
    logger.info(">>> [LOGIN] ✓ JWT signed successfully")
    logger.info("            Algorithm    = HS256")
    logger.info("            Token length = %d chars", len(session_token))
    logger.info("            Preview      = %s...%s", session_token[:25], session_token[-15:])

    # ── Final summary ─────────────────────────────────────────────────────
    logger.info("")
    logger.info(">>> [LOGIN] ✅ LOGIN SUCCESS")
    logger.info("            User         = %s  (%s)", mock_user.display_name, mock_user.username)
    logger.info("            Clearance    = %s", context.clearance_level)
    logger.info("            Department   = %s", context.department)
    logger.info("            Facility     = %s", context.facility)
    logger.info("            Device Trust = %s", context.device_trust)
    logger.info("            Session ID   = %s", context.session_id)
    logger.info("            Expires in   = 3600s (60 minutes)")
    logger.info("━" * 65)
    logger.info("")

    return LoginResponse(
        session_token=session_token,
        user_id=context.user_id,
        display_name=mock_user.display_name,
        role=context.raw_roles[0] if context.raw_roles else "BASE_USER",
        effective_roles=context.effective_roles,
        clearance_level=context.clearance_level.value if hasattr(context.clearance_level, 'value') else str(context.clearance_level),
        device_trust=context.device_trust.value if hasattr(context.device_trust, 'value') else str(context.device_trust),
        department_label=mock_user.department,
        avatar_initials="".join(p[0] for p in mock_user.display_name.replace("Dr. ", "").split() if p).upper()[:2],
        avatar_color="#0EA5E9",
        expires_at=context.expires_at,
    )


@router.post("/logout")
async def logout(request: Request):
    logger.info("")
    logger.info(">>> [LOGOUT] User logged out | client=%s",
                request.client.host if request.client else "unknown")
    logger.info(">>> [LOGOUT] Token cleared client-side (stateless JWT design)")
    logger.info(">>> [LOGOUT] TODO (production): Add token JTI to Redis denylist")
    logger.info("")
    return {
        "status": "logged_out",
        "message": "Session token cleared. Please remove it from client storage.",
    }


@router.get("/me", response_model=MeResponse)
async def get_me(
    request: Request,
    context: SecurityContext = Depends(get_current_context),
):
    logger.info("")
    logger.info(">>> [/me] Dashboard data request | user=%s | session=%s",
                context.user_id, context.session_id)

    mock_user = get_user(context.user_id)
    if mock_user is None:
        logger.error(">>> [/me] ✗ User profile not found for user_id=%s", context.user_id)
        raise HTTPException(status_code=404, detail="User profile not found")

    primary_role = context.raw_roles[0] if context.raw_roles else "BASE_USER"
    ui_meta = ROLE_UI_META.get(primary_role, ROLE_UI_META.get("DATA_ANALYST", {}))

    logger.info(">>> [/me] ✓ Profile found — returning dashboard data")
    logger.info("          display_name    = %s", mock_user.display_name)
    logger.info("          role            = %s", primary_role)
    logger.info("          clearance       = %s", context.clearance_level)
    logger.info("          device_trust    = %s", context.device_trust)
    logger.info("          effective_roles = %s", context.effective_roles)
    
    # Fetch additional metadata straight from the role resolver
    role_resolver: BaseRoleResolver = request.app.state.role_resolver
    
    # RE-RESOLVE: Expand roles and sync clearance level (since JWT is minimal)
    context.effective_roles = role_resolver.resolve(context.raw_roles)
    metadata = role_resolver.get_role_metadata(context.effective_roles)
    max_lvl = metadata.get("max_clearance_level")
    
    if max_lvl is not None:
        level_map = {
            0: ClearanceLevel.PUBLIC,
            1: ClearanceLevel.INTERNAL,
            2: ClearanceLevel.CONFIDENTIAL,
            3: ClearanceLevel.SECRET,
            4: ClearanceLevel.TOP_SECRET,
        }
        context.clearance_level = level_map.get(max_lvl, ClearanceLevel.PUBLIC)
        logger.info("          clearance_sync  = %s (Level %d)", context.clearance_level, max_lvl)
    
    logger.info("          permissions     = %d cards", len(ui_meta.get("permissions", [])))
    logger.info("")

    return MeResponse(
        user_id=context.user_id,
        display_name=mock_user.display_name,
        username=mock_user.username,
        role=primary_role,
        effective_roles=context.effective_roles,
        clearance_level=context.clearance_level.value if hasattr(context.clearance_level, 'value') else str(context.clearance_level),
        device_trust=context.device_trust.value if hasattr(context.device_trust, 'value') else str(context.device_trust),
        department=mock_user.department,
        facility=context.facility,
        department_label=mock_user.department,
        avatar_initials="".join(p[0] for p in mock_user.display_name.replace("Dr. ", "").split() if p).upper()[:2],
        avatar_color="#0EA5E9",
        session_id=context.session_id,
        expires_at=context.expires_at,
        permissions=ui_meta.get("permissions", []),
        badge_color=ui_meta.get("badge_color", "#64748B"),
        allowed_domains=metadata.get("allowed_domains", []),
        max_clearance_level=metadata.get("max_clearance_level")
    )


@router.get("/users", include_in_schema=False)
async def list_demo_users():
    """Dev-only endpoint — lists all demo accounts. Remove in production."""
    if os.environ.get("APP_ENV", "development") != "development":
        raise HTTPException(status_code=404)

    logger.debug(">>> [/users] Demo user list requested")
    from .mock_users import MOCK_USERS
    return {
        "note": "Development mode — remove /auth/users in production",
        "password_for_all": "Apollo@123",
        "users": [
            {
                "username": u.username,
                "display_name": u.display_name,
                "role": u.role,
                "department": u.department,
                "clearance": "Fetched from DB at login",
            }
            for u in MOCK_USERS.values()
        ],
    }
