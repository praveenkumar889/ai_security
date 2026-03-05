"""
SentinelSQL — main.py
Full FastAPI application: Layer 01 Identity + Auth routes + Static frontend.

Run:
    pip install fastapi uvicorn python-jose[cryptography] httpx pydantic python-dotenv
    python -m uvicorn main:app --reload --port 8000

Then open: http://localhost:8000
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from dotenv import load_dotenv

load_dotenv(override=True)

# ── Setup logging FIRST — before any other imports ────────────────────────────
from logging_config import setup_logging
setup_logging()
# ─────────────────────────────────────────────────────────────────────────────

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from layer01_identity import (
    AuthenticationError,
    ClearanceLevel,
    DictRoleResolver,
    RS256SessionTokenIssuer,
    InMemoryDeviceTrustRegistry,
    InMemoryUserProfileStore,
    SecurityContextBuilder,
    TokenError,
)
from auth.mock_users import MOCK_USERS
from auth.routes import router as auth_router

logger = logging.getLogger("sentinelsql.main")

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("")
    logger.info("=" * 70)
    logger.info("  SentinelSQL — Apollo Hospitals Auth Layer")
    logger.info("  Layer 01: Identity & Context")
    logger.info("=" * 70)

    # ── Load user profiles ─────────────────────────────────────────────────
    logger.info("")
    logger.info(">>> [STARTUP] Initializing Neo4j user profile store...")
    from layer01_identity import Neo4jUserProfileStore
    
    profile_store = Neo4jUserProfileStore(
        uri=os.environ.get("NEO4J_URI"),
        username=os.environ.get("NEO4J_USERNAME"),
        password=os.environ.get("NEO4J_PASSWORD"),
        database=os.environ.get("NEO4J_DATABASE", "neo4j"),
    )
    logger.info(">>> [STARTUP] ✓ Neo4j profile store ready")

    # ── Device registry ────────────────────────────────────────────────────
    logger.info("")
    logger.info(">>> [STARTUP] Initializing device trust registry...")
    managed = {"corp-device-abc123", "corp-device-def456"}
    device_registry = InMemoryDeviceTrustRegistry(managed_fingerprints=managed)
    for fp in managed:
        logger.debug("    Registered managed device: %s", fp)
    logger.info(">>> [STARTUP] Device registry ready (%d managed devices) ✓", len(managed))

    # ── Context builder ────────────────────────────────────────────────────
    logger.info("")
    logger.info(">>> [STARTUP] Initializing SecurityContextBuilder...")
    app.state.context_builder = SecurityContextBuilder(
        profile_store=profile_store,
        device_registry=device_registry,
        auth_method="mock-apollo-idp",
    )
    logger.info(">>> [STARTUP] SecurityContextBuilder ready ✓")

    # ── Role resolver ──────────────────────────────────────────────────────
    logger.info("")
    backend = os.environ.get("ROLE_RESOLVER_BACKEND", "neo4j").lower()
    
    if backend == "neo4j":
        logger.info(">>> [STARTUP] Initializing Neo4j role resolver...")
        from layer01_identity import Neo4jRoleResolver
        
        app.state.role_resolver = Neo4jRoleResolver(
            uri=os.environ.get("NEO4J_URI"),
            username=os.environ.get("NEO4J_USERNAME"),
            password=os.environ.get("NEO4J_PASSWORD"),
            database=os.environ.get("NEO4J_DATABASE", "neo4j"),
            enable_caching=True,
        )
        all_roles = app.state.role_resolver.get_all_roles()
        logger.info(">>> [STARTUP] ✓ Neo4j role resolver ready (%d roles)", len(all_roles))
    else:
        logger.info(">>> [STARTUP] Initializing DictRoleResolver...")
        from layer01_identity import DictRoleResolver
        app.state.role_resolver = DictRoleResolver()
        logger.debug("    Hierarchy loaded with %d roles", len(app.state.role_resolver.get_all_roles()))

    # ── Session token issuer ───────────────────────────────────────────────
    logger.info("")
    logger.info(">>> [STARTUP] Initializing RS256 session token issuer...")
    try:
        app.state.token_issuer = RS256SessionTokenIssuer()
        logger.info(">>> [STARTUP] Token issuer ready (algo=RS256, ttl=3600s) ✓")
    except Exception as e:
        logger.error(f"    CRITICAL: Failed to load RS256 keys from .env! {e}")

    # ── Summary ────────────────────────────────────────────────────────────
    logger.info("")
    logger.info("=" * 70)
    logger.info("  DEMO ACCOUNTS  (password: Apollo@123)")
    logger.info("=" * 70)
    logger.info("  %-20s  %-25s  %-15s", "USERNAME", "ROLE", "CLEARANCE")
    logger.info("  " + "-" * 64)
    for u in MOCK_USERS.values():
        logger.info(
            "  %-20s  %-25s  %-15s",
            u.username, u.role,
            "From Neo4j DB",
        )
    logger.info("=" * 70)
    logger.info("  Server   : http://localhost:8000")
    logger.info("  API Docs : http://localhost:8000/api/docs")
    logger.info("  Logs dir : %s", Path(__file__).parent / "logs")
    logger.info("=" * 70)
    logger.info("")

    yield

    logger.info("")
    logger.info(">>> [SHUTDOWN] SentinelSQL shutting down...")
    if hasattr(app.state, "neo4j_driver"):
        app.state.neo4j_driver.close()
        logger.info(">>> [SHUTDOWN] Neo4j driver closed ✓")
    logger.info(">>> [SHUTDOWN] Goodbye.")


app = FastAPI(
    title="SentinelSQL — Apollo Hospitals",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
)

# ── CORS Middleware Configuration ─────────────────────────────────────────────
# Synchronize with CORS_ORIGINS in .env
cors_origins = os.environ.get(
    "CORS_ORIGINS", 
    "http://localhost:8000,http://127.0.0.1:8000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Device-Fingerprint"],
)


@app.exception_handler(AuthenticationError)
async def auth_error(request: Request, exc: AuthenticationError):
    logger.warning(">>> [AUTH ERROR] %s | path=%s", exc, request.url.path)
    return JSONResponse(status_code=401, content={"detail": str(exc)})


@app.exception_handler(TokenError)
async def token_error(request: Request, exc: TokenError):
    logger.warning(">>> [TOKEN ERROR] %s | path=%s", exc, request.url.path)
    return JSONResponse(status_code=401, content={"detail": str(exc)})


app.include_router(auth_router)


@app.get("/", include_in_schema=False)
async def serve_login():
    logger.debug(">>> [HTTP] GET / — serving login page")
    return FileResponse(
        STATIC_DIR / "index.html",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )


@app.get("/dashboard", include_in_schema=False)
async def serve_dashboard():
    logger.debug(">>> [HTTP] GET /dashboard — serving dashboard page")
    return FileResponse(
        STATIC_DIR / "dashboard.html",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )


@app.get("/health")
async def health():
    logger.debug(">>> [HTTP] GET /health")
    return {"status": "ok", "layer": "01-identity", "users": len(MOCK_USERS)}


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
