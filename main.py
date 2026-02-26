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

load_dotenv()
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from layer01_identity import (
    AuthenticationError,
    ClearanceLevel,
    DictRoleResolver,
    HS256SessionTokenIssuer,
    InMemoryDeviceTrustRegistry,
    InMemoryUserProfileStore,
    SecurityContextBuilder,
    TokenError,
)
from auth.mock_users import MOCK_USERS
from auth.routes import router as auth_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("sentinelsql")

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 60)
    logger.info("  SentinelSQL starting up")
    logger.info("=" * 60)

    profile_store = InMemoryUserProfileStore()
    for user in MOCK_USERS.values():
        profile_store.add(user.profile)
    logger.info("Loaded %d user profiles", len(MOCK_USERS))

    device_registry = InMemoryDeviceTrustRegistry(
        managed_fingerprints={"corp-device-abc123", "corp-device-def456"}
    )

    app.state.context_builder = SecurityContextBuilder(
        profile_store=profile_store,
        device_registry=device_registry,
        auth_method="mock-apollo-idp",
    )
    app.state.role_resolver = DictRoleResolver()
    app.state.token_issuer  = HS256SessionTokenIssuer(
        secret_key=os.environ.get("SENTINELSQL_SESSION_SECRET")
    )

    logger.info("Layer 01 Identity ready")
    logger.info("Open http://localhost:8000")
    logger.info("Demo users (password: Apollo@123):")
    for u in MOCK_USERS.values():
        logger.info("  %-18s -> %-25s [%s]", u.username, u.role, u.profile.clearance_level)
    logger.info("=" * 60)
    yield
    # ── Teardown ──────────────────────────────────────────
    if hasattr(app.state, "neo4j_driver"):
        app.state.neo4j_driver.close()
    logger.info("SentinelSQL shutting down.")


app = FastAPI(
    title="SentinelSQL — Apollo Hospitals",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Device-Fingerprint"],
)

@app.exception_handler(AuthenticationError)
async def auth_error(request: Request, exc: AuthenticationError):
    return JSONResponse(status_code=401, content={"detail": str(exc)})

@app.exception_handler(TokenError)
async def token_error(request: Request, exc: TokenError):
    return JSONResponse(status_code=401, content={"detail": str(exc)})

app.include_router(auth_router)

@app.get("/", include_in_schema=False)
async def serve_login():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/dashboard", include_in_schema=False)
async def serve_dashboard():
    return FileResponse(STATIC_DIR / "dashboard.html")

@app.get("/health")
async def health():
    return {"status": "ok", "layer": "01-identity", "users": len(MOCK_USERS)}

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
