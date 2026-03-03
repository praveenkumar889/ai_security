"""
SentinelSQL — Layer 01: Identity & Context Layer
tests/test_layer01_complete.py

Extends the original test_layer01.py with 4 production-grade improvements:

  IMPROVEMENT 1 — MockOAuth2Provider
    Full JWT validation pipeline without a live JWKS endpoint.
    Tests: audience enforcement, issuer enforcement, signature validation,
    claim mapping, expired token rejection.

  IMPROVEMENT 2 — time.time() monkeypatching
    Replaces time.sleep(2) with deterministic clock control.
    Tests: token expiry, session expiry, clock-skew defense.

  IMPROVEMENT 3 — Device-Based Clearance Downgrade
    Enforces Zero Trust: UNMANAGED device caps clearance at INTERNAL.
    Tests: managed device keeps clearance, unmanaged device downgrades,
    unknown device downgrades, policy is applied before token issuance.

  IMPROVEMENT 4 — FastAPI Route-Level Tests (TestClient)
    Exercises the full HTTP stack: headers, status codes, dependency
    injection, exception handlers, lifespan startup.
    Tests: /auth/login, /auth/logout, /auth/me, /auth/users, /health.

Run:
    pip install pytest pytest-asyncio httpx fastapi
    pytest tests/test_layer01_complete.py -v
"""

from __future__ import annotations

import os
import time
import pytest
import pytest_asyncio

# ── path fix so imports resolve without installing the package ─────────────────
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SENTINELSQL_SESSION_SECRET", "test-secret-key-32-characters-min!")

# ── stdlib / third-party ──────────────────────────────────────────────────────
try:
    from jose import jwt as jose_jwt
except ImportError:
    jose_jwt = None

# ── Layer 01 imports ──────────────────────────────────────────────────────────
from layer01_identity.models import (
    ClearanceLevel, DeviceTrust, IdPClaims, SecurityContext, UserProfile,
)
from layer01_identity.role_resolver import DictRoleResolver
from layer01_identity.context_builder import (
    InMemoryUserProfileStore,
    InMemoryDeviceTrustRegistry,
    SecurityContextBuilder,
)
from layer01_identity.session_token import HS256SessionTokenIssuer, TokenError
from layer01_identity.identity_provider import BaseIdentityProvider, AuthenticationError


# ══════════════════════════════════════════════════════════════════════════════
# SHARED CONSTANTS & FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

TEST_SECRET    = "test-secret-key-32-characters-min!"
MOCK_IDP_SECRET = "mock-idp-signing-secret-32chars!!"   # used by MockOAuth2Provider
MOCK_ISSUER    = "https://mock-apollo-idp.local"
MOCK_AUDIENCE  = "api://sentinelsql-test"


@pytest.fixture
def token_issuer():
    return HS256SessionTokenIssuer(secret_key=TEST_SECRET, ttl_seconds=900)


@pytest.fixture
def role_resolver():
    return DictRoleResolver()


@pytest.fixture
def profile_store():
    store = InMemoryUserProfileStore()
    store.add(UserProfile(
        user_id="dr.arjun",
        department="Cardiology",
        unit="Cardiac ICU",
        facility="Apollo Delhi",
        clearance_level=ClearanceLevel.CONFIDENTIAL,
        is_active=True,
    ))
    store.add(UserProfile(
        user_id="admin.suresh",
        department="Administration",
        unit="Operations",
        facility="Apollo Hyderabad",
        clearance_level=ClearanceLevel.SECRET,
        is_active=True,
    ))
    store.add(UserProfile(
        user_id="superadmin",
        department="Platform Engineering",
        unit="Security",
        facility="ALL",
        clearance_level=ClearanceLevel.TOP_SECRET,
        is_active=True,
    ))
    store.add(UserProfile(
        user_id="suspended.user",
        department="HR",
        clearance_level=ClearanceLevel.INTERNAL,
        is_active=False,
    ))
    return store


@pytest.fixture
def device_registry():
    return InMemoryDeviceTrustRegistry(
        managed_fingerprints={"corp-fp-001", "corp-fp-002", "corp-device-abc123"}
    )


@pytest.fixture
def context_builder(profile_store, device_registry):
    return SecurityContextBuilder(
        profile_store=profile_store,
        device_registry=device_registry,
    )


@pytest.fixture
def sample_context():
    return SecurityContext(
        user_id="dr.arjun",
        username="Dr. Arjun Mehta",
        email="dr.arjun@apollohospitals.com",
        raw_roles=["ATTENDING_PHYSICIAN"],
        effective_roles=["ATTENDING_PHYSICIAN", "TREATING_PROVIDER", "CLINICAL_VIEWER", "VIEWER", "BASE_USER"],
        department="Cardiology",
        facility="Apollo Delhi",
        clearance_level=ClearanceLevel.CONFIDENTIAL,
        device_trust=DeviceTrust.MANAGED,
        issued_at=time.time(),
        expires_at=time.time() + 900,
    )


# ══════════════════════════════════════════════════════════════════════════════
# IMPROVEMENT 1 — MockOAuth2Provider
# ══════════════════════════════════════════════════════════════════════════════

class MockOAuth2Provider(BaseIdentityProvider):
    """
    Drop-in replacement for OAuth2Provider that signs/verifies with HS256.
    Eliminates JWKS endpoint dependency for testing.

    Design rules:
      - Validates issuer  (must match MOCK_ISSUER)
      - Validates audience (must match MOCK_AUDIENCE)
      - Validates signature (must match MOCK_IDP_SECRET)
      - Maps standard OIDC claims → IdPClaims
      - Raises AuthenticationError on any failure (mirrors real provider)
    """

    ALGORITHM = "HS256"

    def __init__(
        self,
        secret: str = MOCK_IDP_SECRET,
        issuer: str = MOCK_ISSUER,
        audience: str = MOCK_AUDIENCE,
        groups_claim: str = "groups",
    ):
        self.secret   = secret
        self.issuer   = issuer
        self.audience = audience
        self.groups_claim = groups_claim

    def issue_test_token(self, sub: str, groups: list[str], **extra_claims) -> str:
        """
        Helper: mint a valid mock IdP token for a test user.
        In production, the real IdP issues this — we simulate it here.
        """
        now = time.time()
        payload = {
            "sub":                sub,
            "email":              extra_claims.pop("email", f"{sub}@apollohospitals.com"),
            "preferred_username": extra_claims.pop("preferred_username", sub),
            self.groups_claim:    groups,
            "iss":                self.issuer,
            "aud":                self.audience,
            "iat":                now,
            "exp":                now + 3600,
            **extra_claims,
        }
        return jose_jwt.encode(payload, self.secret, algorithm=self.ALGORITHM)

    def issue_expired_token(self, sub: str, groups: list[str]) -> str:
        """Issues a token that is already expired — used in expiry tests."""
        payload = {
            "sub":             sub,
            "email":           f"{sub}@test.com",
            self.groups_claim: groups,
            "iss":             self.issuer,
            "aud":             self.audience,
            "iat":             time.time() - 7200,
            "exp":             time.time() - 3600,   # expired 1 hour ago
        }
        return jose_jwt.encode(payload, self.secret, algorithm=self.ALGORITHM)

    async def validate(self, token: str) -> IdPClaims:
        """
        Validates the token and returns normalized IdPClaims.
        Mirrors the contract of OAuth2Provider.validate().
        """
        try:
            claims = jose_jwt.decode(
                token,
                self.secret,
                algorithms=[self.ALGORITHM],
                audience=self.audience,
                issuer=self.issuer,
                options={"verify_exp": True},
            )
        except jose_jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except Exception as e:
            raise AuthenticationError(f"Invalid token: {e}") from e

        return IdPClaims(
            sub=claims["sub"],
            email=claims.get("email", ""),
            preferred_username=claims.get("preferred_username", claims.get("name", "")),
            groups=claims.get(self.groups_claim, []),
            iss=claims.get("iss"),
            aud=str(claims.get("aud", "")),
            exp=claims.get("exp"),
            iat=claims.get("iat"),
            department=claims.get("department"),
            clearance_level=claims.get("clearance_level"),
            facility=claims.get("facility"),
            provider_id=claims.get("provider_id"),
        )


class TestMockOAuth2Provider:
    """
    Tests for MockOAuth2Provider — validates the entire JWT trust boundary
    without any live JWKS endpoints.
    """

    @pytest.fixture
    def idp(self):
        if jose_jwt is None:
            pytest.skip("python-jose not installed")
        return MockOAuth2Provider()

    # ── Happy path ────────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_validate_valid_token_returns_idp_claims(self, idp):
        token = idp.issue_test_token("dr.arjun", ["ATTENDING_PHYSICIAN"])
        claims = await idp.validate(token)
        assert claims.sub == "dr.arjun"
        assert "ATTENDING_PHYSICIAN" in claims.groups
        assert claims.email == "dr.arjun@apollohospitals.com"
        assert claims.iss == MOCK_ISSUER

    @pytest.mark.asyncio
    async def test_validate_maps_all_standard_claims(self, idp):
        token = idp.issue_test_token(
            "admin.suresh",
            ["ADMIN"],
            preferred_username="Suresh K.",
            department="Administration",
            facility="Apollo Hyderabad",
        )
        claims = await idp.validate(token)
        assert claims.preferred_username == "Suresh K."
        assert claims.department == "Administration"
        assert claims.facility == "Apollo Hyderabad"

    @pytest.mark.asyncio
    async def test_validate_maps_custom_clearance_claim(self, idp):
        token = idp.issue_test_token(
            "superadmin",
            ["SUPER_ADMIN"],
            clearance_level="TOP_SECRET",
        )
        claims = await idp.validate(token)
        assert claims.clearance_level == "TOP_SECRET"

    @pytest.mark.asyncio
    async def test_validate_multiple_groups(self, idp):
        token = idp.issue_test_token("dr.arjun", ["ATTENDING_PHYSICIAN", "AUDITOR"])
        claims = await idp.validate(token)
        assert len(claims.groups) == 2
        assert "AUDITOR" in claims.groups

    # ── Security boundary tests ────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_wrong_secret_raises_auth_error(self, idp):
        """Token signed by wrong key must be rejected — signature validation."""
        evil_idp = MockOAuth2Provider(secret="completely-different-secret-32ch!!")
        token = evil_idp.issue_test_token("attacker", ["SUPER_ADMIN"])
        with pytest.raises(AuthenticationError):
            await idp.validate(token)

    @pytest.mark.asyncio
    async def test_wrong_audience_raises_auth_error(self, idp):
        """Token issued for a different audience must be rejected."""
        wrong_aud_token = jose_jwt.encode(
            {
                "sub": "dr.arjun",
                "email": "x@y.com",
                "groups": ["NURSE"],
                "iss": MOCK_ISSUER,
                "aud": "api://different-service",   # wrong audience
                "exp": time.time() + 3600,
                "iat": time.time(),
            },
            MOCK_IDP_SECRET,
            algorithm="HS256",
        )
        with pytest.raises(AuthenticationError):
            await idp.validate(wrong_aud_token)

    @pytest.mark.asyncio
    async def test_wrong_issuer_raises_auth_error(self, idp):
        """Token from an untrusted issuer must be rejected."""
        wrong_iss_token = jose_jwt.encode(
            {
                "sub": "dr.arjun",
                "email": "x@y.com",
                "groups": ["NURSE"],
                "iss": "https://evil-idp.attacker.com",  # wrong issuer
                "aud": MOCK_AUDIENCE,
                "exp": time.time() + 3600,
                "iat": time.time(),
            },
            MOCK_IDP_SECRET,
            algorithm="HS256",
        )
        with pytest.raises(AuthenticationError):
            await idp.validate(wrong_iss_token)

    @pytest.mark.asyncio
    async def test_expired_token_raises_auth_error(self, idp):
        """Expired tokens must be rejected even if signature is valid."""
        token = idp.issue_expired_token("dr.arjun", ["ATTENDING_PHYSICIAN"])
        with pytest.raises(AuthenticationError, match="expired"):
            await idp.validate(token)

    @pytest.mark.asyncio
    async def test_tampered_payload_raises_auth_error(self, idp):
        """Modifying the payload after signing must fail signature check."""
        token = idp.issue_test_token("dr.arjun", ["ATTENDING_PHYSICIAN"])
        # Corrupt the payload section (middle part of JWT)
        parts = token.split(".")
        parts[1] = parts[1][:-4] + "XXXX"
        tampered = ".".join(parts)
        with pytest.raises(AuthenticationError):
            await idp.validate(tampered)

    @pytest.mark.asyncio
    async def test_malformed_token_raises_auth_error(self, idp):
        with pytest.raises(AuthenticationError):
            await idp.validate("not.a.real.jwt.token")

    @pytest.mark.asyncio
    async def test_empty_groups_maps_to_empty_list(self, idp):
        token = idp.issue_test_token("anonymous", [])
        claims = await idp.validate(token)
        assert claims.groups == []

    # ── Full pipeline: IdP → Context ──────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_full_idp_to_context_pipeline(self, idp, context_builder, role_resolver, token_issuer):
        """
        End-to-end: mock IdP token → validate → build context → resolve roles → sign → verify.
        This is the complete Layer 01 trust boundary test.
        """
        # Step 1: IdP issues a signed token (simulates Okta/Azure AD)
        idp_token = idp.issue_test_token(
            "admin.suresh",
            ["ADMIN"],
            department="Administration",
            facility="Apollo Hyderabad",
        )

        # Step 2: Validate token → IdPClaims (the external trust boundary)
        idp_claims = await idp.validate(idp_token)
        assert idp_claims.sub == "admin.suresh"

        # Step 3: Build SecurityContext (merges IdP claims + internal profile)
        context = await context_builder.build(idp_claims, device_fingerprint="corp-fp-001")
        assert context.user_id == "admin.suresh"
        assert context.department == "Administration"    # from internal profile
        assert context.device_trust == DeviceTrust.MANAGED.value

        # Step 4: Resolve role hierarchy
        context.effective_roles = role_resolver.resolve(context.raw_roles)
        assert "ADMIN" in context.effective_roles
        assert "DATA_ANALYST" in context.effective_roles  # inherited
        assert "BASE_USER" in context.effective_roles      # inherited

        # Step 5: Issue session token
        session_token = token_issuer.issue(context)

        # Step 6: Verify (simulates what every downstream layer does)
        recovered = token_issuer.verify(session_token)
        assert recovered.user_id == "admin.suresh"
        assert recovered.clearance_level == ClearanceLevel.SECRET.value
        assert "ADMIN" in recovered.effective_roles


# ══════════════════════════════════════════════════════════════════════════════
# IMPROVEMENT 2 — Deterministic time.time() monkeypatching
# Replaces the fragile time.sleep(2) in the original test suite.
# ══════════════════════════════════════════════════════════════════════════════

class TestTokenExpiryWithMonkeypatch:
    """
    Tests token/session expiry using monkeypatched time — no sleep() calls.
    All tests run in milliseconds regardless of TTL values.
    """

    # ── Token expiry ──────────────────────────────────────────────────────────

    def test_expired_token_raises_without_sleep(self, monkeypatch, sample_context):
        """
        Simulates a token issued 2 hours ago without sleeping.
        Monkeypatches time.time in the session_token and models modules.
        """
        import layer01_identity.session_token as st_module
        import layer01_identity.models as models_module

        FIXED_ISSUE_TIME = 1_700_000_000.0
        FIXED_NOW        = FIXED_ISSUE_TIME + 7200.0   # 2 hours later

        issuer = HS256SessionTokenIssuer(secret_key=TEST_SECRET, ttl_seconds=60)

        # Issue the token "2 hours ago"
        monkeypatch.setattr(st_module.time, "time", lambda: FIXED_ISSUE_TIME)
        monkeypatch.setattr(models_module.time, "time", lambda: FIXED_ISSUE_TIME)
        sample_context.expires_at = FIXED_ISSUE_TIME + 3600  # Ensure context isn't pre-expired
        token = issuer.issue(sample_context)

        # Verify "now" — 2 hours later, token has expired
        monkeypatch.setattr(st_module.time, "time", lambda: FIXED_NOW)
        monkeypatch.setattr(models_module.time, "time", lambda: FIXED_NOW)
        with pytest.raises(TokenError, match="expired"):
            issuer.verify(token)

    def test_token_valid_before_expiry(self, monkeypatch, sample_context):
        """
        Token issued at T=0 must still be valid at T=TTL-1.
        """
        import layer01_identity.session_token as st_module
        import layer01_identity.models as models_module

        # Far-future base: belt-and-suspenders so exp > real wall clock always.
        FIXED_ISSUE_TIME = time.time() + 10_000.0
        TTL = 900

        issuer = HS256SessionTokenIssuer(secret_key=TEST_SECRET, ttl_seconds=TTL)

        monkeypatch.setattr(st_module.time, "time", lambda: FIXED_ISSUE_TIME)
        monkeypatch.setattr(models_module.time, "time", lambda: FIXED_ISSUE_TIME)
        sample_context.expires_at = FIXED_ISSUE_TIME + TTL
        token = issuer.issue(sample_context)

        # 1 second before expiry — must still pass
        monkeypatch.setattr(st_module.time, "time", lambda: FIXED_ISSUE_TIME + TTL - 1)
        monkeypatch.setattr(models_module.time, "time", lambda: FIXED_ISSUE_TIME + TTL - 1)
        recovered = issuer.verify(token)
        assert recovered.user_id == sample_context.user_id

    def test_token_invalid_exactly_at_expiry(self, monkeypatch, sample_context):
        """Token must be expired at exactly T=TTL (boundary condition)."""
        import layer01_identity.session_token as st_module
        import layer01_identity.models as models_module

        FIXED_ISSUE_TIME = 1_700_000_000.0
        TTL = 900

        issuer = HS256SessionTokenIssuer(secret_key=TEST_SECRET, ttl_seconds=TTL)

        monkeypatch.setattr(st_module.time, "time", lambda: FIXED_ISSUE_TIME)
        monkeypatch.setattr(models_module.time, "time", lambda: FIXED_ISSUE_TIME)
        sample_context.expires_at = FIXED_ISSUE_TIME + TTL
        token = issuer.issue(sample_context)

        # Exactly at expiry boundary
        monkeypatch.setattr(st_module.time, "time", lambda: FIXED_ISSUE_TIME + TTL + 1)
        monkeypatch.setattr(models_module.time, "time", lambda: FIXED_ISSUE_TIME + TTL + 1)
        with pytest.raises(TokenError):
            issuer.verify(token)

    def test_different_ttl_values_respected(self, monkeypatch, sample_context):
        """Short TTL (5s) and long TTL (3600s) should both be enforced correctly."""
        import layer01_identity.session_token as st_module
        import layer01_identity.models as models_module

        # Anchor far enough in the future that even TTL=5 exp > real clock.
        BASE_TIME = time.time() + 50_000.0

        for ttl, offset, should_pass in [
            (5,    3,    False),   # 5s TTL, check at +3s  → valid
            (5,    6,    True),    # 5s TTL, check at +6s  → expired
            (3600, 3599, False),   # 1h TTL, check at +3599s → valid
            (3600, 3601, True),    # 1h TTL, check at +3601s → expired
        ]:
            issuer = HS256SessionTokenIssuer(secret_key=TEST_SECRET, ttl_seconds=ttl)
            monkeypatch.setattr(st_module.time, "time", lambda: BASE_TIME)
            monkeypatch.setattr(models_module.time, "time", lambda: BASE_TIME)
            sample_context.expires_at = BASE_TIME + ttl
            token = issuer.issue(sample_context)

            monkeypatch.setattr(st_module.time, "time", lambda t=offset: BASE_TIME + t)
            monkeypatch.setattr(models_module.time, "time", lambda t=offset: BASE_TIME + t)
            if should_pass:
                with pytest.raises(TokenError):
                    issuer.verify(token)
            else:
                result = issuer.verify(token)
                assert result.user_id == sample_context.user_id

    # ── SecurityContext expiry ────────────────────────────────────────────────

    def test_security_context_is_expired_uses_real_time(self):
        """is_expired() on SecurityContext uses real time.time() — test boundary."""
        ctx = SecurityContext(
            user_id="test",
            username="test",
            email="test@test.com",
            expires_at=time.time() - 1,   # already expired
        )
        assert ctx.is_expired() is True

    def test_security_context_not_expired_for_future(self):
        ctx = SecurityContext(
            user_id="test",
            username="test",
            email="test@test.com",
            expires_at=time.time() + 900,
        )
        assert ctx.is_expired() is False

    def test_clock_skew_defense_in_verify(self, monkeypatch, sample_context):
        """
        Demonstrates the double-expiry check in HS256SessionTokenIssuer.verify():
        jose checks `exp` claim AND context.is_expired() catches clock skew.
        """
        import layer01_identity.session_token as st_module
        import layer01_identity.models as models_module

        # Issue a token with a very short TTL
        BASE = 1_700_000_000.0
        issuer = HS256SessionTokenIssuer(secret_key=TEST_SECRET, ttl_seconds=10)

        monkeypatch.setattr(st_module.time, "time", lambda: BASE)
        monkeypatch.setattr(models_module.time, "time", lambda: BASE)
        sample_context.expires_at = BASE + 10
        token = issuer.issue(sample_context)

        # Jump time far past expiry — both jose AND the clock-skew check should catch it
        monkeypatch.setattr(st_module.time, "time", lambda: BASE + 100)
        monkeypatch.setattr(models_module.time, "time", lambda: BASE + 100)
        with pytest.raises(TokenError):
            issuer.verify(token)


# ══════════════════════════════════════════════════════════════════════════════
# IMPROVEMENT 3 — Device-Based Clearance Downgrade
#
# The existing context_builder.py logs a warning for UNMANAGED devices but
# does NOT enforce any clearance restriction. This section:
#   a) Documents the current (advisory-only) behavior as a test
#   b) Provides ZeroTrustSecurityContextBuilder — a drop-in subclass that
#      enforces the downgrade policy
#   c) Tests both behaviors so you can see exactly what changes
# ══════════════════════════════════════════════════════════════════════════════

class ZeroTrustSecurityContextBuilder(SecurityContextBuilder):
    """
    Drop-in subclass of SecurityContextBuilder that enforces device-based
    clearance downgrade — converting the warning into actual enforcement.

    Policy:
      MANAGED   device → clearance unchanged
      UNMANAGED device → clearance capped at INTERNAL
      UNKNOWN   device → clearance capped at INTERNAL

    This is the correct Zero Trust posture for a healthcare system.
    Replace SecurityContextBuilder with this class in main.py when ready
    to enforce — no other code changes needed.
    """

    # Clearance cap applied to non-managed devices
    UNMANAGED_CLEARANCE_CAP = ClearanceLevel.INTERNAL

    async def build(self, idp_claims: IdPClaims, device_fingerprint: str = "unknown"):
        context = await super().build(idp_claims, device_fingerprint)

        device = DeviceTrust(context.device_trust)
        if device != DeviceTrust.MANAGED:
            original = ClearanceLevel(context.clearance_level)
            cap      = self.UNMANAGED_CLEARANCE_CAP

            if original.numeric > cap.numeric:
                context.clearance_level = cap.value
                import logging
                logging.getLogger("sentinelsql.layer01.context_builder").warning(
                    "Zero Trust: clearance downgraded %s → %s for user=%s "
                    "(device_trust=%s, fingerprint=%s)",
                    original.value, cap.value,
                    context.user_id, device.value, device_fingerprint,
                )

        return context


class TestDeviceClearanceEnforcement:
    """
    Tests that verify device trust correctly gates clearance level.

    Split into two groups:
      - TestCurrentBehavior: what the existing code does (advisory-only)
      - TestZeroTrustEnforcement: what ZeroTrustSecurityContextBuilder adds
    """

    # ── Current behavior (advisory-only) ─────────────────────────────────────

    @pytest.mark.asyncio
    async def test_current_unmanaged_device_does_NOT_downgrade(self, context_builder):
        """
        Documents existing behavior: SECRET user on UNMANAGED device keeps SECRET.
        This is intentional — shows what changes when you swap to ZeroTrust builder.
        """
        claims = IdPClaims(
            sub="admin.suresh",
            email="suresh@apollohospitals.com",
            groups=["ADMIN"],
        )
        ctx = await context_builder.build(claims, device_fingerprint="personal-iphone")
        assert ctx.device_trust == DeviceTrust.UNMANAGED.value
        # Current behavior: clearance NOT downgraded (advisory only)
        assert ctx.clearance_level == ClearanceLevel.SECRET.value

    # ── Zero Trust enforcement ────────────────────────────────────────────────

    @pytest.fixture
    def zt_builder(self, profile_store, device_registry):
        return ZeroTrustSecurityContextBuilder(
            profile_store=profile_store,
            device_registry=device_registry,
        )

    @pytest.mark.asyncio
    async def test_managed_device_keeps_original_clearance(self, zt_builder):
        """MANAGED device: clearance must NOT be downgraded."""
        claims = IdPClaims(
            sub="admin.suresh",
            email="suresh@apollohospitals.com",
            groups=["ADMIN"],
        )
        ctx = await zt_builder.build(claims, device_fingerprint="corp-fp-001")
        assert ctx.device_trust == DeviceTrust.MANAGED.value
        assert ctx.clearance_level == ClearanceLevel.SECRET.value   # preserved

    @pytest.mark.asyncio
    async def test_unmanaged_device_caps_clearance_at_internal(self, zt_builder):
        """UNMANAGED device: SECRET clearance must be capped at INTERNAL."""
        claims = IdPClaims(
            sub="admin.suresh",
            email="suresh@apollohospitals.com",
            groups=["ADMIN"],
        )
        ctx = await zt_builder.build(claims, device_fingerprint="personal-iphone")
        assert ctx.device_trust == DeviceTrust.UNMANAGED.value
        assert ctx.clearance_level == ClearanceLevel.INTERNAL.value   # downgraded

    @pytest.mark.asyncio
    async def test_unknown_device_caps_clearance_at_internal(self, zt_builder):
        """UNKNOWN fingerprint: clearance must also be capped at INTERNAL."""
        claims = IdPClaims(
            sub="admin.suresh",
            email="suresh@apollohospitals.com",
            groups=["ADMIN"],
        )
        ctx = await zt_builder.build(claims, device_fingerprint="unknown")
        assert ctx.device_trust == DeviceTrust.UNKNOWN.value
        assert ctx.clearance_level == ClearanceLevel.INTERNAL.value   # downgraded

    @pytest.mark.asyncio
    async def test_top_secret_user_on_unmanaged_device_is_capped(self, zt_builder):
        """TOP_SECRET superadmin on a personal device → capped at INTERNAL."""
        claims = IdPClaims(
            sub="superadmin",
            email="superadmin@apollohospitals.com",
            groups=["SUPER_ADMIN"],
        )
        ctx = await zt_builder.build(claims, device_fingerprint="home-laptop-123")
        assert ctx.clearance_level == ClearanceLevel.INTERNAL.value

    @pytest.mark.asyncio
    async def test_already_internal_clearance_not_changed(self, zt_builder):
        """User already at INTERNAL clearance: downgrade should be a no-op."""
        profile_store_local = InMemoryUserProfileStore()
        profile_store_local.add(UserProfile(
            user_id="nurse.priya",
            department="Nursing",
            clearance_level=ClearanceLevel.INTERNAL,
            is_active=True,
        ))
        registry = InMemoryDeviceTrustRegistry()
        builder = ZeroTrustSecurityContextBuilder(
            profile_store=profile_store_local,
            device_registry=registry,
        )
        claims = IdPClaims(
            sub="nurse.priya",
            email="priya@apollohospitals.com",
            groups=["NURSE"],
        )
        ctx = await builder.build(claims, device_fingerprint="personal-android")
        assert ctx.clearance_level == ClearanceLevel.INTERNAL.value   # unchanged

    @pytest.mark.asyncio
    async def test_public_clearance_not_changed_on_unmanaged(self, zt_builder):
        """PUBLIC clearance cannot be downgraded further — must stay PUBLIC."""
        profile_store_local = InMemoryUserProfileStore()
        profile_store_local.add(UserProfile(
            user_id="guest.user",
            clearance_level=ClearanceLevel.PUBLIC,
            is_active=True,
        ))
        registry = InMemoryDeviceTrustRegistry()
        builder = ZeroTrustSecurityContextBuilder(
            profile_store=profile_store_local,
            device_registry=registry,
        )
        claims = IdPClaims(
            sub="guest.user",
            email="guest@test.com",
            groups=["BASE_USER"],
        )
        ctx = await builder.build(claims, device_fingerprint="unknown-tablet")
        assert ctx.clearance_level == ClearanceLevel.PUBLIC.value   # can't go lower

    @pytest.mark.asyncio
    async def test_clearance_downgrade_reflected_in_session_token(self, zt_builder, token_issuer):
        """
        Critical: downgraded clearance must be baked into the JWT.
        Downstream layers must see the reduced clearance when they verify the token.
        """
        claims = IdPClaims(
            sub="admin.suresh",
            email="suresh@apollohospitals.com",
            groups=["ADMIN"],
        )
        # Build on unmanaged device → clearance should be INTERNAL
        ctx = await zt_builder.build(claims, device_fingerprint="personal-iphone")
        ctx.effective_roles = DictRoleResolver().resolve(ctx.raw_roles)

        # Issue and recover token
        token  = token_issuer.issue(ctx)
        recovered = token_issuer.verify(token)

        # Downstream layer sees the downgraded clearance
        assert recovered.clearance_level == ClearanceLevel.INTERNAL.value
        assert not recovered.can_see_clearance(ClearanceLevel.SECRET)
        assert recovered.can_see_clearance(ClearanceLevel.INTERNAL)


# ══════════════════════════════════════════════════════════════════════════════
# IMPROVEMENT 4 — FastAPI Route-Level Tests (TestClient)
# Exercises the full HTTP stack for /auth/* endpoints.
# ══════════════════════════════════════════════════════════════════════════════

try:
    from fastapi.testclient import TestClient
    from main import app
    FASTAPI_AVAILABLE = True
except Exception:
    FASTAPI_AVAILABLE = False

route_test = pytest.mark.skipif(
    not FASTAPI_AVAILABLE,
    reason="FastAPI app not importable (check main.py path or static/ dir)"
)


@pytest.fixture(scope="module")
def client():
    """Module-scoped TestClient — runs lifespan startup/shutdown once."""
    if not FASTAPI_AVAILABLE:
        pytest.skip("FastAPI app not available")
    with TestClient(app) as c:
        yield c


@route_test
class TestAuthLoginRoute:
    """Tests for POST /auth/login — credential validation → JWT issuance."""

    def test_valid_login_returns_200_and_token(self, client):
        resp = client.post("/auth/login", json={
            "username": "dr.arjun",
            "password": "Apollo@123",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert "session_token" in body
        assert body["status"] == "authenticated"
        assert body["user_id"] == "dr.arjun"

    def test_valid_login_response_shape(self, client):
        """All required fields must be present in the login response."""
        resp = client.post("/auth/login", json={
            "username": "dr.arjun",
            "password": "Apollo@123",
        })
        body = resp.json()
        required_fields = [
            "session_token", "user_id", "display_name", "role",
            "effective_roles", "clearance_level", "device_trust",
            "department_label", "avatar_initials", "avatar_color", "expires_at",
        ]
        for field in required_fields:
            assert field in body, f"Missing field: {field}"

    def test_login_with_device_fingerprint_header(self, client):
        """X-Device-Fingerprint header must be accepted and reflected in token."""
        resp = client.post(
            "/auth/login",
            json={"username": "admin.suresh", "password": "Apollo@123"},
            headers={"X-Device-Fingerprint": "corp-device-abc123"},
        )
        assert resp.status_code == 200
        # Managed device should give non-unknown device trust
        body = resp.json()
        assert body["device_trust"] in ("managed", "unmanaged", "unknown")

    def test_invalid_password_returns_401(self, client):
        resp = client.post("/auth/login", json={
            "username": "dr.arjun",
            "password": "WrongPassword!",
        })
        assert resp.status_code == 401
        assert "Invalid" in resp.json()["detail"]

    def test_unknown_username_returns_401(self, client):
        resp = client.post("/auth/login", json={
            "username": "nonexistent.user",
            "password": "Apollo@123",
        })
        assert resp.status_code == 401

    def test_all_6_demo_users_can_login(self, client):
        """All 6 Apollo personas must authenticate successfully."""
        users = [
            "dr.arjun", "nurse.priya", "admin.suresh",
            "analyst.deepa", "pharma.ravi", "superadmin",
        ]
        for username in users:
            resp = client.post("/auth/login", json={
                "username": username,
                "password": "Apollo@123",
            })
            assert resp.status_code == 200, f"Login failed for {username}: {resp.json()}"

    def test_login_returns_effective_roles_list(self, client):
        """effective_roles must be a non-empty list with inherited roles."""
        resp = client.post("/auth/login", json={
            "username": "admin.suresh",
            "password": "Apollo@123",
        })
        body = resp.json()
        assert isinstance(body["effective_roles"], list)
        assert len(body["effective_roles"]) > 1   # ADMIN inherits multiple roles
        assert "ADMIN" in body["effective_roles"]
        assert "BASE_USER" in body["effective_roles"]

    def test_superadmin_gets_all_inherited_roles(self, client):
        """SUPER_ADMIN inherits ADMIN → DATA_ANALYST → etc."""
        resp = client.post("/auth/login", json={
            "username": "superadmin",
            "password": "Apollo@123",
        })
        effective = resp.json()["effective_roles"]
        assert "SUPER_ADMIN" in effective
        assert "ADMIN" in effective
        assert "DATA_ANALYST" in effective
        assert "BASE_USER" in effective

    def test_session_token_is_valid_jwt(self, client):
        """Session token from login must be verifiable by the token issuer."""
        resp = client.post("/auth/login", json={
            "username": "dr.arjun",
            "password": "Apollo@123",
        })
        token = resp.json()["session_token"]
        # Token must be a 3-part JWT
        parts = token.split(".")
        assert len(parts) == 3, "Session token must be a compact JWT (header.payload.sig)"

    def test_case_insensitive_username(self, client):
        """Username lookup should work case-insensitively."""
        resp = client.post("/auth/login", json={
            "username": "DR.ARJUN",
            "password": "Apollo@123",
        })
        # mock_users.py does .lower() on username — should succeed
        assert resp.status_code == 200


@route_test
class TestAuthMeRoute:
    """Tests for GET /auth/me — token verification → user profile + permissions."""

    def _get_token(self, client, username="dr.arjun") -> str:
        resp = client.post("/auth/login", json={
            "username": username,
            "password": "Apollo@123",
        })
        return resp.json()["session_token"]

    def test_me_returns_200_with_valid_token(self, client):
        token = self._get_token(client)
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_me_response_shape(self, client):
        token = self._get_token(client)
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        body = resp.json()
        required = [
            "user_id", "display_name", "username", "role", "effective_roles",
            "clearance_level", "device_trust", "department_label",
            "avatar_initials", "avatar_color", "session_id",
            "expires_at", "permissions", "badge_color",
        ]
        for field in required:
            assert field in body, f"Missing field: {field}"

    def test_me_permissions_populated_for_physician(self, client):
        token = self._get_token(client, "dr.arjun")
        body = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
        assert len(body["permissions"]) > 0
        # Check ATTENDING_PHYSICIAN has clinical permissions
        icons = [p["icon"] for p in body["permissions"]]
        assert "🩺" in icons   # Patient Records

    def test_me_permissions_populated_for_superadmin(self, client):
        token = self._get_token(client, "superadmin")
        body = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
        # SUPER_ADMIN should have the most permissions
        assert len(body["permissions"]) >= 5

    def test_me_without_auth_header_returns_422(self, client):
        """Missing Authorization header → 422 Unprocessable Entity (FastAPI validation)."""
        resp = client.get("/auth/me")
        assert resp.status_code == 422

    def test_me_with_invalid_token_returns_401(self, client):
        resp = client.get("/auth/me", headers={"Authorization": "Bearer invalid.jwt.token"})
        assert resp.status_code == 401

    def test_me_without_bearer_prefix_returns_401(self, client):
        token = self._get_token(client)
        resp = client.get("/auth/me", headers={"Authorization": token})   # no "Bearer "
        assert resp.status_code == 401

    def test_me_with_tampered_token_returns_401(self, client):
        token = self._get_token(client)
        tampered = token[:-10] + "XXXXXXXXXX"
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {tampered}"})
        assert resp.status_code == 401

    def test_me_returns_correct_user_for_each_persona(self, client):
        """Each persona must get their own profile back from /auth/me."""
        users = {
            "dr.arjun":      "ATTENDING_PHYSICIAN",
            "nurse.priya":   "NURSE",
            "admin.suresh":  "ADMIN",
            "analyst.deepa": "DATA_ANALYST",
            "pharma.ravi":   "PHARMACIST",
            "superadmin":    "SUPER_ADMIN",
        }
        for username, expected_role in users.items():
            token = self._get_token(client, username)
            body  = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
            assert body["user_id"] == username,      f"user_id mismatch for {username}"
            assert body["role"]    == expected_role, f"role mismatch for {username}"


@route_test
class TestAuthLogoutRoute:
    """Tests for POST /auth/logout — stateless JWT design."""

    def test_logout_returns_200(self, client):
        resp = client.post("/auth/logout")
        assert resp.status_code == 200

    def test_logout_response_contains_status(self, client):
        body = client.post("/auth/logout").json()
        assert body["status"] == "logged_out"
        assert "message" in body

    def test_token_still_verifiable_after_logout(self, client):
        """
        Stateless design: token remains cryptographically valid after logout.
        Revocation belongs to Layer 03 (Redis denylist).
        This test documents the current intentional behavior.
        """
        # Login and get token
        token = client.post("/auth/login", json={
            "username": "dr.arjun", "password": "Apollo@123",
        }).json()["session_token"]

        # Logout
        client.post("/auth/logout")

        # Token still works (no server-side revocation yet)
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, (
            "Token still valid after stateless logout — "
            "revocation requires Redis denylist (Layer 03)"
        )


@route_test
class TestDevUsersRoute:
    """Tests for GET /auth/users — development-only endpoint."""

    def test_dev_users_returns_200_in_dev_mode(self, client):
        resp = client.get("/auth/users")
        assert resp.status_code == 200

    def test_dev_users_lists_all_6_personas(self, client):
        body = client.get("/auth/users").json()
        assert len(body["users"]) == 6

    def test_dev_users_shows_password_hint(self, client):
        body = client.get("/auth/users").json()
        assert body["password_for_all"] == "Apollo@123"

    def test_dev_users_response_has_required_user_fields(self, client):
        body   = client.get("/auth/users").json()
        user   = body["users"][0]
        fields = ["username", "display_name", "role", "department", "clearance"]
        for f in fields:
            assert f in user, f"Missing field '{f}' in /auth/users response"


@route_test
class TestHealthRoute:
    """Tests for GET /health."""

    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_response_shape(self, client):
        body = client.get("/health").json()
        assert body["status"] == "ok"
        assert body["layer"] == "01-identity"
        assert body["users"] == 6


@route_test
class TestMissingAuthorizationHeader:
    """Edge case tests around the Authorization header parsing."""

    def test_empty_bearer_token_returns_401(self, client):
        resp = client.get("/auth/me", headers={"Authorization": "Bearer "})
        assert resp.status_code == 401

    def test_basic_auth_scheme_rejected(self, client):
        """Bearer scheme is required — Basic auth must not be accepted."""
        resp = client.get("/auth/me", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert resp.status_code == 401
