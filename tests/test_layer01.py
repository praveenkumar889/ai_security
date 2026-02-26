"""
SentinelSQL — Layer 01: Identity & Context Layer
tests/test_layer01.py — Full test suite covering all four components.

Run with:
    pip install pytest pytest-asyncio
    pytest tests/test_layer01.py -v

Test coverage:
  ✓ Models — SecurityContext behavior (expiry, role checks, clearance)
  ✓ RoleResolver — hierarchy flattening, unknown roles, empty input
  ✓ ContextBuilder — clearance resolution, device trust, deprovisioned accounts
  ✓ SessionToken — issue/verify roundtrip, expiry, tamper detection
  ✓ Integration — full Layer 01 pipeline end-to-end
"""

import asyncio
import time
import pytest

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from layer01_identity.models import (
    ClearanceLevel, DeviceTrust, IdPClaims, SecurityContext, UserProfile,
)
from layer01_identity.role_resolver import DictRoleResolver, DEFAULT_ROLE_HIERARCHY
from layer01_identity.context_builder import (
    InMemoryUserProfileStore, InMemoryDeviceTrustRegistry, SecurityContextBuilder,
)
from layer01_identity.session_token import HS256SessionTokenIssuer, TokenError


# ─── FIXTURES ─────────────────────────────────────────────────────────────────

TEST_SECRET = "test-secret-key-32-characters-min!"

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
        user_id="alice",
        department="Analytics",
        unit="BI Team",
        clearance_level=ClearanceLevel.CONFIDENTIAL,
        is_active=True,
    ))
    store.add(UserProfile(
        user_id="bob_admin",
        department="Platform",
        clearance_level=ClearanceLevel.SECRET,
        is_active=True,
    ))
    store.add(UserProfile(
        user_id="charlie_suspended",
        clearance_level=ClearanceLevel.INTERNAL,
        is_active=False,
    ))
    return store

@pytest.fixture
def device_registry():
    return InMemoryDeviceTrustRegistry(managed_fingerprints={"corp-fp-001", "corp-fp-002"})

@pytest.fixture
def context_builder(profile_store, device_registry):
    return SecurityContextBuilder(
        profile_store=profile_store,
        device_registry=device_registry,
    )

@pytest.fixture
def sample_context():
    return SecurityContext(
        user_id="alice",
        username="alice@example.com",
        email="alice@example.com",
        raw_roles=["DATA_ANALYST"],
        effective_roles=["DATA_ANALYST", "REPORT_VIEWER", "VIEWER", "BASE_USER"],
        department="Analytics",
        clearance_level=ClearanceLevel.CONFIDENTIAL,
        device_trust=DeviceTrust.MANAGED,
        issued_at=time.time(),
        expires_at=time.time() + 900,
    )


# ─── MODEL TESTS ──────────────────────────────────────────────────────────────

class TestSecurityContext:
    def test_is_expired_false_for_future(self, sample_context):
        assert sample_context.is_expired() is False

    def test_is_expired_true_for_past(self, sample_context):
        sample_context.expires_at = time.time() - 1
        assert sample_context.is_expired() is True

    def test_has_role_true(self, sample_context):
        assert sample_context.has_role("DATA_ANALYST") is True

    def test_has_role_false(self, sample_context):
        assert sample_context.has_role("SUPER_ADMIN") is False

    def test_has_any_role(self, sample_context):
        assert sample_context.has_any_role("SUPER_ADMIN", "DATA_ANALYST") is True
        assert sample_context.has_any_role("SUPER_ADMIN", "NURSE") is False

    def test_can_see_clearance_equal(self, sample_context):
        assert sample_context.can_see_clearance(ClearanceLevel.CONFIDENTIAL) is True

    def test_can_see_clearance_lower(self, sample_context):
        assert sample_context.can_see_clearance(ClearanceLevel.PUBLIC) is True

    def test_cannot_see_clearance_higher(self, sample_context):
        assert sample_context.can_see_clearance(ClearanceLevel.SECRET) is False

    def test_to_audit_dict_no_sensitive_fields(self, sample_context):
        audit = sample_context.to_audit_dict()
        assert "email" not in audit
        assert "raw_roles" not in audit
        assert "user_id" in audit
        assert "session_id" in audit


class TestClearanceLevel:
    def test_numeric_ordering(self):
        assert ClearanceLevel.PUBLIC.numeric < ClearanceLevel.INTERNAL.numeric
        assert ClearanceLevel.SECRET.numeric < ClearanceLevel.TOP_SECRET.numeric

    def test_can_access_same_level(self):
        assert ClearanceLevel.CONFIDENTIAL.can_access(ClearanceLevel.CONFIDENTIAL)

    def test_can_access_lower(self):
        assert ClearanceLevel.SECRET.can_access(ClearanceLevel.INTERNAL)

    def test_cannot_access_higher(self):
        assert not ClearanceLevel.INTERNAL.can_access(ClearanceLevel.SECRET)


# ─── ROLE RESOLVER TESTS ──────────────────────────────────────────────────────

class TestDictRoleResolver:
    def test_single_role_no_inheritance(self, role_resolver):
        result = role_resolver.resolve(["BASE_USER"])
        assert "BASE_USER" in result
        assert len(result) == 1

    def test_analyst_inherits_correctly(self, role_resolver):
        result = role_resolver.resolve(["DATA_ANALYST"])
        assert "DATA_ANALYST" in result
        assert "REPORT_VIEWER" in result
        assert "VIEWER" in result
        assert "BASE_USER" in result

    def test_admin_gets_all_inherited(self, role_resolver):
        result = role_resolver.resolve(["ADMIN"])
        assert "ADMIN" in result
        assert "DATA_ANALYST" in result
        assert "REPORT_VIEWER" in result
        assert "AUDITOR" in result
        assert "BASE_USER" in result

    def test_multiple_raw_roles_merged(self, role_resolver):
        result = role_resolver.resolve(["NURSE", "AUDITOR"])
        assert "NURSE" in result
        assert "CLINICAL_VIEWER" in result
        assert "VIEWER" in result
        assert "AUDITOR" in result
        assert "REPORT_VIEWER" in result

    def test_no_duplicates_in_result(self, role_resolver):
        result = role_resolver.resolve(["DATA_ANALYST", "SENIOR_ANALYST"])
        assert len(result) == len(set(result))

    def test_result_is_sorted(self, role_resolver):
        result = role_resolver.resolve(["ADMIN"])
        assert result == sorted(result)

    def test_unknown_role_is_included_as_leaf(self, role_resolver):
        result = role_resolver.resolve(["UNKNOWN_ROLE_XYZ"])
        assert "UNKNOWN_ROLE_XYZ" in result

    def test_empty_input_returns_base_user(self, role_resolver):
        result = role_resolver.resolve([])
        assert result == ["BASE_USER"]

    def test_no_privilege_escalation(self, role_resolver):
        """VIEWER should NOT gain ADMIN permissions."""
        result = role_resolver.resolve(["VIEWER"])
        assert "ADMIN" not in result
        assert "DATA_ANALYST" not in result


# ─── CONTEXT BUILDER TESTS ────────────────────────────────────────────────────

class TestSecurityContextBuilder:
    def _make_claims(self, user_id="alice", groups=None, clearance=None):
        return IdPClaims(
            sub=user_id,
            email=f"{user_id}@example.com",
            preferred_username=user_id,
            groups=groups or ["DATA_ANALYST"],
            clearance_level=clearance,
        )

    @pytest.mark.asyncio
    async def test_builds_context_successfully(self, context_builder):
        claims = self._make_claims("alice", ["DATA_ANALYST"])
        ctx = await context_builder.build(claims, "corp-fp-001")
        assert ctx.user_id == "alice"
        assert ctx.email == "alice@example.com"
        assert ctx.department == "Analytics"  # from internal profile
        assert ctx.device_trust == DeviceTrust.MANAGED

    @pytest.mark.asyncio
    async def test_clearance_takes_minimum_of_idp_and_profile(self, context_builder):
        # IdP says SECRET, internal profile says CONFIDENTIAL → take CONFIDENTIAL
        claims = self._make_claims("alice", clearance="SECRET")
        ctx = await context_builder.build(claims)
        assert ctx.clearance_level == ClearanceLevel.CONFIDENTIAL.value

    @pytest.mark.asyncio
    async def test_clearance_defaults_to_public_when_absent(self, context_builder):
        # New user not in profile store, no clearance in IdP claims
        claims = self._make_claims("new_user_xyz", groups=["VIEWER"])
        ctx = await context_builder.build(claims)
        assert ctx.clearance_level == ClearanceLevel.PUBLIC.value

    @pytest.mark.asyncio
    async def test_device_trust_managed(self, context_builder):
        claims = self._make_claims("alice")
        ctx = await context_builder.build(claims, "corp-fp-001")
        assert ctx.device_trust == DeviceTrust.MANAGED.value

    @pytest.mark.asyncio
    async def test_device_trust_unmanaged(self, context_builder):
        claims = self._make_claims("alice")
        ctx = await context_builder.build(claims, "personal-device-abc")
        assert ctx.device_trust == DeviceTrust.UNMANAGED.value

    @pytest.mark.asyncio
    async def test_device_trust_unknown_when_no_fingerprint(self, context_builder):
        claims = self._make_claims("alice")
        ctx = await context_builder.build(claims, "unknown")
        assert ctx.device_trust == DeviceTrust.UNKNOWN.value

    @pytest.mark.asyncio
    async def test_deprovisioned_account_raises(self, context_builder):
        claims = self._make_claims("charlie_suspended")
        with pytest.raises(ValueError, match="deprovisioned"):
            await context_builder.build(claims)

    @pytest.mark.asyncio
    async def test_session_id_is_unique_per_request(self, context_builder):
        claims = self._make_claims("alice")
        ctx1 = await context_builder.build(claims)
        ctx2 = await context_builder.build(claims)
        assert ctx1.session_id != ctx2.session_id

    @pytest.mark.asyncio
    async def test_effective_roles_empty_before_resolver(self, context_builder):
        """effective_roles must be [] here — only populated AFTER resolver runs."""
        claims = self._make_claims("alice", ["ADMIN"])
        ctx = await context_builder.build(claims)
        assert ctx.effective_roles == []
        assert ctx.raw_roles == ["ADMIN"]


# ─── SESSION TOKEN TESTS ──────────────────────────────────────────────────────

class TestHS256SessionTokenIssuer:
    def test_issue_and_verify_roundtrip(self, token_issuer, sample_context):
        token = token_issuer.issue(sample_context)
        recovered = token_issuer.verify(token)
        assert recovered.user_id == sample_context.user_id
        assert recovered.session_id == sample_context.session_id
        assert recovered.effective_roles == sample_context.effective_roles
        assert recovered.clearance_level == sample_context.clearance_level

    def test_verify_expired_token_raises(self, token_issuer, sample_context):
        short_lived = HS256SessionTokenIssuer(secret_key=TEST_SECRET, ttl_seconds=1)
        token = short_lived.issue(sample_context)
        time.sleep(2)
        with pytest.raises(TokenError, match="expired"):
            short_lived.verify(token)

    def test_verify_tampered_token_raises(self, token_issuer, sample_context):
        token = token_issuer.issue(sample_context)
        tampered = token[:-5] + "XXXXX"  # corrupt the signature
        with pytest.raises(TokenError):
            token_issuer.verify(tampered)

    def test_verify_wrong_secret_raises(self, token_issuer, sample_context):
        token = token_issuer.issue(sample_context)
        other_issuer = HS256SessionTokenIssuer(secret_key="different-secret-32-chars-minimum!!")
        with pytest.raises(TokenError):
            other_issuer.verify(token)

    def test_token_is_string(self, token_issuer, sample_context):
        token = token_issuer.issue(sample_context)
        assert isinstance(token, str)
        assert len(token) > 100  # JWT is always substantial

    def test_weak_secret_raises(self):
        with pytest.raises(ValueError, match="32 characters"):
            HS256SessionTokenIssuer(secret_key="short")

    def test_missing_secret_raises(self, monkeypatch):
        monkeypatch.delenv("SENTINELSQL_SESSION_SECRET", raising=False)
        with pytest.raises(EnvironmentError):
            HS256SessionTokenIssuer()


# ─── INTEGRATION TEST ─────────────────────────────────────────────────────────

class TestLayer01Integration:
    """
    Full Layer 01 pipeline: IdPClaims → build() → resolve() → issue() → verify()
    """

    @pytest.mark.asyncio
    async def test_full_pipeline_admin_user(
        self, context_builder, role_resolver, token_issuer
    ):
        # 1. Simulate IdP token validation result
        idp_claims = IdPClaims(
            sub="bob_admin",
            email="bob@example.com",
            preferred_username="bob_admin",
            groups=["ADMIN"],
            iss="https://idp.example.com",
        )

        # 2. Build SecurityContext
        context = await context_builder.build(idp_claims, "corp-fp-002")

        # 3. Resolve role hierarchy
        context.effective_roles = role_resolver.resolve(context.raw_roles)

        # Verify context state
        assert context.user_id == "bob_admin"
        assert "ADMIN" in context.effective_roles
        assert "DATA_ANALYST" in context.effective_roles
        assert "BASE_USER" in context.effective_roles
        assert context.clearance_level == ClearanceLevel.SECRET.value
        assert context.device_trust == DeviceTrust.MANAGED.value
        assert not context.is_expired()

        # 4. Issue session token
        token = token_issuer.issue(context)
        assert isinstance(token, str)

        # 5. Verify token (simulates downstream layer verification)
        recovered = token_issuer.verify(token)
        assert recovered.user_id == "bob_admin"
        assert "ADMIN" in recovered.effective_roles
        assert recovered.clearance_level == ClearanceLevel.SECRET.value

    @pytest.mark.asyncio
    async def test_full_pipeline_analyst_user(
        self, context_builder, role_resolver, token_issuer
    ):
        idp_claims = IdPClaims(
            sub="alice",
            email="alice@example.com",
            preferred_username="alice",
            groups=["SENIOR_ANALYST"],
        )

        context = await context_builder.build(idp_claims, "unknown-device")
        context.effective_roles = role_resolver.resolve(context.raw_roles)

        assert "SENIOR_ANALYST" in context.effective_roles
        assert "DATA_ANALYST" in context.effective_roles
        assert "ADMIN" not in context.effective_roles  # no privilege escalation
        assert context.device_trust == DeviceTrust.UNMANAGED.value
        assert context.clearance_level == ClearanceLevel.CONFIDENTIAL.value

        token = token_issuer.issue(context)
        recovered = token_issuer.verify(token)
        assert not recovered.can_see_clearance(ClearanceLevel.SECRET)
        assert recovered.can_see_clearance(ClearanceLevel.CONFIDENTIAL)
