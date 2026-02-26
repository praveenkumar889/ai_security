"""
SentinelSQL — Layer 01: Identity & Context Layer
identity_provider.py — IdP token validation for OAuth2, SAML, and LDAP.

Zero Trust rule: EVERY request re-validates the token against the IdP's
public keys. No cached trust. No session-level "already authenticated" bypass.

Three providers implemented:
  - OAuth2Provider  → validates RS256 JWT via JWKS endpoint (Okta, Azure AD, Auth0)
  - SAMLProvider    → validates SAML assertion (placeholder — extend with python3-saml)
  - LDAPProvider    → bind-validates credentials against Active Directory / OpenLDAP
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Optional

import httpx
from jose import jwt, JWTError, ExpiredSignatureError

from .models import IdPClaims

logger = logging.getLogger(__name__)


# ─── BASE ─────────────────────────────────────────────────────────────────────

class BaseIdentityProvider(ABC):
    @abstractmethod
    async def validate(self, credential: str) -> IdPClaims:
        """
        Validate the incoming credential (JWT string, SAML assertion, etc.)
        and return normalized IdPClaims.

        Raises:
            AuthenticationError: if validation fails for any reason.
        """
        ...


class AuthenticationError(Exception):
    """Raised when IdP validation fails. Always results in HTTP 401."""
    pass


# ─── OAUTH2 / OIDC ────────────────────────────────────────────────────────────

class OAuth2Provider(BaseIdentityProvider):
    """
    Validates a Bearer JWT token issued by any OIDC-compliant IdP:
      - Okta:    jwks_uri = https://{domain}/oauth2/v1/keys
      - Azure AD: jwks_uri = https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys
      - Auth0:   jwks_uri = https://{domain}/.well-known/jwks.json

    The JWKS is fetched once per instance and cached. Call refresh_jwks()
    to force a refresh (e.g. on key rotation).
    """

    def __init__(
        self,
        jwks_uri: str,
        issuer: str,
        audience: str,
        algorithms: list[str] | None = None,
        # Non-standard claim mappings (if your IdP uses different field names)
        groups_claim: str = "groups",
        department_claim: str = "department",
        clearance_claim: str = "clearance_level",
        facility_claim: str = "facility",
        provider_id_claim: str = "provider_id",
    ):
        self.jwks_uri        = jwks_uri
        self.issuer          = issuer
        self.audience        = audience
        self.algorithms      = algorithms or ["RS256"]
        self.groups_claim    = groups_claim
        self.department_claim = department_claim
        self.clearance_claim = clearance_claim
        self.facility_claim  = facility_claim
        self.provider_id_claim = provider_id_claim

        self._jwks: dict | None = None  # cached JWKS

    async def _get_jwks(self) -> dict:
        if self._jwks is None:
            await self.refresh_jwks()
        return self._jwks  # type: ignore[return-value]

    async def refresh_jwks(self) -> None:
        """Fetch fresh public keys from the IdP."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(self.jwks_uri)
                response.raise_for_status()
                self._jwks = response.json()
                logger.info("JWKS refreshed from %s (%d keys)", self.jwks_uri,
                            len(self._jwks.get("keys", [])))
        except httpx.HTTPError as e:
            raise AuthenticationError(f"Failed to fetch JWKS from IdP: {e}") from e

    async def validate(self, token: str) -> IdPClaims:
        """Decode and verify the JWT. Returns normalized IdPClaims."""
        jwks = await self._get_jwks()
        try:
            claims = jwt.decode(
                token,
                jwks,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
            )
        except ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except JWTError as e:
            # Retry once with fresh JWKS in case of key rotation
            logger.warning("JWT validation failed, refreshing JWKS and retrying: %s", e)
            await self.refresh_jwks()
            jwks = await self._get_jwks()
            try:
                claims = jwt.decode(
                    token, jwks,
                    algorithms=self.algorithms,
                    audience=self.audience,
                    issuer=self.issuer,
                )
            except JWTError as e2:
                raise AuthenticationError(f"Invalid JWT: {e2}") from e2

        return IdPClaims(
            sub=claims["sub"],
            email=claims.get("email", ""),
            preferred_username=claims.get("preferred_username", claims.get("name", "")),
            groups=claims.get(self.groups_claim, []),
            iss=claims.get("iss"),
            aud=str(claims.get("aud", "")),
            exp=claims.get("exp"),
            iat=claims.get("iat"),
            department=claims.get(self.department_claim),
            clearance_level=claims.get(self.clearance_claim),
            facility=claims.get(self.facility_claim),
            provider_id=claims.get(self.provider_id_claim),
        )


# ─── SAML ─────────────────────────────────────────────────────────────────────

class SAMLProvider(BaseIdentityProvider):
    """
    Validates a base64-encoded SAML 2.0 assertion.
    Extend this with python3-saml (pip install python3-saml) for production.

    The validate() method receives the raw SAMLResponse POST parameter value.
    """

    def __init__(self, idp_metadata_url: str, sp_entity_id: str):
        self.idp_metadata_url = idp_metadata_url
        self.sp_entity_id = sp_entity_id

    async def validate(self, saml_response: str) -> IdPClaims:
        """
        TODO: integrate python3-saml here.

        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        auth = OneLogin_Saml2_Auth(request_data, settings)
        auth.process_response()
        if not auth.is_authenticated():
            raise AuthenticationError(auth.get_last_error_reason())
        attributes = auth.get_attributes()
        """
        raise NotImplementedError(
            "SAMLProvider.validate() requires python3-saml integration. "
            "See comments in this method for implementation guide."
        )


# ─── LDAP ─────────────────────────────────────────────────────────────────────

class LDAPProvider(BaseIdentityProvider):
    """
    Authenticates via LDAP bind (Active Directory / OpenLDAP).
    The credential string should be "username:password" (or pass a dict).

    Requires: pip install python-ldap
    """

    def __init__(
        self,
        server_uri: str,          # e.g. "ldap://corp.example.com"
        base_dn: str,             # e.g. "dc=corp,dc=example,dc=com"
        user_search_filter: str = "(sAMAccountName={username})",
        group_attribute: str = "memberOf",
        use_tls: bool = True,
    ):
        self.server_uri = server_uri
        self.base_dn = base_dn
        self.user_search_filter = user_search_filter
        self.group_attribute = group_attribute
        self.use_tls = use_tls

    async def validate(self, credential: str) -> IdPClaims:
        """
        credential: "username:password" string.

        In production, run the synchronous ldap operations in a thread pool:
            import asyncio
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, self._sync_validate, username, password)
        """
        try:
            username, password = credential.split(":", 1)
        except ValueError:
            raise AuthenticationError("LDAP credential must be 'username:password'")

        return await self._async_validate(username, password)

    async def _async_validate(self, username: str, password: str) -> IdPClaims:
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_validate, username, password)

    def _sync_validate(self, username: str, password: str) -> IdPClaims:
        try:
            import ldap  # type: ignore
        except ImportError:
            raise RuntimeError("python-ldap not installed. Run: pip install python-ldap")

        try:
            conn = ldap.initialize(self.server_uri)
            if self.use_tls:
                conn.start_tls_s()

            # Bind with user credentials — this validates the password
            user_dn = f"uid={username},{self.base_dn}"
            conn.simple_bind_s(user_dn, password)

            # Search for the user entry to get attributes
            search_filter = self.user_search_filter.format(username=username)
            results = conn.search_s(
                self.base_dn,
                ldap.SCOPE_SUBTREE,
                search_filter,
                ["mail", "cn", "department", self.group_attribute],
            )
            conn.unbind_s()

            if not results:
                raise AuthenticationError(f"User '{username}' not found in LDAP")

            _, attrs = results[0]
            groups = [
                g.decode().split(",")[0].replace("CN=", "")
                for g in attrs.get(self.group_attribute, [])
            ]

            return IdPClaims(
                sub=username,
                email=attrs.get("mail", [b""])[0].decode(),
                preferred_username=username,
                groups=groups,
                department=attrs.get("department", [b""])[0].decode() or None,
            )

        except ldap.INVALID_CREDENTIALS:
            raise AuthenticationError("Invalid LDAP credentials")
        except ldap.LDAPError as e:
            raise AuthenticationError(f"LDAP error: {e}") from e


# ─── FACTORY ──────────────────────────────────────────────────────────────────

def get_identity_provider(provider_type: str, **kwargs) -> BaseIdentityProvider:
    """
    Factory. Configure via environment / settings.

    Examples:
        idp = get_identity_provider("oauth2",
                  jwks_uri="https://dev.okta.com/oauth2/v1/keys",
                  issuer="https://dev.okta.com",
                  audience="api://sentinelsql")

        idp = get_identity_provider("ldap",
                  server_uri="ldap://corp.example.com",
                  base_dn="dc=corp,dc=example,dc=com")
    """
    if provider_type == "oauth2":
        required = ["jwks_uri", "issuer", "audience"]
        missing = [k for k in required if k not in kwargs]
        if missing:
            raise ValueError(f"OAuth2Provider missing required args: {missing}")
        return OAuth2Provider(**kwargs)

    elif provider_type == "saml":
        return SAMLProvider(
            idp_metadata_url=kwargs["idp_metadata_url"],
            sp_entity_id=kwargs["sp_entity_id"],
        )

    elif provider_type == "ldap":
        return LDAPProvider(**kwargs)

    else:
        raise ValueError(f"Unknown identity provider type: '{provider_type}'")
