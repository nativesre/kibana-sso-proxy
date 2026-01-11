"""
Generic OIDC provider implementation.

This provider works with any OpenID Connect compliant identity provider.
It uses standard OIDC claims and discovery.
"""

from urllib.parse import urlencode

from authlib.integrations.flask_client import OAuth

from providers.base import OIDCProvider, UserInfo
from utils.logger import logger


class GenericOIDCProvider(OIDCProvider):
    """
    Generic OIDC provider for any OpenID Connect compliant IdP.

    Required configuration:
        issuer_url: The OIDC issuer URL (used for discovery)
        client_id: OAuth client ID
        client_secret: OAuth client secret

    Optional configuration:
        scopes: Space-separated scopes (default: 'openid profile email')
        username_claim: Claim to use for username (default: 'preferred_username')
        roles_claim: Claim containing roles (default: 'roles')
        logout_url: Custom logout URL (auto-detected if not provided)
        verify_ssl: Whether to verify SSL certificates (default: True)
    """

    @property
    def name(self) -> str:
        return "generic"

    def _validate_config(self) -> None:
        self._require_config("issuer_url", "client_id", "client_secret")

    @property
    def _discovery_url(self) -> str:
        """Get the OIDC discovery URL."""
        issuer = self.config["issuer_url"].rstrip("/")
        return f"{issuer}/.well-known/openid-configuration"

    def register_oauth(self, oauth: OAuth) -> None:
        """Register the generic OIDC provider with Flask OAuth."""
        scopes = self.config.get("scopes", "openid profile email")

        oauth.register(
            name="oidc",
            client_id=self.config["client_id"],
            client_secret=self.config["client_secret"],
            server_metadata_url=self._discovery_url,
            client_kwargs={"scope": scopes},
        )

    def get_authorization_url_params(self) -> dict:
        """Get additional parameters for authorization."""
        return {}

    def extract_user_info(self, token: dict, userinfo: dict | None = None) -> UserInfo:
        """Extract user information using configurable claims."""
        # Get claims from ID token
        id_token = token.get("id_token", "")
        claims = self.decode_token(id_token) if id_token else {}

        # Merge with userinfo if available (userinfo takes precedence)
        if userinfo:
            claims = {**claims, **userinfo}

        # Get username from configurable claim
        username_claim = self.config.get("username_claim", "preferred_username")
        username = (
            claims.get(username_claim)
            or claims.get("preferred_username")
            or claims.get("email", "").split("@")[0]
            or claims.get("sub")
        )

        return UserInfo(
            user_id=claims.get("sub", ""),
            username=username,
            email=claims.get("email"),
            full_name=claims.get("name"),
            roles=self.extract_roles(token),
            raw_claims=claims,
        )

    def extract_roles(self, token: dict) -> list[str]:
        """
        Extract roles from the token using configurable claim.

        Checks both ID token and access token for roles.
        """
        roles_claim = self.config.get("roles_claim", "roles")
        roles = []

        # Check ID token
        id_token = token.get("id_token", "")
        if id_token:
            claims = self.decode_token(id_token)
            token_roles = claims.get(roles_claim, [])
            if isinstance(token_roles, list):
                roles.extend(token_roles)
            elif isinstance(token_roles, str):
                roles.append(token_roles)

        # Check access token
        access_token = token.get("access_token", "")
        if access_token:
            claims = self.decode_token(access_token)
            token_roles = claims.get(roles_claim, [])
            if isinstance(token_roles, list):
                roles.extend(token_roles)
            elif isinstance(token_roles, str):
                roles.append(token_roles)

        # Also check nested structures common in some providers
        for tok in [id_token, access_token]:
            if not tok:
                continue
            claims = self.decode_token(tok)

            # Check for realm_access.roles (Keycloak-style)
            realm_access = claims.get("realm_access", {})
            if "roles" in realm_access:
                roles.extend(realm_access["roles"])

            # Check for resource_access (Keycloak-style)
            resource_access = claims.get("resource_access", {})
            for resource in resource_access.values():
                if "roles" in resource:
                    roles.extend(resource["roles"])

        unique_roles = list(set(roles))
        if unique_roles:
            logger.debug(f"Extracted roles: {unique_roles}")
        return unique_roles

    def get_logout_url(self, redirect_uri: str) -> str | None:
        """
        Get the logout URL.

        Uses custom logout_url if configured, otherwise tries to
        construct one from the issuer URL.
        """
        custom_logout = self.config.get("logout_url")
        if custom_logout:
            params = urlencode({"post_logout_redirect_uri": redirect_uri})
            return f"{custom_logout}?{params}"

        # Try standard OIDC logout endpoint
        issuer = self.config["issuer_url"].rstrip("/")
        params = urlencode({"post_logout_redirect_uri": redirect_uri})
        return f"{issuer}/protocol/openid-connect/logout?{params}"

    def supports_password_storage(self) -> bool:
        """Generic OIDC providers typically don't support password storage."""
        return False
