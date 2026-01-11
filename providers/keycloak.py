"""
Keycloak OIDC provider implementation.

Keycloak is a full-featured identity provider that supports:
- OpenID Connect
- SAML 2.0
- User federation
- Custom user attributes (used for password storage)
- Client-level role assignments
"""

import requests
from urllib.parse import urlencode

from authlib.integrations.flask_client import OAuth

from providers.base import OIDCProvider, UserInfo
from utils.logger import logger


class KeycloakProvider(OIDCProvider):
    """
    Keycloak OIDC provider.

    Required configuration:
        server_url: Keycloak server URL (e.g., https://keycloak.example.com)
        realm: Keycloak realm name
        client_id: OAuth client ID
        client_secret: OAuth client secret

    Optional configuration:
        verify_ssl: Whether to verify SSL certificates (default: True)
        admin_client_id: Client ID for admin API (defaults to client_id)
        admin_client_secret: Client secret for admin API (defaults to client_secret)
    """

    @property
    def name(self) -> str:
        return "keycloak"

    def _validate_config(self) -> None:
        self._require_config("server_url", "realm", "client_id", "client_secret")

    @property
    def _base_url(self) -> str:
        """Get the base URL for this realm."""
        return f"{self.config['server_url']}/realms/{self.config['realm']}"

    @property
    def _admin_base_url(self) -> str:
        """Get the admin API base URL."""
        return f"{self.config['server_url']}/admin/realms/{self.config['realm']}"

    @property
    def _verify_ssl(self) -> bool:
        """Whether to verify SSL certificates."""
        return self.config.get("verify_ssl", True)

    def register_oauth(self, oauth: OAuth) -> None:
        """Register Keycloak with Flask OAuth."""
        oauth.register(
            name="oidc",
            client_id=self.config["client_id"],
            client_secret=self.config["client_secret"],
            server_metadata_url=f"{self._base_url}/.well-known/openid-configuration",
            client_kwargs={"scope": "openid profile email"},
        )

    def get_authorization_url_params(self) -> dict:
        """Get additional parameters for authorization."""
        return {}

    def extract_user_info(self, token: dict, userinfo: dict | None = None) -> UserInfo:
        """Extract user information from Keycloak token/userinfo."""
        # Prefer userinfo if available, fall back to token claims
        claims = userinfo or {}

        # Get access token claims for roles
        access_token = token.get("access_token", "")
        token_claims = self.decode_token(access_token) if access_token else {}

        # Merge claims (userinfo takes precedence)
        all_claims = {**token_claims, **claims}

        # Extract username (preferred_username is standard OIDC)
        username = (
            all_claims.get("preferred_username")
            or all_claims.get("username")
            or all_claims.get("sub")
        )

        return UserInfo(
            user_id=all_claims.get("sub", ""),
            username=username,
            email=all_claims.get("email"),
            full_name=all_claims.get("name"),
            roles=self.extract_roles(token),
            raw_claims=all_claims,
        )

    def extract_roles(self, token: dict) -> list[str]:
        """
        Extract roles from Keycloak access token.

        Keycloak stores client roles in resource_access[client_id].roles
        """
        access_token = token.get("access_token", "")
        if not access_token:
            return []

        claims = self.decode_token(access_token)
        client_id = self.config["client_id"]

        # Check resource_access for client-specific roles
        resource_access = claims.get("resource_access", {})
        client_access = resource_access.get(client_id, {})
        roles = client_access.get("roles", [])

        if roles:
            logger.debug(f"Extracted roles from resource_access: {roles}")
            return roles

        # Fall back to realm roles
        realm_access = claims.get("realm_access", {})
        realm_roles = realm_access.get("roles", [])
        logger.debug(f"Extracted realm roles: {realm_roles}")
        return realm_roles

    def get_logout_url(self, redirect_uri: str) -> str | None:
        """Get Keycloak logout URL."""
        params = urlencode({"post_logout_redirect_uri": redirect_uri})
        return f"{self._base_url}/protocol/openid-connect/logout?{params}"

    def supports_password_storage(self) -> bool:
        """Keycloak supports password storage via user attributes."""
        return True

    def _get_admin_token(self) -> str | None:
        """Get an admin access token using client credentials."""
        token_url = f"{self._base_url}/protocol/openid-connect/token"

        admin_client_id = self.config.get("admin_client_id", self.config["client_id"])
        admin_client_secret = self.config.get(
            "admin_client_secret", self.config["client_secret"]
        )

        try:
            response = requests.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": admin_client_id,
                    "client_secret": admin_client_secret,
                },
                verify=self._verify_ssl,
                timeout=10,
            )
            response.raise_for_status()
            return response.json().get("access_token")
        except requests.RequestException as e:
            logger.error(f"Failed to get Keycloak admin token: {e}")
            return None

    def get_stored_password(self, user_id: str) -> str | None:
        """Get the stored ES password from Keycloak user attributes."""
        admin_token = self._get_admin_token()
        if not admin_token:
            return None

        try:
            response = requests.get(
                f"{self._admin_base_url}/users/{user_id}",
                headers={"Authorization": f"Bearer {admin_token}"},
                verify=self._verify_ssl,
                timeout=10,
            )
            response.raise_for_status()
            user_data = response.json()
            attributes = user_data.get("attributes", {})
            password_list = attributes.get("es_password", [])
            return password_list[0] if password_list else None
        except requests.RequestException as e:
            logger.error(f"Failed to get user attributes from Keycloak: {e}")
            return None

    def store_password(self, user_id: str, password: str) -> bool:
        """Store the ES password in Keycloak user attributes."""
        admin_token = self._get_admin_token()
        if not admin_token:
            return False

        try:
            # First get current attributes to preserve them
            response = requests.get(
                f"{self._admin_base_url}/users/{user_id}",
                headers={"Authorization": f"Bearer {admin_token}"},
                verify=self._verify_ssl,
                timeout=10,
            )
            response.raise_for_status()
            user_data = response.json()
            attributes = user_data.get("attributes", {})

            # Update the password attribute
            attributes["es_password"] = [password]

            # Patch the user with updated attributes
            response = requests.put(
                f"{self._admin_base_url}/users/{user_id}",
                headers={
                    "Authorization": f"Bearer {admin_token}",
                    "Content-Type": "application/json",
                },
                json={"attributes": attributes},
                verify=self._verify_ssl,
                timeout=10,
            )
            response.raise_for_status()
            logger.info(f"Stored ES password for user {user_id} in Keycloak")
            return True
        except requests.RequestException as e:
            logger.error(f"Failed to store password in Keycloak: {e}")
            return False
