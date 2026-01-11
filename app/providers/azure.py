"""
Azure AD (Microsoft Entra ID) OIDC provider implementation.

Azure AD supports OpenID Connect and can be configured to include
group memberships and app roles in the token.
"""

from urllib.parse import urlencode

from authlib.integrations.flask_client import OAuth

from app.providers.base import OIDCProvider, UserInfo
from app.utils.logger import logger


class AzureADProvider(OIDCProvider):
    """
    Azure AD (Microsoft Entra ID) OIDC provider.

    Required configuration:
        tenant_id: Azure AD tenant ID (or 'common' for multi-tenant)
        client_id: Application (client) ID
        client_secret: Client secret

    Optional configuration:
        use_groups: Extract roles from group memberships (default: False)
        group_to_role_mapping: Dict mapping group IDs to role names
    """

    @property
    def name(self) -> str:
        return "azure"

    def _validate_config(self) -> None:
        self._require_config("tenant_id", "client_id", "client_secret")

    @property
    def _base_url(self) -> str:
        """Get the Azure AD base URL."""
        tenant = self.config["tenant_id"]
        return f"https://login.microsoftonline.com/{tenant}"

    def register_oauth(self, oauth: OAuth) -> None:
        """Register Azure AD with Flask OAuth."""
        oauth.register(
            name="oidc",
            client_id=self.config["client_id"],
            client_secret=self.config["client_secret"],
            server_metadata_url=f"{self._base_url}/v2.0/.well-known/openid-configuration",
            client_kwargs={
                "scope": "openid profile email",
                # Request group claims if configured
                **({"scope": "openid profile email GroupMember.Read.All"}
                   if self.config.get("use_groups") else {}),
            },
        )

    def get_authorization_url_params(self) -> dict:
        """Get additional parameters for Azure AD authorization."""
        return {
            # Force account selection even if already signed in
            "prompt": "select_account",
        }

    def extract_user_info(self, token: dict, userinfo: dict | None = None) -> UserInfo:
        """Extract user information from Azure AD token."""
        # Azure uses id_token for most claims
        id_token = token.get("id_token", "")
        claims = self.decode_token(id_token) if id_token else {}

        # Merge with userinfo if available
        if userinfo:
            claims = {**claims, **userinfo}

        # Azure uses different claim names
        # 'preferred_username' is usually the email in Azure AD
        # 'name' is the display name
        # 'oid' is the object ID (unique user identifier)
        # 'sub' is also unique but may differ between apps

        username = (
            claims.get("preferred_username", "").split("@")[0]  # Use email prefix
            or claims.get("unique_name", "").split("@")[0]
            or claims.get("sub")
        )

        return UserInfo(
            user_id=claims.get("oid") or claims.get("sub", ""),
            username=username,
            email=claims.get("email") or claims.get("preferred_username"),
            full_name=claims.get("name"),
            roles=self.extract_roles(token),
            raw_claims=claims,
        )

    def extract_roles(self, token: dict) -> list[str]:
        """
        Extract roles from Azure AD token.

        Azure AD can include roles in different ways:
        1. App roles: In the 'roles' claim
        2. Groups: In the 'groups' claim (requires group claims enabled)
        """
        id_token = token.get("id_token", "")
        access_token = token.get("access_token", "")

        roles = []

        # Check both tokens for roles
        for tok in [id_token, access_token]:
            if not tok:
                continue
            claims = self.decode_token(tok)

            # Extract app roles
            app_roles = claims.get("roles", [])
            if app_roles:
                roles.extend(app_roles)
                logger.debug(f"Extracted Azure app roles: {app_roles}")

            # Extract groups if configured
            if self.config.get("use_groups"):
                groups = claims.get("groups", [])
                group_mapping = self.config.get("group_to_role_mapping", {})

                for group_id in groups:
                    if group_id in group_mapping:
                        role = group_mapping[group_id]
                        roles.append(role)
                        logger.debug(f"Mapped group {group_id} to role {role}")

        return list(set(roles))  # Remove duplicates

    def get_logout_url(self, redirect_uri: str) -> str | None:
        """Get Azure AD logout URL."""
        params = urlencode({"post_logout_redirect_uri": redirect_uri})
        return f"{self._base_url}/oauth2/v2.0/logout?{params}"

    def supports_password_storage(self) -> bool:
        """Azure AD does not support custom attribute storage via API easily."""
        return False
