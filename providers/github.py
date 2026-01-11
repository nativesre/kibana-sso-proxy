"""
GitHub OAuth provider implementation.

Note: GitHub uses OAuth 2.0, not OpenID Connect. This provider
adapts GitHub's OAuth flow to work with the OIDC-based proxy.
"""

import requests
from urllib.parse import urlencode

from authlib.integrations.flask_client import OAuth

from providers.base import OIDCProvider, UserInfo
from utils.logger import logger


class GitHubProvider(OIDCProvider):
    """
    GitHub OAuth provider.

    Required configuration:
        client_id: GitHub OAuth App client ID
        client_secret: GitHub OAuth App client secret

    Optional configuration:
        org_name: Require membership in this GitHub organization
        team_to_role_mapping: Dict mapping team slugs to role names
        allowed_orgs: List of allowed organization names
    """

    @property
    def name(self) -> str:
        return "github"

    def _validate_config(self) -> None:
        self._require_config("client_id", "client_secret")

    def register_oauth(self, oauth: OAuth) -> None:
        """Register GitHub with Flask OAuth."""
        # GitHub doesn't support OIDC discovery, so we configure manually
        oauth.register(
            name="oidc",
            client_id=self.config["client_id"],
            client_secret=self.config["client_secret"],
            access_token_url="https://github.com/login/oauth/access_token",
            authorize_url="https://github.com/login/oauth/authorize",
            api_base_url="https://api.github.com/",
            client_kwargs={
                "scope": "read:user user:email read:org",
            },
        )

    def get_authorization_url_params(self) -> dict:
        """Get additional parameters for GitHub authorization."""
        return {}

    def extract_user_info(self, token: dict, userinfo: dict | None = None) -> UserInfo:
        """
        Extract user information from GitHub.

        GitHub requires a separate API call to get user info.
        """
        access_token = token.get("access_token", "")

        # Get user info from GitHub API
        user_data = self._get_github_user(access_token)
        if not user_data:
            raise ValueError("Failed to get user info from GitHub")

        # Get user's primary email
        email = user_data.get("email")
        if not email:
            email = self._get_primary_email(access_token)

        return UserInfo(
            user_id=str(user_data.get("id", "")),
            username=user_data.get("login", ""),
            email=email,
            full_name=user_data.get("name"),
            roles=self.extract_roles(token),
            raw_claims=user_data,
        )

    def _get_github_user(self, access_token: str) -> dict:
        """Get user info from GitHub API."""
        try:
            response = requests.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json",
                },
                timeout=10,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to get GitHub user: {e}")
            return {}

    def _get_primary_email(self, access_token: str) -> str | None:
        """Get the user's primary email from GitHub."""
        try:
            response = requests.get(
                "https://api.github.com/user/emails",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json",
                },
                timeout=10,
            )
            response.raise_for_status()
            emails = response.json()

            # Find primary email
            for email in emails:
                if email.get("primary"):
                    return email.get("email")

            # Fall back to first verified email
            for email in emails:
                if email.get("verified"):
                    return email.get("email")

            return None
        except requests.RequestException as e:
            logger.error(f"Failed to get GitHub emails: {e}")
            return None

    def extract_roles(self, token: dict) -> list[str]:
        """
        Extract roles based on GitHub organization/team membership.

        This requires the 'read:org' scope.
        """
        access_token = token.get("access_token", "")
        if not access_token:
            return []

        roles = []

        # Check organization membership if configured
        org_name = self.config.get("org_name")
        allowed_orgs = self.config.get("allowed_orgs", [])
        team_mapping = self.config.get("team_to_role_mapping", {})

        if org_name or allowed_orgs or team_mapping:
            roles = self._get_roles_from_orgs(access_token, org_name, allowed_orgs, team_mapping)

        return roles

    def _get_roles_from_orgs(
        self,
        access_token: str,
        org_name: str | None,
        allowed_orgs: list[str],
        team_mapping: dict,
    ) -> list[str]:
        """Get roles based on organization and team membership."""
        roles = []

        try:
            # Get user's organizations
            response = requests.get(
                "https://api.github.com/user/orgs",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json",
                },
                timeout=10,
            )
            response.raise_for_status()
            user_orgs = [org["login"] for org in response.json()]

            # Check if user is in required org
            if org_name and org_name not in user_orgs:
                logger.warning(f"User not in required organization: {org_name}")
                return []

            # Check if user is in any allowed org
            if allowed_orgs:
                if not any(org in user_orgs for org in allowed_orgs):
                    logger.warning(f"User not in any allowed organization")
                    return []

            # Get roles from team membership
            if team_mapping and org_name:
                roles.extend(
                    self._get_roles_from_teams(access_token, org_name, team_mapping)
                )

        except requests.RequestException as e:
            logger.error(f"Failed to check GitHub org membership: {e}")

        return roles

    def _get_roles_from_teams(
        self, access_token: str, org_name: str, team_mapping: dict
    ) -> list[str]:
        """Get roles based on team membership in an organization."""
        roles = []

        try:
            response = requests.get(
                f"https://api.github.com/orgs/{org_name}/teams",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json",
                },
                timeout=10,
            )

            if response.status_code == 200:
                teams = response.json()
                user_teams = [team["slug"] for team in teams]

                for team_slug, role in team_mapping.items():
                    if team_slug in user_teams:
                        roles.append(role)
                        logger.debug(f"Mapped team {team_slug} to role {role}")

        except requests.RequestException as e:
            logger.error(f"Failed to get GitHub teams: {e}")

        return roles

    def get_logout_url(self, redirect_uri: str) -> str | None:
        """
        GitHub doesn't have a logout endpoint.

        Users remain logged into GitHub even after logging out of the app.
        """
        return None

    def supports_password_storage(self) -> bool:
        """GitHub does not support custom attribute storage."""
        return False
