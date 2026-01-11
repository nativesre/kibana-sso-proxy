"""
Kibana session management service.

Handles obtaining and validating Kibana session cookies.
"""

import requests

from config.settings import KibanaConfig
from utils.logger import logger


class KibanaService:
    """
    Service for managing Kibana sessions.

    Provides methods for:
    - Obtaining session cookies (sid) via internal login
    - Validating existing sessions
    - Building Kibana URLs with proper base path handling
    """

    def __init__(self, config: KibanaConfig):
        """
        Initialize the Kibana service.

        Args:
            config: Kibana configuration
        """
        self.config = config

    def _build_internal_url(self, path: str) -> str:
        """
        Build an internal URL for Kibana API calls.

        Args:
            path: API path (e.g., /internal/security/login)

        Returns:
            Full URL including base path
        """
        base = self.config.internal_url.rstrip("/")
        base_path = self.config.base_path.rstrip("/")
        return f"{base}{base_path}{path}"

    def get_session(self, username: str, password: str) -> str | None:
        """
        Obtain a Kibana session cookie by logging in.

        Uses Kibana's internal security login endpoint to get a session ID.

        Args:
            username: Elasticsearch username
            password: Elasticsearch password

        Returns:
            The session ID (sid) cookie value, or None on failure
        """
        login_url = self._build_internal_url("/internal/security/login")
        home_url = self.get_home_url()

        try:
            response = requests.post(
                login_url,
                json={
                    "providerType": "basic",
                    "providerName": "basic",
                    "currentURL": home_url,
                    "params": {
                        "username": username,
                        "password": password,
                    },
                },
                headers={
                    "kbn-xsrf": "true",
                    "Content-Type": "application/json",
                },
                verify=self.config.verify_ssl,
                timeout=10,
                allow_redirects=False,
            )

            if response.status_code not in (200, 204):
                logger.error(
                    f"Kibana login failed: {response.status_code} - {response.text[:200]}"
                )
                return None

            # Extract session cookie from response
            sid = self._extract_session_cookie(response)
            if sid:
                logger.info(f"Obtained Kibana session for user: {username}")
            else:
                logger.error("No session cookie in Kibana response")

            return sid

        except requests.RequestException as e:
            logger.error(f"Kibana login request failed: {e}")
            return None

    def _extract_session_cookie(self, response: requests.Response) -> str | None:
        """
        Extract the session cookie from a Kibana response.

        Args:
            response: The HTTP response from Kibana

        Returns:
            The session ID value, or None if not found
        """
        # Try to get from cookies
        if "sid" in response.cookies:
            return response.cookies["sid"]

        # Try to parse from Set-Cookie header
        set_cookie = response.headers.get("Set-Cookie", "")
        if "sid=" in set_cookie:
            for part in set_cookie.split(";"):
                part = part.strip()
                if part.startswith("sid="):
                    return part[4:]

        return None

    def check_session_valid(self, session_id: str) -> bool:
        """
        Check if a Kibana session is still valid.

        Args:
            session_id: The session ID to validate

        Returns:
            True if the session is valid
        """
        me_url = self._build_internal_url("/internal/security/me")

        try:
            response = requests.get(
                me_url,
                cookies={"sid": session_id},
                headers={"kbn-xsrf": "true"},
                verify=self.config.verify_ssl,
                timeout=10,
            )
            return response.status_code == 200
        except requests.RequestException as e:
            logger.error(f"Session validation failed: {e}")
            return False

    def get_home_url(self) -> str:
        """
        Get the Kibana home URL for browser redirects.

        Returns:
            Full URL to Kibana home page
        """
        public = self.config.public_url.rstrip("/")
        base_path = self.config.base_path.rstrip("/")
        return f"{public}{base_path}/app/home"

    def build_redirect_url(self, path: str) -> str:
        """
        Build a full Kibana URL from a relative path.

        Args:
            path: Relative path (e.g., /app/discover)

        Returns:
            Full public URL including base path
        """
        public = self.config.public_url.rstrip("/")
        base_path = self.config.base_path.rstrip("/")

        # Don't add base path if already present
        if path.startswith(base_path) and base_path:
            return f"{public}{path}"

        return f"{public}{base_path}{path}"

    def get_cookie_path(self) -> str:
        """
        Get the path for the session cookie.

        The cookie path must match Kibana's base path for the
        browser to send it with requests.

        Returns:
            Cookie path (base path or "/" if no base path)
        """
        if self.config.base_path:
            return self.config.base_path.rstrip("/") or "/"
        return "/"
