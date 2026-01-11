"""
Abstract base class for OIDC providers.

All provider implementations must inherit from this class and implement
the required methods.
"""

from abc import ABC, abstractmethod
from typing import Any
from dataclasses import dataclass

from authlib.integrations.flask_client import OAuth


@dataclass
class UserInfo:
    """Standardized user information across providers."""

    user_id: str          # Unique identifier from the provider
    username: str         # Username for Elasticsearch
    email: str | None     # User's email address
    full_name: str | None # User's display name
    roles: list[str]      # Roles from the provider
    raw_claims: dict      # Original claims from the provider

    def to_dict(self) -> dict:
        """Convert to dictionary for session storage."""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "roles": self.roles,
        }


class OIDCProvider(ABC):
    """
    Abstract base class for OIDC providers.

    Each provider implementation handles the specifics of:
    - OAuth/OIDC configuration
    - Token handling and validation
    - User info extraction
    - Role extraction and mapping
    - Optional: password storage for providers that support it
    """

    def __init__(self, config: dict):
        """
        Initialize the provider with configuration.

        Args:
            config: Provider-specific configuration dictionary
        """
        self.config = config
        self._validate_config()

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the provider name (e.g., 'keycloak', 'azure')."""
        pass

    @abstractmethod
    def _validate_config(self) -> None:
        """
        Validate that all required configuration is present.

        Raises:
            ValueError: If required configuration is missing
        """
        pass

    @abstractmethod
    def register_oauth(self, oauth: OAuth) -> None:
        """
        Register this provider with the Flask OAuth client.

        Args:
            oauth: The Flask OAuth instance
        """
        pass

    @abstractmethod
    def get_authorization_url_params(self) -> dict:
        """
        Get additional parameters for the authorization URL.

        Returns:
            Dictionary of parameters to add to the auth URL
        """
        pass

    @abstractmethod
    def extract_user_info(self, token: dict, userinfo: dict | None = None) -> UserInfo:
        """
        Extract standardized user information from the token and/or userinfo.

        Args:
            token: The OAuth token response
            userinfo: Optional userinfo endpoint response

        Returns:
            Standardized UserInfo object
        """
        pass

    @abstractmethod
    def extract_roles(self, token: dict) -> list[str]:
        """
        Extract roles from the token.

        Args:
            token: The OAuth token response

        Returns:
            List of role names
        """
        pass

    @abstractmethod
    def get_logout_url(self, redirect_uri: str) -> str | None:
        """
        Get the logout URL for this provider.

        Args:
            redirect_uri: URL to redirect to after logout

        Returns:
            The logout URL, or None if logout is not supported
        """
        pass

    def supports_password_storage(self) -> bool:
        """
        Check if this provider supports storing the ES password.

        Override in subclasses that support password storage.

        Returns:
            True if password storage is supported
        """
        return False

    def get_stored_password(self, user_id: str) -> str | None:
        """
        Get the stored Elasticsearch password for a user.

        Override in subclasses that support password storage.

        Args:
            user_id: The user's ID in this provider

        Returns:
            The stored password, or None if not found
        """
        return None

    def store_password(self, user_id: str, password: str) -> bool:
        """
        Store the Elasticsearch password for a user.

        Override in subclasses that support password storage.

        Args:
            user_id: The user's ID in this provider
            password: The password to store

        Returns:
            True if storage was successful
        """
        return False

    def decode_token(self, token: str) -> dict:
        """
        Decode a JWT token without verification.

        This is used to extract claims from the access token.
        Note: This does NOT verify the signature.

        Args:
            token: The JWT token string

        Returns:
            The decoded token payload
        """
        import base64
        import json

        try:
            # Split token and get payload
            parts = token.split(".")
            if len(parts) != 3:
                return {}

            # Decode payload (add padding if needed)
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding

            decoded = base64.urlsafe_b64decode(payload)
            return json.loads(decoded)
        except Exception:
            return {}

    def _require_config(self, *keys: str) -> None:
        """
        Helper to validate required configuration keys.

        Args:
            keys: Configuration keys that must be present

        Raises:
            ValueError: If any required key is missing
        """
        missing = [k for k in keys if not self.config.get(k)]
        if missing:
            raise ValueError(
                f"Missing required configuration for {self.name}: {', '.join(missing)}"
            )
