"""
Elasticsearch user management service.

Handles creating and updating users in Elasticsearch based on
OIDC provider authentication.
"""

import re
from typing import Tuple
import requests

from config.settings import ElasticsearchConfig
from utils.logger import logger


class RoleMapper:
    """
    Flexible role mapping from OIDC provider roles to Elasticsearch roles.

    Supports multiple mapping strategies:
    - Direct mapping: Map specific roles to ES roles
    - Prefix/suffix stripping: Remove prefixes like "kibana_" or suffixes
    - Pass-through: Allow unmapped roles to pass through directly
    - Always include: Roles that are always added regardless of provider roles
    - Regex mapping: Pattern-based role transformations

    Configuration via environment variables:
        ES_ROLE_MAPPING: JSON object mapping provider roles to ES roles
        ES_DEFAULT_ROLES: JSON array of roles when no mapping matches
        ES_ROLE_PASSTHROUGH: Allow unmapped roles to pass through (true/false)
        ES_ROLE_ALWAYS_INCLUDE: JSON array of roles always added
        ES_ROLE_PREFIX_STRIP: Prefix to strip from provider roles
        ES_ROLE_SUFFIX_STRIP: Suffix to strip from provider roles
        ES_ROLE_PREFIX_ADD: Prefix to add to mapped roles
        ES_ROLE_CASE_SENSITIVE: Case-sensitive role matching (true/false)
    """

    def __init__(self, config: ElasticsearchConfig):
        """
        Initialize the role mapper.

        Args:
            config: Elasticsearch configuration with role mapping settings
        """
        self.config = config

        # Normalize mapping keys to lowercase if case-insensitive
        if not config.role_case_sensitive:
            self.role_mapping = {
                k.lower(): v for k, v in config.role_mapping.items()
            }
        else:
            self.role_mapping = config.role_mapping

    def map_roles(self, provider_roles: list[str]) -> list[str]:
        """
        Map provider roles to Elasticsearch roles.

        The mapping process follows these steps:
        1. Strip configured prefix/suffix from provider roles
        2. Apply direct role mapping
        3. If no mapping found and passthrough enabled, use the role directly
        4. Add prefix to mapped roles if configured
        5. Add always-include roles
        6. If still empty, use default roles

        Args:
            provider_roles: List of roles from the OIDC provider

        Returns:
            List of Elasticsearch roles
        """
        es_roles = set()
        mapped_count = 0

        for role in provider_roles:
            # Step 1: Strip prefix/suffix
            processed_role = self._strip_affixes(role)

            # Step 2: Apply direct mapping
            mapped = self._apply_mapping(processed_role)

            if mapped:
                mapped_count += 1
                # Step 4: Add prefix if configured
                for r in mapped:
                    es_roles.add(self._add_prefix(r))
            elif self.config.role_passthrough:
                # Step 3: Pass through unmapped roles
                es_roles.add(self._add_prefix(processed_role))
                logger.debug(f"Passing through unmapped role: {role} -> {processed_role}")

        # Step 5: Add always-include roles
        es_roles.update(self.config.role_always_include)

        # Step 6: Use defaults if nothing mapped
        if not es_roles:
            es_roles.update(self.config.default_roles)
            logger.debug(f"No roles mapped, using defaults: {self.config.default_roles}")

        result = list(es_roles)
        logger.info(f"Role mapping: {provider_roles} -> {result}")
        return result

    def _strip_affixes(self, role: str) -> str:
        """Strip configured prefix and suffix from a role."""
        result = role

        if self.config.role_prefix_strip:
            prefix = self.config.role_prefix_strip
            if not self.config.role_case_sensitive:
                if result.lower().startswith(prefix.lower()):
                    result = result[len(prefix):]
            elif result.startswith(prefix):
                result = result[len(prefix):]

        if self.config.role_suffix_strip:
            suffix = self.config.role_suffix_strip
            if not self.config.role_case_sensitive:
                if result.lower().endswith(suffix.lower()):
                    result = result[:-len(suffix)]
            elif result.endswith(suffix):
                result = result[:-len(suffix)]

        return result

    def _add_prefix(self, role: str) -> str:
        """Add configured prefix to a role."""
        if self.config.role_prefix_add:
            return f"{self.config.role_prefix_add}{role}"
        return role

    def _apply_mapping(self, role: str) -> list[str] | None:
        """
        Apply role mapping rules.

        Returns:
            List of mapped ES roles, or None if no mapping found
        """
        # Determine the key to look up
        lookup_key = role if self.config.role_case_sensitive else role.lower()

        # Direct mapping
        if lookup_key in self.role_mapping:
            mapped = self.role_mapping[lookup_key]
            if isinstance(mapped, list):
                return mapped
            return [mapped]

        # Regex mapping (keys starting with "regex:")
        for key, value in self.role_mapping.items():
            if key.startswith("regex:"):
                pattern = key[6:]  # Remove "regex:" prefix
                flags = 0 if self.config.role_case_sensitive else re.IGNORECASE
                if re.match(pattern, role, flags):
                    if isinstance(value, list):
                        return value
                    return [value]

        return None


class ElasticsearchService:
    """
    Service for managing Elasticsearch users.

    Provides methods for:
    - Creating users with provider-assigned roles
    - Updating user roles and passwords
    - Mapping provider roles to Elasticsearch roles
    """

    def __init__(self, config: ElasticsearchConfig):
        """
        Initialize the Elasticsearch service.

        Args:
            config: Elasticsearch configuration
        """
        self.config = config
        self._auth = (config.admin_user, config.admin_password)
        self._role_mapper = RoleMapper(config)

    def _request(
        self,
        method: str,
        endpoint: str,
        json_data: dict | None = None,
        **kwargs,
    ) -> requests.Response | None:
        """
        Make an authenticated request to Elasticsearch.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (e.g., /_security/user/username)
            json_data: Optional JSON body

        Returns:
            Response object or None on error
        """
        url = f"{self.config.url}{endpoint}"
        try:
            response = requests.request(
                method=method,
                url=url,
                auth=self._auth,
                json=json_data,
                verify=self.config.verify_ssl,
                timeout=10,
                **kwargs,
            )
            return response
        except requests.RequestException as e:
            logger.error(f"Elasticsearch request failed: {method} {endpoint} - {e}")
            return None

    def check_user_exists(self, username: str) -> bool:
        """
        Check if a user exists in Elasticsearch.

        Args:
            username: The username to check

        Returns:
            True if the user exists
        """
        response = self._request("GET", f"/_security/user/{username}")
        return response is not None and response.status_code == 200

    def create_user(
        self,
        username: str,
        password: str,
        roles: list[str],
        email: str | None = None,
        full_name: str | None = None,
    ) -> bool:
        """
        Create a new user in Elasticsearch.

        Args:
            username: Username for the new user
            password: Password for the new user
            roles: List of Elasticsearch roles to assign
            email: Optional email address
            full_name: Optional display name

        Returns:
            True if creation was successful
        """
        user_data = {
            "password": password,
            "roles": roles,
            "metadata": {
                "synced_from": "kibana-sso-proxy",
            },
        }

        if email:
            user_data["email"] = email
        if full_name:
            user_data["full_name"] = full_name

        response = self._request("POST", f"/_security/user/{username}", user_data)

        if response and response.status_code in (200, 201):
            logger.info(f"Created Elasticsearch user: {username} with roles: {roles}")
            return True

        logger.error(
            f"Failed to create user {username}: "
            f"{response.status_code if response else 'No response'} - "
            f"{response.text[:200] if response else 'Unknown error'}"
        )
        return False

    def update_user_roles(
        self,
        username: str,
        roles: list[str],
        email: str | None = None,
        full_name: str | None = None,
    ) -> bool:
        """
        Update an existing user's roles and metadata.

        Args:
            username: Username to update
            roles: New list of roles
            email: Optional email to update
            full_name: Optional display name to update

        Returns:
            True if update was successful
        """
        user_data = {
            "roles": roles,
            "metadata": {
                "synced_from": "kibana-sso-proxy",
            },
        }

        if email:
            user_data["email"] = email
        if full_name:
            user_data["full_name"] = full_name

        response = self._request("PUT", f"/_security/user/{username}", user_data)

        if response and response.status_code == 200:
            logger.info(f"Updated Elasticsearch user: {username} with roles: {roles}")
            return True

        logger.error(
            f"Failed to update user {username}: "
            f"{response.status_code if response else 'No response'}"
        )
        return False

    def update_user_password(self, username: str, password: str) -> bool:
        """
        Update a user's password.

        Args:
            username: Username to update
            password: New password

        Returns:
            True if update was successful
        """
        response = self._request(
            "POST",
            f"/_security/user/{username}/_password",
            {"password": password},
        )

        if response and response.status_code == 200:
            logger.info(f"Updated password for Elasticsearch user: {username}")
            return True

        logger.error(
            f"Failed to update password for {username}: "
            f"{response.status_code if response else 'No response'}"
        )
        return False

    def map_roles(self, provider_roles: list[str]) -> list[str]:
        """
        Map provider roles to Elasticsearch roles.

        Args:
            provider_roles: List of roles from the OIDC provider

        Returns:
            List of Elasticsearch roles
        """
        return self._role_mapper.map_roles(provider_roles)

    def sync_user(
        self,
        username: str,
        password: str,
        provider_roles: list[str],
        email: str | None = None,
        full_name: str | None = None,
        force_password: bool = False,
    ) -> Tuple[str, bool]:
        """
        Sync a user from the OIDC provider to Elasticsearch.

        Creates the user if they don't exist, otherwise updates their roles.
        Password is only updated if force_password is True.

        Args:
            username: Username for the user
            password: Password for the user
            provider_roles: Roles from the OIDC provider
            email: Optional email address
            full_name: Optional display name
            force_password: Force password update for existing users

        Returns:
            Tuple of (username, password_was_updated)
        """
        es_roles = self.map_roles(provider_roles)
        user_exists = self.check_user_exists(username)

        if not user_exists:
            # Create new user
            success = self.create_user(username, password, es_roles, email, full_name)
            if success:
                logger.info(f"Created new user {username} with roles {es_roles}")
                return username, True
            else:
                raise RuntimeError(f"Failed to create user {username}")

        # Update existing user's roles
        self.update_user_roles(username, es_roles, email, full_name)

        # Optionally update password
        if force_password:
            self.update_user_password(username, password)
            logger.info(f"Updated user {username} with new password and roles {es_roles}")
            return username, True

        logger.info(f"Updated user {username} roles to {es_roles}")
        return username, False
