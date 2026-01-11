"""
Configuration management for Kibana SSO Proxy.

Supports multiple OIDC providers and validates configuration at startup.
"""

import os
import json
from dataclasses import dataclass, field
from typing import Any

from app.utils.logger import logger


@dataclass
class ProviderConfig:
    """Configuration for an OIDC provider."""

    type: str  # keycloak, azure, github, generic

    # Common OIDC settings
    client_id: str = ""
    client_secret: str = ""

    # Keycloak-specific
    server_url: str = ""
    realm: str = ""
    admin_client_id: str = ""
    admin_client_secret: str = ""

    # Azure AD-specific
    tenant_id: str = ""
    use_groups: bool = False
    group_to_role_mapping: dict = field(default_factory=dict)

    # GitHub-specific
    org_name: str = ""
    allowed_orgs: list = field(default_factory=list)
    team_to_role_mapping: dict = field(default_factory=dict)

    # Generic OIDC-specific
    issuer_url: str = ""
    scopes: str = "openid profile email"
    username_claim: str = "preferred_username"
    roles_claim: str = "roles"
    logout_url: str = ""

    # SSL verification
    verify_ssl: bool = True

    def to_dict(self) -> dict:
        """Convert to dictionary for provider initialization."""
        return {
            "type": self.type,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "server_url": self.server_url,
            "realm": self.realm,
            "admin_client_id": self.admin_client_id or self.client_id,
            "admin_client_secret": self.admin_client_secret or self.client_secret,
            "tenant_id": self.tenant_id,
            "use_groups": self.use_groups,
            "group_to_role_mapping": self.group_to_role_mapping,
            "org_name": self.org_name,
            "allowed_orgs": self.allowed_orgs,
            "team_to_role_mapping": self.team_to_role_mapping,
            "issuer_url": self.issuer_url,
            "scopes": self.scopes,
            "username_claim": self.username_claim,
            "roles_claim": self.roles_claim,
            "logout_url": self.logout_url,
            "verify_ssl": self.verify_ssl,
        }


@dataclass
class ElasticsearchConfig:
    """
    Elasticsearch connection and role mapping configuration.

    Role Mapping Configuration:
        The role mapper transforms OIDC provider roles to Elasticsearch roles.
        Multiple strategies can be combined for flexible role management.

    Attributes:
        url: Elasticsearch URL
        admin_user: Admin username for user management
        admin_password: Admin password
        verify_ssl: Whether to verify SSL certificates

        role_mapping: Direct mapping from provider roles to ES roles (JSON object)
            Example: {"admin": ["superuser"], "dev": ["developer", "kibana_user"]}
            Supports regex patterns with "regex:" prefix:
            {"regex:team-.*": ["team_member"], "admin": ["superuser"]}

        default_roles: Roles assigned when no mapping matches (JSON array)
            Example: ["viewer"]

        role_passthrough: If true, unmapped roles pass through directly to ES
            Useful when provider roles match ES roles exactly

        role_always_include: Roles always added regardless of mapping (JSON array)
            Example: ["kibana_user"] - ensures all users can access Kibana

        role_prefix_strip: Prefix to remove from provider roles before mapping
            Example: "app_" would transform "app_admin" to "admin"

        role_suffix_strip: Suffix to remove from provider roles before mapping
            Example: "_role" would transform "admin_role" to "admin"

        role_prefix_add: Prefix to add to all mapped roles
            Example: "sso_" would transform "admin" to "sso_admin"

        role_case_sensitive: Whether role matching is case-sensitive (default: false)
    """

    url: str = "http://localhost:9200"
    admin_user: str = "elastic"
    admin_password: str = ""
    verify_ssl: bool = True

    # Role mapping configuration
    role_mapping: dict = field(default_factory=dict)
    default_roles: list = field(default_factory=lambda: ["viewer"])
    role_passthrough: bool = False
    role_always_include: list = field(default_factory=list)
    role_prefix_strip: str = ""
    role_suffix_strip: str = ""
    role_prefix_add: str = ""
    role_case_sensitive: bool = False


@dataclass
class KibanaConfig:
    """Kibana connection configuration."""

    internal_url: str = "http://localhost:5601"  # Internal URL for proxy -> Kibana
    public_url: str = "http://localhost:5601"    # Public URL for browser redirects
    base_path: str = ""                          # Kibana server.basePath setting
    verify_ssl: bool = True


@dataclass
class ProxyConfig:
    """Proxy server configuration."""

    public_url: str = "http://localhost:3000"  # Public URL of this proxy
    session_secret: str = ""
    log_level: str = "INFO"


@dataclass
class Config:
    """Main configuration container."""

    provider: ProviderConfig = field(default_factory=lambda: ProviderConfig(type="generic"))
    elasticsearch: ElasticsearchConfig = field(default_factory=ElasticsearchConfig)
    kibana: KibanaConfig = field(default_factory=KibanaConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)

    def validate(self) -> list[str]:
        """
        Validate the configuration.

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        # Validate provider config
        if not self.provider.client_id:
            errors.append("OIDC_CLIENT_ID is required")
        if not self.provider.client_secret:
            errors.append("OIDC_CLIENT_SECRET is required")

        # Provider-specific validation
        if self.provider.type == "keycloak":
            if not self.provider.server_url:
                errors.append("KEYCLOAK_SERVER_URL is required for Keycloak provider")
            if not self.provider.realm:
                errors.append("KEYCLOAK_REALM is required for Keycloak provider")
        elif self.provider.type == "azure":
            if not self.provider.tenant_id:
                errors.append("AZURE_TENANT_ID is required for Azure provider")
        elif self.provider.type == "generic":
            if not self.provider.issuer_url:
                errors.append("OIDC_ISSUER_URL is required for generic OIDC provider")

        # Validate Elasticsearch config
        if not self.elasticsearch.url:
            errors.append("ELASTICSEARCH_URL is required")
        if not self.elasticsearch.admin_password:
            errors.append("ES_ADMIN_PASSWORD is required")

        # Validate proxy config
        if not self.proxy.session_secret:
            errors.append("SESSION_SECRET is required")
        if self.proxy.session_secret == "change-me-in-production":
            logger.warning("Using default SESSION_SECRET - change this in production!")

        return errors


def _parse_bool(value: str) -> bool:
    """Parse a boolean from environment variable string."""
    return value.lower() in ("true", "1", "yes", "on")


def _parse_json(value: str, default: Any) -> Any:
    """Parse JSON from environment variable string."""
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        logger.warning(f"Failed to parse JSON config: {value}")
        return default


def load_config() -> Config:
    """
    Load configuration from environment variables.

    Environment Variables:
        # Provider Selection
        OIDC_PROVIDER: Provider type (keycloak, azure, github, generic)

        # Common OIDC Settings
        OIDC_CLIENT_ID: OAuth client ID
        OIDC_CLIENT_SECRET: OAuth client secret

        # Keycloak-specific
        KEYCLOAK_SERVER_URL: Keycloak server URL
        KEYCLOAK_REALM: Keycloak realm name
        KEYCLOAK_ADMIN_CLIENT_ID: Admin API client ID (optional)
        KEYCLOAK_ADMIN_CLIENT_SECRET: Admin API client secret (optional)

        # Azure AD-specific
        AZURE_TENANT_ID: Azure AD tenant ID
        AZURE_USE_GROUPS: Use group claims for roles (true/false)
        AZURE_GROUP_ROLE_MAPPING: JSON mapping of group IDs to roles

        # GitHub-specific
        GITHUB_ORG: Required GitHub organization
        GITHUB_ALLOWED_ORGS: JSON array of allowed organizations
        GITHUB_TEAM_ROLE_MAPPING: JSON mapping of team slugs to roles

        # Generic OIDC
        OIDC_ISSUER_URL: OIDC issuer URL (for discovery)
        OIDC_SCOPES: Space-separated scopes
        OIDC_USERNAME_CLAIM: Claim for username
        OIDC_ROLES_CLAIM: Claim for roles
        OIDC_LOGOUT_URL: Custom logout URL

        # Elasticsearch Connection
        ELASTICSEARCH_URL: Elasticsearch URL
        ES_ADMIN_USER: Admin username
        ES_ADMIN_PASSWORD: Admin password

        # Elasticsearch Role Mapping
        ES_ROLE_MAPPING: JSON mapping of provider roles to ES roles
        ES_DEFAULT_ROLES: JSON array of default ES roles
        ES_ROLE_PASSTHROUGH: Pass unmapped roles through (true/false)
        ES_ROLE_ALWAYS_INCLUDE: JSON array of roles always added
        ES_ROLE_PREFIX_STRIP: Prefix to strip from provider roles
        ES_ROLE_SUFFIX_STRIP: Suffix to strip from provider roles
        ES_ROLE_PREFIX_ADD: Prefix to add to mapped roles
        ES_ROLE_CASE_SENSITIVE: Case-sensitive matching (true/false)

        # Kibana
        KIBANA_URL: Internal Kibana URL
        KIBANA_PUBLIC_URL: Public Kibana URL
        KIBANA_BASE_PATH: Kibana base path

        # Proxy
        PUBLIC_URL: Public URL of this proxy
        SESSION_SECRET: Flask session secret key
        LOG_LEVEL: Logging level
        SSL_VERIFY: Verify SSL certificates (true/false)

    Returns:
        Populated Config object
    """
    ssl_verify = _parse_bool(os.environ.get("SSL_VERIFY", "true"))
    provider_type = os.environ.get("OIDC_PROVIDER", "keycloak").lower()

    # Default role mapping
    default_role_mapping = {
        "admin": ["superuser"],
        "kibana_admin": ["kibana_admin", "monitoring_user"],
        "editor": ["editor"],
        "viewer": ["viewer"],
    }

    config = Config(
        provider=ProviderConfig(
            type=provider_type,
            client_id=os.environ.get("OIDC_CLIENT_ID", ""),
            client_secret=os.environ.get("OIDC_CLIENT_SECRET", ""),
            # Keycloak
            server_url=os.environ.get("KEYCLOAK_SERVER_URL", ""),
            realm=os.environ.get("KEYCLOAK_REALM", ""),
            admin_client_id=os.environ.get("KEYCLOAK_ADMIN_CLIENT_ID", ""),
            admin_client_secret=os.environ.get("KEYCLOAK_ADMIN_CLIENT_SECRET", ""),
            # Azure
            tenant_id=os.environ.get("AZURE_TENANT_ID", ""),
            use_groups=_parse_bool(os.environ.get("AZURE_USE_GROUPS", "false")),
            group_to_role_mapping=_parse_json(
                os.environ.get("AZURE_GROUP_ROLE_MAPPING", ""), {}
            ),
            # GitHub
            org_name=os.environ.get("GITHUB_ORG", ""),
            allowed_orgs=_parse_json(
                os.environ.get("GITHUB_ALLOWED_ORGS", ""), []
            ),
            team_to_role_mapping=_parse_json(
                os.environ.get("GITHUB_TEAM_ROLE_MAPPING", ""), {}
            ),
            # Generic OIDC
            issuer_url=os.environ.get("OIDC_ISSUER_URL", ""),
            scopes=os.environ.get("OIDC_SCOPES", "openid profile email"),
            username_claim=os.environ.get("OIDC_USERNAME_CLAIM", "preferred_username"),
            roles_claim=os.environ.get("OIDC_ROLES_CLAIM", "roles"),
            logout_url=os.environ.get("OIDC_LOGOUT_URL", ""),
            verify_ssl=ssl_verify,
        ),
        elasticsearch=ElasticsearchConfig(
            url=os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200"),
            admin_user=os.environ.get("ES_ADMIN_USER", "elastic"),
            admin_password=os.environ.get("ES_ADMIN_PASSWORD", ""),
            verify_ssl=ssl_verify,
            # Role mapping
            role_mapping=_parse_json(
                os.environ.get("ES_ROLE_MAPPING", ""), default_role_mapping
            ),
            default_roles=_parse_json(
                os.environ.get("ES_DEFAULT_ROLES", ""), ["viewer"]
            ),
            role_passthrough=_parse_bool(
                os.environ.get("ES_ROLE_PASSTHROUGH", "false")
            ),
            role_always_include=_parse_json(
                os.environ.get("ES_ROLE_ALWAYS_INCLUDE", ""), []
            ),
            role_prefix_strip=os.environ.get("ES_ROLE_PREFIX_STRIP", ""),
            role_suffix_strip=os.environ.get("ES_ROLE_SUFFIX_STRIP", ""),
            role_prefix_add=os.environ.get("ES_ROLE_PREFIX_ADD", ""),
            role_case_sensitive=_parse_bool(
                os.environ.get("ES_ROLE_CASE_SENSITIVE", "false")
            ),
        ),
        kibana=KibanaConfig(
            internal_url=os.environ.get("KIBANA_URL", "http://localhost:5601"),
            public_url=os.environ.get("KIBANA_PUBLIC_URL", "http://localhost:5601"),
            base_path=os.environ.get("KIBANA_BASE_PATH", ""),
            verify_ssl=ssl_verify,
        ),
        proxy=ProxyConfig(
            public_url=os.environ.get("PUBLIC_URL", "http://localhost:3000"),
            session_secret=os.environ.get("SESSION_SECRET", "change-me-in-production"),
            log_level=os.environ.get("LOG_LEVEL", "INFO"),
        ),
    )

    return config
