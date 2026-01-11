"""
OIDC Provider implementations for Kibana SSO Proxy.

Supported providers:
- Keycloak
- Azure AD (Microsoft Entra ID)
- GitHub
- Generic OIDC (any OpenID Connect compliant provider)
"""

from app.providers.base import OIDCProvider
from app.providers.keycloak import KeycloakProvider
from app.providers.azure import AzureADProvider
from app.providers.github import GitHubProvider
from app.providers.generic import GenericOIDCProvider

__all__ = [
    "OIDCProvider",
    "KeycloakProvider",
    "AzureADProvider",
    "GitHubProvider",
    "GenericOIDCProvider",
]


def get_provider(provider_type: str) -> type[OIDCProvider]:
    """
    Get the provider class for the given provider type.

    Args:
        provider_type: One of 'keycloak', 'azure', 'github', 'generic'

    Returns:
        The provider class (not an instance)

    Raises:
        ValueError: If provider_type is not supported
    """
    providers = {
        "keycloak": KeycloakProvider,
        "azure": AzureADProvider,
        "github": GitHubProvider,
        "generic": GenericOIDCProvider,
    }

    if provider_type not in providers:
        supported = ", ".join(providers.keys())
        raise ValueError(f"Unsupported provider: {provider_type}. Supported: {supported}")

    return providers[provider_type]
