"""
Kibana SSO Proxy Application Package.

This package provides SSO authentication for Kibana using OIDC providers.
"""

from app.main import app, create_app

__all__ = ["app", "create_app"]
