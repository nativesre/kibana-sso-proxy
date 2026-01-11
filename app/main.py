"""
Kibana SSO Proxy - Main Application

A lightweight authentication proxy that enables SSO for Kibana
using any OIDC-compliant identity provider.
"""

import os
import sys
import uuid
import urllib3

# Disable SSL warnings if configured
if os.environ.get("SSL_VERIFY", "true").lower() == "false":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from flask import Flask, redirect, request, session, jsonify, make_response
from authlib.integrations.flask_client import OAuth

from app.config import load_config
from app.providers import get_provider
from app.services import ElasticsearchService, KibanaService
from app.utils.logger import logger, setup_logger


# =============================================================================
# Application Setup
# =============================================================================

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)

    # Load configuration
    config = load_config()

    # Validate configuration
    errors = config.validate()
    if errors:
        for error in errors:
            logger.error(f"Configuration error: {error}")
        logger.error("Please check your environment variables and try again.")
        sys.exit(1)

    # Reconfigure logger with configured level
    setup_logger(level=config.proxy.log_level)

    # Flask configuration
    app.secret_key = config.proxy.session_secret
    app.config["config"] = config

    # Initialize OIDC provider
    provider_class = get_provider(config.provider.type)
    provider = provider_class(config.provider.to_dict())
    app.config["provider"] = provider

    # Initialize OAuth
    oauth = OAuth(app)
    provider.register_oauth(oauth)
    app.config["oauth"] = oauth

    # Initialize services
    app.config["es_service"] = ElasticsearchService(config.elasticsearch)
    app.config["kibana_service"] = KibanaService(config.kibana)

    # Register routes
    register_routes(app)

    return app


def register_routes(app: Flask):
    """Register all application routes."""

    @app.route("/health")
    def health():
        """Health check endpoint for Kubernetes probes."""
        return jsonify({"status": "ok"})

    @app.route("/login")
    def login():
        """Initiate SSO login flow."""
        config = app.config["config"]
        oauth = app.config["oauth"]
        provider = app.config["provider"]
        kibana_service = app.config["kibana_service"]

        # Capture the 'next' parameter for post-login redirect
        next_path = request.args.get("next")
        if next_path:
            session["redirect_after_login"] = kibana_service.build_redirect_url(next_path)
        elif "redirect_after_login" not in session:
            session["redirect_after_login"] = kibana_service.get_home_url()

        # Generate nonce for CSRF protection
        nonce = uuid.uuid4().hex
        session["oauth_nonce"] = nonce

        # Build authorization URL
        redirect_uri = f"{config.proxy.public_url}/auth/callback"
        extra_params = provider.get_authorization_url_params()

        return oauth.oidc.authorize_redirect(redirect_uri, nonce=nonce, **extra_params)

    @app.route("/auth/callback")
    def callback():
        """Handle OAuth callback and complete authentication."""
        config = app.config["config"]
        oauth = app.config["oauth"]
        provider = app.config["provider"]
        es_service = app.config["es_service"]
        kibana_service = app.config["kibana_service"]

        try:
            # Verify OAuth nonce (CSRF protection)
            stored_nonce = session.pop("oauth_nonce", None)
            if not stored_nonce:
                logger.error("No OAuth nonce in session - possible CSRF attack")
                return jsonify({"error": "Invalid session state"}), 401

            # Exchange authorization code for tokens
            token = oauth.oidc.authorize_access_token()
            if not token or not token.get("access_token"):
                logger.error("No access token received from provider")
                return jsonify({"error": "Authentication failed"}), 401

            # Get user info (some providers need this, others have it in token)
            try:
                userinfo = oauth.oidc.userinfo(token=token)
            except Exception:
                userinfo = None  # Some providers don't have userinfo endpoint

            # Extract standardized user info
            user_info = provider.extract_user_info(token, userinfo)
            logger.info(f"User authenticated: {user_info.username}, roles: {user_info.roles}")

            # Determine password for Elasticsearch
            password = None
            force_password = False

            # Try to get stored password if provider supports it
            if provider.supports_password_storage():
                password = provider.get_stored_password(user_info.user_id)

            # Generate new password if not found
            if not password:
                password = str(uuid.uuid4())
                force_password = True

            # Sync user to Elasticsearch
            try:
                es_username, password_updated = es_service.sync_user(
                    username=user_info.username,
                    password=password,
                    provider_roles=user_info.roles,
                    email=user_info.email,
                    full_name=user_info.full_name,
                    force_password=force_password,
                )
            except Exception as e:
                logger.error(f"Failed to sync user to Elasticsearch: {e}")
                return jsonify({"error": "Failed to create user"}), 500

            # Store password in provider if it was newly generated
            if force_password and provider.supports_password_storage():
                provider.store_password(user_info.user_id, password)
                logger.info(f"Stored new password for user {user_info.username}")

            # Get Kibana session
            kibana_sid = kibana_service.get_session(es_username, password)
            if not kibana_sid:
                logger.error("Failed to obtain Kibana session")
                return jsonify({"error": "Failed to create session"}), 500

            # Store user info in session
            session["user"] = {
                "username": user_info.username,
                "provider_user_id": user_info.user_id,
                "email": user_info.email,
                "full_name": user_info.full_name,
                "roles": es_service.map_roles(user_info.roles),
            }

            # Get redirect URL
            redirect_url = session.pop("redirect_after_login", kibana_service.get_home_url())

            # Create response with Kibana session cookie
            response = make_response(redirect(redirect_url))
            response.set_cookie(
                "sid",
                kibana_sid,
                httponly=True,
                path=kibana_service.get_cookie_path(),
            )

            logger.info(f"SSO complete for {user_info.username}, redirecting to: {redirect_url}")
            return response

        except Exception as e:
            logger.error(f"Authentication callback error: {e}", exc_info=True)
            return jsonify({"error": "Authentication failed"}), 500

    @app.route("/auth/logout")
    def logout():
        """Log out user and redirect to provider logout."""
        config = app.config["config"]
        provider = app.config["provider"]
        kibana_service = app.config["kibana_service"]

        # Clear session
        session.clear()

        # Get provider logout URL
        logout_url = provider.get_logout_url(config.proxy.public_url)

        # Create response
        if logout_url:
            response = make_response(redirect(logout_url))
        else:
            # Provider doesn't support logout, redirect to login
            response = make_response(redirect(f"{config.proxy.public_url}/login"))

        # Clear Kibana session cookie
        response.delete_cookie("sid", path=kibana_service.get_cookie_path())

        return response

    @app.route("/auth/user")
    def user_info():
        """Get current user information."""
        if "user" in session:
            return jsonify(session["user"])
        return jsonify({"error": "Not authenticated"}), 401


# =============================================================================
# Application Entry Point
# =============================================================================

app = create_app()

if __name__ == "__main__":
    config = app.config["config"]
    provider = app.config["provider"]

    logger.info("=" * 60)
    logger.info("Kibana SSO Proxy")
    logger.info("=" * 60)
    logger.info(f"  Provider: {provider.name}")
    logger.info(f"  Kibana: {config.kibana.public_url}")
    logger.info(f"  Proxy URL: {config.proxy.public_url}")
    logger.info("=" * 60)

    app.run(host="0.0.0.0", port=3000, debug=True)
