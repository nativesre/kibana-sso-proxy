---
layout: default
title: Kibana SSO Proxy
---

# Kibana SSO Proxy

**Enable Single Sign-On for Kibana without upgrading to Platinum — works with Keycloak, Azure AD, GitHub, and any OIDC provider.**

[Get Started](#quick-start) | [GitHub](https://github.com/nativesre/kibana-sso-proxy) | [Helm Chart](#helm-installation)

---

## The Problem

If you've ever tried to add SSO to Kibana, you've hit the same wall: *"This feature requires a Platinum license."*

Elasticsearch's free Basic license includes native user authentication, but there's no way to connect it to your identity provider. Want to use Keycloak? Azure AD? Okta? You need Platinum.

For startups, side projects, and cost-conscious teams, that's not an option.

## The Solution

**Kibana SSO Proxy** is a lightweight, open-source authentication proxy that brings SSO to Kibana's free tier.

It sits between your users and Kibana, handling the entire OAuth/OIDC flow:

1. Authenticates users against your identity provider
2. Creates/updates matching users in Elasticsearch's native realm
3. Maps IdP roles to Elasticsearch roles
4. Obtains a Kibana session and redirects the user

```
┌──────────┐     ┌───────────────┐     ┌─────────────────┐
│  Browser │────▶│  SSO Proxy    │────▶│  OIDC Provider  │
│          │     │   :3000       │     │  (Keycloak,     │
└──────────┘     └───────┬───────┘     │   Azure AD,     │
                        │             │   GitHub, etc.) │
                        │             └─────────────────┘
                        │
         ┌──────────────┴──────────────┐
         │                             │
         ▼                             ▼
   ┌───────────┐               ┌───────────────┐
   │  Kibana   │◀─────────────▶│ Elasticsearch │
   │   :5601   │               │    :9200      │
   └───────────┘               └───────────────┘
```

---

## Features

### Multi-Provider Support

| Provider | Features |
|----------|----------|
| **Keycloak** | Full support with password storage in user attributes |
| **Azure AD** | App roles and group-based access |
| **GitHub** | Organization and team-based permissions |
| **Generic OIDC** | Works with Okta, Auth0, or any compliant provider |

### Flexible Role Mapping

```bash
# Direct mapping
ES_ROLE_MAPPING='{"admin": ["superuser"], "dev": ["developer"]}'

# Regex patterns
ES_ROLE_MAPPING='{"regex:team-.*": ["team_member"]}'

# Passthrough mode
ES_ROLE_PASSTHROUGH=true
```

### Kubernetes Ready

Deploy with Helm in minutes.

### Secure by Default

- Non-root container
- Minimal image
- SSL verification enabled
- Secure session cookies

---

## Quick Start

### Docker

```bash
docker run -p 3000:3000 \
  -e OIDC_PROVIDER=keycloak \
  -e OIDC_CLIENT_ID=kibana \
  -e OIDC_CLIENT_SECRET=your-secret \
  -e KEYCLOAK_SERVER_URL=https://keycloak.example.com \
  -e KEYCLOAK_REALM=master \
  -e ELASTICSEARCH_URL=http://elasticsearch:9200 \
  -e ES_ADMIN_PASSWORD=your-es-password \
  -e KIBANA_URL=http://kibana:5601 \
  -e PUBLIC_URL=https://kibana.example.com \
  -e SESSION_SECRET=$(openssl rand -hex 32) \
  ghcr.io/nativesre/kibana-sso-proxy:latest
```

### Helm Installation

```bash
# Add the repository
helm repo add kibana-sso-proxy https://nativesre.github.io/kibana-sso-proxy
helm repo update

# Install
helm install kibana-sso kibana-sso-proxy/kibana-sso-proxy -f values.yaml
```

Example `values.yaml`:

```yaml
config:
  OIDC_PROVIDER: "keycloak"
  OIDC_CLIENT_ID: "kibana"
  KEYCLOAK_SERVER_URL: "https://keycloak.example.com"
  KEYCLOAK_REALM: "master"
  ELASTICSEARCH_URL: "http://elasticsearch:9200"
  KIBANA_URL: "http://kibana:5601"
  PUBLIC_URL: "https://kibana.example.com"

secrets:
  OIDC_CLIENT_SECRET: "your-client-secret"
  ES_ADMIN_PASSWORD: "your-es-password"
  SESSION_SECRET: "generate-a-random-secret"

ingress:
  enabled: true
  hosts:
    - host: kibana.example.com
      paths:
        - path: /
```

---

## Provider Setup

### Keycloak

1. Create a client in your realm with **Client authentication: ON**
2. Set redirect URI: `https://your-proxy-url/*`
3. Create client roles and assign to users

```bash
OIDC_PROVIDER=keycloak
KEYCLOAK_SERVER_URL=https://keycloak.example.com
KEYCLOAK_REALM=master
OIDC_CLIENT_ID=kibana
OIDC_CLIENT_SECRET=your-secret
```

### Azure AD

1. Register an application in Azure AD
2. Add redirect URI: `https://your-proxy-url/auth/callback`
3. Configure app roles or use group claims

```bash
OIDC_PROVIDER=azure
AZURE_TENANT_ID=your-tenant-id
OIDC_CLIENT_ID=your-app-id
OIDC_CLIENT_SECRET=your-secret
AZURE_USE_GROUPS=true
```

### GitHub

1. Create an OAuth App in GitHub settings
2. Set callback URL: `https://your-proxy-url/auth/callback`

```bash
OIDC_PROVIDER=github
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-secret
GITHUB_ORG=your-organization  # Optional: restrict to org members
```

### Generic OIDC

Works with any OpenID Connect compliant provider:

```bash
OIDC_PROVIDER=generic
OIDC_ISSUER_URL=https://your-idp.example.com
OIDC_CLIENT_ID=kibana
OIDC_CLIENT_SECRET=your-secret
```

---

## Role Mapping

The proxy includes a powerful role mapper to translate IdP roles to Elasticsearch roles.

### Configuration Options

| Variable | Description | Default |
|----------|-------------|---------|
| `ES_ROLE_MAPPING` | JSON mapping of IdP roles to ES roles | See below |
| `ES_DEFAULT_ROLES` | Roles when no mapping matches | `["viewer"]` |
| `ES_ROLE_PASSTHROUGH` | Pass unmapped roles directly | `false` |
| `ES_ROLE_ALWAYS_INCLUDE` | Roles always added | `[]` |
| `ES_ROLE_PREFIX_STRIP` | Strip prefix from IdP roles | `""` |
| `ES_ROLE_PREFIX_ADD` | Add prefix to ES roles | `""` |

### Examples

**Direct Mapping:**
```bash
ES_ROLE_MAPPING='{"admin": ["superuser"], "editor": ["editor"], "viewer": ["viewer"]}'
```

**Regex Patterns:**
```bash
ES_ROLE_MAPPING='{"regex:team-.*": ["team_member"], "regex:admin-.*": ["superuser"]}'
```

**Prefix Transformation:**
```bash
# IdP role "myapp_admin" → ES role "sso_admin"
ES_ROLE_PREFIX_STRIP="myapp_"
ES_ROLE_PREFIX_ADD="sso_"
ES_ROLE_PASSTHROUGH=true
```

**Always Include:**
```bash
# Everyone gets kibana_user role
ES_ROLE_ALWAYS_INCLUDE='["kibana_user"]'
```

---

## Environment Variables

### Common Settings

| Variable | Description | Required |
|----------|-------------|----------|
| `OIDC_PROVIDER` | Provider: `keycloak`, `azure`, `github`, `generic` | Yes |
| `OIDC_CLIENT_ID` | OAuth client ID | Yes |
| `OIDC_CLIENT_SECRET` | OAuth client secret | Yes |
| `ELASTICSEARCH_URL` | Elasticsearch URL | Yes |
| `ES_ADMIN_PASSWORD` | Elasticsearch admin password | Yes |
| `KIBANA_URL` | Internal Kibana URL | Yes |
| `PUBLIC_URL` | Public URL of this proxy | Yes |
| `SESSION_SECRET` | Flask session secret | Yes |

### Provider-Specific

**Keycloak:**
- `KEYCLOAK_SERVER_URL` - Keycloak server URL
- `KEYCLOAK_REALM` - Realm name

**Azure AD:**
- `AZURE_TENANT_ID` - Azure AD tenant ID
- `AZURE_USE_GROUPS` - Use group claims for roles

**GitHub:**
- `GITHUB_ORG` - Required organization membership

**Generic OIDC:**
- `OIDC_ISSUER_URL` - OIDC issuer URL
- `OIDC_SCOPES` - OAuth scopes
- `OIDC_USERNAME_CLAIM` - Claim for username
- `OIDC_ROLES_CLAIM` - Claim for roles

---

## Why Not...

| Alternative | Limitation |
|-------------|------------|
| **Elasticsearch OIDC Realm** | Requires Platinum license |
| **Nginx auth_request** | Doesn't provision Elasticsearch users |
| **OAuth2 Proxy** | No ES user creation or Kibana session handling |
| **VPN access** | No audit trail of who did what |

---

## Links

- **GitHub:** [github.com/nativesre/kibana-sso-proxy](https://github.com/nativesre/kibana-sso-proxy)
- **Docker Image:** `ghcr.io/nativesre/kibana-sso-proxy`
- **Helm Repository:** `https://nativesre.github.io/kibana-sso-proxy`

---

## License

GPL-3.0 License - Free and open source.

---

<p align="center">
  <a href="https://github.com/nativesre/kibana-sso-proxy">Star on GitHub</a>
</p>
