# Kibana SSO Proxy

A lightweight authentication proxy that enables Single Sign-On (SSO) for Kibana using any OIDC-compliant identity provider. Works with Elasticsearch's **free/basic license**.

## Features

- **Multiple Identity Providers**: Supports Keycloak, Azure AD, GitHub, and any generic OIDC provider
- **Automatic User Sync**: Creates and updates Elasticsearch users from your identity provider
- **Role Mapping**: Flexible mapping from IdP roles/groups to Elasticsearch roles
- **Session Management**: Handles Kibana session creation and renewal
- **Kubernetes Ready**: Includes Helm chart for easy deployment
- **Secure by Default**: Non-root container, minimal dependencies, structured logging

## Architecture

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

### Authentication Flow

1. User visits the proxy (`/login`)
2. Proxy redirects to identity provider for authentication
3. After login, proxy:
   - Extracts user info and roles from the IdP token
   - Creates/updates user in Elasticsearch native realm
   - Obtains Kibana session cookie
   - Sets cookie and redirects user to Kibana
4. User accesses Kibana directly with valid session

## Quick Start

### Using Docker

```bash
# Build the image
docker build -t kibana-sso-proxy .

# Run with environment variables
docker run -p 3000:3000 \
  -e OIDC_PROVIDER=keycloak \
  -e OIDC_CLIENT_ID=kibana \
  -e OIDC_CLIENT_SECRET=your-secret \
  -e KEYCLOAK_SERVER_URL=https://keycloak.example.com \
  -e KEYCLOAK_REALM=master \
  -e ELASTICSEARCH_URL=http://elasticsearch:9200 \
  -e ES_ADMIN_PASSWORD=your-es-password \
  -e KIBANA_URL=http://kibana:5601 \
  -e KIBANA_PUBLIC_URL=https://kibana.example.com \
  -e PUBLIC_URL=https://kibana.example.com \
  -e SESSION_SECRET=$(openssl rand -hex 32) \
  kibana-sso-proxy
```

### Using Helm

```bash
# Add the Helm repository
helm repo add kibana-sso-proxy https://nativesre.github.io/kibana-sso-proxy
helm repo update

# Create your values file
cat > my-values.yaml <<EOF
config:
  OIDC_PROVIDER: "keycloak"
  OIDC_CLIENT_ID: "kibana"
  KEYCLOAK_SERVER_URL: "https://keycloak.example.com"
  KEYCLOAK_REALM: "master"
  ELASTICSEARCH_URL: "http://elasticsearch:9200"
  ES_ADMIN_USER: "elastic"
  KIBANA_URL: "http://kibana:5601"
  KIBANA_PUBLIC_URL: "https://kibana.example.com"
  PUBLIC_URL: "https://kibana.example.com"

secrets:
  OIDC_CLIENT_SECRET: "your-client-secret"
  ES_ADMIN_PASSWORD: "your-es-password"
  SESSION_SECRET: "your-random-secret"
EOF

# Install from repo
helm install kibana-sso kibana-sso-proxy/kibana-sso-proxy -f my-values.yaml

# Or install from local chart
helm install kibana-sso ./helm-chart -f my-values.yaml
```

## Configuration

### Environment Variables

#### Provider Selection

| Variable | Description | Default |
|----------|-------------|---------|
| `OIDC_PROVIDER` | Provider type: `keycloak`, `azure`, `github`, `generic` | `keycloak` |

#### Common OIDC Settings

| Variable | Description | Required |
|----------|-------------|----------|
| `OIDC_CLIENT_ID` | OAuth client ID | Yes |
| `OIDC_CLIENT_SECRET` | OAuth client secret | Yes |

#### Keycloak Settings

| Variable | Description | Required |
|----------|-------------|----------|
| `KEYCLOAK_SERVER_URL` | Keycloak server URL | Yes (for Keycloak) |
| `KEYCLOAK_REALM` | Keycloak realm name | Yes (for Keycloak) |

#### Azure AD Settings

| Variable | Description | Required |
|----------|-------------|----------|
| `AZURE_TENANT_ID` | Azure AD tenant ID | Yes (for Azure) |
| `AZURE_USE_GROUPS` | Use group claims for roles | No |
| `AZURE_GROUP_ROLE_MAPPING` | JSON mapping of group IDs to roles | No |

#### GitHub Settings

| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_ORG` | Required GitHub organization | No |
| `GITHUB_TEAM_ROLE_MAPPING` | JSON mapping of team slugs to roles | No |

#### Generic OIDC Settings

| Variable | Description | Required |
|----------|-------------|----------|
| `OIDC_ISSUER_URL` | OIDC issuer URL | Yes (for generic) |
| `OIDC_SCOPES` | Space-separated scopes | No |
| `OIDC_USERNAME_CLAIM` | Claim for username | No |
| `OIDC_ROLES_CLAIM` | Claim for roles | No |

#### Elasticsearch Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `ELASTICSEARCH_URL` | Elasticsearch URL | `http://localhost:9200` |
| `ES_ADMIN_USER` | Admin username | `elastic` |
| `ES_ADMIN_PASSWORD` | Admin password | Required |

See [Role Mapping](#role-mapping) section for role configuration options.

#### Kibana Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `KIBANA_URL` | Internal Kibana URL | `http://localhost:5601` |
| `KIBANA_PUBLIC_URL` | Public Kibana URL | `http://localhost:5601` |
| `KIBANA_BASE_PATH` | Kibana base path | `` |

#### Proxy Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `PUBLIC_URL` | Public URL of this proxy | `http://localhost:3000` |
| `SESSION_SECRET` | Flask session secret | Required |
| `LOG_LEVEL` | Logging level | `INFO` |
| `SSL_VERIFY` | Verify SSL certificates | `true` |

### Role Mapping

The proxy provides flexible mapping from OIDC provider roles to Elasticsearch roles with multiple strategies.

#### Configuration Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ES_ROLE_MAPPING` | JSON mapping of provider roles to ES roles | See below |
| `ES_DEFAULT_ROLES` | JSON array of roles when no mapping matches | `["viewer"]` |
| `ES_ROLE_PASSTHROUGH` | Pass unmapped roles directly to ES | `false` |
| `ES_ROLE_ALWAYS_INCLUDE` | JSON array of roles always added | `[]` |
| `ES_ROLE_PREFIX_STRIP` | Prefix to strip from provider roles | `` |
| `ES_ROLE_SUFFIX_STRIP` | Suffix to strip from provider roles | `` |
| `ES_ROLE_PREFIX_ADD` | Prefix to add to all mapped roles | `` |
| `ES_ROLE_CASE_SENSITIVE` | Case-sensitive role matching | `false` |

#### Mapping Process

The role mapper processes provider roles in this order:

1. **Strip prefix/suffix** - Remove configured affixes from provider roles
2. **Apply direct mapping** - Match against `ES_ROLE_MAPPING`
3. **Apply regex mapping** - Match keys prefixed with `regex:`
4. **Passthrough** - If enabled, unmapped roles pass through directly
5. **Add prefix** - Apply `ES_ROLE_PREFIX_ADD` to all mapped roles
6. **Always include** - Add `ES_ROLE_ALWAYS_INCLUDE` roles
7. **Default fallback** - Use `ES_DEFAULT_ROLES` if no roles mapped

#### Basic Example

```bash
# Direct mapping
ES_ROLE_MAPPING='{"admin": ["superuser"], "editor": ["editor"], "viewer": ["viewer"]}'
ES_DEFAULT_ROLES='["viewer"]'
```

#### Advanced Examples

**Regex Pattern Matching:**
```bash
# Map any role starting with "team-" to team_member
ES_ROLE_MAPPING='{
  "admin": ["superuser"],
  "regex:team-.*": ["team_member"],
  "regex:project-[0-9]+": ["project_user"]
}'
```

**Role Passthrough (when IdP roles match ES roles):**
```bash
# Pass IdP roles directly to ES, always ensure kibana_user access
ES_ROLE_PASSTHROUGH=true
ES_ROLE_ALWAYS_INCLUDE='["kibana_user"]'
```

**Prefix/Suffix Transformation:**
```bash
# Strip "app_" prefix from IdP roles, add "sso_" prefix to ES roles
# IdP role "app_admin" -> ES role "sso_admin"
ES_ROLE_PREFIX_STRIP="app_"
ES_ROLE_PREFIX_ADD="sso_"
ES_ROLE_PASSTHROUGH=true
```

**Complex Mapping:**
```bash
# Combined configuration for enterprise setup
ES_ROLE_MAPPING='{
  "super-admin": ["superuser"],
  "regex:kibana-.*-admin": ["kibana_admin", "monitoring_user"],
  "regex:team-.*": ["viewer"]
}'
ES_DEFAULT_ROLES='["viewer"]'
ES_ROLE_ALWAYS_INCLUDE='["kibana_user"]'
ES_ROLE_PREFIX_STRIP="prefix_"
ES_ROLE_CASE_SENSITIVE=false
```

#### Default Role Mapping

If `ES_ROLE_MAPPING` is not set, the following default is used:

```json
{
  "admin": ["superuser"],
  "kibana_admin": ["kibana_admin", "monitoring_user"],
  "editor": ["editor"],
  "viewer": ["viewer"]
}
```

## Provider Setup

### Keycloak

1. Create a client in your realm:
   - Client type: **OpenID Connect**
   - Client authentication: **ON**
   - Valid redirect URIs: `https://your-proxy-url/*`

2. Create client roles and assign to users

3. Configure:
   ```bash
   OIDC_PROVIDER=keycloak
   OIDC_CLIENT_ID=kibana
   OIDC_CLIENT_SECRET=your-secret
   KEYCLOAK_SERVER_URL=https://keycloak.example.com
   KEYCLOAK_REALM=master
   ```

### Azure AD

1. Register an application in Azure AD
2. Configure redirect URI: `https://your-proxy-url/auth/callback`
3. Configure:
   ```bash
   OIDC_PROVIDER=azure
   OIDC_CLIENT_ID=your-app-id
   OIDC_CLIENT_SECRET=your-secret
   AZURE_TENANT_ID=your-tenant-id
   ```

### GitHub

1. Create an OAuth App in GitHub
2. Set callback URL: `https://your-proxy-url/auth/callback`
3. Configure:
   ```bash
   OIDC_PROVIDER=github
   OIDC_CLIENT_ID=your-client-id
   OIDC_CLIENT_SECRET=your-client-secret
   GITHUB_ORG=your-organization  # Optional
   ```

### Generic OIDC

```bash
OIDC_PROVIDER=generic
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_ISSUER_URL=https://your-idp.example.com
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /login` | Initiate SSO login |
| `GET /auth/callback` | OAuth callback |
| `GET /auth/logout` | Logout and clear session |
| `GET /auth/user` | Get current user info |
| `GET /health` | Health check endpoint |

## Project Structure

```
kibana-sso-proxy/
├── app.py                 # Main Flask application
├── config/
│   └── settings.py        # Configuration management
├── providers/
│   ├── base.py            # Abstract OIDC provider
│   ├── keycloak.py        # Keycloak implementation
│   ├── azure.py           # Azure AD implementation
│   ├── github.py          # GitHub implementation
│   └── generic.py         # Generic OIDC implementation
├── services/
│   ├── elasticsearch.py   # Elasticsearch user management
│   └── kibana.py          # Kibana session management
├── utils/
│   └── logger.py          # Structured logging
├── helm-chart/            # Kubernetes Helm chart
├── Dockerfile
└── requirements.txt
```

## Security

- Always use HTTPS in production
- Generate a strong `SESSION_SECRET`: `openssl rand -hex 32`
- Store secrets in Kubernetes secrets or a secret manager
- The container runs as non-root user (UID 1000)
- SSL verification is enabled by default

## License

GPL-3.0 License - see [LICENSE](LICENSE) file.

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).
