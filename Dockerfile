# =============================================================================
# Kibana SSO Proxy - Docker Image
# =============================================================================
# Multi-stage build for minimal production image
# =============================================================================

# Build stage - install dependencies
FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# =============================================================================
# Production stage - minimal runtime image
# =============================================================================
FROM python:3.12-slim

# Labels
LABEL org.opencontainers.image.title="Kibana SSO Proxy"
LABEL org.opencontainers.image.description="SSO authentication proxy for Kibana using OIDC providers"
LABEL org.opencontainers.image.source="https://github.com/nativesre/kibana-sso-proxy"
LABEL org.opencontainers.image.licenses="MIT"

# Create non-root user
RUN groupadd --gid 1000 appgroup && \
    useradd --uid 1000 --gid appgroup --shell /bin/bash --create-home appuser

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY --chown=appuser:appgroup app.py .
COPY --chown=appuser:appgroup config/ ./config/
COPY --chown=appuser:appgroup providers/ ./providers/
COPY --chown=appuser:appgroup services/ ./services/
COPY --chown=appuser:appgroup utils/ ./utils/

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:3000/health')" || exit 1

# Run with gunicorn
CMD ["gunicorn", \
     "--bind", "0.0.0.0:3000", \
     "--workers", "2", \
     "--threads", "4", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--capture-output", \
     "app:app"]
