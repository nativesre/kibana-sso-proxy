"""
Structured JSON logging for Kibana SSO Proxy.

Outputs logs in a format compatible with Elasticsearch/Kibana ingestion.
"""

import logging
import json
import os
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """
    Custom formatter that outputs JSON structured logs.

    Output format is compatible with Elasticsearch Common Schema (ECS).
    """

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "@timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": "kibana-sso-proxy",
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields if present
        if hasattr(record, "extra"):
            log_data.update(record.extra)

        return json.dumps(log_data, default=str)


def setup_logger(name: str = "kibana-sso-proxy", level: str | None = None) -> logging.Logger:
    """
    Set up and return a configured logger.

    Args:
        name: Logger name
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        Configured logger instance
    """
    log_level = level or os.environ.get("LOG_LEVEL", "INFO").upper()

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()

    # Create console handler with JSON formatter
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)

    # Prevent propagation to root logger
    logger.propagate = False

    return logger


# Default logger instance
logger = setup_logger()
