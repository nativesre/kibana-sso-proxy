# Contributing to Kibana SSO Proxy

Thank you for your interest in contributing to Kibana SSO Proxy! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We welcome contributors of all experience levels.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/nativesre/kibana-sso-proxy/issues)
2. If not, create a new issue with:
   - A clear, descriptive title
   - Steps to reproduce the bug
   - Expected vs actual behavior
   - Environment details (OS, Python version, provider type)
   - Relevant logs (with sensitive data redacted)

### Suggesting Features

1. Check existing issues for similar suggestions
2. Create a new issue with:
   - Clear description of the feature
   - Use case / motivation
   - Proposed implementation (if applicable)

### Submitting Changes

1. **Fork** the repository
2. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```
3. **Make your changes** following the coding standards below
4. **Test your changes** thoroughly
5. **Commit** with clear messages:
   ```bash
   git commit -m "Add support for XYZ provider"
   ```
6. **Push** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Create a Pull Request** against the `main` branch

## Development Setup

```bash
# Clone your fork
git clone https://github.com/nativesre/kibana-sso-proxy.git
cd kibana-sso-proxy

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-cov black isort mypy

# Run the application
python app.py
```

## Coding Standards

### Python Style

- Follow [PEP 8](https://pep8.org/) style guide
- Use type hints for function signatures
- Maximum line length: 100 characters
- Use meaningful variable and function names

### Code Formatting

We use `black` and `isort` for consistent formatting:

```bash
# Format code
black .
isort .

# Check formatting
black --check .
isort --check .
```

### Type Checking

```bash
mypy --ignore-missing-imports .
```

### Documentation

- Add docstrings to all public functions and classes
- Update README.md if adding new features
- Include inline comments for complex logic

### Example Code Style

```python
"""
Module description here.
"""

from typing import Optional, List

from utils.logger import logger


class MyService:
    """
    Brief description of the service.

    Attributes:
        config: Configuration dictionary
    """

    def __init__(self, config: dict):
        """
        Initialize the service.

        Args:
            config: Configuration dictionary with required keys
        """
        self.config = config

    def process_data(self, items: List[str], limit: Optional[int] = None) -> dict:
        """
        Process a list of items.

        Args:
            items: List of items to process
            limit: Optional maximum number of items

        Returns:
            Dictionary with processing results

        Raises:
            ValueError: If items list is empty
        """
        if not items:
            raise ValueError("Items list cannot be empty")

        result = {"processed": len(items)}
        logger.info(f"Processed {len(items)} items")
        return result
```

## Adding a New Provider

To add support for a new OIDC provider:

1. Create a new file in `providers/` (e.g., `providers/okta.py`)
2. Inherit from `OIDCProvider` base class
3. Implement all abstract methods:
   - `name` property
   - `_validate_config()`
   - `register_oauth()`
   - `get_authorization_url_params()`
   - `extract_user_info()`
   - `extract_roles()`
   - `get_logout_url()`
4. Register the provider in `providers/__init__.py`
5. Add configuration options to `config/settings.py`
6. Update README.md with setup instructions
7. Add tests

Example:

```python
# providers/okta.py
from providers.base import OIDCProvider, UserInfo

class OktaProvider(OIDCProvider):
    @property
    def name(self) -> str:
        return "okta"

    def _validate_config(self) -> None:
        self._require_config("domain", "client_id", "client_secret")

    # ... implement other methods
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_providers.py
```

### Writing Tests

- Place tests in the `tests/` directory
- Name test files `test_*.py`
- Use descriptive test function names
- Include both positive and negative test cases

```python
# tests/test_elasticsearch.py
import pytest
from services.elasticsearch import ElasticsearchService

def test_map_roles_with_valid_mapping():
    """Test role mapping with valid provider roles."""
    config = ElasticsearchConfig(
        role_mapping={"admin": ["superuser"]},
        default_roles=["viewer"]
    )
    service = ElasticsearchService(config)

    result = service.map_roles(["admin"])

    assert "superuser" in result

def test_map_roles_with_unknown_role():
    """Test that unknown roles get default mapping."""
    config = ElasticsearchConfig(
        role_mapping={},
        default_roles=["viewer"]
    )
    service = ElasticsearchService(config)

    result = service.map_roles(["unknown_role"])

    assert result == ["viewer"]
```

## Pull Request Guidelines

### Before Submitting

- [ ] Code follows the style guidelines
- [ ] Tests pass locally
- [ ] New code has test coverage
- [ ] Documentation is updated
- [ ] Commit messages are clear

### PR Description

Include:
- Summary of changes
- Related issue number (if applicable)
- Testing performed
- Screenshots (for UI changes)

### Review Process

1. Automated checks must pass
2. At least one maintainer review required
3. Address review feedback promptly
4. Squash commits if requested

## Release Process

Releases are managed by maintainers:

1. Update version in `helm-chart/Chart.yaml`
2. Update CHANGELOG.md
3. Create a git tag
4. GitHub Actions builds and publishes Docker image

## Questions?

- Open a [Discussion](https://github.com/nativesre/kibana-sso-proxy/discussions)
- Check existing issues and documentation
- Be patient - maintainers are volunteers

Thank you for contributing!
