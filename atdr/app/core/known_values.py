"""Values that ship in ATDR's own files, so anyone can know them.

Standard library only: CI's repository scan (the security-controls job) imports this before any of ATDR's packages
are installed. The settings checks, both doctors and the repository scan use these same sets.
"""

# The default JWT secrets and the classroom demo passwords.
KNOWN_DEFAULT_SECRETS = frozenset({"change-this-dev-secret", "change-this-secret-before-production"})
KNOWN_DEMO_PASSWORDS = frozenset({"admin123", "analyst123", "password", "changeme"})


def is_documentation_placeholder(value: str) -> bool:
    clean = value.strip().lower()
    return not clean or any(marker in clean for marker in ("replace-during", "replace-with", "change-this", "placeholder"))
