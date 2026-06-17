"""Runtime settings, loaded from environment variables (and an optional .env).

Secrets are never hard-coded: the Security Center host and API keys come from the
environment. We authenticate with API keys (``x-apikey`` header) and never create
a session token.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

try:  # python-dotenv is a hard dependency, but stay importable without it.
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    def load_dotenv(*_args, **_kwargs) -> bool:
        return False


@dataclass(slots=True)
class Settings:
    """Resolved configuration for the Tenable.sc client."""

    host: str
    access_key: str
    secret_key: str
    # TLS verification. Tenable.sc often uses a self-signed cert, so this defaults
    # to False; set SC_VERIFY=true (or a CA bundle path) for a trusted cert.
    verify: bool | str = False
    # When False (default), the side-effecting write tools are not registered.
    enable_writes: bool = False


def load_settings() -> Settings:
    """Build :class:`Settings` from the environment.

    Missing credentials are tolerated here so the server can still start and
    report a clear error on the first tool call (rather than failing to launch).
    """
    load_dotenv()

    verify_raw = os.getenv("SC_VERIFY", "").strip()
    if verify_raw.lower() in {"1", "true", "yes", "on"}:
        verify: bool | str = True
    elif verify_raw.lower() in {"", "0", "false", "no", "off"}:
        verify = False
    else:
        verify = verify_raw  # treat as a path to a CA bundle

    return Settings(
        host=os.getenv("SC_HOST", "").strip(),
        access_key=os.getenv("SC_ACCESS_KEY", "").strip(),
        secret_key=os.getenv("SC_SECRET_KEY", "").strip(),
        verify=verify,
        enable_writes=os.getenv("SC_ENABLE_WRITES", "").strip().lower()
        in {"1", "true", "yes", "on"},
    )
