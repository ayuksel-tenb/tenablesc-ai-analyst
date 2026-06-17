"""FastMCP server for Tenable Security Center.

Built on the official MCP SDK's FastMCP (``mcp.server.fastmcp``). Read tools are
always registered; the side-effecting write tools are registered only when
``SC_ENABLE_WRITES`` is enabled. Token / SAML / LDAP / User / Role / Director
endpoints are deliberately never exposed.

Run it::

    tenablesc-ai-analyst-mcp        # or: python -m tenablesc_ai_analyst.server
"""

from __future__ import annotations

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "The 'mcp' package is required. Install it with:  pip install -e ."
    ) from exc

from .client import ScClient
from .config import load_settings
from .tools import register_read_tools, register_write_tools

mcp = FastMCP("tenablesc-ai-analyst")

_settings = load_settings()
_client = ScClient(_settings)
register_read_tools(mcp, _client)
if _settings.enable_writes:
    register_write_tools(mcp, _client)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":  # pragma: no cover
    main()
