"""A vulnerability-analyst MCP server for Tenable Security Center (Tenable.sc).

Exposes read-focused analysis tools over the Tenable.sc REST API (built around
``/rest/analysis``), authenticated with API keys via the ``x-apikey`` header.
Side-effecting "write" tools are isolated and only registered when explicitly
enabled. Token / SAML / LDAP / User / Role / Director endpoints are never exposed.
"""

__version__ = "0.1.0"
