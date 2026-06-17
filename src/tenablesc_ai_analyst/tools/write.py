"""Side-effecting Tenable.sc tools — these CHANGE state on Security Center.

These are registered only when ``SC_ENABLE_WRITES`` is enabled (see server.py).
Every tool's docstring states plainly that it makes a persistent change.
"""

from __future__ import annotations

from typing import Any

from ..client import ScClient


def register_write_tools(mcp, client: ScClient) -> None:
    """Register the write tools. Call only when writes are explicitly enabled."""

    @mcp.tool()
    async def sc_create_accept_risk_rule(
        plugin_id: int,
        repository_ids: list[int],
        ip: str | None = None,
        comment: str = "",
        expires: str = "-1",
    ) -> Any:
        """PERSISTENT CHANGE: create an Accept Risk rule (``/rest/acceptRiskRule``).

        This accepts (hides) the given plugin's risk on the matching hosts in the
        chosen repositories until ``expires`` (``-1`` = never). It alters how
        findings are reported in Security Center.
        """
        body = {
            "plugin": {"id": str(plugin_id)},
            "repositories": [{"id": rid} for rid in repository_ids],
            "hostType": "ip" if ip else "all",
            "hostValue": ip or "",
            "comments": comment,
            "expires": expires,
        }
        return await client.post("/rest/acceptRiskRule", body)

    @mcp.tool()
    async def sc_create_recast_risk_rule(
        plugin_id: int,
        repository_ids: list[int],
        new_severity: int,
        ip: str | None = None,
        comment: str = "",
    ) -> Any:
        """PERSISTENT CHANGE: create a Recast Risk rule (``/rest/recastRiskRule``).

        This re-rates the given plugin's severity (``new_severity``: 0=Info, 1=Low,
        2=Medium, 3=High, 4=Critical) on the matching hosts/repositories. It alters
        reported severity in Security Center.
        """
        body = {
            "plugin": {"id": str(plugin_id)},
            "repositories": [{"id": rid} for rid in repository_ids],
            "newSeverity": str(new_severity),
            "hostType": "ip" if ip else "all",
            "hostValue": ip or "",
            "comments": comment,
        }
        return await client.post("/rest/recastRiskRule", body)

    @mcp.tool()
    async def sc_create_ticket(
        name: str,
        description: str = "",
        assigned_user_id: int | None = None,
    ) -> Any:
        """PERSISTENT CHANGE: create a ticket (``/rest/ticket``).

        Opens a new remediation ticket in Security Center.
        """
        body: dict[str, Any] = {"name": name, "description": description, "status": "0"}
        if assigned_user_id is not None:
            body["assignedUser"] = {"id": assigned_user_id}
        return await client.post("/rest/ticket", body)

    @mcp.tool()
    async def sc_launch_scan(scan_id: int) -> Any:
        """PERSISTENT CHANGE: launch a scan (``/rest/scan/{id}/launch``).

        Immediately starts the given scan, consuming scanner resources and
        touching target hosts.
        """
        return await client.post(f"/rest/scan/{scan_id}/launch", {})
