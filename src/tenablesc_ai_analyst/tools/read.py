"""Read-only Tenable.sc tools.

Core analysis tools wrap ``/rest/analysis`` (the engine behind the Vulnerabilities
views); context tools wrap the asset / repository / plugin / query / scan-result /
scanner / feed endpoints. None of these change state on Security Center.
"""

from __future__ import annotations

from typing import Any

from ..client import ScClient
from ..schemas import AnalysisFilters, SourceType


def register_read_tools(mcp, client: ScClient) -> None:
    """Register every read-only tool on the FastMCP server."""

    # --- /rest/analysis (vulnerability analysis) --------------------------

    @mcp.tool()
    async def sc_list_vulnerabilities(
        filters: AnalysisFilters | None = None,
        source_type: SourceType = "cumulative",
        detailed: bool = False,
        start_offset: int = 0,
        end_offset: int = 100,
    ) -> Any:
        """List vulnerability findings.

        Uses the ``listvuln`` tool (one row per finding) or ``vulndetails``
        (full per-finding detail) when ``detailed`` is True. Filter with the
        shared filter set; page with ``start_offset``/``end_offset``.
        """
        return await client.analysis(
            tool="vulndetails" if detailed else "listvuln",
            filters=(filters or AnalysisFilters()).to_sc(),
            source_type=source_type,
            start_offset=start_offset,
            end_offset=end_offset,
        )

    @mcp.tool()
    async def sc_vuln_summary_by_host(
        filters: AnalysisFilters | None = None,
        source_type: SourceType = "cumulative",
        start_offset: int = 0,
        end_offset: int = 100,
    ) -> Any:
        """Vulnerability counts grouped by host/IP (analysis tool ``sumip``)."""
        return await client.analysis(
            tool="sumip",
            filters=(filters or AnalysisFilters()).to_sc(),
            source_type=source_type,
            start_offset=start_offset,
            end_offset=end_offset,
        )

    @mcp.tool()
    async def sc_vuln_summary_by_plugin(
        filters: AnalysisFilters | None = None,
        source_type: SourceType = "cumulative",
        start_offset: int = 0,
        end_offset: int = 100,
    ) -> Any:
        """Vulnerability counts grouped by plugin (analysis tool ``sumid``)."""
        return await client.analysis(
            tool="sumid",
            filters=(filters or AnalysisFilters()).to_sc(),
            source_type=source_type,
            start_offset=start_offset,
            end_offset=end_offset,
        )

    @mcp.tool()
    async def sc_vuln_summary_by_severity(
        filters: AnalysisFilters | None = None,
        source_type: SourceType = "cumulative",
    ) -> Any:
        """Vulnerability counts grouped by severity (analysis tool ``sumseverity``)."""
        return await client.analysis(
            tool="sumseverity",
            filters=(filters or AnalysisFilters()).to_sc(),
            source_type=source_type,
        )

    @mcp.tool()
    async def sc_vuln_summary_by_cve(
        filters: AnalysisFilters | None = None,
        source_type: SourceType = "cumulative",
        start_offset: int = 0,
        end_offset: int = 100,
    ) -> Any:
        """Vulnerability counts grouped by CVE (analysis tool ``sumcve``)."""
        return await client.analysis(
            tool="sumcve",
            filters=(filters or AnalysisFilters()).to_sc(),
            source_type=source_type,
            start_offset=start_offset,
            end_offset=end_offset,
        )

    @mcp.tool()
    async def sc_remediation_summary(
        filters: AnalysisFilters | None = None,
        source_type: SourceType = "cumulative",
        start_offset: int = 0,
        end_offset: int = 100,
    ) -> Any:
        """Remediation rollup — the fixes that clear the most risk
        (analysis tool ``sumremediation``)."""
        return await client.analysis(
            tool="sumremediation",
            filters=(filters or AnalysisFilters()).to_sc(),
            source_type=source_type,
            start_offset=start_offset,
            end_offset=end_offset,
        )

    @mcp.tool()
    async def sc_vuln_trend(
        filters: AnalysisFilters | None = None,
        source_type: SourceType = "cumulative",
    ) -> Any:
        """Vulnerability trend over time (analysis tool ``trend``)."""
        return await client.analysis(
            tool="trend",
            filters=(filters or AnalysisFilters()).to_sc(),
            source_type=source_type,
        )

    @mcp.tool()
    async def sc_analysis_query(
        type: str = "vuln",
        tool: str = "listvuln",
        filters: list[dict] | None = None,
        source_type: str = "cumulative",
        start_offset: int = 0,
        end_offset: int = 100,
    ) -> Any:
        """Escape hatch: run an arbitrary ``/rest/analysis`` query.

        Provide raw ``type``/``tool``/``filters``/``source_type`` when a dedicated
        tool above doesn't cover the case. ``filters`` are raw Tenable.sc filter
        objects (``{"filterName", "operator", "value"}``).
        """
        return await client.analysis(
            type=type,
            tool=tool,
            filters=filters or [],
            source_type=source_type,
            start_offset=start_offset,
            end_offset=end_offset,
        )

    # --- Context endpoints ------------------------------------------------

    @mcp.tool()
    async def sc_list_assets(
        fields: str = "id,name,description,type,status",
        start_offset: int = 0,
        end_offset: int = 100,
    ) -> Any:
        """List asset lists/groups (``/rest/asset``)."""
        return await client.get(
            "/rest/asset",
            params={"fields": fields, "startOffset": start_offset, "endOffset": end_offset},
        )

    @mcp.tool()
    async def sc_get_asset(asset_id: int) -> Any:
        """Get one asset list by ID (``/rest/asset/{id}``)."""
        return await client.get(f"/rest/asset/{asset_id}")

    @mcp.tool()
    async def sc_list_repositories(fields: str = "id,name,description,type,dataFormat") -> Any:
        """List repositories (``/rest/repository``)."""
        return await client.get("/rest/repository", params={"fields": fields})

    @mcp.tool()
    async def sc_list_solutions(
        filters: AnalysisFilters | None = None,
        source_type: SourceType = "cumulative",
        start_offset: int = 0,
        end_offset: int = 100,
    ) -> Any:
        """List solutions — Tenable.sc surfaces these through the remediation
        analysis (``sumremediation``): each row is a fix and the hosts it clears."""
        return await client.analysis(
            tool="sumremediation",
            filters=(filters or AnalysisFilters()).to_sc(),
            source_type=source_type,
            start_offset=start_offset,
            end_offset=end_offset,
        )

    @mcp.tool()
    async def sc_get_solution(plugin_id: int) -> Any:
        """Get the remediation/solution text for a plugin (``/rest/plugin/{id}``,
        solution-focused fields)."""
        return await client.get(
            f"/rest/plugin/{plugin_id}",
            params={"fields": "id,name,family,solution,synopsis,riskFactor,patchPubDate"},
        )

    @mcp.tool()
    async def sc_search_plugins(
        keyword: str,
        fields: str = "id,name,family,type,riskFactor",
        start_offset: int = 0,
        end_offset: int = 50,
    ) -> Any:
        """Search the plugin catalog by name keyword (``/rest/plugin``)."""
        return await client.get(
            "/rest/plugin",
            params={
                "filterField": "name",
                "op": "like",
                "value": keyword,
                "fields": fields,
                "startOffset": start_offset,
                "endOffset": end_offset,
            },
        )

    @mcp.tool()
    async def sc_get_plugin(plugin_id: int) -> Any:
        """Get full detail for one plugin (``/rest/plugin/{id}``)."""
        return await client.get(f"/rest/plugin/{plugin_id}")

    @mcp.tool()
    async def sc_list_queries(fields: str = "id,name,description,type,tool") -> Any:
        """List saved queries (``/rest/query``)."""
        return await client.get("/rest/query", params={"fields": fields})

    @mcp.tool()
    async def sc_run_query(query_id: int, start_offset: int = 0, end_offset: int = 100) -> Any:
        """Run a saved query by ID via ``/rest/analysis``."""
        return await client.analysis(
            query_id=query_id, start_offset=start_offset, end_offset=end_offset
        )

    @mcp.tool()
    async def sc_list_scan_results(
        fields: str = "id,name,status,startTime,finishTime,scannedIPs,totalChecks",
        start_offset: int = 0,
        end_offset: int = 50,
    ) -> Any:
        """List scan results (``/rest/scanResult``)."""
        return await client.get(
            "/rest/scanResult",
            params={"fields": fields, "startOffset": start_offset, "endOffset": end_offset},
        )

    @mcp.tool()
    async def sc_get_scan_result(scan_result_id: int) -> Any:
        """Get one scan result by ID (``/rest/scanResult/{id}``)."""
        return await client.get(f"/rest/scanResult/{scan_result_id}")

    @mcp.tool()
    async def sc_feed_status() -> Any:
        """Report plugin/feed freshness — when each feed was last updated
        (``/rest/feed``)."""
        return await client.get("/rest/feed")

    @mcp.tool()
    async def sc_list_scanners(fields: str = "id,name,status,version,ip") -> Any:
        """List Nessus scanners and their status (``/rest/scanner``)."""
        return await client.get("/rest/scanner", params={"fields": fields})
