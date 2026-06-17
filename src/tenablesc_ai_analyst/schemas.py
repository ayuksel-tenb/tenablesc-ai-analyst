"""Shared request models — most importantly the reusable analysis filter set."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# Which dataset the analysis runs against.
SourceType = Literal["cumulative", "patched", "individual"]


class AnalysisFilters(BaseModel):
    """Reusable Tenable.sc vulnerability-analysis filters (all optional).

    Used by every ``/rest/analysis`` tool so filter semantics stay consistent.
    """

    severity: str | None = Field(
        None,
        description="Severity IDs, comma-separated. 4=Critical, 3=High, 2=Medium, 1=Low, 0=Info. e.g. '4,3'.",
    )
    plugin_id: str | None = Field(None, description="Tenable plugin ID, e.g. '19506'.")
    ip: str | None = Field(None, description="Host IP address to scope to.")
    repository_id: int | None = Field(None, description="Repository ID to scope to.")
    last_seen: str | None = Field(
        None, description="Days-range last seen, e.g. '0:30' for the last 30 days."
    )
    exploit_available: bool | None = Field(
        None, description="If True, only findings with a known public exploit."
    )
    cve_id: str | None = Field(None, description="CVE ID, e.g. 'CVE-2021-44228'.")

    def to_sc(self) -> list[dict]:
        """Render to Tenable.sc analysis filter objects."""
        out: list[dict] = []
        if self.severity:
            out.append({"filterName": "severity", "operator": "=", "value": self.severity})
        if self.plugin_id:
            out.append({"filterName": "pluginID", "operator": "=", "value": self.plugin_id})
        if self.ip:
            out.append({"filterName": "ip", "operator": "=", "value": self.ip})
        if self.repository_id is not None:
            # The repository filter expects an array of {id} objects.
            out.append(
                {"filterName": "repository", "operator": "=", "value": [{"id": str(self.repository_id)}]}
            )
        if self.last_seen:
            out.append({"filterName": "lastSeen", "operator": "=", "value": self.last_seen})
        if self.exploit_available is not None:
            out.append(
                {
                    "filterName": "exploitAvailable",
                    "operator": "=",
                    "value": "true" if self.exploit_available else "false",
                }
            )
        if self.cve_id:
            out.append({"filterName": "cveID", "operator": "=", "value": self.cve_id})
        return out
