"""Thin async httpx wrapper over the Tenable.sc REST API.

One shared :class:`httpx.AsyncClient` is created lazily (bound to the running
event loop) and reused for every request. Authentication is API-key only, via the
``x-apikey: accesskey=...; secretkey=...`` header — no token is ever created.
All requests funnel through :meth:`ScClient._request` for uniform error handling.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import Settings


class ScError(RuntimeError):
    """Raised for any Security Center request/response error."""


class ScClient:
    """Reusable async client for Tenable.sc."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._base = settings.host.rstrip("/")
        self._client: httpx.AsyncClient | None = None

    def _ensure_client(self) -> httpx.AsyncClient:
        if not (self._settings.host and self._settings.access_key and self._settings.secret_key):
            raise ScError(
                "Security Center is not configured. Set SC_HOST, SC_ACCESS_KEY "
                "and SC_SECRET_KEY (see .env.example)."
            )
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._base,
                headers={
                    "x-apikey": (
                        f"accesskey={self._settings.access_key}; "
                        f"secretkey={self._settings.secret_key}"
                    ),
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                verify=self._settings.verify,
                timeout=httpx.Timeout(60.0),
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _request(
        self, method: str, path: str, *, json: Any = None, params: dict | None = None
    ) -> Any:
        client = self._ensure_client()
        try:
            resp = await client.request(method, path, json=json, params=params)
        except httpx.HTTPError as exc:
            raise ScError(f"Request to {path} failed: {exc}") from exc

        if resp.status_code >= 400:
            raise ScError(f"SC HTTP {resp.status_code} for {path}: {resp.text[:300]}")

        try:
            data = resp.json()
        except ValueError as exc:  # pragma: no cover - non-JSON body
            raise ScError(f"Non-JSON response from {path}") from exc

        # Tenable.sc wraps payloads as {error_code, error_msg, response, ...}.
        if isinstance(data, dict) and data.get("error_code"):
            raise ScError(f"SC error {data['error_code']}: {data.get('error_msg', '')}")
        if isinstance(data, dict) and "response" in data:
            return data["response"]
        return data

    async def get(self, path: str, params: dict | None = None) -> Any:
        return await self._request("GET", path, params=params)

    async def post(self, path: str, json: Any) -> Any:
        return await self._request("POST", path, json=json)

    async def analysis(
        self,
        *,
        type: str = "vuln",
        tool: str = "listvuln",
        filters: list[dict] | None = None,
        source_type: str = "cumulative",
        start_offset: int = 0,
        end_offset: int = 100,
        query_id: int | None = None,
        extra: dict | None = None,
    ) -> Any:
        """POST to ``/rest/analysis``.

        Pass ``query_id`` to run a saved query, or ``tool``/``filters`` to build an
        ad-hoc query. ``extra`` merges additional fields (e.g. sortField) into the
        inner query object.
        """
        if query_id is not None:
            query: dict[str, Any] = {"id": query_id, "startOffset": start_offset, "endOffset": end_offset}
        else:
            query = {
                "type": type,
                "tool": tool,
                "startOffset": start_offset,
                "endOffset": end_offset,
                "filters": filters or [],
            }
        if extra:
            query.update(extra)
        body = {"type": type, "sourceType": source_type, "query": query}
        return await self.post("/rest/analysis", body)
