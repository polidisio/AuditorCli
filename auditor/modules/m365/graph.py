"""Microsoft Graph API client wrapper."""
from __future__ import annotations

from typing import Any

import httpx


GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


class GraphClient:
    def __init__(self, access_token: str) -> None:
        self._token = access_token
        self._headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

    async def get(self, path: str, beta: bool = False, params: dict | None = None) -> dict[str, Any]:
        base = GRAPH_BETA if beta else GRAPH_BASE
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(f"{base}{path}", headers=self._headers, params=params)
            r.raise_for_status()
            return r.json()

    async def get_all_pages(self, path: str, beta: bool = False) -> list[dict[str, Any]]:
        """Follow @odata.nextLink pagination, return all items."""
        items: list[dict[str, Any]] = []
        base = GRAPH_BETA if beta else GRAPH_BASE
        url: str | None = f"{base}{path}"

        async with httpx.AsyncClient(timeout=30) as client:
            while url:
                r = await client.get(url, headers=self._headers)
                r.raise_for_status()
                data = r.json()
                items.extend(data.get("value", []))
                url = data.get("@odata.nextLink")

        return items
