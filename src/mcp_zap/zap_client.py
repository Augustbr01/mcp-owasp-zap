"""Cliente HTTP fino para a API do OWASP ZAP."""

from __future__ import annotations

from typing import Any, Literal

import httpx

from .config import Settings

Kind = Literal["view", "action", "other"]

RISK_IDS = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3}


class ZapError(RuntimeError):
    pass


class ZapClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = httpx.AsyncClient(
            base_url=settings.base_url,
            timeout=settings.timeout,
            headers={"X-ZAP-API-Key": settings.api_key} if settings.api_key else {},
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def call(
        self,
        component: str,
        kind: Kind,
        name: str,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Chama /JSON/<component>/<kind>/<name>/ e devolve o JSON decodificado."""
        query = {k: _fmt(v) for k, v in (params or {}).items() if v is not None}
        path = f"/JSON/{component}/{kind}/{name}/"
        try:
            resp = await self._client.get(path, params=query)
        except httpx.RequestError as exc:
            raise ZapError(
                f"Não consegui falar com o ZAP em {self._settings.base_url}: {exc}. "
                "O ZAP está rodando com a API habilitada?"
            ) from exc

        if resp.status_code >= 400:
            raise ZapError(f"ZAP respondeu {resp.status_code} em {path}: {_snip(resp.text)}")
        if not resp.content:
            raise ZapError(
                f"Resposta vazia em {path} — normalmente é API key ausente/errada "
                "(defina ZAP_API_KEY)."
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise ZapError(f"Resposta não-JSON em {path}: {_snip(resp.text)}") from exc

        if isinstance(data, dict) and "code" in data and "message" in data:
            raise ZapError(f"Erro do ZAP em {path}: {data.get('code')} - {data.get('message')}")
        return data

    async def raw(self, component: str, name: str, params: dict[str, Any] | None = None) -> str:
        """Endpoints /OTHER/ que devolvem texto/binário (relatórios, etc.)."""
        query = {k: _fmt(v) for k, v in (params or {}).items() if v is not None}
        resp = await self._client.get(f"/OTHER/{component}/other/{name}/", params=query)
        resp.raise_for_status()
        return resp.text


def _fmt(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _snip(text: str, limit: int = 300) -> str:
    text = text.strip().replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "…"
