"""Servidor MCP que expõe o OWASP ZAP ao Claude."""

from __future__ import annotations

import asyncio
from typing import Any

from mcp.server import MCPServer

from .config import ConfigError, Settings
from .zap_client import RISK_IDS, ZapClient, ZapError

settings = Settings.from_env()
client = ZapClient(settings)

mcp = MCPServer(
    name="mcp-zap",
    version="0.1.0",
    instructions=(
        "Controla uma instância do OWASP ZAP via API.\n"
        "PADRÃO: quando o usuário pedir 'um scan' (sem detalhar), use zap_full_scan — "
        "ele faz o combo completo (spider + todos os scanners + scan ativo) e devolve "
        "os achados unificados. É o comportamento esperado por padrão.\n"
        "As tools individuais (zap_spider, zap_active_scan, zap_scan_status) existem "
        "para controle fino quando o usuário quiser passos separados.\n"
        "Sempre revise os alertas: separe achados reais de 'verdadeiro mas sem impacto "
        "no contexto', e explique em linguagem simples.\n"
        "Só rode scans ativos contra alvos que o usuário tem autorização para testar."
    ),
)


def _guard(url: str) -> None:
    settings.check_target(url)


# --------------------------------------------------------------------------- #
# Status / diagnóstico
# --------------------------------------------------------------------------- #
@mcp.tool(description="Verifica a conexão com o ZAP e retorna versão e modo atual.")
async def zap_status() -> dict[str, Any]:
    version = await client.call("core", "view", "version")
    mode = await client.call("core", "view", "mode")
    return {
        "connected": True,
        "base_url": settings.base_url,
        "version": version.get("version"),
        "mode": mode.get("mode"),
        "allowed_hosts": list(settings.allowed_hosts) or "todos (sem allowlist)",
    }


# --------------------------------------------------------------------------- #
# Sites / URLs conhecidas
# --------------------------------------------------------------------------- #
@mcp.tool(description="Lista os sites (hosts) que o ZAP já viu no seu histórico.")
async def zap_sites() -> list[str]:
    data = await client.call("core", "view", "sites")
    return data.get("sites", [])


@mcp.tool(
    description=(
        "Lista URLs conhecidas pelo ZAP. Passe 'baseurl' para filtrar por um site "
        "específico (ex.: https://exemplo.com)."
    )
)
async def zap_urls(baseurl: str = "") -> list[str]:
    data = await client.call("core", "view", "urls", {"baseurl": baseurl or None})
    return data.get("urls", [])


# --------------------------------------------------------------------------- #
# Spider (descoberta de conteúdo)
# --------------------------------------------------------------------------- #
@mcp.tool(
    description=(
        "Inicia o spider tradicional para rastrear e mapear as URLs de um alvo. "
        "Retorna o scanId. Use zap_scan_status(scan_id, kind='spider') para o progresso."
    )
)
async def zap_spider(url: str, max_children: int = 0, recurse: bool = True) -> dict[str, Any]:
    _guard(url)
    data = await client.call(
        "spider",
        "action",
        "scan",
        {
            "url": url,
            "maxChildren": max_children or None,
            "recurse": recurse,
        },
    )
    return {"scan_id": data.get("scan"), "kind": "spider", "url": url}


# --------------------------------------------------------------------------- #
# Active scan (teste de vulnerabilidades — intrusivo)
# --------------------------------------------------------------------------- #
@mcp.tool(
    description=(
        "Inicia um SCAN ATIVO contra o alvo — envia payloads de ataque, é intrusivo. "
        "Só use com autorização. Faça o spider antes. Retorna o scanId; acompanhe com "
        "zap_scan_status(scan_id, kind='ascan')."
    )
)
async def zap_active_scan(
    url: str, recurse: bool = True, in_scope_only: bool = False
) -> dict[str, Any]:
    if not settings.allow_active_scan:
        raise ConfigError("Scan ativo desabilitado (ZAP_ALLOW_ACTIVE_SCAN=false).")
    _guard(url)
    data = await client.call(
        "ascan",
        "action",
        "scan",
        {"url": url, "recurse": recurse, "inScopeOnly": in_scope_only},
    )
    return {"scan_id": data.get("scan"), "kind": "ascan", "url": url}


@mcp.tool(
    description=(
        "Progresso de um scan. kind='spider' ou 'ascan'. "
        "Se scan_id for omitido, usa o scan mais recente daquele tipo. "
        "Retorna a porcentagem concluída (100 = terminou)."
    )
)
async def zap_scan_status(scan_id: str = "", kind: str = "spider") -> dict[str, Any]:
    component = "spider" if kind == "spider" else "ascan"
    data = await client.call(component, "view", "status", {"scanId": scan_id or None})
    status = data.get("status")
    return {"kind": kind, "scan_id": scan_id or "último", "percent": status, "done": status == "100"}


@mcp.tool(description="Para um scan em andamento. kind='spider' ou 'ascan'.")
async def zap_stop_scan(scan_id: str = "", kind: str = "spider") -> dict[str, Any]:
    component = "spider" if kind == "spider" else "ascan"
    name = "stop" if scan_id else "stopAllScans"
    await client.call(component, "action", name, {"scanId": scan_id or None})
    return {"stopped": True, "kind": kind, "scan_id": scan_id or "todos"}


# --------------------------------------------------------------------------- #
# Alerts (achados)
# --------------------------------------------------------------------------- #
@mcp.tool(
    description=(
        "Retorna resumo de alertas por nível de risco. Passe 'baseurl' para filtrar por site."
    )
)
async def zap_alerts_summary(baseurl: str = "") -> dict[str, Any]:
    data = await client.call("alert", "view", "alertsSummary", {"baseurl": baseurl or None})
    return data.get("alertsSummary", data)


@mcp.tool(
    description=(
        "Lista alertas (vulnerabilidades) encontrados. Filtre por 'baseurl' e por "
        "'risk' (informational|low|medium|high). 'limit' limita a quantidade retornada."
    )
)
async def zap_alerts(
    baseurl: str = "", risk: str = "", start: int = 0, limit: int = 50
) -> dict[str, Any]:
    data = await client.call(
        "alert",
        "view",
        "alerts",
        {"baseurl": baseurl or None, "start": start, "count": limit},
    )
    alerts = data.get("alerts", [])
    if risk:
        wanted = RISK_IDS.get(risk.lower())
        if wanted is None:
            raise ConfigError(f"risk inválido: {risk!r}. Use informational|low|medium|high.")
        alerts = [a for a in alerts if int(a.get("riskcode", -1)) == wanted]
    trimmed = [
        {
            "name": a.get("name"),
            "risk": a.get("risk"),
            "confidence": a.get("confidence"),
            "url": a.get("url"),
            "param": a.get("param"),
            "solution": _short(a.get("solution", "")),
            "cweid": a.get("cweid"),
        }
        for a in alerts
    ]
    return {"count": len(trimmed), "alerts": trimmed}


# --------------------------------------------------------------------------- #
# Relatório
# --------------------------------------------------------------------------- #
@mcp.tool(description="Gera um relatório HTML completo do estado atual do ZAP.")
async def zap_report_html() -> str:
    return await client.raw("core", "htmlreport")


# --------------------------------------------------------------------------- #
# Combo completo (comportamento padrão de "um scan")
# --------------------------------------------------------------------------- #
async def _wait_scan(component: str, scan_id: str, deadline: float) -> str:
    """Aguarda um scan terminar; devolve a última porcentagem vista."""
    while True:
        data = await client.call(component, "view", "status", {"scanId": scan_id})
        pct = data.get("status", "0")
        if pct == "100" or asyncio.get_event_loop().time() >= deadline:
            return pct
        await asyncio.sleep(3)


@mcp.tool(
    description=(
        "SCAN COMPLETO (padrão). Faz o combo inteiro contra a URL: (1) spider para "
        "mapear, (2) liga TODOS os scanners ativos, (3) roda o scan ativo, e (4) "
        "devolve os alertas unificados (passivo + ativo) agrupados por risco. "
        "É intrusivo — use só com autorização. 'attack_strength' aceita "
        "LOW|MEDIUM|HIGH|INSANE (padrão HIGH). 'max_wait' é o tempo-limite em "
        "segundos (padrão 900); se estourar, retorna o parcial com os scan ids."
    )
)
async def zap_full_scan(
    url: str,
    attack_strength: str = "HIGH",
    clear_previous: bool = True,
    max_wait: int = 900,
) -> dict[str, Any]:
    if not settings.allow_active_scan:
        raise ConfigError("Scan ativo desabilitado (ZAP_ALLOW_ACTIVE_SCAN=false).")
    _guard(url)
    strength = attack_strength.upper()
    if strength not in {"LOW", "MEDIUM", "HIGH", "INSANE"}:
        raise ConfigError(f"attack_strength inválido: {attack_strength!r}.")

    deadline = asyncio.get_event_loop().time() + max_wait
    steps: list[str] = []

    if clear_previous:
        await client.call("core", "action", "deleteAllAlerts")
        steps.append("alertas anteriores limpos")

    # 1) Spider — também alimenta o scanner passivo (headers, cookies, etc.)
    sp = await client.call("spider", "action", "scan", {"url": url, "recurse": True})
    spider_id = str(sp.get("scan"))
    sp_pct = await _wait_scan("spider", spider_id, deadline)
    steps.append(f"spider {sp_pct}%")

    # 2) Liga todos os scanners ativos e ajusta a força de ataque
    await client.call("ascan", "action", "enableAllScanners")
    for pid in ("0", "1", "2", "3", "4"):
        await client.call(
            "ascan", "action", "setPolicyAttackStrength",
            {"id": pid, "attackStrength": strength},
        )
    steps.append(f"todos os scanners ligados (força {strength})")

    # 3) Scan ativo
    sc = await client.call("ascan", "action", "scan", {"url": url, "recurse": True})
    ascan_id = str(sc.get("scan"))
    as_pct = await _wait_scan("ascan", ascan_id, deadline)
    steps.append(f"scan ativo {as_pct}%")

    done = sp_pct == "100" and as_pct == "100"

    # 4) Achados unificados
    summary = await client.call("alert", "view", "alertsSummary", {"baseurl": url})
    raw = await client.call("alert", "view", "alerts", {"baseurl": url, "count": 500})
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for a in raw.get("alerts", []):
        key = (a.get("name"), a.get("risk"))
        g = grouped.setdefault(
            key,
            {"risk": a.get("risk"), "name": a.get("name"), "confidence": a.get("confidence"),
             "cweid": a.get("cweid"), "urls": set(), "params": set()},
        )
        g["urls"].add(a.get("url"))
        if a.get("param"):
            g["params"].add(a.get("param"))
    order = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}
    findings = [
        {
            "risk": g["risk"], "name": g["name"], "confidence": g["confidence"],
            "cweid": g["cweid"], "affected_urls": len(g["urls"]),
            "params": sorted(g["params"]),
        }
        for g in sorted(grouped.values(), key=lambda x: -order.get(x["risk"], 0))
    ]
    return {
        "target": url,
        "completed": done,
        "note": None if done else "tempo-limite atingido; scan pode seguir no ZAP",
        "spider_id": spider_id,
        "ascan_id": ascan_id,
        "steps": steps,
        "summary_by_risk": summary.get("alertsSummary", summary),
        "finding_types": len(findings),
        "findings": findings,
    }


def _short(text: str, limit: int = 240) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "…"


def main() -> None:
    try:
        mcp.run(transport="stdio")
    finally:
        try:
            asyncio.run(client.aclose())
        except Exception:
            pass


if __name__ == "__main__":
    main()
