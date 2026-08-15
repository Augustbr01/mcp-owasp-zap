#!/usr/bin/env python3
"""Dashboard local para dirigir o OWASP ZAP pelo navegador.

Roda SÓ em 127.0.0.1. Você cola uma URL, clica "Analisar" e o site dispara o
combo completo (spider + todos os scanners + scan ativo) direto na API do ZAP,
mostrando o progresso ao vivo e o resultado.

Uso:
    ZAP_API_KEY=sua_key uv run python webui/app.py
    # abra http://127.0.0.1:8000
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import httpx

WEB_HOST = os.environ.get("WEB_HOST", "127.0.0.1")
WEB_PORT = int(os.environ.get("WEB_PORT", "8000"))
ZAP_BASE = os.environ.get("ZAP_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
ZAP_KEY = os.environ.get("ZAP_API_KEY", "")
_raw_hosts = os.environ.get("ZAP_ALLOWED_HOSTS", "").strip()
ALLOWED_HOSTS = tuple(h.strip().lower() for h in _raw_hosts.split(",") if h.strip())

HERE = Path(__file__).parent
DATA = HERE / "data"
DATA.mkdir(exist_ok=True)
_zap = httpx.Client(
    base_url=ZAP_BASE,
    timeout=60.0,
    headers={"X-ZAP-API-Key": ZAP_KEY} if ZAP_KEY else {},
)

# Estado do scan atual (um scan por vez — suficiente para uso local)
_lock = threading.Lock()
_state: dict = {
    "running": False,
    "phase": "ocioso",
    "target": None,
    "spider": 0,
    "ascan": 0,
    "completed": False,
    "error": None,
    "summary": {},
    "findings": [],
    "steps": [],
}

RISK_ORDER = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}


def zap(component: str, kind: str, name: str, **params) -> dict:
    q = {k: _fmt(v) for k, v in params.items() if v is not None}
    r = _zap.get(f"/JSON/{component}/{kind}/{name}/", params=q)
    r.raise_for_status()
    data = r.json()
    if isinstance(data, dict) and "code" in data and "message" in data:
        raise RuntimeError(f"ZAP: {data['code']} - {data['message']}")
    return data


def _fmt(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _allowed(url: str) -> bool:
    if not ALLOWED_HOSTS:
        return True
    host = (urlparse(url).hostname or "").lower()
    return any(
        host == a or (a.startswith(".") and host.endswith(a)) for a in ALLOWED_HOSTS
    )


def _set(**kw) -> None:
    with _lock:
        _state.update(kw)


def _step(msg: str) -> None:
    with _lock:
        _state["steps"].append(msg)


def run_scan(url: str) -> None:
    try:
        _set(running=True, phase="limpando", target=url, spider=0, ascan=0,
             completed=False, error=None, summary={}, findings=[], steps=[])
        zap("core", "action", "deleteAllAlerts")
        _step("alertas anteriores limpos")

        # 1) Spider (também alimenta o scanner passivo: headers, cookies...)
        _set(phase="spider")
        sp = zap("spider", "action", "scan", url=url, recurse=True)
        sid = str(sp.get("scan"))
        while True:
            pct = int(zap("spider", "view", "status", scanId=sid).get("status", "0"))
            _set(spider=pct)
            if pct >= 100:
                break
            threading.Event().wait(2)
        _step("spider concluído")

        # 2) Liga todos os scanners ativos, força alta
        _set(phase="configurando")
        zap("ascan", "action", "enableAllScanners")
        for pid in ("0", "1", "2", "3", "4"):
            zap("ascan", "action", "setPolicyAttackStrength", id=pid, attackStrength="HIGH")
        _step("todos os scanners ligados (força HIGH)")

        # 3) Scan ativo
        _set(phase="scan ativo")
        sc = zap("ascan", "action", "scan", url=url, recurse=True)
        aid = str(sc.get("scan"))
        while True:
            pct = int(zap("ascan", "view", "status", scanId=aid).get("status", "0"))
            _set(ascan=pct)
            if pct >= 100:
                break
            threading.Event().wait(3)
        _step("scan ativo concluído")

        # 4) Coleta e agrupa achados
        _set(phase="coletando resultados")
        summary = zap("alert", "view", "alertsSummary", baseurl=url).get("alertsSummary", {})
        raw = zap("alert", "view", "alerts", baseurl=url, count=500).get("alerts", [])
        grouped: dict = {}
        for a in raw:
            key = (a.get("name"), a.get("risk"))
            g = grouped.setdefault(key, {
                "name": a.get("name"), "risk": a.get("risk"),
                "confidence": a.get("confidence"), "cweid": a.get("cweid"),
                "description": a.get("description", ""), "solution": a.get("solution", ""),
                "urls": [], "params": set(), "evidence": a.get("evidence", ""),
                "attack": a.get("attack", ""),
            })
            if a.get("url") and a["url"] not in g["urls"]:
                g["urls"].append(a["url"])
            if a.get("param"):
                g["params"].add(a["param"])
        findings = []
        for g in sorted(grouped.values(), key=lambda x: -RISK_ORDER.get(x["risk"], 0)):
            g["params"] = sorted(g["params"])
            findings.append(g)
        _set(summary=summary, findings=findings)

        # Ponte para o Claude Code: salva o resultado num arquivo que a IA lê.
        # Também apaga a análise anterior (era de outro scan).
        with _lock:
            snapshot = {k: _state[k] for k in ("target", "summary", "findings", "steps")}
        (DATA / "last_scan.json").write_text(
            json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
        (DATA / "ai_analysis.json").unlink(missing_ok=True)

        _set(phase="concluído", completed=True, running=False)
    except Exception as exc:  # noqa: BLE001
        _set(phase="erro", error=str(exc), running=False)


class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, status=200) -> None:
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _html(self, body: bytes, ctype="text/html; charset=utf-8", status=200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self._html((HERE / "index.html").read_bytes())
        elif path == "/api/status":
            with _lock:
                self._json(dict(_state))
        elif path == "/api/health":
            try:
                v = zap("core", "view", "version").get("version")
                self._json({"connected": True, "version": v, "zap": ZAP_BASE})
            except Exception as exc:  # noqa: BLE001
                self._json({"connected": False, "error": str(exc)})
        elif path == "/api/ai":
            f = DATA / "ai_analysis.json"
            if f.exists():
                self._json(json.loads(f.read_text(encoding="utf-8")))
            else:
                self._json({"present": False})
        elif path == "/api/report":
            try:
                r = _zap.get("/OTHER/core/other/htmlreport/")
                self._html(r.content)
            except Exception as exc:  # noqa: BLE001
                self._html(f"<h1>Erro ao gerar relatório: {exc}</h1>".encode(), status=500)
        else:
            self._html(b"nao encontrado", status=404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}

        if path == "/api/scan":
            with _lock:
                if _state["running"]:
                    return self._json({"error": "Já existe um scan em andamento."}, status=409)
            url = (body.get("url") or "").strip()
            if not url.startswith(("http://", "https://")):
                return self._json({"error": "URL inválida (use http:// ou https://)."}, status=400)
            if not _allowed(url):
                return self._json(
                    {"error": f"Host fora da allowlist (ZAP_ALLOWED_HOSTS)."}, status=403)
            threading.Thread(target=run_scan, args=(url,), daemon=True).start()
            self._json({"started": True, "target": url})
        elif path == "/api/stop":
            try:
                zap("spider", "action", "stopAllScans")
                zap("ascan", "action", "stopAllScans")
            except Exception:  # noqa: BLE001
                pass
            _set(running=False, phase="parado")
            self._json({"stopped": True})
        else:
            self._json({"error": "rota desconhecida"}, status=404)

    def log_message(self, *args) -> None:
        pass


def main() -> None:
    print(f"Dashboard ZAP em http://{WEB_HOST}:{WEB_PORT}")
    print(f"Falando com o ZAP em {ZAP_BASE}" + ("" if ZAP_KEY else "  (SEM API key!)"))
    if not ALLOWED_HOSTS:
        print("Sem allowlist — qualquer alvo é aceito. Só escaneie o que você tem permissão.")
    ThreadingHTTPServer((WEB_HOST, WEB_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
