# mcp-zap

Servidor MCP que conecta o Claude (ou qualquer cliente MCP) ao **OWASP ZAP** via
API REST. Permite pedir ao Claude para rodar spider, scans ativos, listar URLs,
ver alertas e gerar relatório — funciona com **qualquer instância do ZAP**, é só
apontar `ZAP_BASE_URL` e `ZAP_API_KEY`.

## Requisitos

- OWASP ZAP rodando com a API habilitada (padrão: `http://127.0.0.1:8080`)
- [`uv`](https://docs.astral.sh/uv/) (gerenciador de projetos Python)
- A **API key** do ZAP (em `~/.ZAP/config.xml`, tag `<api><key>`)

## Instalação

```bash
git clone https://github.com/SEU_USUARIO/mcp-zap.git
cd mcp-zap
uv sync
cp .env.example .env   # ajuste ZAP_BASE_URL e ZAP_API_KEY
```

## Como o ZAP precisa estar rodando

O jeito mais simples é o modo daemon (sem interface):

```bash
zap.sh -daemon -port 8080 -host 127.0.0.1 \
  -config api.key=SUA_API_KEY
```

Ou abra a interface normal do ZAP — a API já fica ativa em `127.0.0.1:8080`.
Pegue a key atual com:

```bash
grep -A2 '<api>' ~/.ZAP/config.xml
```

## Registrar no Claude Code

Rode dentro da pasta do projeto (usa o diretório atual):

```bash
claude mcp add zap --scope user \
  --env ZAP_BASE_URL=http://127.0.0.1:8080 \
  --env ZAP_API_KEY=SUA_API_KEY \
  -- uv --directory "$(pwd)" run mcp-zap
```

Verifique com `claude mcp list` (deve mostrar `zap: ... ✔ Connected`).
Se você trocar a API key do ZAP, remova e adicione de novo (`claude mcp remove zap`).

### Outros clientes MCP (Claude Desktop, etc.)

Adicione ao JSON de configuração do seu cliente:

```json
{
  "mcpServers": {
    "zap": {
      "command": "uv",
      "args": ["--directory", "/caminho/para/mcp-zap", "run", "mcp-zap"],
      "env": {
        "ZAP_BASE_URL": "http://127.0.0.1:8080",
        "ZAP_API_KEY": "SUA_API_KEY"
      }
    }
  }
}
```

## Variáveis de ambiente

| Variável | Padrão | Descrição |
|---|---|---|
| `ZAP_BASE_URL` | `http://127.0.0.1:8080` | Endereço da API do ZAP |
| `ZAP_API_KEY` | *(vazio)* | API key do ZAP (recomendado) |
| `ZAP_TIMEOUT` | `60` | Timeout das requisições (s) |
| `ZAP_ALLOWED_HOSTS` | *(vazio)* | Allowlist de hosts alvo, separados por vírgula. Se vazio, permite qualquer alvo. Ex.: `exemplo.com,.meudominio.com` |
| `ZAP_ALLOW_ACTIVE_SCAN` | `true` | `false` desabilita scans ativos (intrusivos) |

## Ferramentas expostas

| Tool | O que faz |
|---|---|
| `zap_full_scan` | **Combo completo (padrão):** spider + liga todos os scanners + scan ativo + achados unificados |
| `zap_status` | Confirma conexão; versão e modo do ZAP |
| `zap_sites` | Sites já vistos no histórico |
| `zap_urls` | URLs conhecidas (filtra por `baseurl`) |
| `zap_spider` | Rastreia/mapeia um alvo → `scan_id` |
| `zap_active_scan` | **Scan ativo (intrusivo)** de vulnerabilidades → `scan_id` |
| `zap_scan_status` | Progresso de um scan (`kind=spider\|ascan`) |
| `zap_stop_scan` | Para um scan em andamento |
| `zap_alerts_summary` | Contagem de alertas por risco |
| `zap_alerts` | Lista de vulnerabilidades (filtra por `baseurl`/`risk`) |
| `zap_report_html` | Relatório HTML completo |

## Fluxo típico (peça ao Claude)

Simples — deixe o combo completo fazer tudo:

- "Faça um scan em https://alvo.exemplo" → `zap_full_scan` (spider + todos os scanners + scan ativo + achados)

Ou passo a passo, se quiser controle fino:

1. "Verifique se o ZAP está conectado" → `zap_status`
2. "Rode o spider em https://alvo.exemplo" → `zap_spider`
3. "Como está o spider?" → `zap_scan_status`
4. "Faça um scan ativo nesse alvo" → `zap_active_scan`
5. "Me mostre os alertas de risco alto" → `zap_alerts(risk='high')`

## Dashboard local (webui/)

Uma interface web pra dirigir o ZAP pelo navegador (roda só em `127.0.0.1`):

```bash
ZAP_API_KEY=SUA_KEY uv run python webui/app.py
# abra http://127.0.0.1:8000
```

Você cola a URL, clica **Analisar**, e o site dispara o combo completo direto
na API do ZAP, com progresso ao vivo e achados coloridos por risco.

**Análise inteligente sem API paga (ponte com o Claude Code):**
1. O scan salva o resultado em `webui/data/last_scan.json`.
2. No Claude Code você pede: **"analise o último scan"**.
3. O Claude lê o arquivo, raciocina sobre a intenção (lógica de negócio, IDOR,
   bypass de auth…) e grava `webui/data/ai_analysis.json`.
4. O painel **"Análise inteligente"** no site mostra o resultado.

Assim a inteligência é a do seu Claude Code (assinatura), sem chave de API.

## ⚠️ Uso responsável

Scan ativo envia payloads de ataque reais. **Só rode contra alvos que você tem
autorização explícita para testar.** Use `ZAP_ALLOWED_HOSTS` para travar os alvos
permitidos e `ZAP_ALLOW_ACTIVE_SCAN=false` para bloquear scans intrusivos.

## Rodar manualmente (debug)

```bash
ZAP_API_KEY=SUA_KEY uv run mcp-zap   # fala MCP por stdio
```
