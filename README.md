<p align="center">
  <img src="assets/hero-banner.png" alt="Trellix HX MCP Server" width="800" />
</p>

<p align="center">
  <strong>A comprehensive MCP server for Trellix (FireEye) HX On-Prem appliances</strong><br>
  <em>Give any AI assistant full access to your endpoint security platform</em>
</p>

<p align="center">
  <a href="#-quick-start"><img src="https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white" alt="Python" /></a>
  <a href="#-tools-31"><img src="https://img.shields.io/badge/MCP_Tools-31-orange?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCI+PHRleHQgeT0iMjAiIGZvbnQtc2l6ZT0iMjAiPvCflKc8L3RleHQ+PC9zdmc+" alt="Tools" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green" alt="License" /></a>
  <a href="#-security-notes"><img src="https://img.shields.io/badge/Security-On--Prem-red?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCI+PHRleHQgeT0iMjAiIGZvbnQtc2l6ZT0iMjAiPvCblKE8L3RleHQ+PC9zdmc+" alt="Security" /></a>
</p>

---

## ✨ What is this?

**Trellix HX MCP Server** bridges the gap between AI assistants and your on-premises Trellix (FireEye) HX endpoint security appliance. Using the [Model Context Protocol](https://modelcontextprotocol.io/), it exposes **31 security tools** that any MCP-compatible AI (Claude, Cursor, Windsurf, etc.) can use to:

- 🔍 **Hunt threats** across your fleet of endpoints
- 🚨 **Triage alerts** and drill into detection details
- 🛡️ **Contain compromised hosts** with network isolation
- 📦 **Acquire forensic evidence** remotely
- 📊 **Search IOCs** across enterprise-wide sweeps
- 🧠 **Analyze indicators** and detection conditions

### Key Features

| Feature | Description |
|---|---|
| 🔐 **Token-based auth** | Automatic session token acquisition & refresh |
| ⚡ **Rate limiting** | 5 req/s token-bucket to protect your appliance |
| 🎯 **Structured errors** | Clean, actionable error messages from HX API |
| 🔄 **Hostname resolution** | `resolve_hostname` converts names → agent IDs |
| 📦 **Modern packaging** | Install via `pip install .` or `pip install '.[chat]'` |

---

## 🎬 Demo

### AI Security Analyst Chat

Ask questions in natural language — the AI automatically calls the right HX tools and summarizes results:

<p align="center">
  <img src="assets/chat-demo.png" alt="LLM Chat Demo" width="600" />
</p>

```
You ▸ Show me the latest critical alerts

  🔧 Calling list_alerts({"limit": 5})

HX Analyst ▸ Found 970 alerts across your fleet. Here are the latest 5:

  1. Alert #247566 — Source: TP — Host: WORKSTATION01 — Status: New
  2. Alert #247592 — Source: IOC — Host: SERVER03 — Indicator: OPENCTI-indicators_ipv4
  3. Alert #247510 — Source: MAL — Host: LAPTOP42 — File quarantined
```

### Interactive Test Runner

Validate all tools against your real appliance in seconds:

<p align="center">
  <img src="assets/test-runner.png" alt="Test Runner Demo" width="600" />
</p>

---

## 🛡️ Tools (31)

| Category | Tools | Description |
|---|---|---|
| **System** | `get_version`, `get_appliance_stats` | Appliance version & health metrics |
| **Hosts** | `resolve_hostname`, `list_hosts`, `get_host_details`, `list_host_sets`, `get_host_set_members`, `update_static_host_set` | Hostname resolution, endpoint inventory & groups |
| **Alerts** | `list_alerts`, `get_alert_details`, `list_source_alerts`, `list_quarantined_files`, `list_containment_states`, `manage_containment` | Alert triage, drilldown & network containment |
| **Intel** | `list_indicators`, `get_indicator_details`, `list_indicator_categories`, `list_conditions` | IOC & threat indicator management |
| **Forensics** | `list_file_acquisitions`, `create_file_acquisition`, `download_file_acquisition`, `list_triages`, `trigger_triage`, `list_bulk_acquisitions` | Remote evidence collection & download |
| **Search** | `list_searches`, `get_search_counts`, `list_policies`, `list_host_policies_channels` | Enterprise IOC sweeps & policies |
| **Scripts** | `list_scripts`, `download_scripts_zip` | Response script management |

---

## ⚡ Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/bry4nsec/trellix-hx-mcp.git
cd trellix-hx-mcp
python3 -m venv venv
source venv/bin/activate
pip install .              # core MCP server
pip install '.[chat]'      # + LLM chat client (optional)
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your HX appliance credentials
```

```ini
# .env
HX_HOST=https://your-hx-appliance.example.com
HX_USER=your_api_username
HX_PASS=your_api_password

# Optional: for chat.py
LLM_ENDPOINT=https://api.openai.com/v1
LLM_MODEL=gpt-4o
LLM_API_KEY=your_llm_api_key
```

### 3. Verify Connection

```bash
python test_tools.py          # run all read-only tools
python test_tools.py -i       # interactive mode
```

---

## 🔌 Integration

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "trellix-hx": {
      "command": "/path/to/trellix-hx-mcp/venv/bin/python",
      "args": ["/path/to/trellix-hx-mcp/server.py"],
      "env": {
        "HX_HOST": "https://your-hx-appliance.example.com",
        "HX_USER": "your_api_user",
        "HX_PASS": "your_api_pass"
      }
    }
  }
}
```

### Cursor / Windsurf / Continue.dev

All MCP-compatible editors support the same configuration format. Point the MCP client at `server.py` with your environment variables.

### MCP Inspector (for testing)

```bash
mcp dev server.py
```

Opens an interactive web UI to browse and test all 31 tools.

### LLM Chat Client (standalone)

```bash
python chat.py
```

An interactive terminal chat powered by OpenAI-compatible APIs with automatic function calling.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    MCP Client (Claude, Cursor, etc.)         │
│                                                              │
│   "Show me hosts with recent alerts"                         │
│    ↓                                                         │
│   LLM decides to call: list_alerts(limit: 10)                │
│    ↓                                                         │
│   Tool result → LLM summarizes → User sees clean output      │
└──────────────┬───────────────────────────────────────────────┘
               │  MCP Protocol (stdio / SSE)
               ▼
┌──────────────────────────────────────────────────────────────┐
│                    server.py  (FastMCP)                       │
│                                                              │
│   ┌─────────┐  ┌─────────────┐  ┌──────────────────┐        │
│   │ Token   │  │ Rate        │  │ Structured       │        │
│   │ Auth    │  │ Limiter     │  │ Error Handler    │        │
│   │         │  │ (5 req/s)   │  │ (HXAPIError)     │        │
│   └────┬────┘  └──────┬──────┘  └────────┬─────────┘        │
│        └───────────────┼─────────────────┘                   │
│                        ▼                                     │
│              _query(method, endpoint)                         │
│                        │                                     │
│   ┌────────────────────┼────────────────────────┐            │
│   │ 31 Tools: hosts, alerts, indicators, acqs,  │            │
│   │ searches, policies, scripts, containment... │            │
│   └────────────────────┼────────────────────────┘            │
└────────────────────────┼─────────────────────────────────────┘
                         │  HTTPS + X-FeApi-Token
                         ▼
┌──────────────────────────────────────────────────────────────┐
│              Trellix HX On-Prem Appliance                    │
│              (HX v3 REST API)                                │
│                                                              │
│   /hx/api/v3/hosts    /hx/api/v3/alerts                      │
│   /hx/api/v3/indicators   /hx/api/v3/acqs/files             │
│   /hx/api/v3/searches     /hx/api/v3/scripts      ...       │
└──────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
trellix-hx-mcp/
├── server.py          # MCP server — 31 tools with token auth & rate limiting
├── test_tools.py      # Interactive test runner (batch + pick-and-run)
├── chat.py            # LLM chat client (OpenAI-compatible)
├── pyproject.toml     # Modern Python packaging (pip install .)
├── requirements.txt   # Fallback dependency list
├── dev.nix            # Nix development environment
├── assets/            # README images
├── .env.example       # Template credentials (safe to commit)
└── .gitignore         # Protects .env, venv/, __pycache__/
```

---

## 🔐 Security Notes

> [!CAUTION]
> **Never commit your `.env` file.** It contains your real HX appliance credentials. Use `.env.example` as a template.

- Uses **HTTP Basic Auth** for initial token acquisition, then **session tokens** for all subsequent requests
- `verify=False` for self-signed certificates (standard in on-prem deployments)
- `urllib3` InsecureRequestWarning is suppressed for clean output
- Rate-limited to **5 requests/second** to prevent appliance overload
- Write operations (`manage_containment`, `trigger_triage`, `create_file_acquisition`) are clearly documented with ⚠️ warnings
- The test runner requires explicit confirmation (`y/N`) before executing any write operation

---

## 📋 Requirements

| Requirement | Details |
|---|---|
| **Python** | 3.10+ |
| **HX Appliance** | Trellix HX On-Prem with v3 API access |
| **API User** | Account with appropriate role permissions |
| **Network** | HTTPS access to the appliance from the server host |

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feat/new-tool`)
3. Test against a real appliance using `python test_tools.py`
4. Submit a Pull Request

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built with ❤️ for the SOC community</sub><br>
  <sub>Powered by <a href="https://modelcontextprotocol.io/">Model Context Protocol</a> and <a href="https://github.com/jlowin/fastmcp">FastMCP</a></sub>
</p>
