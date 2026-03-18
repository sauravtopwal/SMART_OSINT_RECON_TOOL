# 🔍 Smart OSINT Recon Agent — MCP Server for Claude Desktop

A personal intelligence analyst that runs inside **Claude Desktop** via the MCP (Model Context Protocol).

Give it any target — a domain, IP, email, or person — and it automatically investigates across **14 reconnaissance tools**, scores the findings, and generates a complete report — all inside a single Claude conversation.

---

## 🚀 What It Can Do

| Tool | What It Does |
|---|---|
| `classify_target` | Auto-detects target type (domain, IP, email, phone) |
| `whois_lookup` | Registrar, creation date, expiry, nameservers |
| `dns_lookup` | A, AAAA, MX, TXT, NS, CNAME, SOA records |
| `subdomain_enum` | Subdomain discovery via crt.sh |
| `rdap_lookup` | Modern WHOIS (RDAP) structured data |
| `breach_check` | HaveIBeenPwned email breach check |
| `email_permutations` | Generate likely email formats |
| `github_dork` | Search GitHub for exposed secrets/keys |
| `pastebin_search` | Search Pastebin dumps for exposed data |
| `shodan_lookup` | Open ports, services, CVEs via Shodan |
| `http_headers` | Server fingerprint + security headers |
| `ssl_cert_analysis` | SSL validity, expiry, SANs, issuer |
| `ip_reputation` | AbuseIPDB + VirusTotal reputation check |
| `threat_intel` | URLhaus + ThreatFox malware/IOC feeds |
| `full_passive_recon` | Runs WHOIS + DNS + subdomains + RDAP in one call |
| `risk_score` | Scores all findings 0–100 with severity rating |
| `generate_report` | Full Markdown recon report with recommendations |

---

## 🛠️ Requirements

- **Claude Desktop** — [Download here](https://claude.ai/desktop)
- **Python 3.11 or 3.12** — [Download here](https://www.python.org/downloads/release/python-3119/)
- Windows / Mac / Linux

---

## ⚙️ Installation

### Step 1 — Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/osint-recon-agent.git
cd osint-recon-agent
```

### Step 2 — Create a virtual environment

**Mac/Linux:**
```bash
python3.11 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell):**
```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Add API keys (optional)

Open `osint_mcp_server.py` and find the `CONFIG` section at the top:

```python
CONFIG = {
    "SHODAN_API_KEY":  "YOUR_SHODAN_API_KEY",
    "HIBP_API_KEY":    "YOUR_HIBP_API_KEY",
    "VIRUSTOTAL_KEY":  "YOUR_VIRUSTOTAL_API_KEY",
    "ABUSEIPDB_KEY":   "YOUR_ABUSEIPDB_API_KEY",
}
```

> ⚠️ API keys are optional. 12 out of 14 tools work without any key.

| Service | Free Tier | Get Key |
|---|---|---|
| Shodan | ✅ Yes | [shodan.io](https://shodan.io) |
| HaveIBeenPwned | ❌ ~$4/mo | [haveibeenpwned.com](https://haveibeenpwned.com/API/Key) |
| VirusTotal | ✅ Yes | [virustotal.com](https://virustotal.com) |
| AbuseIPDB | ✅ Yes | [abuseipdb.com](https://abuseipdb.com) |

### Step 5 — Test the server

**Mac/Linux:**
```bash
python osint_mcp_server.py
```

**Windows:**
```powershell
& "C:\path\to\.venv\Scripts\python.exe" osint_mcp_server.py
```

> Terminal should hang silently — that means it's working. Press `Ctrl+C` to stop.

### Step 6 — Configure Claude Desktop

Find your Python path:

**Mac/Linux:**
```bash
which python
```

**Windows:**
```powershell
py -3.11 -c "import sys; print(sys.executable)"
```

Open Claude Desktop config file:

- **Mac:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `C:\Users\YourName\AppData\Roaming\Claude\claude_desktop_config.json`

Add this (replace paths with your actual paths):

**Mac/Linux:**
```json
{
  "mcpServers": {
    "osint-agent": {
      "command": "/path/to/.venv/bin/python",
      "args": ["/path/to/osint_mcp_server.py"]
    }
  }
}
```

**Windows:**
```json
{
  "mcpServers": {
    "osint-agent": {
      "command": "C:\\path\\to\\.venv\\Scripts\\python.exe",
      "args": ["C:\\path\\to\\osint_mcp_server.py"]
    }
  }
}
```

### Step 7 — Restart Claude Desktop

Fully quit and reopen Claude Desktop. Look for the **🔨 hammer icon** in the chat bar — that confirms all 14 tools are loaded.

---

## 💬 Example Prompts

```
Run a complete recon on google.com and give me a risk score report
```
```
Check if test@gmail.com has appeared in any data breaches
```
```
Investigate IP 8.8.8.8 — check reputation and open ports
```
```
Find all subdomains of microsoft.com
```
```
Do a full OSINT recon on tesla.com and generate a markdown report
```

---

## 🏗️ Architecture

```
Input (domain / IP / email / person)
          ↓
    AI Orchestrator (Claude)
          ↓
┌─────────────────────────────────┐
│  Passive    │  OSINT   │  Tech  │
│  Recon      │  Sources │  Recon │
│  WHOIS/DNS  │  Breaches│  Shodan│
└─────────────────────────────────┘
          ↓
   Aggregation & Correlation
          ↓
      Risk Scoring (0-100)
          ↓
   Full Markdown Report ✅
```

---

## ⚠️ Legal Disclaimer

This tool is intended for **ethical and legal use only** — security research, penetration testing with permission, bug bounty programs, and defensive investigations. Do not use against targets you do not have permission to investigate. The author is not responsible for any misuse.

---

## 🧑‍💻 Built With

- Python 3.11
- [MCP SDK](https://github.com/anthropics/mcp)
- Claude Desktop
- Shodan · HaveIBeenPwned · URLhaus · ThreatFox · crt.sh

---

## 📄 License

MIT License — free to use, modify, and distribute.
