"""
tools/vuln_scan.py — Vulnerability Scanning tools for RedTeam MCP
Covers: nikto, HTTP headers, CVE analysis, nmap vuln scripts
"""

import json
import subprocess
import httpx
from packaging.version import Version

from utils.helpers import validate_target, validate_url


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


def nikto_scan(target: str, port: int = 80, ssl: bool = False, extra_args: str = "") -> str:
    """
    Run Nikto web vulnerability scanner against a target.
    Identifies outdated software, misconfigurations, and dangerous files.
    """
    cmd = ["nikto", "-h", target, "-p", str(port), "-Format", "txt", "-maxtime", "120"]
    if ssl:
        cmd.append("-ssl")
    if extra_args:
        cmd += extra_args.split()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=150)
        return r.stdout or "No output from nikto"
    except FileNotFoundError:
        return "nikto not installed. Run: sudo apt install nikto"
    except subprocess.TimeoutExpired:
        return "nikto timed out after 150s"
    except Exception as e:
        return f"nikto error: {e}"


def check_http_headers(url: str, verify_ssl: bool = True) -> str:
    """
    Analyze HTTP response headers for missing security controls.
    Checks: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy.
    Also reveals Server and X-Powered-By version info.
    """
    if not validate_url(url):
        return "Error: invalid URL — must start with http:// or https://"

    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    try:
        resp    = httpx.get(url, timeout=10, follow_redirects=True, verify=verify_ssl)
        headers = dict(resp.headers)
        missing = [
            h for h in security_headers
            if h.lower() not in {k.lower() for k in headers}
        ]
        result = {
            "url":                      url,
            "status_code":              resp.status_code,
            "server":                   headers.get("server", "not disclosed"),
            "x_powered_by":             headers.get("x-powered-by", "not disclosed"),
            "missing_security_headers": missing,
            "present_security_headers": [h for h in security_headers if h not in missing],
            "all_headers":              dict(headers),
        }
        return json.dumps(result, indent=2)
    except Exception as e:
        return f"HTTP header check failed: {e}"


def analyze_service_version(service: str, version: str) -> str:
    """
    Match a service name + version against the internal CVE knowledge base.
    Uses proper semver range comparison — no false positives from substring matching.
    Covers Apache, OpenSSH, vsftpd, Samba, Log4j, IIS, OpenSSL, Struts, Drupal.
    """
    service_lower = service.lower().strip()
    hits = []

    for entry in CVE_DB:
        if entry["service"] not in service_lower:
            continue
        try:
            v = Version(version)
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
        cve_list.append(f"[{h['severity']}] {', '.join(h['cves'])} — {h['description']}")

    result = {
        "service":    service,
        "version":    version,
        "known_cves": cve_list,
        "note":       "No known CVEs in local DB" if not hits else f"{len(hits)} match(es) found",
        "nvd_url":    f"https://nvd.nist.gov/vuln/search/results?query={service}+{version}",
    }
    return json.dumps(result, indent=2)


def run_nmap_vuln_scripts(target: str, ports: str = "80,443,22,21,25") -> str:
    """
    Run nmap --script vuln against specified ports.
    Uses nmap's built-in vulnerability detection scripts.
    """
    if not validate_target(target):
        return "Error: invalid target"
    try:
        r = subprocess.run(
            ["nmap", "-sV", "--script", "vuln", "-p", ports, target],
            capture_output=True, text=True, timeout=300,
        )
        return r.stdout or "No output from nmap vuln scripts"
    except FileNotFoundError:
        return "nmap not installed. Run: sudo apt install nmap"
    except subprocess.TimeoutExpired:
        return "nmap vuln scripts timed out after 300s"
    except Exception as e:
        return f"nmap vuln scripts error: {e}"


def register_vuln_tools(mcp) -> None:
    """Register all vulnerability scanning tools with an MCP server instance."""

    @mcp.tool()
    def tool_nikto_scan(target: str, port: int = 80, ssl: bool = False, extra_args: str = "") -> str:
        """Run Nikto web vulnerability scanner against a target."""
        return nikto_scan(target, port, ssl, extra_args)

    @mcp.tool()
    def tool_check_http_headers(url: str, verify_ssl: bool = True) -> str:
        """Analyze HTTP security headers for a URL."""
        return check_http_headers(url, verify_ssl)

    @mcp.tool()
    def tool_analyze_service_version(service: str, version: str) -> str:
        """Match service + version against internal CVE knowledge base."""
        return analyze_service_version(service, version)

    @mcp.tool()
    def tool_run_nmap_vuln_scripts(target: str, ports: str = "80,443,22,21,25") -> str:
        """Run nmap vulnerability detection scripts against a target."""
        return run_nmap_vuln_scripts(target, ports)
