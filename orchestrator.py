"""
orchestrator.py — Full MCP Orchestrator Server for RedTeam MCP
===============================================================
Exposes both individual tools AND high-level workflow tools.
Use this for Claude Desktop integration with full workflow automation.

Usage:
    python orchestrator.py

    # Test with MCP Inspector
    mcp dev orchestrator.py

Connect via Claude Desktop config:
    {
      "mcpServers": {
        "redteam": {
          "command": "/path/to/venv/bin/python",
          "args": ["/path/to/AI-Powered-Red-Team-Automation/orchestrator.py"]
        }
      }
    }
"""

import json
import urllib.parse

from mcp.server.fastmcp import FastMCP

from tools.recon     import register_recon_tools, nmap_scan, dns_recon, whois_lookup, subdomain_enum, banner_grab
from tools.vuln_scan import register_vuln_tools, check_http_headers, nikto_scan, analyze_service_version
from tools.exploit   import register_exploit_tools
from tools.reporting import register_reporting_tools, set_engagement_scope, generate_report, log_finding

mcp = FastMCP("redteam-orchestrator")

# Register all individual tools
register_recon_tools(mcp)
register_vuln_tools(mcp)
register_exploit_tools(mcp)
register_reporting_tools(mcp)


# ── High-level workflow tools ─────────────────────────────────────────────────

@mcp.tool()
def full_recon_workflow(target: str) -> str:
    """
    Run a full recon workflow on a target.
    Stages: WHOIS → DNS recon → subdomain enum → nmap -sV → banner grab on port 80.
    Returns a combined asset inventory.
    """
    results = {
        "whois":      whois_lookup(target)[:1000],
        "dns":        dns_recon(target),
        "subdomains": subdomain_enum(target),
        "nmap":       nmap_scan(target, ports="1-1000", scan_type="-sV"),
        "banner_80":  banner_grab(target, port=80),
    }
    summary = {}
    for k, v in results.items():
        s = str(v)
        summary[k] = (s[:500] + "...[truncated]") if len(s) > 500 else v
    return json.dumps(summary, indent=2)


@mcp.tool()
def web_app_assessment(url: str) -> str:
    """
    Assess a web application for security issues.
    Stages: HTTP security headers → Nikto scan.
    Auto-detects port and SSL from the URL.
    """
    parsed = urllib.parse.urlparse(url)
    host   = parsed.hostname or url
    port   = parsed.port or (443 if parsed.scheme == "https" else 80)
    ssl    = parsed.scheme == "https"

    results = {
        "headers": check_http_headers(url),
        "nikto":   nikto_scan(host, port=port, ssl=ssl),
    }
    summary = {}
    for k, v in results.items():
        s = str(v)
        summary[k] = (s[:500] + "...[truncated]") if len(s) > 500 else v
    return json.dumps(summary, indent=2)


@mcp.tool()
def quick_triage(target: str) -> str:
    """
    Quick triage of a target — top 20 ports + service detection.
    Completes in ~60 seconds. Returns open ports and service versions.
    """
    TOP_PORTS = "21,22,23,25,53,80,110,139,143,443,445,993,995,1433,3306,3389,5432,6379,8080,8443"
    return nmap_scan(target, ports=TOP_PORTS, scan_type="-sV -T4")


@mcp.tool()
def cve_check_services(services_json: str) -> str:
    """
    Check a list of services against the CVE database.
    Input: JSON list of {"service": "apache", "version": "2.4.49"} objects.
    Returns CVE matches for each service.
    """
    try:
        services = json.loads(services_json)
    except json.JSONDecodeError:
        return "Error: services_json must be a valid JSON array"

    results = []
    for item in services:
        service = item.get("service", "")
        version = item.get("version", "")
        if service and version:
            result = analyze_service_version(service, version)
            results.append(json.loads(result))

    return json.dumps(results, indent=2)


@mcp.tool()
def generate_engagement_report(
    client_name: str,
    tester_name: str,
    scope:       str,
    fmt:         str = "markdown",
) -> str:
    """
    Set engagement metadata and generate the final pentest report.
    Pulls all findings logged via log_finding() during the session.
    Format: markdown (default) or json.
    """
    set_engagement_scope(
        client_name=client_name,
        scope=scope,
        start_date="",
        tester_name=tester_name,
        engagement_type="pentest",
    )
    return generate_report(fmt)


if __name__ == "__main__":
    mcp.run(transport="stdio")
