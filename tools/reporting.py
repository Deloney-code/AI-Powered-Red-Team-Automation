"""
tools/reporting.py — Finding Logging & Report Generation for RedTeam MCP
Covers: engagement scope, finding logging, report generation (Markdown + JSON)
"""

import json
import os
from datetime import datetime

# ── Module-level state ────────────────────────────────────────────────────────

findings:        list[dict] = []
engagement_meta: dict       = {}

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
ICONS = {
    "Critical":      "🔴",
    "High":          "🟠",
    "Medium":        "🟡",
    "Low":           "🔵",
    "Informational": "⚪",
}


# ── Functions ─────────────────────────────────────────────────────────────────

def set_engagement_scope(
    client_name:     str,
    scope:           str,
    start_date:      str,
    tester_name:     str,
    engagement_type: str = "pentest",
) -> str:
    """
    Set engagement metadata used in the final report header.
    Call this at the start of every engagement.
    """
    global engagement_meta
    engagement_meta = {
        "client_name":     client_name,
        "scope":           scope,
        "start_date":      start_date or datetime.now().strftime("%Y-%m-%d"),
        "tester_name":     tester_name,
        "engagement_type": engagement_type,
        "set_at":          datetime.now().isoformat(),
    }
    return f"Engagement scope set — Client: {client_name} | Tester: {tester_name} | Type: {engagement_type}"


def log_finding(
    title:          str,
    severity:       str,
    target:         str,
    description:    str,
    evidence:       str,
    recommendation: str,
    cvss_score:     float = None,
    cve:            str   = None,
) -> str:
    """
    Log a single finding.
    Severity: Critical / High / Medium / Low / Informational
    """
    if severity not in SEVERITY_ORDER:
        severity = "Informational"

    finding = {
        "id":             f"FIND-{len(findings)+1:03d}",
        "title":          title,
        "severity":       severity,
        "target":         target,
        "description":    description,
        "evidence":       evidence,
        "recommendation": recommendation,
        "cvss_score":     cvss_score,
        "cve":            cve,
        "logged_at":      datetime.now().isoformat(),
    }
    findings.append(finding)
    return f"Logged {finding['id']} — [{severity}] {title}"


def list_findings() -> str:
    """
    Return all findings logged this session, grouped by severity with counts.
    """
    if not findings:
        return "No findings logged yet."

    counts = {s: len([f for f in findings if f["severity"] == s]) for s in SEVERITY_ORDER}
    lines  = [f"Total findings: {len(findings)}\n"]

    for sev in SEVERITY_ORDER:
        sev_findings = [f for f in findings if f["severity"] == sev]
        if not sev_findings:
            continue
        lines.append(f"{ICONS[sev]} {sev} ({counts[sev]})")
        for f in sev_findings:
            cve_tag = f" [{f['cve']}]" if f.get("cve") else ""
            lines.append(f"  • {f['id']}: {f['title']}{cve_tag} — {f['target']}")

    return "\n".join(lines)


def generate_report(fmt: str = "markdown") -> str:
    """
    Compile all logged findings into a professional pentest report.
    Output format: markdown or json.
    Saves to reports/ directory.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    client      = engagement_meta.get("client_name", "Unknown Client")
    tester      = engagement_meta.get("tester_name", "Red Team Operator")
    scope       = engagement_meta.get("scope",       "As discussed")
    eng_type    = engagement_meta.get("engagement_type", "pentest")
    safe_client = client.replace(" ", "_")

    counts = {s: len([f for f in findings if f["severity"] == s]) for s in SEVERITY_ORDER}

    if counts["Critical"] > 0:   risk = "CRITICAL"
    elif counts["High"] > 0:     risk = "HIGH"
    elif counts["Medium"] > 0:   risk = "MEDIUM"
    elif counts["Low"] > 0:      risk = "LOW"
    else:                         risk = "INFORMATIONAL"

    # ── JSON format ───────────────────────────────────────────────────────────
    if fmt == "json":
        data = {
            "client":         client,
            "tester":         tester,
            "scope":          scope,
            "engagement_type": eng_type,
            "overall_risk":   risk,
            "counts":         counts,
            "findings":       findings,
            "generated_at":   datetime.now().isoformat(),
        }
        fname = f"{safe_client}_report_{timestamp}.json"
        fpath = os.path.join(REPORTS_DIR, fname)
        with open(fpath, "w") as fp:
            json.dump(data, fp, indent=2)
        return f"JSON report saved to: {fpath}"

    # ── Markdown format ───────────────────────────────────────────────────────
    lines = [
        "# Penetration Test Report",
        f"**CONFIDENTIAL — {client.upper()}**\n",
        "---\n",
        "## Engagement Details\n",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Client** | {client} |",
        f"| **Lead Tester** | {tester} |",
        f"| **Engagement Type** | {eng_type} |",
        f"| **Scope** | {scope} |",
        f"| **Report Date** | {datetime.now().strftime('%Y-%m-%d')} |",
        f"| **Overall Risk** | **{risk}** |\n",
        "---\n",
        "## Executive Summary\n",
        f"This assessment identified **{len(findings)} finding(s)** "
        f"with an overall risk rating of **{risk}**.\n",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for s in SEVERITY_ORDER:
        lines.append(f"| {ICONS[s]} {s} | {counts[s]} |")

    lines += ["\n---\n", "## Findings\n"]

    if not findings:
        lines.append("*No findings were logged.*\n")
    else:
        for sev in SEVERITY_ORDER:
            sev_findings = [f for f in findings if f["severity"] == sev]
            if not sev_findings:
                continue
            lines.append(f"\n### {ICONS[sev]} {sev} Severity\n")
            for finding in sev_findings:
                cvss  = f"  \n**CVSS:** {finding['cvss_score']}" if finding.get("cvss_score") else ""
                cve   = f"  \n**CVE:** {finding['cve']}" if finding.get("cve") else ""
                lines += [
                    f"#### {finding['id']}: {finding['title']}\n",
                    f"**Severity:** {finding['severity']}{cvss}{cve}  \n**Target:** `{finding['target']}`\n",
                    f"**Description:**\n{finding['description']}\n",
                    f"**Evidence:**\n```\n{finding['evidence']}\n```\n",
                    f"**Recommendation:**\n{finding['recommendation']}\n",
                    "---\n",
                ]

    lines += [
        "## Disclaimer\n",
        "This report was generated by an authorized red team operator. "
        "All testing was conducted within the agreed scope of work.\n",
        f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Prepared by: {tester}*",
    ]

    content = "\n".join(lines)
    fname   = f"{safe_client}_pentest_report_{timestamp}.md"
    fpath   = os.path.join(REPORTS_DIR, fname)
    with open(fpath, "w") as fp:
        fp.write(content)

    return f"Report saved to: {fpath}\nRisk: {risk} | Findings: {len(findings)}"


# ── MCP Registration ──────────────────────────────────────────────────────────

def register_reporting_tools(mcp) -> None:
    """Register all reporting tools with an MCP server instance."""

    @mcp.tool()
    def tool_set_engagement_scope(
        client_name: str, scope: str, start_date: str,
        tester_name: str, engagement_type: str = "pentest"
    ) -> str:
        """Set engagement metadata for the final report."""
        return set_engagement_scope(client_name, scope, start_date, tester_name, engagement_type)

    @mcp.tool()
    def tool_log_finding(
        title: str, severity: str, target: str,
        description: str, evidence: str, recommendation: str,
        cvss_score: float = None, cve: str = None
    ) -> str:
        """Log a penetration test finding with severity, evidence, and recommendation."""
        return log_finding(title, severity, target, description, evidence, recommendation, cvss_score, cve)

    @mcp.tool()
    def tool_list_findings() -> str:
        """List all findings logged this session grouped by severity."""
        return list_findings()

    @mcp.tool()
    def tool_generate_report(fmt: str = "markdown") -> str:
        """Generate a professional pentest report in markdown or json format."""
        return generate_report(fmt)
