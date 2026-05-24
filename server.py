"""
server.py — Lightweight MCP Server for RedTeam MCP
====================================================
Exposes individual tools only (no workflow automation).
Use this if you want to call tools one at a time from Claude Desktop.

Usage:
    python server.py

Connect via Claude Desktop config:
    {
      "mcpServers": {
        "redteam": {
          "command": "/path/to/venv/bin/python",
          "args": ["/path/to/AI-Powered-Red-Team-Automation/server.py"]
        }
      }
    }
"""

from mcp.server.fastmcp import FastMCP

from tools.recon     import register_recon_tools
from tools.vuln_scan import register_vuln_tools
from tools.exploit   import register_exploit_tools
from tools.reporting import register_reporting_tools

mcp = FastMCP("redteam-server")

register_recon_tools(mcp)
register_vuln_tools(mcp)
register_exploit_tools(mcp)
register_reporting_tools(mcp)

if __name__ == "__main__":
    mcp.run(transport="stdio")
