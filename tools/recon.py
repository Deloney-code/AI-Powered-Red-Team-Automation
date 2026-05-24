"""
tools/recon.py — Recon & Enumeration tools for RedTeam MCP
Covers: nmap, DNS, WHOIS, subdomain enum, banner grabbing
"""

import json
import socket
import subprocess
import re
import ipaddress

from utils.helpers import validate_target, validate_port, truncate_output


def nmap_scan(target: str, ports: str = "1-1000", scan_type: str = "-sV", extra_args: str = "") -> str:
    """
    Port scan with service/version detection.
    Returns raw nmap output including open ports, services, and versions.
    """
    if not validate_target(target):
        return "Error: invalid target — must be a valid IP or hostname"
    if not re.match(r'^[\d\-,]+$', str(ports)):
        return "Error: invalid port specification"
    if not re.match(r'^[-a-zA-Z0-9 ]*$', str(scan_type) + str(extra_args)):
        return "Error: invalid scan flags"

    cmd = ["nmap"] + scan_type.split()
    if extra_args:
        cmd += extra_args.split()
    cmd += ["-p", str(ports), "--open", target]

    try:
        r = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=120)
        return r.stdout or r.stderr or "No output from nmap"
    except subprocess.TimeoutExpired:
        return "nmap timed out after 120s"
    except FileNotFoundError:
        return "nmap not installed. Run: sudo apt install nmap"
    except Exception as e:
        return f"nmap error: {e}"


def dns_recon(target: str) -> str:
    """
    Enumerate A, MX, NS, TXT, AAAA, CNAME records for a domain using dig.
    Errors are separated from real records.
    """
    records: dict = {}
    errors:  dict = {}
    for rtype in ["A", "MX", "NS", "TXT", "AAAA", "CNAME"]:
        try:
            r = subprocess.run(
                ["dig", "+short", rtype, target],
                capture_output=True, text=True, timeout=8,
            )
            if r.stdout.strip():
                records[rtype] = r.stdout.strip().splitlines()
        except Exception as e:
            errors[rtype] = str(e)
    return json.dumps({"domain": target, "records": records, "errors": errors}, indent=2)


def whois_lookup(target: str) -> str:
    """
    WHOIS registration data for a domain or IP.
    Reveals registrar, owner, creation dates, nameservers.
    """
    try:
        r = subprocess.run(["whois", target], capture_output=True, text=True, timeout=15)
        return r.stdout[:3000]
    except FileNotFoundError:
        return "whois not installed. Run: sudo apt install whois"
    except Exception as e:
        return f"whois error: {e}"


def subdomain_enum(target: str, wordlist: str = None) -> str:
    """
    DNS bruteforce using a built-in wordlist or a custom wordlist file.
    Returns resolved subdomains with IPs.
    """
    default_subs = [
        "www", "mail", "ftp", "admin", "dev", "staging", "api", "vpn",
        "remote", "test", "portal", "shop", "blog", "secure", "mx",
        "ns1", "ns2", "smtp", "pop", "imap", "webmail", "jenkins",
        "gitlab", "jira", "confluence", "dashboard", "app", "auth",
        "login", "cdn", "static", "beta", "prod",
    ]
    subs = default_subs
    if wordlist:
        try:
            with open(wordlist) as f:
                subs = [line.strip() for line in f if line.strip()]
        except Exception as e:
            subs = default_subs

    found = []
    for sub in subs:
        fqdn = f"{sub}.{target}"
        try:
            ip = socket.gethostbyname(fqdn)
            found.append({"subdomain": fqdn, "ip": ip})
        except socket.gaierror:
            pass

    return json.dumps({"domain": target, "found": found, "checked": len(subs)}, indent=2)


def banner_grab(host: str, port: int, timeout: int = 5) -> str:
    """
    Connect to a port and read the raw service banner.
    Uses HTTP/1.1 with Host header for web ports.
    """
    if not validate_port(port):
        return "Error: invalid port"
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            s.sendall(request.encode())
            result = s.recv(512).decode("utf-8", errors="replace")
        return result
    except Exception as e:
        return f"Banner grab failed: {e}"


def register_recon_tools(mcp) -> None:
    """Register all recon tools with an MCP server instance."""

    @mcp.tool()
    def tool_nmap_scan(target: str, ports: str = "1-1000", scan_type: str = "-sV", extra_args: str = "") -> str:
        """Port scan with service/version detection using nmap."""
        return nmap_scan(target, ports, scan_type, extra_args)

    @mcp.tool()
    def tool_dns_recon(target: str) -> str:
        """Enumerate DNS records (A, MX, NS, TXT, AAAA, CNAME) for a domain."""
        return dns_recon(target)

    @mcp.tool()
    def tool_whois_lookup(target: str) -> str:
        """WHOIS registration lookup for a domain or IP address."""
        return whois_lookup(target)

    @mcp.tool()
    def tool_subdomain_enum(target: str, wordlist: str = None) -> str:
        """Enumerate subdomains via DNS bruteforce."""
        return subdomain_enum(target, wordlist)

    @mcp.tool()
    def tool_banner_grab(host: str, port: int, timeout: int = 5) -> str:
        """Grab the service banner from a host:port."""
        return banner_grab(host, port, timeout)
