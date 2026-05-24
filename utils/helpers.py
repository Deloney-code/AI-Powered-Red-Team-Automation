"""
utils/helpers.py — Shared utility functions for RedTeam MCP
"""

import re
import ipaddress
import urllib.parse
from datetime import datetime


def validate_ip(ip: str) -> bool:
    """Return True if ip is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port) -> bool:
    """Return True if port is a valid integer between 1 and 65535."""
    try:
        return 1 <= int(port) <= 65535
    except (TypeError, ValueError):
        return False


def validate_url(url: str) -> bool:
    """Return True if url starts with http:// or https://"""
    return isinstance(url, str) and url.startswith(("http://", "https://"))


def validate_target(t: str) -> bool:
    """Return True if t is a valid IP address or safe hostname."""
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return bool(re.match(r'^[a-zA-Z0-9.\-]+$', t))


def sanitize_target(target: str) -> str:
    """Strip any characters that are not safe in a target string."""
    return re.sub(r'[^a-zA-Z0-9.\-]', '', target)


def truncate_output(text: str, max_chars: int = 3000) -> str:
    """Truncate text to max_chars, appending a note if truncated."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n... [{len(text) - max_chars} bytes truncated]"


def ts() -> str:
    """Return current time as HH:MM:SS string."""
    return datetime.now().strftime("%H:%M:%S")
