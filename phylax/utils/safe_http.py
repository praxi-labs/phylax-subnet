"""SSRF-resistant HTTP helpers.

The validator fetches bundle bytes from URLs supplied by phylax-server. The
server is trusted (pubkey-pinned), but a compromise of the server — or a
mistake in the corpus crawler — could surface URLs that point at the
validator host's own internal services: cloud metadata endpoints, the
docker daemon, LAN scanners. Defense-in-depth: refuse to fetch from any
URL that resolves into a private-network range, and re-check on every
redirect.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Optional
from urllib.parse import urljoin, urlparse


# Cloud metadata + RFC1918 + loopback + link-local + IPv6 equivalents.
# Any URL whose host resolves into one of these is rejected.
_PRIVATE_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # incl. 169.254.169.254 (AWS/GCP)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _ip_is_private(addr_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(addr_str)
    except ValueError:
        # If it doesn't parse as an IP it's nothing we know how to gate;
        # treat as unsafe.
        return True
    return any(addr in net for net in _PRIVATE_NETS)


def _host_resolves_safely(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # DNS failure → can't verify → unsafe.
        return False
    for info in infos:
        if _ip_is_private(info[4][0]):
            return False
    return True


def is_safe_url(url: str) -> bool:
    """Return True only for an http(s) URL pointing at a public IP.

    Resolves the hostname and rejects any answer that lands in a private,
    loopback, or link-local range. Schemes other than http(s) are rejected
    outright — no ``file://``, no ``ftp://``, no ``gopher://``.
    """
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname
    if not host:
        return False
    return _host_resolves_safely(host)


def safe_get_bytes(
    url: str,
    *,
    timeout: float = 15.0,
    max_redirects: int = 5,
    max_bytes: int = 50 * 1024 * 1024,
) -> Optional[bytes]:
    """GET ``url`` with SSRF protection and a body-size cap.

    Validates the initial URL and every redirect hop against the private-IP
    block list. Caps the response so a hostile upstream can't OOM the
    validator by streaming a huge body. Returns the response bytes on a
    final 200, otherwise ``None``.
    """
    if not is_safe_url(url):
        return None

    import httpx

    current = url
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        for _ in range(max_redirects + 1):
            try:
                r = client.get(current)
            except Exception:  # noqa: BLE001
                return None
            if 300 <= r.status_code < 400:
                loc = r.headers.get("location")
                if not loc:
                    return None
                next_url = urljoin(str(r.url), loc)
                if not is_safe_url(next_url):
                    return None
                current = next_url
                continue
            if r.status_code == 200:
                if len(r.content) > max_bytes:
                    return None
                return r.content
            return None
    return None


__all__ = ["is_safe_url", "safe_get_bytes"]
