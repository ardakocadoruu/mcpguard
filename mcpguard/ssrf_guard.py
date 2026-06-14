"""SSRF (Server-Side Request Forgery) protection for the mcpguard HTTP fetcher.

When mcpguard fetches an npm package tarball URL it trusts that the URL comes
from the npm registry.  However two attack paths exist:

1. A **malicious package's registry metadata** could contain a ``dist.tarball``
   field pointing at an internal address.
2. A **redirect chain** from a legitimate URL could bounce to an internal host
   (e.g. ``registry.npmjs.org → 169.254.169.254``).

Both paths are closed by :class:`SSRFGuard`:

* :meth:`SSRFGuard.validate_url` is called before the first request is issued.
* :meth:`SSRFGuard.safe_httpx_event_hook` returns an httpx event-hook dict
  that re-validates every redirect target before the client follows it.

Internal / private IP ranges blocked
-------------------------------------
* ``10.0.0.0/8``        — RFC 1918 private
* ``172.16.0.0/12``     — RFC 1918 private
* ``192.168.0.0/16``    — RFC 1918 private
* ``127.0.0.0/8``       — loopback
* ``169.254.0.0/16``    — link-local / AWS EC2 instance metadata (IMDS)
* ``0.0.0.0/8``         — "this network"
* ``100.64.0.0/10``     — IANA shared address (carrier-grade NAT)
* ``::1/128``           — IPv6 loopback
* ``fc00::/7``          — IPv6 unique local (ULA)
* ``fe80::/10``         — IPv6 link-local

Allowed schemes: ``http``, ``https`` only.
Allowed ports: 80, 443, or any port ≥ 1024 and ≤ 65535.
Credentials in URL (``user:pass@host``) are always rejected.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import ParseResult, urlparse

import httpx

__all__ = ["SSRFError", "SSRFGuard", "BLOCKED_RANGES"]

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Blocked IP ranges
# ---------------------------------------------------------------------------

#: All IP networks that must never be the final destination of an HTTP request.
BLOCKED_RANGES: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # IPv4
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 private
    ipaddress.ip_network("172.16.0.0/12"),       # RFC 1918 private
    ipaddress.ip_network("192.168.0.0/16"),      # RFC 1918 private
    ipaddress.ip_network("127.0.0.0/8"),         # loopback
    ipaddress.ip_network("169.254.0.0/16"),      # link-local / AWS IMDS
    ipaddress.ip_network("0.0.0.0/8"),           # "this network"
    ipaddress.ip_network("100.64.0.0/10"),       # IANA shared / CGN
    ipaddress.ip_network("192.0.0.0/24"),        # IANA protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),       # benchmark testing
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2 (documentation)
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3 (documentation)
    ipaddress.ip_network("240.0.0.0/4"),         # reserved
    ipaddress.ip_network("255.255.255.255/32"),  # broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),             # loopback
    ipaddress.ip_network("fc00::/7"),            # unique local (ULA)
    ipaddress.ip_network("fe80::/10"),           # link-local
    ipaddress.ip_network("::/128"),              # unspecified
    ipaddress.ip_network("::ffff:0:0/96"),       # IPv4-mapped (covered above, belt & braces)
]

#: Schemes that mcpguard is allowed to fetch from.
_ALLOWED_SCHEMES: frozenset[str] = frozenset(["http", "https"])

#: Ports always permitted regardless of the ≥ 1024 rule.
_PRIVILEGED_EXCEPTIONS: frozenset[int] = frozenset([80, 443])

#: Well-known service ports above 1024 that mcpguard explicitly blocks.
#: These are common targets in SSRF attacks against internal infrastructure
#: (databases, caches, message queues) that a package scanner has no reason
#: to connect to.
_BLOCKED_SERVICE_PORTS: frozenset[int] = frozenset([
    3306,   # MySQL
    3307,   # MySQL alternate
    5432,   # PostgreSQL
    5433,   # PostgreSQL alternate
    6379,   # Redis
    6380,   # Redis TLS
    27017,  # MongoDB
    27018,  # MongoDB alternate
    5672,   # RabbitMQ AMQP
    5671,   # RabbitMQ AMQP TLS
    9200,   # Elasticsearch HTTP
    9300,   # Elasticsearch transport
    2181,   # ZooKeeper
    2379,   # etcd client
    2380,   # etcd peer
    11211,  # Memcached
    9092,   # Kafka
])


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class SSRFError(Exception):
    """Raised when a URL or resolved IP violates the SSRF policy.

    Attributes:
        url:    The URL that triggered the check.
        reason: Human-readable explanation of which rule was violated.
    """

    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"SSRF policy violation for {url!r}: {reason}")


# ---------------------------------------------------------------------------
# Guard class
# ---------------------------------------------------------------------------

class SSRFGuard:
    """Validates URLs and resolved IPs against the SSRF policy.

    This class is **stateless** — all methods can be called on a single shared
    instance.  The singleton :data:`ssrf_guard` at the bottom of this module is
    intended for use across the codebase.

    Usage::

        from mcpguard.ssrf_guard import ssrf_guard, SSRFError

        try:
            ssrf_guard.validate_url(tarball_url)
        except SSRFError as exc:
            raise PackageFetchError(pkg, str(exc)) from exc

        async with httpx.AsyncClient(
            event_hooks=ssrf_guard.safe_httpx_event_hook(),
            follow_redirects=True,
        ) as client:
            resp = await client.get(tarball_url)
    """

    def validate_url(self, url: str) -> None:
        """Validate *url* against the SSRF policy before issuing any request.

        Checks performed (in order):

        1. Parse the URL — reject if malformed.
        2. Reject non-http/https schemes.
        3. Reject embedded credentials (``user:pass@host``).
        4. Extract and validate the port number.
        5. Resolve the hostname to IP addresses (DNS lookup) and check each
           against :data:`BLOCKED_RANGES`.
        6. If the hostname is already a raw IP literal, validate it directly
           without a DNS round-trip.

        Args:
            url: The URL string to validate.

        Raises:
            SSRFError: On any policy violation.
        """
        parsed = self._parse_or_raise(url)

        # 1. Scheme
        scheme = parsed.scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise SSRFError(
                url,
                f"Scheme {scheme!r} is not allowed — only {sorted(_ALLOWED_SCHEMES)} are permitted",
            )

        # 2. Credentials in URL
        if parsed.username or parsed.password:
            raise SSRFError(
                url,
                "Credentials embedded in URL (user:pass@host) are not permitted",
            )

        # 3. Hostname present
        hostname = parsed.hostname
        if not hostname:
            raise SSRFError(url, "URL has no hostname")

        # 4. Port validation
        port = parsed.port
        if port is not None:
            self._check_port(url, port)

        # 5 & 6. IP / DNS resolution check
        self._check_hostname(url, hostname)

    def _check_port(self, url: str, port: int) -> None:
        """Verify *port* is within the allowed range.

        Ports below 1024 (privileged / well-known) are blocked except for
        80 (HTTP) and 443 (HTTPS).  Ports above 65535 are invalid.

        Args:
            url:  Original URL string (for error messages).
            port: Numeric port extracted from the URL.

        Raises:
            SSRFError: If the port is forbidden or out of range.
        """
        if port > 65535:
            raise SSRFError(url, f"Port {port} is out of range (max 65535)")
        if port < 1024 and port not in _PRIVILEGED_EXCEPTIONS:
            raise SSRFError(
                url,
                f"Port {port} is a privileged port (< 1024) and not 80 or 443. "
                f"This could target system services.",
            )
        if port in _BLOCKED_SERVICE_PORTS:
            raise SSRFError(
                url,
                f"Port {port} is a blocked service port (database/cache/queue). "
                f"mcpguard only fetches from HTTP/HTTPS package registry endpoints.",
            )

    def _check_hostname(self, url: str, hostname: str) -> None:
        """Resolve *hostname* and check all resulting IPs against blocked ranges.

        If *hostname* is already an IP literal it is checked directly.
        Otherwise a DNS lookup is performed and every returned address is
        validated.  We check *all* addresses because an adversary can return
        a mix of public and private addresses (DNS rebinding mitigation).

        Args:
            url:      Original URL string (for error messages).
            hostname: Hostname or IP string extracted from the URL.

        Raises:
            SSRFError: If any resolved address is in a blocked range.
        """
        # Try parsing as a raw IP first (no DNS needed).
        try:
            addr = ipaddress.ip_address(hostname)
            self._check_ip(url, addr)
            return
        except ValueError:
            pass  # Not an IP literal — continue to DNS resolution.

        # DNS resolution.
        try:
            addr_infos = socket.getaddrinfo(hostname, None)
        except OSError as exc:
            raise SSRFError(url, f"DNS resolution failed for {hostname!r}: {exc}") from exc

        if not addr_infos:
            raise SSRFError(url, f"DNS returned no addresses for {hostname!r}")

        for family, _type, _proto, _canonname, sockaddr in addr_infos:
            raw_ip = sockaddr[0]  # (ip, port) or (ip, port, flowinfo, scopeid)
            try:
                addr = ipaddress.ip_address(raw_ip)
            except ValueError:
                log.warning("Could not parse resolved address %r for %s", raw_ip, hostname)
                continue
            self._check_ip(url, addr)

    def _check_ip(
        self,
        url: str,
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> None:
        """Raise :class:`SSRFError` if *addr* falls in any blocked range.

        Args:
            url:  Original URL (for error messages).
            addr: Resolved IP address to check.

        Raises:
            SSRFError: If *addr* is in :data:`BLOCKED_RANGES`.
        """
        for network in BLOCKED_RANGES:
            if addr in network:
                raise SSRFError(
                    url,
                    f"Resolved IP {addr} is in blocked network {network} "
                    f"(internal/private/loopback address)",
                )

    # -----------------------------------------------------------------------
    # httpx integration
    # -----------------------------------------------------------------------

    def safe_httpx_event_hook(self) -> dict[str, list]:  # type: ignore[type-arg]
        """Return an httpx ``event_hooks`` dict that re-validates every redirect.

        Pass the returned dict to :class:`httpx.AsyncClient` (or the sync
        counterpart) so that every redirect target is validated before the
        client follows it:

        .. code-block:: python

            async with httpx.AsyncClient(
                event_hooks=ssrf_guard.safe_httpx_event_hook(),
                follow_redirects=True,
            ) as client:
                response = await client.get(tarball_url)

        The hook fires on every ``request`` event, which covers both the
        initial request and any redirected requests.  If the URL fails
        validation an :class:`SSRFError` is raised, which propagates out of
        the ``client.get()`` call.

        Returns:
            A dict suitable for the ``event_hooks`` parameter of
            :class:`httpx.AsyncClient` / :class:`httpx.Client`.
        """
        guard = self  # capture for closure

        async def _async_request_hook(request: httpx.Request) -> None:
            try:
                guard.validate_url(str(request.url))
            except SSRFError as exc:
                log.error(
                    "SSRF policy blocked request to %s: %s",
                    request.url,
                    exc.reason,
                )
                raise

        def _sync_request_hook(request: httpx.Request) -> None:
            try:
                guard.validate_url(str(request.url))
            except SSRFError as exc:
                log.error(
                    "SSRF policy blocked request to %s: %s",
                    request.url,
                    exc.reason,
                )
                raise

        return {
            "request": [_async_request_hook, _sync_request_hook],
        }

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _parse_or_raise(url: str) -> ParseResult:
        """Parse *url* with :func:`urllib.parse.urlparse`.

        Args:
            url: Raw URL string.

        Returns:
            A :class:`urllib.parse.ParseResult`.

        Raises:
            SSRFError: If the URL cannot be parsed or has no scheme.
        """
        try:
            parsed = urlparse(url)
        except Exception as exc:  # noqa: BLE001
            raise SSRFError(url, f"URL parse error: {exc}") from exc

        if not parsed.scheme:
            raise SSRFError(url, "URL has no scheme")
        return parsed


#: Module-level singleton — import and use directly.
ssrf_guard: SSRFGuard = SSRFGuard()
