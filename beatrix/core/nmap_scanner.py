"""
BEATRIX Network Scanner — nmap integration

Wraps python-nmap for structured port/service/vuln scanning.
Returns typed results that feed directly into Beatrix findings.

Usage:
    scanner = NetworkScanner()
    result = await scanner.tcp_scan("target.com", ports="1-1000")
    result = await scanner.service_scan("target.com")
    result = await scanner.vuln_scan("target.com")
    result = await scanner.udp_scan("target.com", ports="53,161,500")
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import nmap

# =============================================================================
# DATA TYPES
# =============================================================================

class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"
    UNFILTERED = "unfiltered"


class ScanType(Enum):
    TCP_SYN = "-sS"        # SYN scan (root)
    TCP_CONNECT = "-sT"    # Connect scan (no root)
    UDP = "-sU"            # UDP scan (root)
    SERVICE = "-sV"        # Version detection
    OS = "-O"              # OS detection
    SCRIPT = "-sC"         # Default scripts
    VULN = "--script=vuln" # Vuln scripts
    AGGRESSIVE = "-A"      # OS + version + script + traceroute
    PING = "-sn"           # Host discovery only
    FIN = "-sF"            # FIN scan (firewall evasion)
    NULL = "-sN"           # NULL scan (firewall evasion)
    XMAS = "-sX"           # Xmas scan (firewall evasion)


@dataclass
class PortResult:
    port: int
    protocol: str  # tcp / udp
    state: PortState
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: str = ""
    scripts: Dict[str, str] = field(default_factory=dict)

    @property
    def is_open(self) -> bool:
        return self.state == PortState.OPEN

    @property
    def banner(self) -> str:
        parts = [self.product, self.version, self.extra_info]
        return " ".join(p for p in parts if p).strip()


@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    state: str = "unknown"
    os_matches: List[Dict[str, Any]] = field(default_factory=list)
    ports: List[PortResult] = field(default_factory=list)
    scripts: Dict[str, str] = field(default_factory=dict)
    scan_time: float = 0.0

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.is_open]

    @property
    def services(self) -> Dict[int, str]:
        return {p.port: p.banner or p.service for p in self.open_ports}

    @property
    def os_guess(self) -> str:
        if self.os_matches:
            return self.os_matches[0].get("name", "unknown")
        return "unknown"


@dataclass
class ScanResult:
    target: str
    scan_type: str
    hosts: List[HostResult] = field(default_factory=list)
    command_line: str = ""
    started: Optional[datetime] = None
    elapsed: float = 0.0
    error: str = ""

    @property
    def all_open_ports(self) -> List[PortResult]:
        ports = []
        for h in self.hosts:
            ports.extend(h.open_ports)
        return ports

    @property
    def summary(self) -> str:
        total_open = len(self.all_open_ports)
        hosts_up = sum(1 for h in self.hosts if h.state == "up")
        return f"{hosts_up} hosts up, {total_open} open ports ({self.elapsed:.1f}s)"


# =============================================================================
# SCANNER
# =============================================================================

class NetworkScanner:
    """Async wrapper around python-nmap."""

    def __init__(self, nmap_path: str = "nmap", timeout: int = 300):
        self.nmap_path = nmap_path
        self.timeout = timeout
        self._scanner = nmap.PortScanner()

    # ---- High-level scans ----

    async def tcp_scan(
        self, target: str, ports: str = "1-1000",
        arguments: str = "", sudo: bool = False,
    ) -> ScanResult:
        """SYN scan (root) or connect scan (no root)."""
        scan_flag = ScanType.TCP_SYN.value if sudo else ScanType.TCP_CONNECT.value
        args = f"{scan_flag} {arguments}".strip()
        return await self._run(target, ports, args, "tcp_scan", sudo)

    async def service_scan(
        self, target: str, ports: str = "1-1000",
        arguments: str = "",
    ) -> ScanResult:
        """Version detection on open ports."""
        args = f"{ScanType.SERVICE.value} {arguments}".strip()
        return await self._run(target, ports, args, "service_scan")

    async def vuln_scan(
        self, target: str, ports: str = "1-1000",
        arguments: str = "",
    ) -> ScanResult:
        """Run nmap vuln scripts against target."""
        args = f"{ScanType.SERVICE.value} {ScanType.SCRIPT.value} {ScanType.VULN.value} {arguments}".strip()
        return await self._run(target, ports, args, "vuln_scan")

    async def udp_scan(
        self, target: str, ports: str = "53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,1434,1900,4500,5353,49152",
        arguments: str = "",
    ) -> ScanResult:
        """UDP scan (requires root)."""
        args = f"{ScanType.UDP.value} {arguments}".strip()
        return await self._run(target, ports, args, "udp_scan", sudo=True)

    async def aggressive_scan(
        self, target: str, ports: str = "1-1000",
        arguments: str = "",
    ) -> ScanResult:
        """OS + version + default scripts + traceroute."""
        args = f"{ScanType.AGGRESSIVE.value} {arguments}".strip()
        return await self._run(target, ports, args, "aggressive_scan", sudo=True)

    async def ping_sweep(self, target: str) -> ScanResult:
        """Host discovery only — no port scan."""
        args = ScanType.PING.value
        return await self._run(target, None, args, "ping_sweep")

    async def stealth_scan(
        self, target: str, ports: str = "1-1000",
        technique: str = "fin",
    ) -> ScanResult:
        """Firewall evasion scans: fin, null, xmas."""
        flags = {
            "fin": ScanType.FIN.value,
            "null": ScanType.NULL.value,
            "xmas": ScanType.XMAS.value,
        }
        args = flags.get(technique, ScanType.FIN.value)
        return await self._run(target, ports, args, f"stealth_{technique}", sudo=True)

    async def custom_scan(
        self, target: str, ports: Optional[str] = None,
        arguments: str = "", sudo: bool = False,
    ) -> ScanResult:
        """Run arbitrary nmap arguments."""
        return await self._run(target, ports, arguments, "custom_scan", sudo)

    # ---- Quick recon helpers ----

    async def top_ports(self, target: str, count: int = 100) -> ScanResult:
        """Scan top N most common ports."""
        args = f"-sT --top-ports {count}"
        return await self._run(target, None, args, f"top_{count}")

    async def grab_banners(self, target: str, ports: str) -> Dict[int, str]:
        """Quick banner grab on specific ports."""
        result = await self.service_scan(target, ports)
        banners = {}
        for p in result.all_open_ports:
            if p.banner:
                banners[p.port] = p.banner
        return banners

    # ---- Internal ----

    async def _run(
        self, target: str, ports: Optional[str],
        arguments: str, scan_name: str, sudo: bool = False,
    ) -> ScanResult:
        """Run nmap in a thread to keep async."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._scan_sync, target, ports, arguments, scan_name, sudo,
        )

    def _scan_sync(
        self, target: str, ports: Optional[str],
        arguments: str, scan_name: str, sudo: bool = False,
    ) -> ScanResult:
        result = ScanResult(
            target=target, scan_type=scan_name, started=datetime.now(timezone.utc),
        )
        try:
            kwargs: Dict[str, Any] = {"arguments": arguments}
            if ports:
                kwargs["ports"] = ports
            if sudo:
                kwargs["sudo"] = True
            kwargs["timeout"] = self.timeout

            self._scanner.scan(hosts=target, **kwargs)
            result.command_line = self._scanner.command_line()

            for host in self._scanner.all_hosts():
                hr = self._parse_host(host)
                result.hosts.append(hr)

            # Elapsed time
            scan_info = self._scanner.scanstats()
            result.elapsed = float(scan_info.get("elapsed", 0))

        except nmap.PortScannerError as e:
            result.error = f"nmap error: {e}"
        except Exception as e:
            result.error = f"scan error: {e}"

        return result

    def _parse_host(self, host: str) -> HostResult:
        nm = self._scanner
        hr = HostResult(ip=host)

        # Hostname
        try:
            hostnames = nm[host].hostnames()
            if hostnames:
                hr.hostname = hostnames[0].get("name", "")
        except Exception:
            pass

        # State
        hr.state = nm[host].state()

        # OS detection
        try:
            if "osmatch" in nm[host]:
                hr.os_matches = nm[host]["osmatch"]
        except Exception:
            pass

        # Host scripts
        try:
            if "hostscript" in nm[host]:
                for script in nm[host]["hostscript"]:
                    hr.scripts[script["id"]] = script.get("output", "")
        except Exception:
            pass

        # Ports
        for proto in nm[host].all_protocols():
            ports = sorted(nm[host][proto].keys())
            for port in ports:
                info = nm[host][proto][port]
                state_raw = info.get("state", "unknown")
                try:
                    state = PortState(state_raw)
                except ValueError:
                    state = PortState.FILTERED

                pr = PortResult(
                    port=port,
                    protocol=proto,
                    state=state,
                    service=info.get("name", ""),
                    product=info.get("product", ""),
                    version=info.get("version", ""),
                    extra_info=info.get("extrainfo", ""),
                    cpe=info.get("cpe", ""),
                )

                # NSE script results
                if "script" in info:
                    for sid, output in info["script"].items():
                        pr.scripts[sid] = output

                hr.ports.append(pr)

        return hr


# =============================================================================
# CONVENIENCE
# =============================================================================

async def quick_scan(target: str, ports: str = "1-1000") -> ScanResult:
    """One-liner: scan and return results."""
    s = NetworkScanner()
    return await s.tcp_scan(target, ports)
