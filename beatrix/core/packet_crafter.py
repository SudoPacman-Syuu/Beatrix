"""
BEATRIX Packet Crafter — scapy integration

Low-level network probing for bug bounty recon:
- TCP flag manipulation (SYN, FIN, NULL, XMAS)
- ICMP probes (ping, traceroute, MTU discovery)
- DNS enumeration (zone transfer attempts, record queries)
- Custom packet crafting for WAF/firewall fingerprinting
- Protocol-specific probes (HTTP, TLS, etc.)

All functions are async-safe (scapy runs in executor threads).

Usage:
    crafter = PacketCrafter()
    alive = await crafter.ping("target.com")
    result = await crafter.syn_probe("target.com", 443)
    records = await crafter.dns_query("target.com", "MX")
    hops = await crafter.traceroute("target.com")
"""

from __future__ import annotations

import asyncio

# Suppress scapy's noisy startup
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import (  # noqa: E402
    ARP,
    DNS,
    DNSQR,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    RandShort,
    conf,
    sr1,
    srp,
)

# Disable scapy's verbose by default
conf.verb = 0


# =============================================================================
# DATA TYPES
# =============================================================================

class ProbeType(Enum):
    SYN = "SYN"
    FIN = "FIN"
    NULL = "NULL"
    XMAS = "XMAS"
    ACK = "ACK"
    WINDOW = "WINDOW"
    ICMP_ECHO = "ICMP_ECHO"
    UDP = "UDP"


class PortInference(Enum):
    """Inferred port state from probe response."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_OR_FILTERED = "open|filtered"
    UNFILTERED = "unfiltered"


@dataclass
class ProbeResult:
    target: str
    port: int
    probe_type: ProbeType
    inference: PortInference
    ttl: int = 0
    window_size: int = 0
    flags: str = ""
    raw_response: Optional[str] = None
    rtt_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DNSRecord:
    name: str
    record_type: str  # A, AAAA, MX, TXT, CNAME, NS, SOA, etc.
    value: str
    ttl: int = 0


@dataclass
class TraceHop:
    hop: int
    ip: str
    hostname: str = ""
    rtt_ms: float = 0.0
    is_target: bool = False


# =============================================================================
# PACKET CRAFTER
# =============================================================================

class PacketCrafter:
    """Low-level network probing with scapy."""

    def __init__(self, timeout: float = 3.0, iface: Optional[str] = None):
        self.timeout = timeout
        self.iface = iface

    # ---- ICMP ----

    async def ping(self, target: str, count: int = 1) -> bool:
        """Simple ICMP echo — returns True if host responds."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._ping_sync, target, count)

    def _ping_sync(self, target: str, count: int) -> bool:
        for _ in range(count):
            pkt = IP(dst=target) / ICMP()
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            if resp is not None:
                return True
        return False

    async def icmp_probe(self, target: str) -> Dict[str, Any]:
        """ICMP echo with full response details."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._icmp_probe_sync, target)

    def _icmp_probe_sync(self, target: str) -> Dict[str, Any]:
        import time
        pkt = IP(dst=target) / ICMP()
        start = time.monotonic()
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        rtt = (time.monotonic() - start) * 1000

        if resp is None:
            return {"alive": False, "target": target}

        return {
            "alive": True,
            "target": target,
            "ip": resp.src,
            "ttl": resp.ttl,
            "rtt_ms": round(rtt, 2),
            "icmp_type": resp[ICMP].type if resp.haslayer(ICMP) else None,
            "icmp_code": resp[ICMP].code if resp.haslayer(ICMP) else None,
        }

    # ---- TCP probes ----

    async def syn_probe(self, target: str, port: int) -> ProbeResult:
        """SYN probe — infer open/closed/filtered from response."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._tcp_probe_sync, target, port, "S", ProbeType.SYN)

    async def fin_probe(self, target: str, port: int) -> ProbeResult:
        """FIN probe — firewall evasion."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._tcp_probe_sync, target, port, "F", ProbeType.FIN)

    async def null_probe(self, target: str, port: int) -> ProbeResult:
        """NULL probe (no flags) — firewall evasion."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._tcp_probe_sync, target, port, "", ProbeType.NULL)

    async def xmas_probe(self, target: str, port: int) -> ProbeResult:
        """XMAS probe (FIN+PSH+URG) — firewall evasion."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._tcp_probe_sync, target, port, "FPU", ProbeType.XMAS)

    async def ack_probe(self, target: str, port: int) -> ProbeResult:
        """ACK probe — detect stateful vs stateless firewall."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._tcp_probe_sync, target, port, "A", ProbeType.ACK)

    async def window_probe(self, target: str, port: int) -> ProbeResult:
        """Window scan — ACK with window size analysis."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._tcp_probe_sync, target, port, "A", ProbeType.WINDOW)

    def _tcp_probe_sync(self, target: str, port: int, flags: str, probe_type: ProbeType) -> ProbeResult:
        import time
        pkt = IP(dst=target) / TCP(dport=port, sport=int(RandShort()), flags=flags)
        start = time.monotonic()
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        rtt = (time.monotonic() - start) * 1000

        result = ProbeResult(
            target=target, port=port, probe_type=probe_type,
            inference=PortInference.FILTERED, rtt_ms=round(rtt, 2),
        )

        if resp is None:
            # No response
            if probe_type in (ProbeType.SYN, ProbeType.ACK):
                result.inference = PortInference.FILTERED
            else:
                result.inference = PortInference.OPEN_OR_FILTERED
            return result

        if resp.haslayer(TCP):
            tcp = resp[TCP]
            result.flags = str(tcp.flags)
            result.ttl = resp.ttl
            result.window_size = tcp.window

            if probe_type == ProbeType.SYN:
                if tcp.flags == 0x12:  # SYN-ACK
                    result.inference = PortInference.OPEN
                elif tcp.flags & 0x04:  # RST
                    result.inference = PortInference.CLOSED
            elif probe_type == ProbeType.ACK:
                if tcp.flags & 0x04:  # RST
                    result.inference = PortInference.UNFILTERED
                else:
                    result.inference = PortInference.FILTERED
            elif probe_type == ProbeType.WINDOW:
                if tcp.flags & 0x04:
                    result.inference = PortInference.OPEN if tcp.window > 0 else PortInference.CLOSED
            elif probe_type in (ProbeType.FIN, ProbeType.NULL, ProbeType.XMAS):
                if tcp.flags & 0x04:  # RST
                    result.inference = PortInference.CLOSED
                else:
                    result.inference = PortInference.OPEN_OR_FILTERED

        elif resp.haslayer(ICMP):
            icmp = resp[ICMP]
            if icmp.type == 3 and icmp.code in (1, 2, 3, 9, 10, 13):
                result.inference = PortInference.FILTERED

        return result

    async def multi_probe(
        self, target: str, ports: List[int],
        probe_type: ProbeType = ProbeType.SYN,
    ) -> List[ProbeResult]:
        """Probe multiple ports concurrently."""
        probe_fn = {
            ProbeType.SYN: self.syn_probe,
            ProbeType.FIN: self.fin_probe,
            ProbeType.NULL: self.null_probe,
            ProbeType.XMAS: self.xmas_probe,
            ProbeType.ACK: self.ack_probe,
            ProbeType.WINDOW: self.window_probe,
        }.get(probe_type, self.syn_probe)

        tasks = [probe_fn(target, p) for p in ports]
        return await asyncio.gather(*tasks)

    # ---- DNS ----

    async def dns_query(
        self, domain: str, qtype: str = "A",
        nameserver: str = "8.8.8.8",
    ) -> List[DNSRecord]:
        """Query DNS records."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._dns_query_sync, domain, qtype, nameserver,
        )

    def _dns_query_sync(
        self, domain: str, qtype: str, nameserver: str,
    ) -> List[DNSRecord]:
        qtypes = {
            "A": 1, "AAAA": 28, "MX": 15, "NS": 2,
            "TXT": 16, "CNAME": 5, "SOA": 6, "PTR": 12,
            "SRV": 33, "ANY": 255,
        }
        qtype_num = qtypes.get(qtype.upper(), 1)

        pkt = IP(dst=nameserver) / UDP(dport=53) / DNS(
            rd=1, qd=DNSQR(qname=domain, qtype=qtype_num)
        )
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        records: List[DNSRecord] = []

        if resp is None or not resp.haslayer(DNS):
            return records

        dns = resp[DNS]
        for i in range(dns.ancount):
            try:
                rr = dns.an[i]
                rdata = str(rr.rdata)
                if isinstance(rr.rdata, bytes):
                    rdata = rr.rdata.decode("utf-8", errors="replace")
                records.append(DNSRecord(
                    name=rr.rrname.decode() if isinstance(rr.rrname, bytes) else str(rr.rrname),
                    record_type=qtype,
                    value=rdata,
                    ttl=rr.ttl,
                ))
            except Exception:
                continue

        return records

    async def dns_all_records(
        self, domain: str, nameserver: str = "8.8.8.8",
    ) -> Dict[str, List[DNSRecord]]:
        """Query all common record types."""
        types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        results: Dict[str, List[DNSRecord]] = {}
        for qt in types:
            recs = await self.dns_query(domain, qt, nameserver)
            if recs:
                results[qt] = recs
        return results

    # ---- Traceroute ----

    async def traceroute(
        self, target: str, max_hops: int = 30,
        dport: int = 80,
    ) -> List[TraceHop]:
        """TCP traceroute."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._traceroute_sync, target, max_hops, dport,
        )

    def _traceroute_sync(
        self, target: str, max_hops: int, dport: int,
    ) -> List[TraceHop]:
        import time
        hops: List[TraceHop] = []

        try:
            resolved = socket.gethostbyname(target)
        except socket.gaierror:
            return hops

        for ttl in range(1, max_hops + 1):
            pkt = IP(dst=target, ttl=ttl) / TCP(dport=dport, flags="S")
            start = time.monotonic()
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            rtt = (time.monotonic() - start) * 1000

            if resp is None:
                hops.append(TraceHop(hop=ttl, ip="*", rtt_ms=0))
                continue

            ip = resp.src
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror):
                hostname = ""

            is_target = ip == resolved
            hops.append(TraceHop(
                hop=ttl, ip=ip, hostname=hostname,
                rtt_ms=round(rtt, 2), is_target=is_target,
            ))

            if is_target:
                break

        return hops

    # ---- ARP (local network) ----

    async def arp_scan(self, network: str = "192.168.1.0/24") -> List[Dict[str, str]]:
        """ARP scan on local network."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._arp_scan_sync, network)

    def _arp_scan_sync(self, network: str) -> List[Dict[str, str]]:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        answered, _ = srp(pkt, timeout=self.timeout, verbose=0)
        hosts = []
        for sent, recv in answered:
            hosts.append({
                "ip": recv.psrc,
                "mac": recv.hwsrc,
            })
        return hosts

    # ---- Firewall fingerprinting ----

    async def fingerprint_firewall(
        self, target: str, port: int = 80,
    ) -> Dict[str, Any]:
        """Run multiple probe types to infer firewall behavior."""
        results = {}
        probes = [
            ("syn", self.syn_probe),
            ("fin", self.fin_probe),
            ("null", self.null_probe),
            ("xmas", self.xmas_probe),
            ("ack", self.ack_probe),
            ("window", self.window_probe),
        ]

        for name, fn in probes:
            r = await fn(target, port)
            results[name] = {
                "inference": r.inference.value,
                "flags": r.flags,
                "ttl": r.ttl,
                "window": r.window_size,
                "rtt_ms": r.rtt_ms,
            }

        # Analysis
        syn = results.get("syn", {}).get("inference", "")
        ack = results.get("ack", {}).get("inference", "")
        fin = results.get("fin", {}).get("inference", "")

        if syn == "open" and ack == "filtered":
            results["_analysis"] = "Stateful firewall detected (SYN passes, ACK blocked)"
        elif syn == "filtered" and fin == "open|filtered":
            results["_analysis"] = "Packet-filtering firewall (SYN blocked, FIN not rejected)"
        elif syn == "open" and ack == "unfiltered":
            results["_analysis"] = "No stateful firewall / minimal filtering"
        else:
            results["_analysis"] = "Mixed responses — inspect individual probe results"

        return results

    # ---- TLS probe ----

    async def tls_probe(self, target: str, port: int = 443) -> Dict[str, Any]:
        """Quick TLS handshake probe — returns certificate and protocol info."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._tls_probe_sync, target, port)

    def _tls_probe_sync(self, target: str, port: int) -> Dict[str, Any]:
        import socket as sock
        import ssl

        result: Dict[str, Any] = {"target": target, "port": port}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with sock.create_connection((target, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=target) as tls:
                    result["version"] = tls.version()
                    result["cipher"] = tls.cipher()
                    cert = tls.getpeercert(binary_form=False)
                    if cert:
                        result["subject"] = dict(x[0] for x in cert.get("subject", ()))
                        result["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                        result["notBefore"] = cert.get("notBefore")
                        result["notAfter"] = cert.get("notAfter")
                        result["san"] = [
                            v for t, v in cert.get("subjectAltName", ())
                        ]
                    else:
                        result["cert"] = "binary_only"
        except Exception as e:
            result["error"] = str(e)

        return result
