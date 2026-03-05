"""
BEATRIX Kill Chain Engine

Implements the Cyber Kill Chain for structured attack progression.
Each phase builds on the previous, tracking state through the engagement.

Kill Chain Phases:
1. Reconnaissance - Target discovery and enumeration
2. Weaponization - Payload and attack preparation
3. Delivery - Initial probing and request delivery
4. Exploitation - Vulnerability exploitation
5. Installation - Persistence (if applicable)
6. Command & Control - Data exfiltration testing
7. Actions on Objectives - Final impact assessment
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional


class KillChainPhase(Enum):
    """Cyber Kill Chain phases adapted for web application testing"""

    RECONNAISSANCE = 1
    WEAPONIZATION = 2
    DELIVERY = 3
    EXPLOITATION = 4
    INSTALLATION = 5
    COMMAND_CONTROL = 6
    ACTIONS_ON_OBJECTIVES = 7

    @property
    def name_pretty(self) -> str:
        return {
            KillChainPhase.RECONNAISSANCE: "Reconnaissance",
            KillChainPhase.WEAPONIZATION: "Weaponization",
            KillChainPhase.DELIVERY: "Delivery",
            KillChainPhase.EXPLOITATION: "Exploitation",
            KillChainPhase.INSTALLATION: "Installation",
            KillChainPhase.COMMAND_CONTROL: "Command & Control",
            KillChainPhase.ACTIONS_ON_OBJECTIVES: "Actions on Objectives",
        }[self]

    @property
    def description(self) -> str:
        return {
            KillChainPhase.RECONNAISSANCE: "Target discovery, subdomain enum, port scan, service detection",
            KillChainPhase.WEAPONIZATION: "Payload crafting, attack planning, WAF fingerprinting",
            KillChainPhase.DELIVERY: "Initial probing, endpoint discovery, parameter fuzzing",
            KillChainPhase.EXPLOITATION: "Vulnerability exploitation, injection testing",
            KillChainPhase.INSTALLATION: "Persistence mechanisms, backdoor testing",
            KillChainPhase.COMMAND_CONTROL: "Data exfiltration, callback testing, OOB channels",
            KillChainPhase.ACTIONS_ON_OBJECTIVES: "Impact assessment, final exploitation, reporting",
        }[self]

    @property
    def icon(self) -> str:
        return {
            KillChainPhase.RECONNAISSANCE: "🔍",
            KillChainPhase.WEAPONIZATION: "⚔️",
            KillChainPhase.DELIVERY: "📦",
            KillChainPhase.EXPLOITATION: "💥",
            KillChainPhase.INSTALLATION: "🔧",
            KillChainPhase.COMMAND_CONTROL: "📡",
            KillChainPhase.ACTIONS_ON_OBJECTIVES: "🎯",
        }[self]

    @property
    def modules(self) -> List[str]:
        """Default modules for this phase — maps to actual engine module keys."""
        return {
            KillChainPhase.RECONNAISSANCE: [
                "crawl", "endpoint_prober", "js_analysis", "headers", "github_recon"
            ],
            KillChainPhase.WEAPONIZATION: [
                "takeover", "error_disclosure", "cache_poisoning", "prototype_pollution"
            ],
            KillChainPhase.DELIVERY: [
                "cors", "redirect", "oauth_redirect", "http_smuggling", "websocket"
            ],
            KillChainPhase.EXPLOITATION: [
                "injection", "ssrf", "idor", "bac", "auth", "ssti", "xxe",
                "deserialization", "graphql", "mass_assignment", "business_logic",
                "redos", "payment", "nuclei"
            ],
            KillChainPhase.INSTALLATION: [
                "file_upload"
            ],
            KillChainPhase.COMMAND_CONTROL: [],
            KillChainPhase.ACTIONS_ON_OBJECTIVES: [],
        }[self]


class PhaseStatus(Enum):
    """Status of a kill chain phase"""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    SKIPPED = auto()
    FAILED = auto()


@dataclass
class PhaseResult:
    """Result from executing a kill chain phase"""
    phase: KillChainPhase
    status: PhaseStatus
    started_at: datetime
    completed_at: Optional[datetime] = None

    # Results
    findings: List[Any] = field(default_factory=list)
    discovered_assets: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    # Stats
    modules_run: List[str] = field(default_factory=list)
    requests_sent: int = 0

    # Data to pass to next phase
    context: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return 0.0


@dataclass
class KillChainState:
    """
    Tracks the state of a kill chain execution.

    The kill chain maintains context between phases, allowing
    later phases to build on discoveries from earlier phases.
    """
    target: str
    started_at: datetime = field(default_factory=datetime.now)
    current_phase: KillChainPhase = KillChainPhase.RECONNAISSANCE

    # Phase results
    phase_results: Dict[KillChainPhase, PhaseResult] = field(default_factory=dict)

    # Accumulated context (passed between phases)
    context: Dict[str, Any] = field(default_factory=lambda: {
        "subdomains": [],
        "endpoints": [],
        "parameters": [],
        "technologies": [],
        "findings": [],
        "credentials": [],
    })

    # Control
    paused: bool = False
    cancelled: bool = False

    @property
    def completed_phases(self) -> List[KillChainPhase]:
        """Phases that have been completed"""
        return [
            phase for phase, result in self.phase_results.items()
            if result.status == PhaseStatus.COMPLETED
        ]

    @property
    def all_findings(self) -> List[Any]:
        """All findings from all phases"""
        findings = []
        for result in self.phase_results.values():
            findings.extend(result.findings)
        return findings

    def advance_phase(self) -> Optional[KillChainPhase]:
        """Move to the next phase, returns None if at end"""
        phases = list(KillChainPhase)
        current_idx = phases.index(self.current_phase)

        if current_idx < len(phases) - 1:
            self.current_phase = phases[current_idx + 1]
            return self.current_phase
        return None

    def get_phase_result(self, phase: KillChainPhase) -> Optional[PhaseResult]:
        """Get result for a specific phase"""
        return self.phase_results.get(phase)

    def merge_context(self, new_context: Dict[str, Any]) -> None:
        """Merge new context from a phase into the accumulated context"""
        for key, value in new_context.items():
            if key in self.context and isinstance(self.context[key], list):
                # Extend lists, avoiding duplicates
                existing = set(str(x) for x in self.context[key])
                for item in value:
                    if str(item) not in existing:
                        self.context[key].append(item)
            else:
                self.context[key] = value


class KillChainExecutor:
    """
    Executes the kill chain against a target.

    Usage:
        executor = KillChainExecutor(engine)
        state = await executor.execute("example.com", phases=[1, 2, 3, 4])
    """

    def __init__(self, engine: Any, on_event: Optional[Callable] = None):
        self.engine = engine
        self.phase_handlers: Dict[KillChainPhase, Callable] = {}
        self._on_event = on_event  # Callback for real-time progress
        self._toolkit = None  # Lazy singleton — shared across all phases
        self._register_default_handlers()

    def _emit(self, event: str, **kwargs) -> None:
        """Emit a progress event to the callback."""
        if self._on_event:
            self._on_event(event, kwargs)

    @property
    def toolkit(self):
        """Lazy singleton ExternalToolkit — avoids repeated shutil.which() probing."""
        if self._toolkit is None:
            from beatrix.core.external_tools import ExternalToolkit
            self._toolkit = ExternalToolkit()
        return self._toolkit

    def _register_default_handlers(self) -> None:
        """Register default phase handlers mapping kill chain phases to scanner modules."""

        self.phase_handlers[KillChainPhase.RECONNAISSANCE] = self._handle_recon
        self.phase_handlers[KillChainPhase.WEAPONIZATION] = self._handle_weaponization
        self.phase_handlers[KillChainPhase.DELIVERY] = self._handle_delivery
        self.phase_handlers[KillChainPhase.EXPLOITATION] = self._handle_exploitation
        self.phase_handlers[KillChainPhase.INSTALLATION] = self._handle_installation
        self.phase_handlers[KillChainPhase.COMMAND_CONTROL] = self._handle_c2
        self.phase_handlers[KillChainPhase.ACTIONS_ON_OBJECTIVES] = self._handle_actions

    # =========================================================================
    # PHASE HANDLERS
    # =========================================================================

    # Per-scanner timeout (seconds) — prevents any single scanner from blocking the hunt.
    # Effectiveness is the priority: scanners get enough time to be thorough.
    SCANNER_TIMEOUT = 600  # 10 minutes default

    # Override timeouts for scanners that legitimately need more time.
    # Nuclei runs 12,600+ templates across ALL discovered URLs — needs real time.
    # Network pipeline phases have their own internal timeouts.
    SCANNER_TIMEOUT_OVERRIDES = {
        "nuclei": 3600,       # 1 hour — nuclei manages its own internal timeout
        "nmap_nse": 1800,     # 30 minutes — full NSE pipeline
        "ssh_auditor": 900,   # 15 minutes — SSH fingerprint + cred checks
        "packet_crafter": 900,  # 15 minutes — firewall analysis
        "origin_ip_discovery": 300,  # 5 minutes — CDN bypass / origin IP lookup
    }

    async def _run_scanner(self, scanner_name: str, target: str, context: Dict[str, Any],
                           scan_context=None) -> Dict[str, Any]:
        """
        Run a single scanner module from the engine and return structured output.

        Respects the preset's module list — if a module isn't in the requested
        list, it's silently skipped (unless the list is empty = run everything).

        Each scanner is wrapped in asyncio.wait_for with SCANNER_TIMEOUT to
        prevent any single module from hanging the entire hunt.
        """
        import asyncio

        from beatrix.scanners import ScanContext

        result = {"findings": [], "assets": [], "context": {}, "modules": [], "requests": 0}

        # Module filtering: skip if not in requested modules (empty = run all)
        requested_modules = context.get("modules", [])
        if requested_modules and scanner_name not in requested_modules:
            return result

        scanner = self.engine.modules.get(scanner_name)
        if scanner is None:
            return result

        # Mark this module as actually executed
        result["modules"] = [scanner_name]

        self._emit("scanner_start", scanner=scanner_name, target=target)

        try:
            url = target if "://" in target else f"https://{target}"
            ctx = scan_context or ScanContext.from_url(url)

            # Propagate crawl context so scanners have access to
            # discovered JS files, forms, technologies, etc.
            if not ctx.extra and context.get("crawl_extra"):
                ctx.extra = context["crawl_extra"]

            # Inject PoC server reference so scanners can register live PoCs
            if context.get("poc_server"):
                ctx.extra["poc_server"] = context["poc_server"]
            if context.get("oob_detector"):
                ctx.extra["oob_detector"] = context["oob_detector"]

            # Propagate auth credentials so scanners can make authenticated requests
            if context.get("auth"):
                ctx.extra["auth"] = context["auth"]

            async def _collect():
                async with scanner:
                    # Inject auth headers into the scanner's HTTP client
                    if context.get("auth") and hasattr(scanner, 'apply_auth'):
                        scanner.apply_auth(context["auth"])
                    async for finding in scanner.scan(ctx):
                        # Stamp module attribution if scanner didn't set it
                        if not finding.scanner_module:
                            finding.scanner_module = scanner_name
                        result["findings"].append(finding)
                        self._emit("finding", scanner=scanner_name, finding=finding)

            await asyncio.wait_for(_collect(), timeout=self.SCANNER_TIMEOUT_OVERRIDES.get(scanner_name, self.SCANNER_TIMEOUT))
        except asyncio.TimeoutError:
            effective_timeout = self.SCANNER_TIMEOUT_OVERRIDES.get(scanner_name, self.SCANNER_TIMEOUT)
            self._emit("scanner_error", scanner=scanner_name,
                       error=f"Timed out after {effective_timeout}s (partial results: {len(result['findings'])} findings)")
        except Exception as e:
            self._emit("scanner_error", scanner=scanner_name, error=str(e))

        self._emit("scanner_done", scanner=scanner_name, findings=len(result["findings"]))
        return result

    async def _run_scanner_on_urls(self, scanner_name: str, urls: list,
                                     context: Dict[str, Any]) -> Dict[str, Any]:
        """Run a scanner against multiple discovered URLs."""
        from beatrix.scanners import ScanContext

        result = {"findings": [], "assets": [], "context": {}, "modules": [], "requests": 0}

        # Module filtering: skip if not in requested modules (empty = run all)
        requested_modules = context.get("modules", [])
        if requested_modules and scanner_name not in requested_modules:
            return result

        scanner = self.engine.modules.get(scanner_name)
        if scanner is None:
            return result

        if not urls:
            return result

        # Mark this module as actually executed
        result["modules"] = [scanner_name]

        self._emit("scanner_start", scanner=scanner_name, target=f"{len(urls)} URLs")

        try:
            async def _collect_multi():
                async with scanner:
                    # Inject auth headers into the scanner's HTTP client
                    if context.get("auth") and hasattr(scanner, 'apply_auth'):
                        scanner.apply_auth(context["auth"])
                    for i, url in enumerate(urls):
                        try:
                            ctx = ScanContext.from_url(url)
                            ctx.extra = context.get("crawl_extra", {})
                            # Inject PoC server + OOB detector
                            if context.get("poc_server"):
                                ctx.extra["poc_server"] = context["poc_server"]
                            if context.get("oob_detector"):
                                ctx.extra["oob_detector"] = context["oob_detector"]
                            # Propagate auth credentials
                            if context.get("auth"):
                                ctx.extra["auth"] = context["auth"]

                            async for finding in scanner.scan(ctx):
                                # Stamp module attribution if scanner didn't set it
                                if not finding.scanner_module:
                                    finding.scanner_module = scanner_name
                                result["findings"].append(finding)
                                self._emit("finding", scanner=scanner_name, finding=finding)
                        except Exception as e:
                            self._emit("scanner_error", scanner=scanner_name,
                                       error=f"Error on URL {i+1}/{len(urls)} ({url}): {e}")
                            continue

            await asyncio.wait_for(_collect_multi(), timeout=self.SCANNER_TIMEOUT_OVERRIDES.get(scanner_name, self.SCANNER_TIMEOUT))
        except asyncio.TimeoutError:
            effective_timeout = self.SCANNER_TIMEOUT_OVERRIDES.get(scanner_name, self.SCANNER_TIMEOUT)
            self._emit("scanner_error", scanner=scanner_name,
                       error=f"Timed out after {effective_timeout}s scanning {len(urls)} URLs (partial results: {len(result['findings'])} findings)")
        except Exception as e:
            self._emit("scanner_error", scanner=scanner_name, error=str(e))

        self._emit("scanner_done", scanner=scanner_name, findings=len(result["findings"]))
        return result

    async def _merge_scanner_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge multiple scanner results into a single phase output."""
        merged = {"findings": [], "assets": [], "context": {}, "modules": [], "requests": 0}
        for r in results:
            merged["findings"].extend(r.get("findings", []))
            merged["assets"].extend(r.get("assets", []))
            merged["modules"].extend(r.get("modules", []))
            merged["requests"] += r.get("requests", 0)
            merged["context"].update(r.get("context", {}))
        return merged

    async def _handle_recon(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Phase 1 — Reconnaissance: Subdomain enum → Crawl → Port scan → Analyze.

        The crawler is the foundation. Without it, every subsequent scanner
        sees a bare URL with zero parameters, zero forms, zero endpoints.

        External tools (subfinder, nmap) are optional and gracefully skipped.
        """
        from beatrix.scanners import ScanContext

        results = []
        url = target if "://" in target else f"https://{target}"
        domain = url.split("://", 1)[1].split("/")[0].split(":")[0]

        # ── Step 0: Subdomain enumeration — subfinder + amass (optional) ──────
        # Only run for deep scans (not quick preset — too slow)
        requested_modules = context.get("modules", [])
        run_deep_recon = not requested_modules  # empty = full scan

        if run_deep_recon:
            toolkit = self.toolkit

            # Subfinder
            try:
                from beatrix.core.subfinder import SubfinderRunner
                subfinder = SubfinderRunner()
                if subfinder.available:
                    self._emit("info", message=f"Running subfinder on {domain}")
                    subdomains = await subfinder.enumerate(domain)
                    if subdomains:
                        context["subdomains"] = subdomains
                        self._emit("info", message=f"Subfinder found {len(subdomains)} subdomains")
                    else:
                        self._emit("info", message="Subfinder: no subdomains found")
            except Exception as e:
                self._emit("scanner_error", scanner="subfinder", error=str(e))

            # Amass — subdomain enumeration (active for deep scans, passive otherwise)
            try:
                if toolkit.amass.available:
                    self._emit("info", message=f"Running amass enum on {domain}")
                    amass_subs = await toolkit.amass.enumerate(domain, passive=False)
                    if amass_subs:
                        existing = set(context.get("subdomains", []))
                        new_subs = [s for s in amass_subs if s not in existing]
                        context.setdefault("subdomains", []).extend(new_subs)
                        self._emit("info", message=f"Amass found {len(new_subs)} new subdomains ({len(amass_subs)} total)")
            except Exception as e:
                self._emit("scanner_error", scanner="amass", error=str(e))

        # ── Step 1: Crawl the target ──────────────────────────────────────────
        crawler = self.engine.modules.get("crawl")
        crawl_result = None

        if crawler:
            self._emit("crawl_start", target=url)
            try:
                crawl_result = await crawler.crawl(url, auth=context.get("auth"))

                # Store crawl data in context for later phases
                context["crawl_result"] = crawl_result
                context["resolved_url"] = crawl_result.resolved_url or url
                context["discovered_urls"] = list(crawl_result.urls)
                context["urls_with_params"] = list(crawl_result.urls_with_params)
                context["js_files"] = list(crawl_result.js_files)
                context["forms"] = crawl_result.forms
                context["technologies"] = crawl_result.technologies
                # Normalize to dict for consistent downstream use
                if isinstance(context["technologies"], list):
                    context["technologies"] = {t: "" for t in context["technologies"]}
                context["discovered_paths"] = list(crawl_result.paths)
                context["cookies"] = crawl_result.cookies
                context["crawl_extra"] = {
                    "js_files": list(crawl_result.js_files),
                    "forms": crawl_result.forms,
                    "technologies": crawl_result.technologies,
                    "paths": list(crawl_result.paths),
                }

                # Use resolved URL for all subsequent scanners
                url = crawl_result.resolved_url or url

                self._emit("crawl_done",
                    pages=crawl_result.pages_crawled,
                    urls=len(crawl_result.urls),
                    params_urls=len(crawl_result.urls_with_params),
                    js_files=len(crawl_result.js_files),
                    forms=len(crawl_result.forms),
                    technologies=crawl_result.technologies,
                    resolved_url=url,
                )

            except Exception as e:
                self._emit("crawl_error", error=str(e))

        # ── Step 2: Network Reconnaissance Pipeline ─────────────────────────
        # 3-phase adaptive pipeline: DISCOVER → ANALYZE → AUDIT
        # Each phase's output drives the next. Replaces the old 1-1000 scan.
        if run_deep_recon:
            context["network"] = {
                "open_ports": [],
                "filtered_ports": [],
                "services": {},
                "firewall_profile": {},
                "bypass_findings": [],
                "nse_findings": [],
                "ssh_audit": [],
                "origin_ips": [],
                "cdn_detected": None,
                "cdn_ips": [],
                "scan_target": domain,  # May be replaced with origin IP
                "findings": [],
            }

            # ── Phase 0: CDN Detection & Origin IP Discovery ─────────────
            # Detects Cloudflare/Akamai/Fastly/CloudFront and attempts to find
            # the real origin IP via 6+ techniques (DNS history, crt.sh SSL,
            # MX records, subdomain correlation, misconfig checks, WHOIS).
            # If an origin IP is found, nmap scans THAT instead of the CDN edge.
            try:
                from beatrix.scanners.origin_ip_discovery import OriginIPDiscovery
                from beatrix.core.types import Finding, Severity, Confidence

                self._emit("info", message=f"Phase 0: CDN/WAF detection and origin IP discovery for {domain}")
                origin_discovery = OriginIPDiscovery()  # Reads API keys from env vars
                origin_result = await origin_discovery.discover(domain)

                context["network"]["cdn_detected"] = origin_result.cdn_detected
                context["network"]["cdn_ips"] = origin_result.cdn_ips

                if origin_result.cdn_detected:
                    self._emit("info", message=f"Phase 0: CDN detected — {origin_result.cdn_detected} (IPs: {', '.join(origin_result.cdn_ips)})")

                    # Generate info finding about CDN detection
                    cdn_finding = Finding(
                        severity=Severity.INFO,
                        confidence=Confidence.CONFIRMED,
                        url=domain,
                        title=f"CDN/WAF Detected: {origin_result.cdn_detected}",
                        description=(
                            f"Target {domain} is behind {origin_result.cdn_detected} CDN/WAF.\n"
                            f"CDN edge IPs: {', '.join(origin_result.cdn_ips)}\n"
                            f"Direct port scanning of CDN IPs reveals CDN infrastructure, "
                            f"not the target's actual attack surface."
                        ),
                        evidence={
                            "cdn": origin_result.cdn_detected,
                            "cdn_ips": origin_result.cdn_ips,
                            "techniques_used": origin_result.techniques_used,
                        },
                        scanner_module="origin_ip_discovery",
                    )
                    context["network"]["findings"].append(cdn_finding)

                if origin_result.discovered_ips:
                    context["network"]["origin_ips"] = origin_result.discovered_ips
                    # Log all discovered IPs
                    for ip_info in origin_result.discovered_ips:
                        conf_pct = ip_info.get('confidence', 0) * 100
                        validated = "validated" if ip_info.get('validated') else "unvalidated"
                        self._emit("info", message=(
                            f"  Origin IP: {ip_info['ip']} — {conf_pct:.0f}% confidence "
                            f"({ip_info.get('source', 'unknown')}, {validated})"
                        ))

                    # Pick best origin IP: validated first, then highest confidence
                    best_ip = None
                    # Sort: validated + high confidence first
                    sorted_ips = sorted(
                        origin_result.discovered_ips,
                        key=lambda x: (x.get('validated', False), x.get('confidence', 0)),
                        reverse=True,
                    )
                    best_ip = sorted_ips[0]

                    if best_ip.get('confidence', 0) >= 0.6 and not best_ip.get('hosting_provider_detected'):
                        origin_ip = best_ip['ip']
                        context["network"]["scan_target"] = origin_ip
                        self._emit("info", message=(
                            f"Phase 0: Using origin IP {origin_ip} "
                            f"({best_ip.get('confidence', 0) * 100:.0f}% confidence, "
                            f"source: {best_ip.get('source', 'unknown')}) "
                            f"for network scanning instead of CDN"
                        ))

                        # Generate finding for origin IP discovery
                        origin_finding = Finding(
                            severity=Severity.MEDIUM,
                            confidence=Confidence.FIRM if best_ip.get('validated') else Confidence.TENTATIVE,
                            url=domain,
                            title=f"Origin IP Discovered: {origin_ip} (bypasses {origin_result.cdn_detected or 'CDN'})",
                            description=(
                                f"The real origin IP of {domain} was discovered at {origin_ip}.\n"
                                f"Source: {best_ip.get('source', 'unknown')}\n"
                                f"Confidence: {best_ip.get('confidence', 0) * 100:.0f}%\n"
                                f"Validated: {best_ip.get('validated', False)}\n\n"
                                f"This IP can be used to bypass {origin_result.cdn_detected or 'CDN'} "
                                f"protections by sending requests directly to the origin server "
                                f"with the Host header set to {domain}.\n\n"
                                f"Techniques used: {', '.join(origin_result.techniques_used)}"
                            ),
                            evidence={
                                "origin_ip": origin_ip,
                                "confidence": best_ip.get('confidence', 0),
                                "source": best_ip.get('source', 'unknown'),
                                "validated": best_ip.get('validated', False),
                                "all_discovered": [
                                    {"ip": ip["ip"], "confidence": ip.get("confidence", 0), "source": ip.get("source")}
                                    for ip in origin_result.discovered_ips
                                ],
                                "cdn_bypassed": origin_result.cdn_detected,
                            },
                            scanner_module="origin_ip_discovery",
                        )
                        context["network"]["findings"].append(origin_finding)
                    else:
                        self._emit("info", message=(
                            f"Phase 0: Best origin IP {best_ip['ip']} has low confidence "
                            f"({best_ip.get('confidence', 0) * 100:.0f}%) — scanning domain directly"
                        ))

                elif origin_result.cdn_detected:
                    self._emit("info", message=(
                        f"Phase 0: CDN detected ({origin_result.cdn_detected}) but no origin IPs found. "
                        f"Network scan will target CDN edge. Set SECURITYTRAILS_API_KEY, "
                        f"CENSYS_API_ID/SECRET, or SHODAN_API_KEY for better results."
                    ))
                else:
                    self._emit("info", message=f"Phase 0: No CDN detected — scanning {domain} directly")

                # Add origin IP findings to results
                if context["network"]["findings"]:
                    results.append({
                        "findings": list(context["network"]["findings"]),
                        "assets": [], "context": {}, "modules": ["origin_ip_discovery"], "requests": 0,
                    })

            except ImportError as e:
                self._emit("info", message=f"origin_ip_discovery import failed ({e}) — scanning domain directly")
            except Exception as e:
                self._emit("scanner_error", scanner="origin_ip_discovery", error=str(e))

            # The target for all nmap/network scans — either origin IP or domain
            scan_target = context["network"].get("scan_target", domain)

            # ── Phase 1: DISCOVER (nmap) ──────────────────────────────────
            try:
                import nmap as _nmap_check  # noqa: F811, F401

                from beatrix.core.nmap_scanner import NetworkScanner
                nmap_scanner = NetworkScanner()

                # 1a: Full TCP SYN scan — all 65535 ports
                scan_label = f"{scan_target} (origin IP)" if scan_target != domain else domain
                self._emit("info", message=f"Network Phase 1a: Full TCP SYN scan on {scan_label} (all 65535 ports)")
                full_scan = await nmap_scanner.full_tcp_scan(scan_target, timeout=600)

                open_port_nums = []
                filtered_port_nums = []
                open_port_details = []

                if full_scan and full_scan.hosts:
                    for host in full_scan.hosts:
                        for port in host.ports:
                            if port.state.value == "open":
                                svc = f" ({port.service})" if port.service else ""
                                open_port_details.append(f"{port.port}/{port.protocol}{svc}")
                                open_port_nums.append(port.port)
                            elif port.state.value == "filtered":
                                filtered_port_nums.append(port.port)

                context["open_ports"] = open_port_details  # Legacy compat
                context["network"]["filtered_ports"] = filtered_port_nums

                if open_port_nums:
                    self._emit("info", message=f"Phase 1a: {len(open_port_nums)} open ports, {len(filtered_port_nums)} filtered")

                    # 1b: Service/version scan on open ports only
                    port_str = ",".join(str(p) for p in open_port_nums)
                    self._emit("info", message=f"Network Phase 1b: Service fingerprint on {len(open_port_nums)} open ports")
                    svc_scan = await nmap_scanner.service_scan(scan_target, ports=port_str)

                    # Build services map grouped by type
                    services_map: Dict[str, list] = {}
                    enriched_ports = []
                    if svc_scan and svc_scan.hosts:
                        for host in svc_scan.hosts:
                            for port in host.open_ports:
                                svc_name = port.service.lower() if port.service else "unknown"
                                # Normalize service names
                                if svc_name in ("https", "ssl/http", "https-alt"):
                                    svc_key = "https"
                                elif svc_name in ("http", "http-alt", "http-proxy"):
                                    svc_key = "http"
                                elif svc_name in ("ssh",):
                                    svc_key = "ssh"
                                elif svc_name in ("ftp", "ftps"):
                                    svc_key = "ftp"
                                elif svc_name in ("smtp", "smtps", "submission"):
                                    svc_key = "smtp"
                                elif svc_name in ("domain", "dns"):
                                    svc_key = "dns"
                                elif svc_name in ("mysql", "mariadb"):
                                    svc_key = "mysql"
                                elif svc_name in ("postgresql",):
                                    svc_key = "postgres"
                                elif svc_name in ("redis",):
                                    svc_key = "redis"
                                elif svc_name in ("mongod", "mongodb"):
                                    svc_key = "mongodb"
                                elif svc_name in ("ms-wbt-server", "rdp"):
                                    svc_key = "rdp"
                                elif svc_name in ("vnc",):
                                    svc_key = "vnc"
                                elif svc_name in ("microsoft-ds", "netbios-ssn"):
                                    svc_key = "smb"
                                else:
                                    svc_key = svc_name

                                services_map.setdefault(svc_key, []).append(port.port)
                                enriched_ports.append({
                                    "port": port.port,
                                    "protocol": port.protocol,
                                    "service": port.service,
                                    "product": port.product,
                                    "version": port.version,
                                    "cpe": port.cpe,
                                    "banner": port.banner,
                                    "scripts": port.scripts,
                                })

                    context["network"]["open_ports"] = enriched_ports
                    context["network"]["services"] = services_map
                    self._emit("info", message=f"Phase 1b: Services detected: {', '.join(f'{k}:{v}' for k, v in services_map.items())}")

                    # 1c-1e: NSE script scans (vuln, discovery, auth) on open ports
                    nse_findings = []
                    from beatrix.core.types import Finding, Severity, Confidence

                    # 1c: Vuln scripts
                    self._emit("info", message=f"Network Phase 1c: NSE vuln scripts on {len(open_port_nums)} ports")
                    try:
                        vuln_scan = await nmap_scanner.nse_vuln_scan(scan_target, port_str, timeout=600)
                        if vuln_scan and vuln_scan.hosts:
                            for host in vuln_scan.hosts:
                                for port in host.ports:
                                    for script_id, output in port.scripts.items():
                                        if "VULNERABLE" in output.upper() or "vulnerable" in output.lower():
                                            f = Finding(
                                                severity=Severity.HIGH,
                                                confidence=Confidence.FIRM,
                                                url=f"{domain}:{port.port}",
                                                title=f"NSE Vuln: {script_id} on port {port.port}",
                                                description=f"nmap NSE script '{script_id}' found a vulnerability on {domain}:{port.port}.\n\n{output[:2000]}",
                                                evidence={"script": script_id, "port": port.port, "output": output[:3000]},
                                                scanner_module="nmap_nse",
                                            )
                                            nse_findings.append(f)
                    except Exception as e:
                        self._emit("scanner_error", scanner="nmap_nse_vuln", error=str(e))

                    # 1d: Discovery scripts
                    self._emit("info", message=f"Network Phase 1d: NSE discovery scripts")
                    try:
                        disc_scan = await nmap_scanner.nse_discovery_scan(scan_target, port_str, timeout=600)
                        if disc_scan and disc_scan.hosts:
                            for host in disc_scan.hosts:
                                for port in host.ports:
                                    for script_id, output in port.scripts.items():
                                        # Store interesting discovery info
                                        enriched = next((p for p in enriched_ports if p["port"] == port.port), None)
                                        if enriched:
                                            enriched["scripts"][script_id] = output
                    except Exception as e:
                        self._emit("scanner_error", scanner="nmap_nse_discovery", error=str(e))

                    # 1e: Auth scripts
                    self._emit("info", message=f"Network Phase 1e: NSE auth scripts")
                    try:
                        auth_scan = await nmap_scanner.nse_auth_scan(scan_target, port_str, timeout=600)
                        if auth_scan and auth_scan.hosts:
                            for host in auth_scan.hosts:
                                for port in host.ports:
                                    for script_id, output in port.scripts.items():
                                        if any(kw in output.lower() for kw in ("anonymous", "default", "no password", "allowed")):
                                            f = Finding(
                                                severity=Severity.CRITICAL if "no password" in output.lower() else Severity.HIGH,
                                                confidence=Confidence.FIRM,
                                                url=f"{domain}:{port.port}",
                                                title=f"NSE Auth: {script_id} — weak auth on port {port.port}",
                                                description=f"nmap NSE script '{script_id}' found weak authentication on {domain}:{port.port}.\n\n{output[:2000]}",
                                                evidence={"script": script_id, "port": port.port, "output": output[:3000]},
                                                scanner_module="nmap_nse",
                                            )
                                            nse_findings.append(f)
                    except Exception as e:
                        self._emit("scanner_error", scanner="nmap_nse_auth", error=str(e))

                    context["network"]["nse_findings"] = nse_findings
                    if nse_findings:
                        self._emit("info", message=f"NSE scripts produced {len(nse_findings)} findings")
                        # Add NSE findings to main results
                        results.append({"findings": nse_findings, "assets": [], "context": {}, "modules": ["nmap_nse"], "requests": 0})

                    # 1f: Selective UDP scan (top 50 — DNS, SNMP, NTP, SSDP)
                    self._emit("info", message=f"Network Phase 1f: UDP scan (top 50 ports)")
                    try:
                        udp_scan = await nmap_scanner.selective_udp_scan(scan_target, top_n=50, timeout=120)
                        if udp_scan and udp_scan.hosts:
                            for host in udp_scan.hosts:
                                for port in host.open_ports:
                                    svc_key = port.service.lower() if port.service else "udp"
                                    services_map.setdefault(f"udp/{svc_key}", []).append(port.port)
                                    enriched_ports.append({
                                        "port": port.port, "protocol": "udp",
                                        "service": port.service, "product": port.product,
                                        "version": port.version, "cpe": port.cpe,
                                        "banner": port.banner, "scripts": port.scripts,
                                    })
                                    open_port_details.append(f"{port.port}/udp ({port.service})")
                            context["network"]["services"] = services_map
                            context["open_ports"] = open_port_details
                    except Exception as e:
                        self._emit("scanner_error", scanner="nmap_udp", error=str(e))

                else:
                    self._emit("info", message=f"Phase 1a: No open ports found on {scan_label}")

            except ImportError:
                self._emit("info", message="python-nmap not installed — network scanning skipped")
            except Exception as e:
                self._emit("scanner_error", scanner="nmap_pipeline", error=str(e))

            # ── Phase 2: ANALYZE (scapy) — firewall characterization ──────
            filtered_ports = context["network"].get("filtered_ports", [])
            if filtered_ports:
                try:
                    from beatrix.core.packet_crafter import PacketCrafter
                    crafter = PacketCrafter(timeout=3.0)
                    from beatrix.core.types import Finding, Severity, Confidence

                    # 2a: Firewall fingerprint on sampled filtered ports
                    sample_ports = filtered_ports[:5]  # Sample up to 5
                    self._emit("info", message=f"Network Phase 2a: Firewall fingerprint on {len(sample_ports)} filtered ports")
                    fw_profile = {}
                    for fp in sample_ports:
                        try:
                            fw = await crafter.fingerprint_firewall(scan_target, port=fp)
                            fw_profile[fp] = fw
                        except Exception:
                            continue

                    # Determine overall firewall type
                    fw_types = [v.get("_type", "unknown") for v in fw_profile.values()]
                    if fw_types:
                        from collections import Counter
                        overall_type = Counter(fw_types).most_common(1)[0][0]
                    else:
                        overall_type = "unknown"

                    context["network"]["firewall_profile"] = {
                        "type": overall_type,
                        "per_port": fw_profile,
                        "bypass_vectors": [],
                    }
                    self._emit("info", message=f"Phase 2a: Firewall type: {overall_type}")

                    # 2b: Source port bypass on filtered ports
                    self._emit("info", message=f"Network Phase 2b: Source port bypass testing")
                    bypass_findings = []
                    for fp in sample_ports:
                        try:
                            bypass_results = await crafter.source_port_bypass(scan_target, fp)
                            for br in bypass_results:
                                if br["bypass"]:
                                    context["network"]["firewall_profile"]["bypass_vectors"].append(
                                        f"source_port_{br['source_port']}_to_{fp}"
                                    )
                                    bypass_findings.append(Finding(
                                        severity=Severity.HIGH,
                                        confidence=Confidence.CONFIRMED,
                                        url=f"{domain}:{fp}",
                                        title=f"Firewall Bypass: Source port {br['source_port']} bypasses filter on port {fp}",
                                        description=(
                                            f"The firewall on {domain} allows traffic to filtered port {fp} when "
                                            f"originating from source port {br['source_port']}. This indicates the "
                                            f"firewall trusts traffic from 'service' ports, which is a misconfiguration "
                                            f"that can be exploited to access filtered services."
                                        ),
                                        evidence=br,
                                        scanner_module="packet_crafter",
                                    ))
                        except Exception:
                            continue

                    # 2c: Fragment bypass
                    self._emit("info", message=f"Network Phase 2c: IP fragmentation bypass testing")
                    for fp in sample_ports[:5]:
                        try:
                            frag_results = await crafter.fragment_bypass(scan_target, fp)
                            for fr in frag_results:
                                if fr.get("bypass"):
                                    context["network"]["firewall_profile"]["bypass_vectors"].append(
                                        f"fragment_{fr['fragment_size']}_to_{fp}"
                                    )
                                    bypass_findings.append(Finding(
                                        severity=Severity.HIGH,
                                        confidence=Confidence.CONFIRMED,
                                        url=f"{domain}:{fp}",
                                        title=f"Firewall Bypass: IP fragmentation (size={fr['fragment_size']}) bypasses filter on port {fp}",
                                        description=(
                                            f"The firewall on {domain} does not reassemble IP fragments, allowing "
                                            f"fragmented packets to reach port {fp}. Fragment size: {fr['fragment_size']} bytes."
                                        ),
                                        evidence=fr,
                                        scanner_module="packet_crafter",
                                    ))
                        except Exception:
                            continue

                    # 2d: TTL mapping
                    self._emit("info", message=f"Network Phase 2d: TTL-based firewall location mapping")
                    try:
                        sample_port = sample_ports[0] if sample_ports else 80
                        ttl_result = await crafter.ttl_map(scan_target, port=sample_port, max_hops=20)
                        context["network"]["firewall_profile"]["ttl_map"] = ttl_result
                        if ttl_result.get("firewall_hop"):
                            self._emit("info", message=f"Phase 2d: Firewall detected at hop {ttl_result['firewall_hop']}")
                    except Exception as e:
                        self._emit("scanner_error", scanner="ttl_map", error=str(e))

                    context["network"]["bypass_findings"] = bypass_findings
                    if bypass_findings:
                        self._emit("info", message=f"Phase 2: {len(bypass_findings)} firewall bypass findings")
                        results.append({"findings": bypass_findings, "assets": [], "context": {}, "modules": ["packet_crafter"], "requests": 0})

                except ImportError:
                    self._emit("info", message="scapy not installed — firewall analysis skipped")
                except Exception as e:
                    self._emit("scanner_error", scanner="firewall_analysis", error=str(e))
            else:
                self._emit("info", message="Phase 2: No filtered ports — firewall analysis skipped")

            # ── Phase 3: AUDIT — service-specific deep auditing ───────────
            services_map = context["network"].get("services", {})

            # 3a: SSH audit (paramiko)
            ssh_ports = services_map.get("ssh", [])
            if ssh_ports:
                try:
                    from beatrix.core.ssh_auditor import SSHAuditor
                    from beatrix.core.types import Finding, Severity, Confidence

                    auditor = SSHAuditor(timeout=10.0)
                    ssh_findings = []

                    for ssh_port in ssh_ports:
                        self._emit("info", message=f"Network Phase 3: SSH audit on {domain}:{ssh_port}")

                        # Fingerprint
                        fp = await auditor.fingerprint(scan_target, port=ssh_port)
                        context["network"]["ssh_audit"].append({
                            "port": ssh_port,
                            "banner": fp.banner,
                            "version": fp.ssh_version,
                            "server": fp.server_software,
                            "key_type": fp.key_type,
                            "key_bits": fp.key_bits,
                            "kex": fp.kex_algorithms,
                            "ciphers": fp.ciphers,
                            "macs": fp.macs,
                            "risks": fp.risks,
                        })

                        # Convert SSH risks to findings
                        for risk in fp.risks:
                            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                                       "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
                            ssh_findings.append(Finding(
                                severity=sev_map.get(risk["severity"], Severity.MEDIUM),
                                confidence=Confidence.CONFIRMED,
                                url=f"{domain}:{ssh_port}",
                                title=f"SSH: {risk['issue']} (port {ssh_port})",
                                description=f"{risk['issue']}\nDetail: {risk['detail']}\nRemediation: {risk['remediation']}",
                                evidence={"banner": fp.banner, "risk": risk, "port": ssh_port},
                                scanner_module="ssh_auditor",
                            ))

                        # Default credential check
                        self._emit("info", message=f"SSH: Checking default credentials on {domain}:{ssh_port}")
                        try:
                            valid_creds = await auditor.check_default_creds(scan_target, port=ssh_port)
                            for cred in valid_creds:
                                ssh_findings.append(Finding(
                                    severity=Severity.CRITICAL,
                                    confidence=Confidence.CONFIRMED,
                                    url=f"{domain}:{ssh_port}",
                                    title=f"SSH Default Credentials: {cred.username}:{cred.password} on port {ssh_port}",
                                    description=(
                                        f"Default SSH credentials work on {domain}:{ssh_port}.\n"
                                        f"Username: {cred.username}\nPassword: {'(empty)' if not cred.password else cred.password}\n"
                                        f"This allows direct system access."
                                    ),
                                    evidence={"username": cred.username, "port": ssh_port},
                                    scanner_module="ssh_auditor",
                                ))
                        except Exception as e:
                            self._emit("scanner_error", scanner="ssh_cred_check", error=str(e))

                    if ssh_findings:
                        self._emit("info", message=f"SSH audit produced {len(ssh_findings)} findings")
                        results.append({"findings": ssh_findings, "assets": [], "context": {}, "modules": ["ssh_auditor"], "requests": 0})
                        context["network"]["findings"].extend(ssh_findings)

                except ImportError:
                    self._emit("info", message="paramiko not installed — SSH audit skipped")
                except Exception as e:
                    self._emit("scanner_error", scanner="ssh_auditor", error=str(e))

            # 3b: Service-specific NSE scripts for non-web services
            nse_service_targets = {
                svc: ports for svc, ports in services_map.items()
                if svc in ("ftp", "smtp", "dns", "mysql", "postgres", "redis",
                           "mongodb", "smb", "rdp", "vnc")
            }

            if nse_service_targets:
                try:
                    from beatrix.core.nmap_scanner import NetworkScanner  # noqa: F811
                    from beatrix.core.types import Finding, Severity, Confidence
                    nmap_scanner = NetworkScanner()  # noqa: F811

                    for svc, ports in nse_service_targets.items():
                        port_str = ",".join(str(p) for p in ports)
                        self._emit("info", message=f"Network Phase 3: {svc} audit (ports {port_str})")
                        try:
                            svc_result = await nmap_scanner.nse_service_scripts(scan_target, port_str, svc, timeout=300)
                            if svc_result and svc_result.hosts:
                                for host in svc_result.hosts:
                                    for port in host.ports:
                                        for script_id, output in port.scripts.items():
                                            # Flag critical unauthenticated access
                                            output_lower = output.lower()
                                            is_critical = any(kw in output_lower for kw in
                                                ("no auth", "anonymous", "no password", "unauthenticated",
                                                 "backdoor", "vulnerable"))
                                            if is_critical:
                                                svc_finding = Finding(
                                                    severity=Severity.CRITICAL,
                                                    confidence=Confidence.FIRM,
                                                    url=f"{domain}:{port.port}",
                                                    title=f"Service Audit: {script_id} on {svc} port {port.port}",
                                                    description=f"NSE script '{script_id}' flagged a critical issue on {svc} service.\n\n{output[:2000]}",
                                                    evidence={"script": script_id, "service": svc, "port": port.port, "output": output[:3000]},
                                                    scanner_module="nmap_nse",
                                                )
                                                context["network"]["findings"].append(svc_finding)
                                                results.append({"findings": [svc_finding], "assets": [], "context": {}, "modules": ["nmap_nse"], "requests": 0})
                        except Exception as e:
                            self._emit("scanner_error", scanner=f"nse_{svc}", error=str(e))

                except ImportError:
                    pass
                except Exception as e:
                    self._emit("scanner_error", scanner="nse_service_audit", error=str(e))

            # 3c: TLS audit on all SSL/TLS ports
            tls_ports = services_map.get("https", []) + services_map.get("ssl", [])
            if tls_ports:
                try:
                    from beatrix.core.nmap_scanner import NetworkScanner  # noqa: F811
                    nmap_scanner = NetworkScanner()  # noqa: F811
                    port_str = ",".join(str(p) for p in set(tls_ports))
                    self._emit("info", message=f"Network Phase 3: TLS audit on ports {port_str}")
                    tls_scan = await nmap_scanner.nse_service_scripts(scan_target, port_str, "ssl", timeout=300)
                    if tls_scan and tls_scan.hosts:
                        from beatrix.core.types import Finding, Severity, Confidence
                        for host in tls_scan.hosts:
                            for port in host.ports:
                                for script_id, output in port.scripts.items():
                                    output_lower = output.lower()
                                    if any(kw in output_lower for kw in ("vulnerable", "heartbleed", "poodle", "weak", "sslv3", "tlsv1.0")):
                                        f = Finding(
                                            severity=Severity.HIGH if "heartbleed" in output_lower else Severity.MEDIUM,
                                            confidence=Confidence.CONFIRMED,
                                            url=f"{domain}:{port.port}",
                                            title=f"TLS Weakness: {script_id} on port {port.port}",
                                            description=f"NSE script '{script_id}' found TLS weakness.\n\n{output[:2000]}",
                                            evidence={"script": script_id, "port": port.port, "output": output[:3000]},
                                            scanner_module="nmap_nse",
                                        )
                                        context["network"]["findings"].append(f)
                                        results.append({"findings": [f], "assets": [], "context": {}, "modules": ["nmap_nse"], "requests": 0})
                except ImportError:
                    pass
                except Exception as e:
                    self._emit("scanner_error", scanner="tls_audit", error=str(e))

            # Summary
            net = context["network"]
            total_findings = len(net.get("findings", [])) + len(net.get("nse_findings", [])) + len(net.get("bypass_findings", []))
            self._emit("info", message=(
                f"Network pipeline complete: {len(net.get('open_ports', []))} services, "
                f"{len(net.get('filtered_ports', []))} filtered, "
                f"fw={net.get('firewall_profile', {}).get('type', 'n/a')}, "
                f"{total_findings} network findings"
            ))

            # ── Nuclei Network Scan — protocol-specific checks on non-HTTP ports ──
            # Feeds discovered services (Redis, MongoDB, FTP, SMTP, etc.) to nuclei's
            # network templates for unauthenticated access, default creds, CVEs.
            nuclei_net = self.engine.modules.get("nuclei")
            if nuclei_net and hasattr(nuclei_net, 'available') and nuclei_net.available:
                services = net.get("services", {})
                http_ports = set(services.get("http", []) + services.get("https", []))
                network_targets = []
                for svc_name, ports in services.items():
                    if svc_name in ("http", "https"):
                        continue
                    for port in ports:
                        network_targets.append(f"{scan_target}:{port}")

                if network_targets:
                    try:
                        nuclei_net.add_network_targets(network_targets)

                        # Configure auth for network scan
                        auth = context.get("auth")
                        if auth and hasattr(auth, 'nuclei_header_flags'):
                            nuclei_net.set_auth(auth.nuclei_header_flags())

                        net_ctx = ScanContext.from_url(url)
                        self._emit("info", message=f"Nuclei network scan: {len(network_targets)} non-HTTP services")

                        net_result = {"findings": [], "assets": [], "context": {}, "modules": ["nuclei_network"], "requests": 0}
                        async with nuclei_net:
                            async for finding in nuclei_net.scan_network(net_ctx):
                                if not finding.scanner_module:
                                    finding.scanner_module = "nuclei_network"
                                net_result["findings"].append(finding)
                                self._emit("finding", scanner="nuclei_network", finding=finding)

                        if net_result["findings"]:
                            results.append(net_result)
                            self._emit("scanner_done", scanner="nuclei_network", findings=len(net_result["findings"]))
                    except Exception as e:
                        self._emit("scanner_error", scanner="nuclei_network", error=str(e))

        # ── Step 3: External crawlers — katana, gospider, hakrawler, gau ──
        # Feed discovered URLs back into the attack surface
        if run_deep_recon:
            # Build auth header dict for external tools that accept -H flags
            _ext_auth_headers = {}
            _auth_obj = context.get("auth")
            if _auth_obj and hasattr(_auth_obj, 'all_headers'):
                _ext_auth_headers = _auth_obj.all_headers()

            try:
                discovered_urls = set(context.get("discovered_urls", []))
                urls_with_params = set(context.get("urls_with_params", []))

                # GAU — historical URLs from Wayback Machine, OTX, Common Crawl
                if toolkit.gau.available:
                    self._emit("info", message=f"Running gau on {domain} (historical URL discovery)")
                    try:
                        gau_urls = await toolkit.gau.fetch_urls(domain, subs=True)
                        if gau_urls:
                            for u in gau_urls:
                                discovered_urls.add(u)
                                if "?" in u:
                                    urls_with_params.add(u)
                            self._emit("info", message=f"GAU found {len(gau_urls)} historical URLs")
                    except Exception as e:
                        self._emit("scanner_error", scanner="gau", error=str(e))

                # Katana — deep JS crawling and endpoint extraction
                if toolkit.katana.available:
                    self._emit("info", message=f"Running katana on {url} (deep JS crawling)")
                    try:
                        katana_result = await toolkit.katana.crawl(
                            url, depth=3, js_crawl=True,
                            custom_headers=_ext_auth_headers or None,
                        )
                        for u in katana_result.get("urls", []):
                            discovered_urls.add(u)
                            if "?" in u:
                                urls_with_params.add(u)
                        js_from_katana = katana_result.get("js_urls", [])
                        if js_from_katana:
                            context.setdefault("js_files", []).extend(js_from_katana)
                        form_urls = katana_result.get("form_urls", [])
                        if form_urls:
                            for fu in form_urls:
                                discovered_urls.add(fu)
                                urls_with_params.add(fu)
                            context.setdefault("form_urls", []).extend(form_urls)
                        self._emit("info", message=f"Katana found {len(katana_result.get('urls', []))} URLs, {len(js_from_katana)} JS files, {len(form_urls)} forms")
                    except Exception as e:
                        self._emit("scanner_error", scanner="katana", error=str(e))

                # Gospider — web spidering
                if toolkit.gospider.available:
                    self._emit("info", message=f"Running gospider on {url}")
                    try:
                        spider_result = await toolkit.gospider.spider(
                            url, depth=2,
                            custom_headers=_ext_auth_headers or None,
                        )
                        for u in spider_result.get("urls", []):
                            discovered_urls.add(u)
                            if "?" in u:
                                urls_with_params.add(u)
                        for sub in spider_result.get("subdomains", []):
                            context.setdefault("subdomains", []).append(sub)
                        # Consume JS files and forms from gospider
                        spider_js = spider_result.get("js_files", [])
                        if spider_js:
                            context.setdefault("js_files", []).extend(spider_js)
                        spider_forms = spider_result.get("forms", [])
                        if spider_forms:
                            for fu in spider_forms:
                                discovered_urls.add(fu)
                                urls_with_params.add(fu)
                            context.setdefault("form_urls", []).extend(spider_forms)
                        self._emit("info", message=f"Gospider found {len(spider_result.get('urls', []))} URLs, {len(spider_js)} JS, {len(spider_forms)} forms")
                    except Exception as e:
                        self._emit("scanner_error", scanner="gospider", error=str(e))

                # Hakrawler — endpoint crawler
                if toolkit.hakrawler.available:
                    self._emit("info", message=f"Running hakrawler on {url}")
                    try:
                        hak_urls = await toolkit.hakrawler.crawl(url, depth=2)
                        for u in hak_urls:
                            discovered_urls.add(u)
                            if "?" in u:
                                urls_with_params.add(u)
                        self._emit("info", message=f"Hakrawler found {len(hak_urls)} URLs")
                    except Exception as e:
                        self._emit("scanner_error", scanner="hakrawler", error=str(e))

                # Merge all discovered URLs back into context
                context["discovered_urls"] = sorted(discovered_urls)
                context["urls_with_params"] = sorted(urls_with_params)

            except Exception as e:
                self._emit("scanner_error", scanner="external_crawlers", error=str(e))

        # ── Step 4: Tech fingerprinting — whatweb + webanalyze ─────────────
        if run_deep_recon:
            try:
                combined_techs = {}
                # Preserve existing technologies from crawler (List[str] → Dict[str, str])
                existing = context.get("technologies", [])
                if isinstance(existing, list):
                    for tech in existing:
                        combined_techs[tech] = ""
                elif isinstance(existing, dict):
                    combined_techs.update(existing)

                # WhatWeb — deep tech fingerprinting (1800+ plugins)
                if toolkit.whatweb.available:
                    self._emit("info", message=f"Running whatweb on {url} (tech fingerprinting)")
                    try:
                        whatweb_techs = await toolkit.whatweb.fingerprint(url)
                        if whatweb_techs:
                            combined_techs.update(whatweb_techs)
                            self._emit("info", message=f"WhatWeb identified {len(whatweb_techs)} technologies")
                    except Exception as e:
                        self._emit("scanner_error", scanner="whatweb", error=str(e))

                # Webanalyze — Wappalyzer fingerprint database
                if toolkit.webanalyze.available:
                    self._emit("info", message=f"Running webanalyze on {url} (Wappalyzer fingerprinting)")
                    try:
                        wa_techs = await toolkit.webanalyze.fingerprint(url)
                        if wa_techs:
                            combined_techs.update(wa_techs)
                            self._emit("info", message=f"Webanalyze identified {len(wa_techs)} technologies")
                    except Exception as e:
                        self._emit("scanner_error", scanner="webanalyze", error=str(e))

                if combined_techs:
                    context["technologies"] = combined_techs

            except Exception as e:
                self._emit("scanner_error", scanner="tech_fingerprint", error=str(e))

        # ── Step 5: Dirsearch — directory and file brute-force ─────────────
        if run_deep_recon:
            try:
                if toolkit.dirsearch.available:
                    # Adapt extensions based on detected technology stack
                    techs_lower = " ".join(
                        k.lower() for k in context.get("technologies", {})
                    ) if isinstance(context.get("technologies"), dict) else ""
                    ext_parts = ["html", "js", "json", "txt", "xml", "yml", "yaml", "env", "bak", "old"]
                    if any(t in techs_lower for t in ("php", "wordpress", "drupal", "joomla", "laravel")):
                        ext_parts.extend(["php", "phtml", "inc", "php.bak"])
                    if any(t in techs_lower for t in ("asp", ".net", "iis")):
                        ext_parts.extend(["asp", "aspx", "ashx", "asmx", "config"])
                    if any(t in techs_lower for t in ("java", "spring", "tomcat", "struts")):
                        ext_parts.extend(["jsp", "jspa", "do", "action", "java"])
                    if any(t in techs_lower for t in ("python", "django", "flask", "fastapi")):
                        ext_parts.extend(["py", "pyc"])
                    if any(t in techs_lower for t in ("ruby", "rails")):
                        ext_parts.extend(["rb", "erb"])
                    if any(t in techs_lower for t in ("node", "express", "next")):
                        ext_parts.extend(["mjs", "ts", "tsx", "jsx"])
                    extensions = ",".join(sorted(set(ext_parts)))

                    self._emit("info", message=f"Running dirsearch on {url} (extensions: {extensions})")
                    try:
                        ds_result = await toolkit.dirsearch.scan(url, extensions=extensions)
                        ds_found = ds_result.get("found", [])
                        if ds_found:
                            base = url.rstrip("/")
                            dirsearch_details = []
                            for entry in ds_found:
                                path = entry.get("path", "")
                                status = entry.get("status", 0)
                                size = entry.get("size", 0)
                                redirect = entry.get("redirect", "")
                                if path:
                                    full_url = f"{base}{path}" if path.startswith("/") else f"{base}/{path}"
                                    context.setdefault("discovered_urls", []).append(full_url)
                                    context.setdefault("discovered_paths", []).append(path)
                                    dirsearch_details.append({
                                        "path": path,
                                        "url": full_url,
                                        "status": status,
                                        "size": size,
                                        "redirect": redirect,
                                    })
                            context["dirsearch_results"] = dirsearch_details
                            self._emit("info", message=f"Dirsearch found {len(ds_found)} paths")
                    except Exception as e:
                        self._emit("scanner_error", scanner="dirsearch", error=str(e))
            except Exception as e:
                self._emit("scanner_error", scanner="dirsearch", error=str(e))

        # ── Step 6-9: Run recon scanners concurrently ─────────────────────
        # These scanners are independent — run them in parallel for speed
        import asyncio

        js_scan_ctx = None
        js_files = context.get("js_files", [])
        if crawl_result and crawl_result.js_files:
            js_files = list(set(js_files + list(crawl_result.js_files)))
        if js_files:
            js_scan_ctx = ScanContext.from_url(url)
            js_scan_ctx.extra = {"js_files": js_files}

        scanner_tasks = [
            self._run_scanner("endpoint_prober", url, context),
            self._run_scanner("js_analysis", url, context, scan_context=js_scan_ctx),
            self._run_scanner("headers", url, context),
            self._run_scanner("github_recon", url, context),
        ]

        # ── Nuclei Recon — fast tech/panel/WAF detection ──────────────────
        # Runs scan_recon() in parallel with other recon scanners.
        # Feeds technology fingerprints and exposed panels back for Phase 4.
        nuclei = self.engine.modules.get("nuclei")
        if nuclei and hasattr(nuclei, 'available') and nuclei.available:
            async def _nuclei_recon_task():
                """Run nuclei recon pass and return structured result."""
                result = {"findings": [], "assets": [], "context": {}, "modules": ["nuclei_recon"], "requests": 0}
                try:
                    # Feed discovered URLs (from crawl + dirsearch)
                    recon_urls = context.get("discovered_urls", [])
                    if hasattr(nuclei, 'add_urls') and recon_urls:
                        nuclei.add_urls(recon_urls)

                    # Feed tech fingerprints for intelligent tag selection
                    if hasattr(nuclei, 'set_technologies'):
                        techs = context.get("technologies", {})
                        nuclei.set_technologies(techs)

                    # Configure auth for authenticated recon
                    auth = context.get("auth")
                    if auth and hasattr(auth, 'nuclei_header_flags'):
                        nuclei.set_auth(auth.nuclei_header_flags())

                    recon_ctx = ScanContext.from_url(url)
                    recon_ctx.extra = {"technologies": context.get("technologies", {})}

                    self._emit("scanner_start", scanner="nuclei_recon", target=url)
                    async with nuclei:
                        async for finding in nuclei.scan_recon(recon_ctx):
                            if not finding.scanner_module:
                                finding.scanner_module = "nuclei_recon"
                            result["findings"].append(finding)
                            self._emit("finding", scanner="nuclei_recon", finding=finding)

                            # Extract tech discoveries from nuclei findings to enrich
                            # the technology fingerprint for Phase 4
                            title_lower = (getattr(finding, "title", "") or "").lower()
                            for tech_key in nuclei.TECH_TAG_MAP:
                                if tech_key in title_lower:
                                    context.setdefault("technologies", {})[tech_key] = True

                    self._emit("scanner_done", scanner="nuclei_recon", findings=len(result["findings"]))
                except asyncio.TimeoutError:
                    self._emit("scanner_error", scanner="nuclei_recon", error="Timed out")
                except Exception as e:
                    self._emit("scanner_error", scanner="nuclei_recon", error=str(e))
                return result

            scanner_tasks.append(asyncio.wait_for(
                _nuclei_recon_task(),
                timeout=self.SCANNER_TIMEOUT_OVERRIDES.get("nuclei", self.SCANNER_TIMEOUT)
            ))

        concurrent_results = await asyncio.gather(*scanner_tasks, return_exceptions=True)
        for r in concurrent_results:
            if isinstance(r, Exception):
                self._emit("scanner_error", scanner="recon", error=str(r))
            else:
                results.append(r)

        # ── Step 7: Extract JS-discovered endpoints and feed them back ────
        # JS bundle scanner and endpoint_prober store discovered URLs only
        # inside Finding objects. Without this extraction, exploitation
        # scanners starve on SPAs (0 URLs with params).
        discovered_urls = set(context.get("discovered_urls", []))
        urls_with_params = set(context.get("urls_with_params", []))
        base_url = url.rstrip("/")

        for r in results:
            for finding in r.get("findings", []):
                scanner = getattr(finding, "scanner_module", "") if hasattr(finding, "scanner_module") else ""

                # --- JS bundle: extract API routes from evidence JSON ---
                if scanner == "js_analysis" and "API Routes Disclosed" in (getattr(finding, "title", "") or ""):
                    try:
                        evidence = getattr(finding, "evidence", None)
                        if evidence and isinstance(evidence, str):
                            endpoints = json.loads(evidence)
                            if isinstance(endpoints, list):
                                for ep in endpoints:
                                    if not ep or not isinstance(ep, str):
                                        continue
                                    # Resolve relative paths to full URLs
                                    if ep.startswith(("http://", "https://")):
                                        full = ep
                                    elif ep.startswith("/"):
                                        full = f"{base_url}{ep}"
                                    else:
                                        full = f"{base_url}/{ep}"
                                    discovered_urls.add(full)
                                    if "?" in full or "=" in full:
                                        urls_with_params.add(full)
                                self._emit("info", message=f"Extracted {len(endpoints)} API endpoints from JS bundle analysis into attack surface")
                    except (json.JSONDecodeError, TypeError):
                        pass

                # --- Endpoint prober: extract live endpoints ---
                if scanner == "endpoint_prober":
                    ep_url = getattr(finding, "url", "")
                    if ep_url and ep_url.startswith(("http://", "https://")):
                        discovered_urls.add(ep_url)
                        if "?" in ep_url or "=" in ep_url:
                            urls_with_params.add(ep_url)

                # --- Internal hosts from JS (may reveal additional targets) ---
                if scanner == "js_analysis" and "Internal Hostnames" in (getattr(finding, "title", "") or ""):
                    try:
                        evidence = getattr(finding, "evidence", None)
                        if evidence and isinstance(evidence, str):
                            hosts = json.loads(evidence)
                            if isinstance(hosts, list):
                                context.setdefault("internal_hosts", []).extend(hosts)
                    except (json.JSONDecodeError, TypeError):
                        pass

        # Update context with the enriched URL sets
        prev_url_count = len(context.get("discovered_urls", []))
        prev_param_count = len(context.get("urls_with_params", []))
        context["discovered_urls"] = sorted(discovered_urls)
        context["urls_with_params"] = sorted(urls_with_params)
        self._emit("info", message=(
            f"Attack surface after recon: {len(discovered_urls)} URLs "
            f"(+{len(discovered_urls) - prev_url_count} from JS/endpoint analysis), "
            f"{len(urls_with_params)} with params (+{len(urls_with_params) - prev_param_count})"
        ))

        merged = await self._merge_scanner_results(results)

        # Add discovered assets to the merged result
        all_discovered = sorted(discovered_urls)
        if crawl_result:
            all_discovered = sorted(set(all_discovered + list(crawl_result.urls)))

        merged["assets"] = all_discovered[:200]
        merged["context"] = {
            "endpoints": all_discovered,
            "parameters": list(crawl_result.parameters.keys()) if crawl_result else [],
            "technologies": context.get("technologies", {}),
        }

        return merged

    async def _handle_weaponization(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 2 — Weaponization: takeover, error disclosure, cache poisoning, prototype pollution."""
        url = context.get("resolved_url", target if "://" in target else f"https://{target}")

        results = []
        # Takeover works on the base domain
        results.append(await self._run_scanner("takeover", url, context))

        # Error disclosure — run on discovered URLs that might have interesting error pages
        discovered = context.get("discovered_urls", [url])
        sample_urls = list(set(discovered))[:20]
        results.append(await self._run_scanner_on_urls("error_disclosure", sample_urls, context))

        # Cache poisoning — test for unkeyed header/param manipulation
        results.append(await self._run_scanner("cache_poisoning", url, context))

        # Prototype pollution — test JSON bodies and query params for __proto__
        discovered_with_params = context.get("urls_with_params", [])
        if discovered_with_params:
            results.append(await self._run_scanner_on_urls(
                "prototype_pollution", discovered_with_params[:15], context))
        else:
            results.append(await self._run_scanner("prototype_pollution", url, context))

        return await self._merge_scanner_results(results)

    async def _handle_delivery(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 3 — Delivery: CORS, redirects, OAuth, HTTP smuggling, WebSocket."""
        url = context.get("resolved_url", target if "://" in target else f"https://{target}")

        results = []

        # Expand HTTP targets from network context — test ALL HTTP ports, not just 443
        http_targets = [url]
        net = context.get("network", {})
        services = net.get("services", {})
        domain = url.split("://", 1)[1].split("/")[0].split(":")[0] if "://" in url else url.split("/")[0].split(":")[0]
        for port in services.get("http", []):
            if port != 80:
                http_targets.append(f"http://{domain}:{port}")
            else:
                http_targets.append(f"http://{domain}")
        for port in services.get("https", []):
            if port != 443:
                http_targets.append(f"https://{domain}:{port}")
        http_targets = list(dict.fromkeys(http_targets))  # Dedupe preserving order

        # If origin IP was discovered, also test directly against origin (bypasses CDN/WAF)
        origin_ips = net.get("origin_ips", [])
        scan_target = net.get("scan_target", domain)
        if scan_target != domain:
            # Add origin IP HTTP targets — these bypass CDN protections
            origin_http = f"http://{scan_target}"
            origin_https = f"https://{scan_target}"
            if origin_http not in http_targets:
                http_targets.append(origin_http)
            if origin_https not in http_targets:
                http_targets.append(origin_https)
            self._emit("info", message=f"Delivery: also testing origin IP {scan_target} directly (CDN bypass)")

        if len(http_targets) > 1:
            self._emit("info", message=f"Delivery phase testing {len(http_targets)} HTTP ports: {', '.join(http_targets)}")

        # CORS — test base URL and any API endpoints found
        results.append(await self._run_scanner("cors", url, context))

        # Redirect — test URLs that have redirect-like parameters
        urls_with_params = context.get("urls_with_params", [])
        if urls_with_params:
            results.append(await self._run_scanner_on_urls("redirect", urls_with_params, context))
        else:
            results.append(await self._run_scanner("redirect", url, context))

        # OAuth redirect — test OAuth/SSO redirect_uri manipulation
        results.append(await self._run_scanner("oauth_redirect", url, context))

        # HTTP smuggling — CL.TE, TE.CL, H2 desync — on ALL HTTP ports
        for ht in http_targets:
            results.append(await self._run_scanner("http_smuggling", ht, context))

        # WebSocket — check for WS upgrade, CSWSH, auth issues
        results.append(await self._run_scanner("websocket", url, context))

        return await self._merge_scanner_results(results)

    async def _handle_exploitation(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Phase 4 — Exploitation: Full vulnerability testing.

        Runs ALL exploitation scanners against crawled URLs.
        Context propagation is critical — without crawled URLs+params,
        injection scanners find 0 insertion points on the bare domain.

        Network context integration:
        - Tests all HTTP ports from network scan, not just 443
        - SSH audit findings are already in results from Phase 1
        - Firewall bypass findings are already in results from Phase 1
        - Origin IP bypass triggers testing against unprotected origin
        """
        from beatrix.scanners import ScanContext

        url = context.get("resolved_url", target if "://" in target else f"https://{target}")

        # Build list of all HTTP targets from network context
        net = context.get("network", {})
        services = net.get("services", {})
        domain = url.split("://", 1)[1].split("/")[0].split(":")[0] if "://" in url else url.split("/")[0].split(":")[0]
        extra_http_urls = []
        for port in services.get("http", []):
            u = f"http://{domain}" if port == 80 else f"http://{domain}:{port}"
            if u != url:
                extra_http_urls.append(u)
        for port in services.get("https", []):
            u = f"https://{domain}" if port == 443 else f"https://{domain}:{port}"
            if u != url:
                extra_http_urls.append(u)

        # Origin IP direct testing (bypasses CDN/WAF)
        scan_target = net.get("scan_target", domain)
        if scan_target != domain:
            origin_urls = [f"http://{scan_target}", f"https://{scan_target}"]
            extra_http_urls.extend([u for u in origin_urls if u not in extra_http_urls])
            self._emit("info", message=f"Exploitation: including origin IP {scan_target} as direct target (CDN bypass)")

        # ── Initialize OOB detection ──
        # Prefer the local PoC server (started in execute()) for reliable HTTP callbacks.
        # Fall back to interact.sh for DNS-only OOB when the local server can't be reached.
        if not context.get("oob_available"):
            # Check if local PoC client already provides OOB
            poc_client = context.get("poc_client")
            if poc_client and poc_client.detector:
                context["oob_detector"] = poc_client.detector
                context["oob_domain"] = poc_client.oob_domain
                context["oob_available"] = True
                self._emit("info", message=f"OOB detector using local PoC server ({context['oob_domain']})")
            else:
                # Fall back to interact.sh for DNS-based OOB
                try:
                    from beatrix.core.oob_detector import InteractshClient
                    interactsh = InteractshClient()
                    await interactsh.__aenter__()
                    context["interactsh_client"] = interactsh
                    context["oob_detector"] = interactsh.detector
                    context["oob_domain"] = interactsh.oob_domain
                    context["oob_available"] = True
                    self._emit("info", message=f"OOB detector initialized via interact.sh (domain: {context['oob_domain']})")
                except Exception:
                    context["oob_available"] = False
                    self._emit("info", message="OOB detector unavailable — blind callback verification disabled")

        results = []
        urls_with_params = context.get("urls_with_params", [])

        # Build a combined target list: URLs with params PLUS JS-discovered API endpoints
        # Many JS routes (e.g. /api/v1/users, /resource/feed) lack query params but
        # still accept POST bodies, path params, and headers — they *must* be tested.
        discovered = context.get("discovered_urls", [])
        api_endpoints = [u for u in discovered
                         if any(p in u for p in ("/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql", "/internal/", "/admin/"))]

        # Include extra HTTP ports from network scan as additional injection targets
        injection_targets = list(dict.fromkeys(urls_with_params + api_endpoints + extra_http_urls))

        # ── Injection variants — need URLs with parameters or API endpoints ───
        if injection_targets:
            # Cap at 50 to stay within timeout budget (300s per scanner)
            capped = injection_targets[:50]
            self._emit("info", message=f"Testing {len(capped)} URLs for injection ({len(urls_with_params)} with params + {len(api_endpoints)} API endpoints)")
            results.append(await self._run_scanner_on_urls("injection", capped, context))
            results.append(await self._run_scanner_on_urls("ssti", capped, context))
            results.append(await self._run_scanner_on_urls("ssrf", capped, context))
            results.append(await self._run_scanner_on_urls("mass_assignment", capped[:30], context))
            results.append(await self._run_scanner_on_urls("redos", capped[:10], context))
        else:
            results.append(await self._run_scanner("injection", url, context))
            results.append(await self._run_scanner("ssti", url, context))
            results.append(await self._run_scanner("ssrf", url, context))
            results.append(await self._run_scanner("mass_assignment", url, context))
            results.append(await self._run_scanner("redos", url, context))

        # ── XXE — targets XML-accepting endpoints ─────────────────────────────
        # Also test discovered API endpoints that might accept XML
        xxe_targets = list(dict.fromkeys([url] + api_endpoints[:15]))
        results.append(await self._run_scanner_on_urls("xxe", xxe_targets, context))

        # ── Deserialization — tests for insecure deserialization ───────────────
        results.append(await self._run_scanner_on_urls("deserialization", xxe_targets, context))

        # ── IDOR/BAC — test base URL and discovered API endpoints ─────────
        # JS-discovered API routes are prime IDOR/BAC targets
        discovered = context.get("discovered_urls", [])
        api_urls = [u for u in discovered if "/api/" in u or "/v1/" in u or "/v2/" in u or "/v3/" in u or "/graphql" in u or "/rest/" in u]
        idor_targets = list(set([url] + api_urls[:30]))  # Base URL + API endpoints
        results.append(await self._run_scanner_on_urls("idor", idor_targets, context))
        results.append(await self._run_scanner_on_urls("bac", idor_targets, context))

        # ── Auth — runs on base URL checking for auth issues ──────────────────
        results.append(await self._run_scanner("auth", url, context))

        # ── GraphQL — discovers and tests GraphQL endpoints ───────────────────
        results.append(await self._run_scanner("graphql", url, context))

        # ── Business logic — boundary conditions, race conditions ─────────────
        results.append(await self._run_scanner("business_logic", url, context))

        # ── Payment — checkout flow manipulation ──────────────────────────────
        results.append(await self._run_scanner("payment", url, context))

        # ── Nuclei Exploit — full CVE/exploit scan with workflows ─────────
        # Multi-mode nuclei: exploit pass + headless DOM checks + authenticated
        # Replaces the old single scan() call with intelligent split-phase execution.
        nuclei = self.engine.modules.get("nuclei")
        if nuclei and hasattr(nuclei, 'available') and nuclei.available:
            # Feed nuclei ALL discovered URLs for comprehensive coverage
            all_urls = list(set(
                context.get("discovered_urls", []) +
                urls_with_params +
                [url]
            ))
            if hasattr(nuclei, 'add_urls'):
                nuclei.add_urls(all_urls)

            # Feed technology fingerprint for intelligent tag selection + exclusion
            if hasattr(nuclei, 'set_technologies'):
                techs = context.get("technologies", {})
                nuclei.set_technologies(techs)

            # Configure authentication for nuclei
            auth = context.get("auth")
            if auth and hasattr(auth, 'nuclei_header_flags'):
                nuclei.set_auth(auth.nuclei_header_flags())
                self._emit("info", message="Nuclei: authenticated scanning enabled")

            # Wire interactsh — unify OOB detection with Beatrix's OOB detector
            if context.get("oob_domain"):
                oob_domain = context["oob_domain"]
                # Extract the interactsh server from the OOB domain
                # e.g. "abc123.oast.fun" → "oast.fun"
                parts = oob_domain.split(".", 1)
                if len(parts) > 1:
                    nuclei.set_interactsh(server=f"https://{parts[1]}")
                    self._emit("info", message=f"Nuclei: OOB detection via {parts[1]}")

            # --- Exploit pass: CVEs, injections, auth bypass, workflows ---
            self._emit("info", message=f"Nuclei exploit scan: {len(all_urls)} URLs with intelligent template selection")
            exploit_result = {"findings": [], "assets": [], "context": {}, "modules": ["nuclei_exploit"], "requests": 0}
            try:
                exploit_ctx = ScanContext.from_url(url)
                exploit_ctx.extra = {
                    "technologies": context.get("technologies", {}),
                    "auth": auth,
                }
                async with nuclei:
                    async for finding in nuclei.scan_exploit(exploit_ctx):
                        if not finding.scanner_module:
                            finding.scanner_module = "nuclei"
                        exploit_result["findings"].append(finding)
                        self._emit("finding", scanner="nuclei", finding=finding)
                results.append(exploit_result)
                self._emit("scanner_done", scanner="nuclei_exploit", findings=len(exploit_result["findings"]))
            except Exception as e:
                self._emit("scanner_error", scanner="nuclei_exploit", error=str(e))

            # --- Headless pass: DOM XSS, prototype pollution, JS-based vulns ---
            headless_result = {"findings": [], "assets": [], "context": {}, "modules": ["nuclei_headless"], "requests": 0}
            try:
                headless_ctx = ScanContext.from_url(url)
                self._emit("info", message="Nuclei headless scan: DOM-based vulnerability checks")
                async with nuclei:
                    async for finding in nuclei.scan_headless(headless_ctx):
                        if not finding.scanner_module:
                            finding.scanner_module = "nuclei_headless"
                        headless_result["findings"].append(finding)
                        self._emit("finding", scanner="nuclei_headless", finding=finding)
                if headless_result["findings"]:
                    results.append(headless_result)
                    self._emit("scanner_done", scanner="nuclei_headless", findings=len(headless_result["findings"]))
            except Exception as e:
                self._emit("scanner_error", scanner="nuclei_headless", error=str(e))
        else:
            self._emit("info", message="Nuclei not available — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

        # ── SmartFuzzer — verified, deduplicated fuzzing with ffuf backend ─────
        # Runs on parameterized URLs to discover additional vulns that scanners
        # miss, then verifies and deduplicates so only confirmed findings survive.
        if urls_with_params:
            try:
                from beatrix.core.smart_fuzzer import SmartFuzzer, VerifiedFinding as _VF
                from beatrix.core.types import Finding as _F, Severity as _S, Confidence as _C

                fuzzer = SmartFuzzer(threads=50, verify_top_n=50, verbose=False)
                fuzz_targets = urls_with_params[:30]  # Thorough coverage
                self._emit("info", message=f"Running SmartFuzzer on {len(fuzz_targets)} parameterized URLs")

                for fuzz_url in fuzz_targets:
                    # Build FUZZ-marked URL from parameterized URL
                    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                    parsed = urlparse(fuzz_url)
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    for param_name in list(params.keys())[:3]:
                        fuzz_params = dict(params)
                        fuzz_params[param_name] = ['FUZZ']
                        fuzz_query = urlencode(fuzz_params, doseq=True)
                        fuzz_marked = urlunparse(parsed._replace(query=fuzz_query))
                        try:
                            verified = await fuzzer.scan(fuzz_marked, parameter=param_name)
                            for vf in verified:
                                sev_map = {"critical": _S.CRITICAL, "high": _S.HIGH, "medium": _S.MEDIUM, "low": _S.LOW}
                                results.append({"findings": [_F(
                                    severity=sev_map.get(vf.severity, _S.HIGH),
                                    confidence=_C.CONFIRMED if vf.confidence.value == "confirmed" else _C.FIRM,
                                    url=vf.url,
                                    title=f"SmartFuzzer: {vf.category.value} in {param_name}",
                                    description=f"Verified {vf.category.value} via SmartFuzzer.\nEvidence: {vf.evidence}",
                                    evidence={"payload": vf.payload, "evidence": vf.evidence,
                                              "alternatives": vf.alternative_payloads[:3]},
                                    parameter=param_name,
                                    payload=vf.payload,
                                    poc_curl=vf.poc_curl,
                                    poc_python=vf.poc_python,
                                    cwe_id=vf.cwe,
                                    scanner_module="smart_fuzzer",
                                )], "assets": [], "context": {}, "modules": ["smart_fuzzer"], "requests": 0})
                                self._emit("info", message=f"SmartFuzzer CONFIRMED {vf.category.value} in {param_name}")
                        except Exception:
                            pass
                self._emit("info", message=f"SmartFuzzer complete: {len(fuzzer.findings)} verified findings")
            except ImportError:
                self._emit("info", message="SmartFuzzer unavailable (ffuf not installed)")
            except Exception as e:
                self._emit("scanner_error", scanner="smart_fuzzer", error=str(e))

        # ── Deep exploitation — sqlmap, dalfox, commix on confirmed vulns ─────
        # Only run when tools are available AND internal scanners found issues
        try:
            toolkit = self.toolkit

            # Collect confirmed vulnerabilities from internal scanner results
            all_findings = []
            for r in results:
                all_findings.extend(r.get("findings", []))

            sqli_targets = []
            xss_targets = []
            cmdi_targets = []
            jwt_tokens = []

            for finding in all_findings:
                ftitle = getattr(finding, "title", "") or ""
                ftitle_lower = ftitle.lower() if isinstance(ftitle, str) else ""
                finding_url = getattr(finding, "url", "") or url
                finding_param = getattr(finding, "parameter", "") or ""
                evidence = getattr(finding, "evidence", {}) or {}

                # Extract HTTP method + POST data from finding's request string
                request_str = getattr(finding, "request", "") or ""
                finding_method = "GET"
                finding_data = None
                if request_str:
                    first_line = request_str.split("\n", 1)[0].strip()
                    if first_line.startswith("POST"):
                        finding_method = "POST"
                        # POST data often follows double-newline in request dump
                        if "\n\n" in request_str:
                            finding_data = request_str.split("\n\n", 1)[1].strip()

                if "sql" in ftitle_lower or "sqli" in ftitle_lower:
                    sqli_targets.append({
                        "url": finding_url, "param": finding_param,
                        "method": finding_method, "data": finding_data,
                    })
                if "xss" in ftitle_lower or "cross-site scripting" in ftitle_lower:
                    xss_targets.append({"url": finding_url, "param": finding_param})
                if "command" in ftitle_lower or "cmdi" in ftitle_lower or "os_command" in ftitle_lower:
                    cmdi_targets.append({
                        "url": finding_url, "param": finding_param,
                        "data": finding_data,
                    })
                if "jwt" in ftitle_lower:
                    token = evidence.get("token", "") if isinstance(evidence, dict) else ""
                    if token:
                        jwt_tokens.append(token)

            # sqlmap — deep SQLi exploitation on confirmed injection points
            if toolkit.sqlmap.available and sqli_targets:
                self._emit("info", message=f"Running sqlmap on {len(sqli_targets)} confirmed SQLi targets")
                for target_info in sqli_targets[:5]:  # Limit to avoid runaway
                    try:
                        sqlmap_result = await toolkit.sqlmap.exploit(
                            url=target_info["url"],
                            param=target_info.get("param"),
                            method=target_info.get("method", "GET"),
                            data=target_info.get("data"),
                            level=3,
                            risk=2,
                        )
                        if sqlmap_result.get("vulnerable"):
                            from beatrix.core.types import Finding, Severity
                            results.append({"findings": [Finding(
                                severity=Severity.CRITICAL,
                                url=target_info["url"],
                                title=f"SQLmap confirmed SQLi — DBMS: {sqlmap_result.get('dbms', 'unknown')}",
                                description=(
                                    f"sqlmap confirmed SQL injection.\n"
                                    f"DBMS: {sqlmap_result.get('dbms')}\n"
                                    f"Current DB: {sqlmap_result.get('current_db')}\n"
                                    f"Current User: {sqlmap_result.get('current_user')}\n"
                                    f"DBA: {sqlmap_result.get('is_dba')}\n"
                                    f"Databases: {', '.join(sqlmap_result.get('databases', []))}\n"
                                    f"Injection type: {sqlmap_result.get('injection_type')}"
                                ),
                                evidence=sqlmap_result,
                                scanner_module="sqlmap",
                            )], "assets": [], "context": {}, "modules": ["sqlmap"], "requests": 0})
                            self._emit("info", message=f"sqlmap CONFIRMED SQLi on {target_info['url']} (DBMS: {sqlmap_result.get('dbms')})")
                    except Exception as e:
                        self._emit("scanner_error", scanner="sqlmap", error=str(e))

            # dalfox — XSS validation and WAF bypass on confirmed XSS
            if toolkit.dalfox.available and xss_targets:
                self._emit("info", message=f"Running dalfox on {len(xss_targets)} confirmed XSS targets")
                for target_info in xss_targets[:10]:
                    try:
                        dalfox_findings = await toolkit.dalfox.scan(
                            url=target_info["url"],
                            param=target_info.get("param"),
                        )
                        for df in dalfox_findings:
                            from beatrix.core.types import Finding, Severity
                            results.append({"findings": [Finding(
                                severity=Severity.HIGH,
                                url=df.get("url", target_info["url"]),
                                title=f"Dalfox confirmed XSS — {df.get('type', 'reflected')}",
                                description=(
                                    f"Dalfox confirmed XSS vulnerability.\n"
                                    f"Type: {df.get('type')}\n"
                                    f"Payload: {df.get('payload')}\n"
                                    f"Evidence: {df.get('evidence')}"
                                ),
                                evidence=df,
                                scanner_module="dalfox",
                            )], "assets": [], "context": {}, "modules": ["dalfox"], "requests": 0})
                            self._emit("info", message=f"dalfox CONFIRMED XSS on {target_info['url']}")
                    except Exception as e:
                        self._emit("scanner_error", scanner="dalfox", error=str(e))

            # commix — command injection exploitation on confirmed CMDi
            if toolkit.commix.available and cmdi_targets:
                self._emit("info", message=f"Running commix on {len(cmdi_targets)} confirmed CMDi targets")
                for target_info in cmdi_targets[:5]:
                    try:
                        commix_result = await toolkit.commix.exploit(
                            url=target_info["url"],
                            param=target_info.get("param"),
                            data=target_info.get("data"),
                        )
                        if commix_result.get("vulnerable"):
                            from beatrix.core.types import Finding, Severity
                            results.append({"findings": [Finding(
                                severity=Severity.CRITICAL,
                                url=target_info["url"],
                                title=f"Commix confirmed command injection — OS: {commix_result.get('os', 'unknown')}",
                                description=(
                                    f"Commix confirmed OS command injection.\n"
                                    f"Technique: {commix_result.get('technique')}\n"
                                    f"OS: {commix_result.get('os')}"
                                ),
                                evidence=commix_result,
                                scanner_module="commix",
                            )], "assets": [], "context": {}, "modules": ["commix"], "requests": 0})
                            self._emit("info", message=f"commix CONFIRMED CMDi on {target_info['url']}")
                    except Exception as e:
                        self._emit("scanner_error", scanner="commix", error=str(e))

            # jwt_tool — deep JWT analysis on discovered tokens
            if toolkit.jwt_tool.available and jwt_tokens:
                self._emit("info", message=f"Running jwt_tool on {len(jwt_tokens)} JWT tokens")
                for token in jwt_tokens[:5]:
                    try:
                        jwt_result = await toolkit.jwt_tool.analyze(token)
                        if jwt_result.get("vulnerabilities"):
                            from beatrix.core.types import Finding, Severity
                            vuln_types = [v["type"] for v in jwt_result["vulnerabilities"]]

                            # Include decoded header/payload in evidence
                            enriched_evidence = dict(jwt_result)
                            enriched_evidence["token_prefix"] = token[:50]

                            # Attempt role-escalation tamper PoC for algorithm/claim vulns
                            tampered_token = None
                            for vuln in jwt_result["vulnerabilities"]:
                                vtype = vuln.get("type", "").lower()
                                if any(k in vtype for k in ("none", "confusion", "blank", "crack")):
                                    try:
                                        tampered_token = await toolkit.jwt_tool.tamper(
                                            token, "role", "admin"
                                        )
                                        if tampered_token:
                                            enriched_evidence["tampered_token"] = tampered_token
                                            enriched_evidence["tamper_claim"] = "role → admin"
                                    except Exception:
                                        pass
                                    break

                            desc_parts = [
                                "jwt_tool discovered JWT vulnerabilities:",
                                *[f"  - {v['type']}: {v['detail']}" for v in jwt_result["vulnerabilities"]],
                            ]
                            if jwt_result.get("header"):
                                desc_parts.append(f"\nJWT Header: {jwt_result['header']}")
                            if jwt_result.get("payload"):
                                desc_parts.append(f"JWT Payload: {jwt_result['payload']}")
                            if tampered_token:
                                desc_parts.append(f"\nRole-escalation PoC token: {tampered_token[:80]}...")

                            results.append({"findings": [Finding(
                                severity=Severity.HIGH,
                                url=url,
                                title=f"jwt_tool found JWT vulnerabilities: {', '.join(vuln_types)}",
                                description="\n".join(desc_parts),
                                evidence=enriched_evidence,
                                scanner_module="jwt_tool",
                            )], "assets": [], "context": {}, "modules": ["jwt_tool"], "requests": 0})
                            self._emit("info", message=f"jwt_tool found {len(jwt_result['vulnerabilities'])} JWT vulnerabilities")
                    except Exception as e:
                        self._emit("scanner_error", scanner="jwt_tool", error=str(e))

        except Exception as e:
            self._emit("scanner_error", scanner="deep_exploitation", error=str(e))

        return await self._merge_scanner_results(results)

    async def _handle_installation(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 5 — Installation: file upload, persistence mechanisms."""
        url = context.get("resolved_url", target if "://" in target else f"https://{target}")

        results = []
        # File upload — extension bypass, polyglot uploads, path traversal in filenames
        results.append(await self._run_scanner("file_upload", url, context))

        return await self._merge_scanner_results(results)

    async def _handle_c2(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 6 — C2: OOB callback correlation, CORS PoC validation, exfiltration testing.

        The OOB detector and PoC server were initialized before scanning.
        This phase:
        1. Polls for OOB callbacks from exploitation payloads
        2. Checks if CORS PoC pages collected exfiltrated data
        3. Reviews token enumeration results for weak nonces
        4. Converts all confirmed interactions into findings
        5. Uses firewall profile from network scan to assess exfil channels
        """
        results = []

        # Log firewall-informed exfiltration assessment
        net = context.get("network", {})
        fw_profile = net.get("firewall_profile", {})
        if fw_profile.get("type"):
            bypass_vectors = fw_profile.get("bypass_vectors", [])
            if bypass_vectors:
                self._emit("info", message=f"C2: Firewall has {len(bypass_vectors)} bypass vectors — exfiltration channels likely open")
            elif fw_profile["type"] == "stateful":
                self._emit("info", message="C2: Stateful firewall detected — DNS/ICMP exfiltration may be needed")
            elif fw_profile["type"] == "none":
                self._emit("info", message="C2: No firewall detected — direct TCP exfiltration possible")

        # OOB detector should already be initialized.
        # If it wasn't (e.g., Phase 4 was skipped), try now.
        if not context.get("oob_available"):
            poc_client = context.get("poc_client")
            if poc_client and poc_client.detector:
                context["oob_detector"] = poc_client.detector
                context["oob_available"] = True
            else:
                try:
                    from beatrix.core.oob_detector import InteractshClient
                    interactsh = InteractshClient()
                    await interactsh.__aenter__()
                    context["interactsh_client"] = interactsh
                    context["oob_detector"] = interactsh.detector
                    context["oob_available"] = True
                    self._emit("info", message="OOB detector initialized (late — Phase 4 was skipped)")
                except Exception:
                    context["oob_available"] = False

        # ── 1. Poll OOB detector for callbacks from exploitation phase ────────
        oob = context.get("oob_detector")
        if oob and context.get("oob_available"):
            try:
                interactions = await oob.poll(timeout=10.0)
                if interactions:
                    from beatrix.core.types import Finding, Severity, Confidence
                    self._emit("info", message=f"OOB detector received {len(interactions)} callback(s)!")
                    for interaction in interactions:
                        sev = Severity.CRITICAL if interaction.vuln_type in ("rce", "ssrf") else Severity.HIGH
                        results.append({"findings": [Finding(
                            severity=sev,
                            confidence=Confidence.CONFIRMED,
                            url=interaction.target_url or target,
                            title=f"OOB callback confirmed: {interaction.vuln_type or 'blind'} via {interaction.type.name}",
                            description=(
                                f"Out-of-band {interaction.type.name} callback received.\n"
                                f"Vulnerability type: {interaction.vuln_type or 'unknown'}\n"
                                f"Target URL: {interaction.target_url}\n"
                                f"Parameter: {interaction.parameter}\n"
                                f"Callback from: {interaction.client_ip}\n"
                                f"This confirms the vulnerability is exploitable — the server made an external request to our canary."
                            ),
                            impact=(
                                f"The server-side {interaction.vuln_type or 'blind'} vulnerability is confirmed exploitable. "
                                f"The target server made an out-of-band {interaction.type.name} request to our controlled endpoint, "
                                f"proving that an attacker can force the server to make arbitrary external requests."
                            ),
                            evidence={"interaction_type": interaction.type.name, "client_ip": interaction.client_ip,
                                      "raw": interaction.raw_data, "payload_id": interaction.payload_id},
                            parameter=interaction.parameter,
                            scanner_module="oob_detector",
                        )], "assets": [], "context": {}, "modules": ["oob_detector"], "requests": 0})
                else:
                    self._emit("info", message="OOB detector: no callbacks received (clean, or payloads not triggered)")
            except Exception as e:
                self._emit("scanner_error", scanner="oob_detector", error=str(e))

        # ── 2. Check CORS PoC exfiltration results ───────────────────────────
        poc_server = context.get("poc_server")
        if poc_server:
            try:
                exfil_data = poc_server.get_exfil_data()
                if exfil_data:
                    from beatrix.core.types import Finding, Severity, Confidence
                    self._emit("info", message=f"CORS PoC collected {len(exfil_data)} exfiltration result(s)!")
                    for exfil in exfil_data:
                        results.append({"findings": [Finding(
                            severity=Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            url=target,
                            title=f"CORS Exploitation Validated — Data Exfiltrated",
                            description=(
                                f"The CORS PoC page successfully read and exfiltrated data from the target.\n"
                                f"Finding ID: {exfil.finding_id}\n"
                                f"Data collected at: {exfil.timestamp.isoformat()}\n"
                                f"Content-Type: {exfil.content_type}\n"
                                f"Data length: {len(exfil.data)} bytes\n"
                                f"This proves that an attacker-controlled page can steal authenticated data cross-origin."
                            ),
                            impact=(
                                "Cross-origin data theft confirmed. A malicious website visited by an authenticated user "
                                "can silently read and exfiltrate sensitive data from this application's API responses."
                            ),
                            evidence=exfil.data[:2000],
                            scanner_module="cors_poc_validator",
                        )], "assets": [], "context": {}, "modules": ["cors_poc_validator"], "requests": 0})

                # Check enumeration results for weak tokens
                for key, enum_result in poc_server._enum_results.items():
                    if enum_result.predictable and enum_result.tokens:
                        from beatrix.core.types import Finding, Severity, Confidence
                        results.append({"findings": [Finding(
                            severity=Severity.MEDIUM,
                            confidence=Confidence.FIRM,
                            url=enum_result.target_url or target,
                            title="Predictable CSRF/Nonce Tokens Detected",
                            description=(
                                f"Token enumeration revealed weak randomness.\n"
                                f"Tokens collected: {len(enum_result.tokens)}\n"
                                f"Unique tokens: {len(set(enum_result.tokens))}\n"
                                f"Entropy score: {enum_result.entropy_score:.2f}\n"
                                f"Sample tokens: {', '.join(enum_result.tokens[:5])}\n"
                                f"Predictable tokens allow CSRF attacks or session fixation."
                            ),
                            impact=(
                                "CSRF tokens or session nonces are predictable, enabling an attacker to forge "
                                "valid tokens and bypass CSRF protections. This allows unauthorized state-changing "
                                "actions on behalf of authenticated users."
                            ),
                            cwe_id="CWE-330",
                            scanner_module="token_enumerator",
                        )], "assets": [], "context": {}, "modules": ["token_enumerator"], "requests": 0})

                # Log PoC server summary
                summary = poc_server.summary()
                self._emit("info", message=(
                    f"PoC server summary: {summary['oob_callbacks_received']} callbacks, "
                    f"{summary['exfil_entries']} exfil entries, "
                    f"{summary['poc_pages_registered']} PoC pages served"
                ))
            except Exception as e:
                self._emit("scanner_error", scanner="poc_server", error=str(e))

        return await self._merge_scanner_results(results)

    async def _handle_actions(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 7 — Actions on Objectives: validate credentials, generate Metasploit RCs.

        This phase performs post-exploitation tasks:
        1. Credential validation — test leaked secrets discovered in recon
        2. Metasploit RC generation — create exploit scripts for critical findings
        3. Final impact assessment
        """
        results = []

        # ── Step 1: Credential validation — upgrade leaked secrets from Info → Critical ──
        try:
            from beatrix.scanners.credential_validator import (
                CredentialTest,
                CredentialType,
                CredentialValidator,
            )

            # Collect leaked credentials from prior phase findings
            cred_tests = []
            all_phase_findings = context.get("all_findings", [])

            # Check all findings for credential-like evidence
            for finding in all_phase_findings:
                scanner = getattr(finding, "scanner_module", "") or ""
                evidence = getattr(finding, "evidence", None)
                title = getattr(finding, "title", "") or ""
                title_lower = title.lower()

                # GitHub recon findings often contain secrets
                if scanner == "github_recon" or "secret" in title_lower or "token" in title_lower or "key" in title_lower:
                    if evidence and isinstance(evidence, dict):
                        secret_value = evidence.get("value") or evidence.get("secret") or evidence.get("token") or ""
                        secret_type = evidence.get("type", "").lower()

                        if secret_value and len(secret_value) > 8:
                            cred_type = CredentialType.GENERIC
                            if "github" in secret_type or "github" in title_lower:
                                cred_type = CredentialType.GITHUB_TOKEN
                            elif "aws" in secret_type or "aws" in title_lower:
                                cred_type = CredentialType.AWS_KEY
                            elif "stripe" in secret_type:
                                cred_type = CredentialType.STRIPE_KEY
                            elif "jwt" in secret_type:
                                cred_type = CredentialType.JWT_SECRET
                            elif "mongo" in secret_type:
                                cred_type = CredentialType.MONGODB_URI
                            elif "redis" in secret_type:
                                cred_type = CredentialType.REDIS_PASSWORD
                            elif "sendgrid" in secret_type:
                                cred_type = CredentialType.SENDGRID_KEY
                            elif "slack" in secret_type:
                                cred_type = CredentialType.SLACK_WEBHOOK
                            elif "api" in secret_type:
                                cred_type = CredentialType.API_KEY

                            cred_tests.append(CredentialTest(
                                credential_type=cred_type,
                                value=secret_value,
                                context={"source": scanner, "finding_title": title},
                            ))

            if cred_tests:
                self._emit("info", message=f"Validating {len(cred_tests)} discovered credentials...")
                validator = CredentialValidator(timeout=10)
                reports = await validator.validate_batch(cred_tests[:20])  # Cap at 20

                from beatrix.core.types import Finding, Severity
                for report in reports:
                    if report.is_live:
                        results.append({"findings": [Finding(
                            severity=report.risk_level,
                            url=target,
                            title=f"Confirmed Live Credential: {report.credential_type.value}",
                            description=(
                                f"Credential validation confirmed this secret is LIVE.\n"
                                f"Type: {report.credential_type.value}\n"
                                f"Result: {report.result.value}\n"
                                f"Access level: {report.access_level or 'unknown'}\n"
                                f"Details: {report.details}"
                            ),
                            evidence={"validation_result": report.result.value,
                                      "access_level": report.access_level,
                                      "service_info": report.service_info,
                                      "raw_response": report.raw_response},
                            scanner_module="credential_validator",
                        )], "assets": [], "context": {}, "modules": ["credential_validator"], "requests": 0})
                        self._emit("info", message=f"CONFIRMED live credential: {report.credential_type.value} — {report.details[:80]}")
                    elif report.result.value == "partial":
                        results.append({"findings": [Finding(
                            severity=report.risk_level,
                            url=target,
                            title=f"Potentially Live Credential: {report.credential_type.value}",
                            description=f"Partial validation: {report.details}",
                            evidence={"validation_result": report.result.value},
                            scanner_module="credential_validator",
                        )], "assets": [], "context": {}, "modules": ["credential_validator"], "requests": 0})

                validated_live = sum(1 for r in reports if r.is_live)
                self._emit("info", message=f"Credential validation: {validated_live}/{len(reports)} confirmed live")
        except ImportError:
            pass  # credential_validator not available
        except Exception as e:
            self._emit("scanner_error", scanner="credential_validator", error=str(e))

        # ── Step 2: Metasploit RC generation for critical findings ────────────
        try:
            toolkit = self.toolkit
            if toolkit.metasploit.available:
                from beatrix.core.types import Severity

                # Collect all critical/high findings from all phases
                critical_findings = []
                for finding in context.get("all_findings", []):
                    sev = getattr(finding, "severity", None)
                    if sev in (Severity.CRITICAL, Severity.HIGH):
                        critical_findings.append(finding)

                # Also check if any exploitation findings warrant Metasploit PoCs
                # This is available after the scan completes — for now emit guidance
                self._emit("info", message="Metasploit available — RC files can be generated for confirmed RCE/SQLi findings post-scan")
        except Exception:
            pass

        # ── Step 3: VRT classification — enrich all findings with Bugcrowd priority + CVSS ──
        try:
            from beatrix.utils.vrt_classifier import VRTClassifier
            all_findings = context.get("all_findings", [])
            vrt_enriched = 0
            for finding in all_findings:
                title = getattr(finding, "title", "") or ""
                evidence_str = str(getattr(finding, "evidence", "") or "")
                severity_str = getattr(finding, "severity", "").value if hasattr(getattr(finding, "severity", None), "value") else ""
                vrt = VRTClassifier.classify(title, evidence_str, severity_str)
                if vrt:
                    # Store VRT data in evidence dict or as attribute
                    if not hasattr(finding, '_vrt_classification'):
                        finding._vrt_classification = vrt
                    vrt_enriched += 1
            if vrt_enriched:
                self._emit("info", message=f"VRT classification: enriched {vrt_enriched}/{len(all_findings)} findings with Bugcrowd priority + CVSS scores")
        except ImportError:
            pass
        except Exception as e:
            self._emit("scanner_error", scanner="vrt_classifier", error=str(e))

        # ── Step 4: PoC Chain Engine — generate exploit chains + reproduction guides ──
        try:
            from beatrix.core.poc_chain_engine import PoCChainEngine
            from beatrix.core.correlation_engine import EventCorrelationEngine

            all_findings = context.get("all_findings", [])
            if len(all_findings) >= 2:
                # Feed findings into correlation engine to discover chains
                corr_engine = EventCorrelationEngine()
                for finding in all_findings:
                    module = getattr(finding, "scanner_module", "unknown")
                    corr_engine.ingest_finding({
                        "type": module,
                        "title": getattr(finding, "title", ""),
                        "url": getattr(finding, "url", ""),
                        "severity": getattr(finding, "severity", "").value if hasattr(getattr(finding, "severity", None), "value") else "info",
                        "evidence": getattr(finding, "evidence", ""),
                        "parameter": getattr(finding, "parameter", ""),
                    }, module=module)

                corr_engine.detect_chains()

                if corr_engine.chains:
                    poc_engine = PoCChainEngine(target)
                    poc_chains = poc_engine.process_correlation_results(corr_engine)
                    self._emit("info", message=f"PoC Chain Engine generated {len(poc_chains)} exploit chains from {len(corr_engine.chains)} correlated attack paths")
                    context["poc_chains"] = poc_chains
                    context["correlation_engine"] = corr_engine
        except ImportError:
            pass
        except Exception as e:
            self._emit("scanner_error", scanner="poc_chain_engine", error=str(e))

        return await self._merge_scanner_results(results) if results else {
            "findings": [], "assets": [], "context": {}, "modules": ["validate"], "requests": 0
        }

    def register_handler(
        self,
        phase: KillChainPhase,
        handler: Callable
    ) -> None:
        """Register a custom handler for a phase"""
        self.phase_handlers[phase] = handler

    async def execute(
        self,
        target: str,
        phases: Optional[List[int]] = None,
        skip_phases: Optional[List[int]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> KillChainState:
        """
        Execute kill chain against target.

        Args:
            target: Target domain/URL
            phases: Specific phases to run (1-7), None = all
            skip_phases: Phases to skip
            context: Initial context to seed the execution

        Returns:
            KillChainState with all results
        """
        state = KillChainState(target=target)

        if context:
            state.context.update(context)

        # Determine which phases to run
        all_phases = list(KillChainPhase)
        if phases:
            run_phases = [p for p in all_phases if p.value in phases]
        else:
            run_phases = all_phases

        if skip_phases:
            run_phases = [p for p in run_phases if p.value not in skip_phases]

        # ── Start local PoC server before any scanning phases ──
        # Provides OOB callback receiver, CORS PoC hosting, token enumeration,
        # and clickjacking validation without needing external services.
        poc_client = None
        try:
            from beatrix.core.oob_detector import LocalPoCClient
            poc_client = LocalPoCClient()
            await poc_client.__aenter__()
            state.context["poc_client"] = poc_client
            state.context["poc_server"] = poc_client.poc_server
            state.context["poc_server_url"] = poc_client.poc_server.base_url
            self._emit("info", message=f"PoC server started on {poc_client.poc_server.base_url}")
        except Exception as e:
            self._emit("info", message=f"PoC server unavailable: {e}")
            state.context["poc_server"] = None

        # ── Session validator: calibrate if auth is configured ─────────
        # Modeled on Burp Suite's session validation: probe the target once
        # to discover an auth-sensitive endpoint, capture what "logged in"
        # looks like, then re-check between phases to detect session death.
        session_validator = None
        auth = state.context.get("auth")
        if auth and hasattr(auth, 'has_auth') and auth.has_auth:
            try:
                from beatrix.core.auth_config import SessionValidator
                session_validator = SessionValidator(target, auth)
                calibrated = await session_validator.calibrate()
                if calibrated:
                    state.context["session_validator"] = session_validator
                    self._emit("info", message=(
                        f"Session validator calibrated: "
                        f"{session_validator.fingerprint.check_url}"
                    ))
                else:
                    self._emit("info", message=(
                        "Session validator: no auth-sensitive endpoint found "
                        "— session expiry will be detected via 401/403 tracking"
                    ))
                    session_validator = None
            except Exception as e:
                self._emit("info", message=f"Session validator setup failed: {e}")
                session_validator = None

        # Execute each phase
        try:
            for phase in run_phases:
                if state.cancelled:
                    break

                while state.paused:
                    await asyncio.sleep(0.5)

                state.current_phase = phase

                # ── Between-phase session health check ────────────────
                # Before each phase after recon, verify the session is still
                # alive. If it's dead, attempt re-authentication so subsequent
                # scanners don't silently run unauthenticated.
                if (session_validator
                        and phase != KillChainPhase.RECONNAISSANCE
                        and auth and hasattr(auth, 'has_login_creds')
                        and auth.has_login_creds):
                    try:
                        alive = await session_validator.is_session_alive(force=True)
                        if not alive and session_validator.needs_reauth:
                            self._emit("info", message=(
                                "⚠ Session expired — attempting re-authentication..."
                            ))
                            try:
                                from beatrix.core.auto_login import perform_auto_login
                                login_result = await perform_auto_login(auth, target)
                                if login_result.success:
                                    # Update auth credentials with fresh session
                                    if login_result.cookies:
                                        auth.cookies.update(login_result.cookies)
                                    if login_result.headers:
                                        auth.headers.update(login_result.headers)
                                    if login_result.token:
                                        auth.bearer_token = login_result.token
                                    session_validator.reset()
                                    # Re-calibrate with new session
                                    await session_validator.calibrate()
                                    self._emit("info", message=(
                                        "✓ Re-authentication successful — "
                                        "session refreshed"
                                    ))
                                else:
                                    self._emit("info", message=(
                                        "⚠ Re-authentication failed — "
                                        "continuing with expired session"
                                    ))
                            except Exception as e:
                                self._emit("info", message=(
                                    f"⚠ Re-auth error: {e} — "
                                    f"continuing with existing session"
                                ))
                    except Exception:
                        pass  # Session check failure is non-fatal

                # Before Phase 7, inject all accumulated findings into context
                # so _handle_actions can access them for credential validation
                if phase == KillChainPhase.ACTIONS_ON_OBJECTIVES:
                    state.context["all_findings"] = state.all_findings

                result = await self._execute_phase(phase, state)
                state.phase_results[phase] = result

                # Merge context for next phase
                state.merge_context(result.context)

                # Stop if phase failed critically
                if result.status == PhaseStatus.FAILED and result.errors:
                    break
        finally:
            # Cleanup local PoC client + server
            if poc_client:
                try:
                    # Log callback summary before shutdown
                    if poc_client.poc_server:
                        summary = poc_client.poc_server.summary()
                        if summary["oob_callbacks_received"] > 0:
                            self._emit("info", message=(
                                f"PoC server received {summary['oob_callbacks_received']} OOB callback(s), "
                                f"{summary['exfil_entries']} exfil entries"
                            ))
                    await poc_client.__aexit__(None, None, None)
                except Exception:
                    pass

            # Cleanup remote InteractshClient if one was also started
            interactsh = state.context.get("interactsh_client")
            if interactsh:
                try:
                    await interactsh.__aexit__(None, None, None)
                except Exception:
                    pass

        return state

    async def _execute_phase(
        self,
        phase: KillChainPhase,
        state: KillChainState
    ) -> PhaseResult:
        """Execute a single phase"""
        result = PhaseResult(
            phase=phase,
            status=PhaseStatus.RUNNING,
            started_at=datetime.now(),
        )

        try:
            # Get handler for this phase
            handler = self.phase_handlers.get(phase)

            if handler:
                self._emit("phase_start", phase=phase.name_pretty, icon=phase.icon, description=phase.description)

                # Run the handler
                phase_output = await handler(state.target, state.context)

                result.findings = phase_output.get("findings", [])
                result.discovered_assets = phase_output.get("assets", [])
                result.context = phase_output.get("context", {})
                result.modules_run = phase_output.get("modules", [])
                result.requests_sent = phase_output.get("requests", 0)
                result.status = PhaseStatus.COMPLETED

                self._emit("phase_done", phase=phase.name_pretty,
                           findings=len(result.findings),
                           duration=result.duration)
            else:
                # No handler registered, skip
                result.status = PhaseStatus.SKIPPED

        except Exception as e:
            result.status = PhaseStatus.FAILED
            result.errors.append(str(e))

        result.completed_at = datetime.now()
        return result
