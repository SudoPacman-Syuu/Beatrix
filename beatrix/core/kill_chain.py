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
        """Default modules for this phase"""
        return {
            KillChainPhase.RECONNAISSANCE: [
                "subdomain", "portscan", "probe", "crawl", "js_analysis"
            ],
            KillChainPhase.WEAPONIZATION: [
                "waf_detect", "payload_gen", "fingerprint"
            ],
            KillChainPhase.DELIVERY: [
                "fuzz", "param_discovery", "endpoint_enum"
            ],
            KillChainPhase.EXPLOITATION: [
                "injection", "auth_bypass", "idor", "bac", "cors", "ssrf"
            ],
            KillChainPhase.INSTALLATION: [
                "file_upload", "webshell", "persistence"
            ],
            KillChainPhase.COMMAND_CONTROL: [
                "exfil", "oob", "callback"
            ],
            KillChainPhase.ACTIONS_ON_OBJECTIVES: [
                "poc_gen", "report", "validate"
            ],
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
        self._register_default_handlers()

    def _emit(self, event: str, **kwargs) -> None:
        """Emit a progress event to the callback."""
        if self._on_event:
            self._on_event(event, kwargs)

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

    # Per-scanner timeout (seconds) — prevents any single scanner from blocking the hunt
    SCANNER_TIMEOUT = 300  # 5 minutes

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

            async def _collect():
                async with scanner:
                    async for finding in scanner.scan(ctx):
                        # Stamp module attribution if scanner didn't set it
                        if not finding.scanner_module:
                            finding.scanner_module = scanner_name
                        result["findings"].append(finding)
                        self._emit("finding", scanner=scanner_name, finding=finding)

            await asyncio.wait_for(_collect(), timeout=self.SCANNER_TIMEOUT)
        except asyncio.TimeoutError:
            self._emit("scanner_error", scanner=scanner_name,
                       error=f"Timed out after {self.SCANNER_TIMEOUT}s (partial results: {len(result['findings'])} findings)")
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
            async with scanner:
                for i, url in enumerate(urls):
                    try:
                        ctx = ScanContext.from_url(url)
                        ctx.extra = context.get("crawl_extra", {})

                        async for finding in scanner.scan(ctx):
                            # Stamp module attribution if scanner didn't set it
                            if not finding.scanner_module:
                                finding.scanner_module = scanner_name
                            result["findings"].append(finding)
                            self._emit("finding", scanner=scanner_name, finding=finding)
                    except Exception:
                        continue
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

        # ── Step 0: Subfinder — subdomain enumeration (optional) ──────────────
        # Only run for deep scans (not quick preset — too slow)
        requested_modules = context.get("modules", [])
        run_deep_recon = not requested_modules  # empty = full scan

        if run_deep_recon:
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

        # ── Step 1: Crawl the target ──────────────────────────────────────────
        crawler = self.engine.modules.get("crawl")
        crawl_result = None

        if crawler:
            self._emit("crawl_start", target=url)
            try:
                crawl_result = await crawler.crawl(url)

                # Store crawl data in context for later phases
                context["crawl_result"] = crawl_result
                context["resolved_url"] = crawl_result.resolved_url or url
                context["discovered_urls"] = list(crawl_result.urls)
                context["urls_with_params"] = list(crawl_result.urls_with_params)
                context["js_files"] = list(crawl_result.js_files)
                context["forms"] = crawl_result.forms
                context["technologies"] = crawl_result.technologies
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

        # ── Step 2: Nmap port scan (optional external tool) ───────────────────
        if run_deep_recon:
            try:
                import nmap as _nmap_check  # noqa: F811, F401 — verify python-nmap is installed

                from beatrix.core.nmap_scanner import NetworkScanner
                nmap_scanner = NetworkScanner()
                self._emit("info", message=f"Running nmap service scan on {domain}")
                scan_result = await nmap_scanner.service_scan(domain, ports="1-1000")
                if scan_result and scan_result.hosts:
                    open_ports = []
                    for host in scan_result.hosts:
                        for port in host.ports:
                            if port.state.value == "open":
                                svc = f" ({port.service})" if port.service else ""
                                open_ports.append(f"{port.port}/{port.protocol}{svc}")
                    context["open_ports"] = open_ports
                    if open_ports:
                        self._emit("info", message=f"Nmap found {len(open_ports)} open ports: {', '.join(open_ports[:10])}")
            except ImportError:
                pass  # python-nmap not installed — skip silently
            except Exception as e:
                self._emit("scanner_error", scanner="nmap", error=str(e))

        # ── Steps 3-6: Run recon scanners concurrently ─────────────────────
        # These scanners are independent — run them in parallel for speed
        import asyncio

        js_scan_ctx = None
        if crawl_result and crawl_result.js_files:
            js_scan_ctx = ScanContext.from_url(url)
            js_scan_ctx.extra = {"js_files": list(crawl_result.js_files)}

        scanner_tasks = [
            self._run_scanner("endpoint_prober", url, context),
            self._run_scanner("js_analysis", url, context, scan_context=js_scan_ctx),
            self._run_scanner("headers", url, context),
            self._run_scanner("github_recon", url, context),
        ]

        concurrent_results = await asyncio.gather(*scanner_tasks, return_exceptions=True)
        for r in concurrent_results:
            if isinstance(r, Exception):
                self._emit("scanner_error", scanner="recon", error=str(r))
            else:
                results.append(r)

        merged = await self._merge_scanner_results(results)

        # Add discovered assets to the merged result
        if crawl_result:
            merged["assets"] = list(crawl_result.urls)[:100]
            merged["context"] = {
                "endpoints": list(crawl_result.urls),
                "parameters": list(crawl_result.parameters.keys()),
                "technologies": crawl_result.technologies,
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

        # HTTP smuggling — CL.TE, TE.CL, H2 desync
        results.append(await self._run_scanner("http_smuggling", url, context))

        # WebSocket — check for WS upgrade, CSWSH, auth issues
        results.append(await self._run_scanner("websocket", url, context))

        return await self._merge_scanner_results(results)

    async def _handle_exploitation(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Phase 4 — Exploitation: Full vulnerability testing.

        Runs ALL exploitation scanners against crawled URLs.
        Context propagation is critical — without crawled URLs+params,
        injection scanners find 0 insertion points on the bare domain.
        """
        url = context.get("resolved_url", target if "://" in target else f"https://{target}")

        results = []
        urls_with_params = context.get("urls_with_params", [])

        # ── Injection variants — need URLs with parameters ────────────────────
        if urls_with_params:
            self._emit("info", message=f"Testing {len(urls_with_params)} URLs with parameters for injection")
            results.append(await self._run_scanner_on_urls("injection", urls_with_params, context))
            results.append(await self._run_scanner_on_urls("ssti", urls_with_params, context))
            results.append(await self._run_scanner_on_urls("ssrf", urls_with_params, context))
            results.append(await self._run_scanner_on_urls("mass_assignment", urls_with_params, context))
            results.append(await self._run_scanner_on_urls("redos", urls_with_params[:10], context))
        else:
            results.append(await self._run_scanner("injection", url, context))
            results.append(await self._run_scanner("ssti", url, context))
            results.append(await self._run_scanner("ssrf", url, context))
            results.append(await self._run_scanner("mass_assignment", url, context))
            results.append(await self._run_scanner("redos", url, context))

        # ── XXE — targets XML-accepting endpoints ─────────────────────────────
        results.append(await self._run_scanner("xxe", url, context))

        # ── Deserialization — tests for insecure deserialization ───────────────
        results.append(await self._run_scanner("deserialization", url, context))

        # ── IDOR/BAC — runs on base URL checking for ID patterns ──────────────
        results.append(await self._run_scanner("idor", url, context))
        results.append(await self._run_scanner("bac", url, context))

        # ── Auth — runs on base URL checking for auth issues ──────────────────
        results.append(await self._run_scanner("auth", url, context))

        # ── GraphQL — discovers and tests GraphQL endpoints ───────────────────
        results.append(await self._run_scanner("graphql", url, context))

        # ── Business logic — boundary conditions, race conditions ─────────────
        results.append(await self._run_scanner("business_logic", url, context))

        # ── Payment — checkout flow manipulation ──────────────────────────────
        results.append(await self._run_scanner("payment", url, context))

        # ── Nuclei — runs on ALL discovered URLs with dynamic templates ───────
        nuclei = self.engine.modules.get("nuclei")
        if nuclei and hasattr(nuclei, 'available') and nuclei.available:
            # Feed nuclei all discovered URLs
            all_urls = list(set(
                context.get("discovered_urls", []) +
                urls_with_params +
                [url]
            ))
            if hasattr(nuclei, 'add_urls'):
                nuclei.add_urls(all_urls)

            # Feed technology fingerprint for dynamic template selection
            if hasattr(nuclei, 'set_technologies'):
                techs = context.get("technologies", [])
                nuclei.set_technologies(techs)

            self._emit("info", message=f"Scanning {len(all_urls)} URLs with nuclei templates")
            results.append(await self._run_scanner("nuclei", url, context))
        else:
            self._emit("info", message="Nuclei not available — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

        return await self._merge_scanner_results(results)

    async def _handle_installation(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 5 — Installation: file upload, persistence mechanisms."""
        url = context.get("resolved_url", target if "://" in target else f"https://{target}")

        results = []
        # File upload — extension bypass, polyglot uploads, path traversal in filenames
        results.append(await self._run_scanner("file_upload", url, context))

        return await self._merge_scanner_results(results)

    async def _handle_c2(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 6 — C2: OOB detection, exfiltration testing."""
        results = []

        # OOB detection via interact.sh (enrichment for SSRF/XXE findings)
        try:
            from beatrix.core.oob_detector import OOBDetector
            oob = OOBDetector()
            # Store OOB detector in context so scanners can optionally use it
            context["oob_detector"] = oob
            context["oob_available"] = True
            self._emit("info", message="OOB detector initialized — available for callback verification")
        except Exception:
            context["oob_available"] = False

        return await self._merge_scanner_results(results)

    async def _handle_actions(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 7 — Actions on Objectives: validate and report findings."""
        # Validation happens at engine level, this phase aggregates final results
        return {"findings": context.get("findings", []), "assets": [], "context": {}, "modules": ["validate"], "requests": 0}

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

        # Execute each phase
        for phase in run_phases:
            if state.cancelled:
                break

            while state.paused:
                await asyncio.sleep(0.5)

            state.current_phase = phase
            result = await self._execute_phase(phase, state)
            state.phase_results[phase] = result

            # Merge context for next phase
            state.merge_context(result.context)

            # Stop if phase failed critically
            if result.status == PhaseStatus.FAILED and result.errors:
                break

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
