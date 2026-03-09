"""
BEATRIX Scan Output Manager

Creates and manages a per-scan output directory containing organized results
from every tool and scanner that Beatrix runs.

Directory structure:
    {target}-scan-{DD}-{Mon}-{YYYY}_{HH}-{MM}-{SS}/
        scan_info.txt
        recon/
            subfinder_{target}.txt
            amass_{target}.txt
            nmap_{target}.txt
            katana_{target}.txt
            gospider_{target}.txt
            hakrawler_{target}.txt
            gau_{target}.txt
            whatweb_{target}.json
            webanalyze_{target}.json
            dirsearch_{target}.json
            crawl_{target}.json
            endpoint_prober_{target}.json
            js_analysis_{target}.json
            headers_{target}.json
            github_recon_{target}.json
            technologies_{target}.json
        weaponization/
            takeover_{target}.json
            error_disclosure_{target}.json
            cache_poisoning_{target}.json
            prototype_pollution_{target}.json
        delivery/
            cors_{target}.json
            redirect_{target}.json
            http_smuggling_{target}.json
            websocket_{target}.json
        exploitation/
            injection_{target}.json
            ssrf_{target}.json
            idor_{target}.json
            auth_{target}.json
            nuclei_{target}.json
            ...
        installation/
            file_upload_{target}.json
        c2/
            oob_callbacks_{target}.json
        findings/
            all_findings_{target}.json
            findings_summary_{target}.txt
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# Map kill chain phase numbers to directory names
_PHASE_DIRS = {
    1: "recon",
    2: "weaponization",
    3: "delivery",
    4: "exploitation",
    5: "installation",
    6: "c2",
    7: "objectives",
}

# Map scanner module keys to their kill chain phase
_SCANNER_PHASE = {
    "crawl": 1, "endpoint_prober": 1, "js_analysis": 1, "headers": 1,
    "github_recon": 1,
    "takeover": 2, "error_disclosure": 2, "cache_poisoning": 2,
    "prototype_pollution": 2,
    "cors": 3, "redirect": 3, "oauth_redirect": 3, "http_smuggling": 3,
    "websocket": 3,
    "injection": 4, "ssti": 4, "ssrf": 4, "idor": 4, "bac": 4, "auth": 4,
    "graphql": 4, "mass_assignment": 4, "business_logic": 4, "redos": 4,
    "payment": 4, "nuclei": 4, "xxe": 4, "deserialization": 4, "dom_xss": 4,
    "backslash": 4, "param_miner": 4, "sequencer": 4,
    "file_upload": 5,
}


def _sanitize_target(target: str) -> str:
    """Convert a target URL/domain into a safe filesystem name.

    Examples:
        https://example.com      → example.com
        https://api.example.com  → api.example.com
        192.168.1.1              → 192.168.1.1
        http://example.com:8080  → example.com_8080
    """
    # Strip scheme
    name = re.sub(r'^https?://', '', target)
    # Strip trailing slash/path
    name = name.split('/')[0]
    # Replace colon (port) with underscore
    name = name.replace(':', '_')
    # Remove or replace any remaining unsafe chars
    name = re.sub(r'[^\w.\-]', '_', name)
    return name


class ScanOutputManager:
    """Manages organized output for a single scan run.

    Creates a timestamped directory named after the target and provides
    methods to write tool output, scanner results, and findings.
    """

    def __init__(self, target: str, base_dir: Optional[Path] = None):
        """
        Args:
            target: The scan target (URL or domain).
            base_dir: Parent directory for the scan folder. Defaults to cwd.
        """
        self.target = target
        self.target_safe = _sanitize_target(target)
        self.base_dir = Path(base_dir) if base_dir else Path.cwd()
        self.started_at = datetime.now()

        # Build directory name: {target}-scan-{DD}-{Mon}-{YYYY}_{HH}-{MM}-{SS}
        ts = self.started_at.strftime("%d-%b-%Y_%H-%M-%S")
        self.scan_dir = self.base_dir / f"{self.target_safe}-scan-{ts}"

        # Create the top-level directory
        self.scan_dir.mkdir(parents=True, exist_ok=True)

        # Write initial scan info
        self._write_scan_info()

    def _write_scan_info(self) -> None:
        """Write a scan_info.txt with basic metadata."""
        info = (
            f"Beatrix Scan Output\n"
            f"{'=' * 40}\n"
            f"Target:    {self.target}\n"
            f"Started:   {self.started_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Directory: {self.scan_dir}\n"
        )
        (self.scan_dir / "scan_info.txt").write_text(info)

    def _phase_dir(self, phase: int) -> Path:
        """Get or create the directory for a kill chain phase."""
        dirname = _PHASE_DIRS.get(phase, f"phase_{phase}")
        d = self.scan_dir / dirname
        d.mkdir(exist_ok=True)
        return d

    def _findings_dir(self) -> Path:
        """Get or create the findings directory."""
        d = self.scan_dir / "findings"
        d.mkdir(exist_ok=True)
        return d

    # ── External tool raw output ─────────────────────────────────────────

    def write_tool_output(self, tool_name: str, raw_output: str,
                          phase: int = 1) -> Path:
        """Write raw stdout from an external tool.

        Args:
            tool_name: e.g. "subfinder", "nmap", "katana"
            raw_output: The raw stdout string from the tool
            phase: Kill chain phase number (default: 1 for recon)

        Returns:
            Path to the written file.
        """
        d = self._phase_dir(phase)
        filename = f"{tool_name}_{self.target_safe}.txt"
        path = d / filename
        path.write_text(raw_output)
        return path

    def write_tool_json(self, tool_name: str, data: Any,
                        phase: int = 1) -> Path:
        """Write parsed/structured tool output as JSON.

        Args:
            tool_name: e.g. "whatweb", "webanalyze"
            data: Structured data (dict, list, etc.)
            phase: Kill chain phase number

        Returns:
            Path to the written file.
        """
        d = self._phase_dir(phase)
        filename = f"{tool_name}_{self.target_safe}.json"
        path = d / filename
        path.write_text(json.dumps(data, indent=2, default=str))
        return path

    # ── Scanner results ──────────────────────────────────────────────────

    def write_scanner_result(self, scanner_key: str, result: Dict[str, Any]) -> Path:
        """Write a scanner's full result dict as JSON.

        Args:
            scanner_key: Engine module key (e.g. "cors", "injection")
            result: The result dict from _run_scanner()

        Returns:
            Path to the written file.
        """
        phase = _SCANNER_PHASE.get(scanner_key, 4)
        d = self._phase_dir(phase)
        # Serialize findings within the result
        serializable = self._make_serializable(result)
        filename = f"{scanner_key}_{self.target_safe}.json"
        path = d / filename
        path.write_text(json.dumps(serializable, indent=2, default=str))
        return path

    # ── Context snapshots ────────────────────────────────────────────────

    def write_context_snapshot(self, label: str, data: Dict[str, Any],
                               phase: int = 1) -> Path:
        """Write a snapshot of context data (e.g. technologies, subdomains).

        Args:
            label: Descriptive label (e.g. "technologies", "subdomains")
            data: The data to write
            phase: Kill chain phase number

        Returns:
            Path to the written file.
        """
        d = self._phase_dir(phase)
        filename = f"{label}_{self.target_safe}.json"
        path = d / filename
        path.write_text(json.dumps(data, indent=2, default=str))
        return path

    # ── Findings ─────────────────────────────────────────────────────────

    def write_findings(self, findings: List[Any]) -> Path:
        """Write all findings as JSON.

        Args:
            findings: List of Finding objects

        Returns:
            Path to the written file.
        """
        d = self._findings_dir()
        serializable = [self._finding_to_dict(f) for f in findings]
        path = d / f"all_findings_{self.target_safe}.json"
        path.write_text(json.dumps(serializable, indent=2, default=str))
        return path

    def write_findings_summary(self, findings: List[Any],
                                duration: float = 0.0) -> Path:
        """Write a human-readable findings summary.

        Args:
            findings: List of Finding objects
            duration: Total scan duration in seconds

        Returns:
            Path to the written file.
        """
        d = self._findings_dir()
        path = d / f"findings_summary_{self.target_safe}.txt"

        lines = [
            f"Beatrix Scan Results — {self.target}",
            f"{'=' * 60}",
            f"Scan started:  {self.started_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Duration:      {duration:.1f}s",
            f"Total findings: {len(findings)}",
            "",
        ]

        # Count by severity
        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev = str(getattr(f, 'severity', 'UNKNOWN'))
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        if sev_counts:
            lines.append("By severity:")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if sev in sev_counts:
                    lines.append(f"  {sev}: {sev_counts[sev]}")
            lines.append("")

        # List each finding
        lines.append("Findings:")
        lines.append("-" * 60)
        for i, f in enumerate(findings, 1):
            sev = getattr(f, 'severity', 'UNKNOWN')
            title = getattr(f, 'title', 'Unknown')
            url = getattr(f, 'url', '')
            scanner = getattr(f, 'scanner_module', '')
            lines.append(f"  [{i}] [{sev}] {title}")
            if url:
                lines.append(f"      URL: {url}")
            if scanner:
                lines.append(f"      Scanner: {scanner}")
            lines.append("")

        path.write_text("\n".join(lines))
        return path

    # ── Finalization ─────────────────────────────────────────────────────

    def finalize(self, duration: float = 0.0, preset: str = "",
                 modules_run: Optional[List[str]] = None) -> None:
        """Update scan_info.txt with final stats."""
        info_path = self.scan_dir / "scan_info.txt"
        existing = info_path.read_text() if info_path.exists() else ""
        addendum = (
            f"\n{'=' * 40}\n"
            f"Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Duration:  {duration:.1f}s\n"
            f"Preset:    {preset}\n"
        )
        if modules_run:
            addendum += f"Modules:   {', '.join(sorted(modules_run))}\n"
        info_path.write_text(existing + addendum)

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _finding_to_dict(finding: Any) -> Dict[str, Any]:
        """Convert a Finding dataclass to a serializable dict."""
        if hasattr(finding, '__dataclass_fields__'):
            d = {}
            for field_name in finding.__dataclass_fields__:
                val = getattr(finding, field_name, None)
                if hasattr(val, 'value'):  # Enum
                    d[field_name] = val.value
                elif hasattr(val, 'name'):  # Named enum
                    d[field_name] = val.name
                else:
                    d[field_name] = val
            return d
        elif hasattr(finding, '__dict__'):
            return {k: (v.name if hasattr(v, 'name') and hasattr(v, 'value') else v)
                    for k, v in finding.__dict__.items()}
        return {"raw": str(finding)}

    @staticmethod
    def _make_serializable(obj: Any) -> Any:
        """Recursively make an object JSON-serializable."""
        if isinstance(obj, dict):
            return {k: ScanOutputManager._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [ScanOutputManager._make_serializable(v) for v in obj]
        elif isinstance(obj, set):
            return sorted(str(v) for v in obj)
        elif hasattr(obj, '__dataclass_fields__'):
            return ScanOutputManager._finding_to_dict(obj)
        elif hasattr(obj, 'name') and hasattr(obj, 'value'):
            return obj.name
        elif isinstance(obj, Path):
            return str(obj)
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        return str(obj)
