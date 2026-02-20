#!/usr/bin/env python3
"""
BEATRIX Live Integration Tests

Actually runs scanners against safe targets and validates:
1. Real scanner output (findings structure)
2. Report generation (Markdown, JSON, HTML)
3. End-to-end pipeline integrity

Run standalone: python tests/live_integration.py
(NOT discovered by pytest — run directly)
"""

import asyncio
import json
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from beatrix.core.engine import BeatrixEngine
from beatrix.core.types import Confidence, Finding, Severity
from beatrix.reporters import ReportGenerator

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
INFO = "\033[94mℹ\033[0m"
BOLD = "\033[1m"
RESET = "\033[0m"

results = {"passed": 0, "failed": 0, "errors": []}


def check(description: str, condition: bool, detail: str = ""):
    if condition:
        results["passed"] += 1
        print(f"  {PASS} {description}")
    else:
        results["failed"] += 1
        results["errors"].append(f"{description}: {detail}")
        print(f"  {FAIL} {description} — {detail}")


async def test_probe():
    """Test probe against example.com."""
    print(f"\n{BOLD}1. Probe Test (example.com){RESET}")
    engine = BeatrixEngine()
    result = await engine.probe("example.com")

    check("Target is alive", result["alive"])
    check("Status code is 200", result["status_code"] == 200)
    check("Page title detected", result.get("title") is not None and len(result["title"]) > 0,
          f"title={result.get('title')}")
    check("Server header detected", result.get("server") is not None)


async def test_strike_headers():
    """Test strike with headers module against example.com."""
    print(f"\n{BOLD}2. Strike Test — Headers (example.com){RESET}")
    engine = BeatrixEngine()
    result = await engine.strike("https://example.com", "headers")

    check("No errors", len(result.errors) == 0, str(result.errors))
    check("Duration > 0", result.duration > 0, f"duration={result.duration}")
    check("Has findings", len(result.findings) > 0, f"found={len(result.findings)}")

    if result.findings:
        f = result.findings[0]
        check("Finding has title", bool(f.title), f"title={f.title}")
        check("Finding has severity", f.severity is not None)
        check("Finding has URL", bool(f.url))
        check("Finding has description", bool(f.description))
        check("Finding has scanner_module", bool(f.scanner_module))
        check("Severity is LOW or INFO", f.severity in (Severity.LOW, Severity.INFO),
              f"severity={f.severity.value}")


async def test_strike_cors():
    """Test CORS scanner against httpbin.org (known to have permissive CORS)."""
    print(f"\n{BOLD}3. Strike Test — CORS (httpbin.org){RESET}")
    engine = BeatrixEngine()
    result = await engine.strike("https://httpbin.org/get", "cors")

    check("No errors", len(result.errors) == 0, str(result.errors))
    check("Duration > 0", result.duration > 0)
    # httpbin.org has wildcard CORS, should detect it
    print(f"  {INFO} Found {len(result.findings)} CORS findings")
    for f in result.findings:
        check(f"CORS finding: {f.title}", f.severity is not None)


async def test_js_analysis():
    """Test JS analysis against example.com (should find nothing significant)."""
    print(f"\n{BOLD}4. Strike Test — JS Analysis (example.com){RESET}")
    engine = BeatrixEngine()
    result = await engine.strike("https://example.com", "js_analysis")

    check("No errors", len(result.errors) == 0, str(result.errors))
    check("Duration > 0", result.duration > 0)
    print(f"  {INFO} Found {len(result.findings)} JS findings (expect 0 for example.com)")


async def test_report_generation():
    """Test all three report formats with real data."""
    print(f"\n{BOLD}5. Report Generation Tests{RESET}")

    tmp_dir = Path(tempfile.mkdtemp(prefix="beatrix_reports_"))

    try:
        # Create findings from a real scan
        engine = BeatrixEngine()
        result = await engine.strike("https://example.com", "headers")
        findings = result.findings

        if not findings:
            # If example.com has no header findings, create synthetic ones
            findings = [
                Finding(
                    title="Missing HSTS Header",
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    url="https://example.com",
                    description="Strict-Transport-Security header not set.",
                    remediation="Add HSTS header.",
                    scanner_module="headers",
                ),
            ]

        check("Have findings to report", len(findings) > 0, f"count={len(findings)}")

        reporter = ReportGenerator(output_dir=tmp_dir)

        # --- Markdown Single Report ---
        md_path = reporter.generate_report(findings[0], program="TestBounty")
        check("Markdown report created", md_path.exists())
        md_content = md_path.read_text()
        check("Markdown has title", f"# {findings[0].title}" in md_content)
        check("Markdown has severity", findings[0].severity.value.upper() in md_content)
        check("Markdown has CVSS range", "CVSS" in md_content)
        check("Markdown has endpoint", "example.com" in md_content)
        check("Markdown has classification", "## Classification" in md_content)
        check("Markdown has remediation", "## Remediation" in md_content)
        print(f"  {INFO} Markdown report: {md_path} ({md_path.stat().st_size} bytes)")

        # --- Markdown Batch Report ---
        batch_path = reporter.generate_batch_report(findings, "example.com", "TestBounty")
        check("Batch report created", batch_path.exists())
        batch_content = batch_path.read_text()
        check("Batch has executive summary", "Executive Summary" in batch_content)
        check("Batch has all findings", all(f.title in batch_content for f in findings))
        check("Batch has total count", f"Total Findings**: {len(findings)}" in batch_content)
        check("Batch has methodology", "Methodology" in batch_content)
        print(f"  {INFO} Batch report: {batch_path} ({batch_path.stat().st_size} bytes)")

        # --- JSON Export ---
        json_path = tmp_dir / "findings.json"
        reporter.export_json(findings, json_path)
        check("JSON report created", json_path.exists())

        data = json.loads(json_path.read_text())
        check("JSON is array", isinstance(data, list))
        check("JSON has correct count", len(data) == len(findings))

        for item in data:
            check("JSON item has all fields", all(
                k in item for k in ["title", "severity", "confidence", "url",
                                     "description", "scanner_module", "found_at"]
            ))

        # Verify severity values are valid strings
        valid_sevs = {"critical", "high", "medium", "low", "info"}
        for item in data:
            check(f"JSON severity valid: {item['severity']}", item["severity"] in valid_sevs)

        # Verify found_at is ISO format
        for item in data:
            try:
                datetime.fromisoformat(item["found_at"])
                check("JSON found_at is ISO timestamp", True)
            except ValueError:
                check("JSON found_at is ISO timestamp", False, item["found_at"])

        print(f"  {INFO} JSON report: {json_path} ({json_path.stat().st_size} bytes)")

        # --- Print a sample report ---
        print(f"\n{BOLD}  Sample Markdown Report (first 30 lines):{RESET}")
        for line in md_content.split("\n")[:30]:
            print(f"    {line}")

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


async def test_event_pipeline():
    """Test that the event callback pipeline works end-to-end."""
    print(f"\n{BOLD}6. Event Pipeline Test{RESET}")
    events = []

    def on_event(event, data):
        events.append((event, data))

    engine = BeatrixEngine(on_event=on_event)

    # Run a quick scan (just recon) against example.com
    state = await engine.kill_chain.execute(
        target="https://example.com",
        phases=[1],  # Recon only
    )

    check("Got events", len(events) > 0, f"count={len(events)}")

    event_types = [e[0] for e in events]
    check("Has phase_start event", "phase_start" in event_types)
    check("Has crawl_start event", "crawl_start" in event_types)
    check("Has phase_done event", "phase_done" in event_types)

    # Check crawl results
    crawl_done = [e for e in events if e[0] == "crawl_done"]
    if crawl_done:
        data = crawl_done[0][1]
        check("Crawl returned pages", data.get("pages", 0) > 0, f"pages={data.get('pages')}")
        check("Crawl returned URLs", data.get("urls", 0) >= 0, f"urls={data.get('urls')}")
        print(f"  {INFO} Crawl stats: {data.get('pages')} pages, {data.get('urls')} URLs, "
              f"{data.get('js_files')} JS files")

    check("Kill chain state returned", state is not None)
    check("Has phase results", len(state.phase_results) > 0)

    print(f"  {INFO} Total events captured: {len(events)}")
    for event_type in set(event_types):
        count = event_types.count(event_type)
        print(f"    • {event_type}: {count}")


async def test_validators():
    """Test validators with real findings."""
    print(f"\n{BOLD}7. Validator Tests{RESET}")

    engine = BeatrixEngine()
    result = await engine.strike("https://example.com", "headers")

    if result.findings:
        for finding in result.findings[:3]:
            validation = engine.validate_finding(finding)
            check(f"Validated: {finding.title[:40]}",
                  "impact_verdict" in validation and "readiness_verdict" in validation)
            print(f"    Impact passed: {validation['impact_verdict'].passed}, "
                  f"Readiness score: {validation['readiness_verdict'].score}, "
                  f"Submittable: {validation['submittable']}")
    else:
        print(f"  {INFO} No findings to validate (example.com is clean)")


async def test_nuclei_integration():
    """Test nuclei scanner availability."""
    print(f"\n{BOLD}8. Nuclei Integration Test{RESET}")
    from beatrix.scanners.nuclei import NucleiScanner

    n = NucleiScanner()
    check("Nuclei scanner instantiated", n is not None)
    check("Nuclei binary detected", n.available, "nuclei binary not found in PATH")

    if n.available:
        print(f"  {INFO} Nuclei is available and integrated")
    else:
        print(f"  {INFO} Nuclei not installed — install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")


async def main():
    print(f"\n{'='*60}")
    print(f"{BOLD}  BEATRIX — Live Integration Test Suite{RESET}")
    print(f"{'='*60}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Python: {sys.version.split()[0]}")

    await test_probe()
    await test_strike_headers()
    await test_strike_cors()
    await test_js_analysis()
    await test_report_generation()
    await test_event_pipeline()
    await test_validators()
    await test_nuclei_integration()

    # Summary
    total = results["passed"] + results["failed"]
    print(f"\n{'='*60}")
    print(f"{BOLD}  RESULTS: {results['passed']}/{total} passed, {results['failed']} failed{RESET}")
    print(f"{'='*60}")

    if results["errors"]:
        print(f"\n{BOLD}  Failures:{RESET}")
        for err in results["errors"]:
            print(f"  {FAIL} {err}")

    return 0 if results["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
