"""
BEATRIX Report Generator

Auto-generates bug bounty reports from findings.
Outputs Markdown reports ready for HackerOne/Bugcrowd submission.
"""

import json  # noqa: F401
from dataclasses import asdict  # noqa: F401
from datetime import datetime
from pathlib import Path
from typing import List, Optional  # noqa: F401

from beatrix.core.types import Finding, Severity


class ReportGenerator:
    """
    Generates professional bug bounty reports from findings.
    """

    SEVERITY_CVSS = {
        Severity.CRITICAL: "9.0-10.0",
        Severity.HIGH: "7.0-8.9",
        Severity.MEDIUM: "4.0-6.9",
        Severity.LOW: "0.1-3.9",
        Severity.INFO: "0.0",
    }

    def __init__(self, output_dir: Path = Path("./reports")):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        finding: Finding,
        program: str = "Unknown",
        researcher: str = "Security Researcher",
    ) -> Path:
        """Generate a Markdown report for a single finding"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = "".join(c if c.isalnum() else "_" for c in finding.title[:50])
        filename = f"{timestamp}_{safe_title}.md"
        filepath = self.output_dir / filename

        report = self._format_report(finding, program, researcher)
        filepath.write_text(report)

        return filepath

    def generate_batch_report(
        self,
        findings: List[Finding],
        target: str,
        program: str = "Unknown",
    ) -> Path:
        """Generate a combined report for multiple findings"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = "".join(c if c.isalnum() else "_" for c in target[:30])
        filename = f"{timestamp}_{safe_target}_scan_report.md"
        filepath = self.output_dir / filename

        report = self._format_batch_report(findings, target, program)
        filepath.write_text(report)

        return filepath

    def _format_report(
        self,
        finding: Finding,
        program: str,
        researcher: str,
    ) -> str:
        """Format a single finding as a full report"""

        return f"""# {finding.title}

## Summary
{finding.description}

## Severity
**{finding.severity.value.upper()}** (CVSS {self.SEVERITY_CVSS.get(finding.severity, "N/A")})

## Affected Endpoint
```
{finding.url}
```

## Technical Details

### Evidence
```
{finding.evidence or "See request/response below"}
```

### Request
```http
{finding.request or "N/A"}
```

### Response
```http
{finding.response or "N/A"}
```

## Impact
{finding.impact or self._generate_impact(finding)}

## Proof of Concept
{self._generate_poc(finding)}

## Remediation
{finding.remediation or "Implement proper security controls."}

## References
{self._format_references(finding.references)}

## Classification
- **OWASP**: {finding.owasp_category or "N/A"}
- **MITRE ATT&CK**: {finding.mitre_technique or "N/A"}
- **CWE**: {finding.cwe_id or "N/A"}

---
**Program**: {program}
**Discovered**: {finding.found_at.strftime("%Y-%m-%d %H:%M:%S")}
**Scanner**: BEATRIX v0.1.0 ({finding.scanner_module})
**Researcher**: {researcher}
"""

    def _format_batch_report(
        self,
        findings: List[Finding],
        target: str,
        program: str,
    ) -> str:
        """Format multiple findings as a scan report"""

        # Group by severity
        by_severity = {}
        for f in findings:
            sev = f.severity.value
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(f)

        # Summary stats
        summary = f"""# Security Scan Report: {target}

## Executive Summary
- **Target**: {target}
- **Scan Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Total Findings**: {len(findings)}
- **Critical**: {len(by_severity.get('critical', []))}
- **High**: {len(by_severity.get('high', []))}
- **Medium**: {len(by_severity.get('medium', []))}
- **Low**: {len(by_severity.get('low', []))}
- **Info**: {len(by_severity.get('info', []))}

---

"""

        # Add each finding
        for i, finding in enumerate(findings, 1):
            summary += f"""
## Finding #{i}: {finding.title}

**Severity**: {finding.severity.icon} {finding.severity.value.upper()}
**URL**: `{finding.url}`
**Confidence**: {finding.confidence.value}

### Description
{finding.description}

### Evidence
```
{finding.evidence or "N/A"}
```

### Remediation
{finding.remediation or "See vendor documentation."}

---
"""

        summary += f"""
## Methodology
Automated scan performed using BEATRIX autonomous security scanner.

**Program**: {program}
**Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

        return summary

    def _generate_impact(self, finding: Finding) -> str:
        """Generate impact description based on finding type"""

        title_lower = finding.title.lower()

        if "cors" in title_lower:
            return """An attacker can host a malicious webpage that makes authenticated cross-origin
requests to this endpoint. If a victim visits the attacker's page while logged in,
the attacker can read sensitive data from the response."""

        if "sql" in title_lower or "injection" in title_lower:
            return """An attacker could extract, modify, or delete data from the database.
In severe cases, this could lead to full database compromise or remote code execution."""

        if "xss" in title_lower:
            return """An attacker can execute arbitrary JavaScript in the context of the victim's
browser session. This can be used to steal session tokens, perform actions on
behalf of the user, or redirect to malicious sites."""

        return "This vulnerability could be exploited by an attacker to compromise the security of the application or its users."

    def _generate_poc(self, finding: Finding) -> str:
        """Generate proof of concept code"""

        title_lower = finding.title.lower()

        if "cors" in title_lower:
            return f"""```html
<html>
<body>
<h1>CORS PoC</h1>
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', '{finding.url}', true);
xhr.withCredentials = true;
xhr.onload = function() {{
    console.log('Response:', xhr.responseText);
    document.body.innerHTML += '<pre>' + xhr.responseText + '</pre>';
}};
xhr.send();
</script>
</body>
</html>
```"""

        if finding.poc_curl:
            return f"```bash\n{finding.poc_curl}\n```"

        return "```\nManual verification required.\n```"

    def _format_references(self, refs: List[str]) -> str:
        """Format references as markdown list"""
        if not refs:
            return "- N/A"
        return "\n".join(f"- {ref}" for ref in refs)

    def export_json(self, findings: List[Finding], filepath: Path, target: str = None) -> None:
        """Export findings as JSON for further processing.

        Produces a standardised ``{"findings": [...], "metadata": {...}}``
        envelope compatible with ``beatrix validate``.
        """
        from datetime import datetime

        finding_list = []
        for f in findings:
            d = {
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "url": f.url,
                "description": f.description,
                "evidence": f.evidence,
                "request": f.request,
                "response": f.response,
                "remediation": f.remediation,
                "scanner_module": f.scanner_module,
                "found_at": f.found_at.isoformat(),
            }
            finding_list.append(d)

        report = {
            "findings": finding_list,
            "metadata": {
                "tool": "beatrix",
                "version": "1.0.0",
                "target": target,
                "total_findings": len(finding_list),
                "generated_at": datetime.utcnow().isoformat() + "Z",
            },
        }

        filepath.write_text(json.dumps(report, indent=2, default=str))
