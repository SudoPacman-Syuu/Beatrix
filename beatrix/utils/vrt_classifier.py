"""
Bugcrowd Vulnerability Rating Taxonomy (VRT) Classifier
========================================================
Maps vulnerability findings to Bugcrowd VRT categories with P1-P5 priority ratings.
Includes CVSS 3.1 scoring and filters out P5 informational issues.

Reference: https://bugcrowd.com/vulnerability-rating-taxonomy
Version: 1.17 (August 2025)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Priority(Enum):
    """Bugcrowd Priority Ratings"""
    P1 = 1  # Critical - Immediate attention required
    P2 = 2  # High - Significant security impact
    P3 = 3  # Medium - Moderate security impact
    P4 = 4  # Low - Minor security impact
    P5 = 5  # Informational - Best practice / theoretical
    VARIES = 0  # Context-dependent


@dataclass
class CVSSScore:
    """CVSS 3.1 Score Components"""
    # Base Score Metrics
    attack_vector: str = "N"      # N=Network, A=Adjacent, L=Local, P=Physical
    attack_complexity: str = "L"   # L=Low, H=High
    privileges_required: str = "N" # N=None, L=Low, H=High
    user_interaction: str = "N"    # N=None, R=Required
    scope: str = "U"               # U=Unchanged, C=Changed
    confidentiality: str = "H"     # N=None, L=Low, H=High
    integrity: str = "H"           # N=None, L=Low, H=High
    availability: str = "N"        # N=None, L=Low, H=High

    def calculate_base_score(self) -> float:
        """Calculate CVSS 3.1 Base Score"""
        # Attack Vector values
        av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        # Attack Complexity values
        ac_values = {"L": 0.77, "H": 0.44}
        # Privileges Required values (scope unchanged)
        pr_values_u = {"N": 0.85, "L": 0.62, "H": 0.27}
        # Privileges Required values (scope changed)
        pr_values_c = {"N": 0.85, "L": 0.68, "H": 0.5}
        # User Interaction values
        ui_values = {"N": 0.85, "R": 0.62}
        # CIA Impact values
        cia_values = {"N": 0, "L": 0.22, "H": 0.56}

        # Get values
        av = av_values.get(self.attack_vector, 0.85)
        ac = ac_values.get(self.attack_complexity, 0.77)
        pr = pr_values_c.get(self.privileges_required, 0.85) if self.scope == "C" else pr_values_u.get(self.privileges_required, 0.85)
        ui = ui_values.get(self.user_interaction, 0.85)

        c = cia_values.get(self.confidentiality, 0.56)
        i = cia_values.get(self.integrity, 0.56)
        a = cia_values.get(self.availability, 0)

        # Calculate Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Calculate Impact
        isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))

        if self.scope == "U":
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)

        # Calculate Base Score
        if impact <= 0:
            return 0.0

        if self.scope == "U":
            base_score = min(impact + exploitability, 10)
        else:
            base_score = min(1.08 * (impact + exploitability), 10)

        # Round up to 1 decimal
        return round(base_score * 10) / 10

    def get_severity_rating(self) -> str:
        """Get severity rating from CVSS score"""
        score = self.calculate_base_score()
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 0.1:
            return "Low"
        return "None"

    def get_vector_string(self) -> str:
        """Generate CVSS 3.1 vector string"""
        return f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/PR:{self.privileges_required}/UI:{self.user_interaction}/S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/A:{self.availability}"


@dataclass
class VRTClassification:
    """Bugcrowd VRT Classification"""
    priority: Priority
    category: str
    subcategory: str
    variant: str = ""
    cvss: CVSSScore = field(default_factory=CVSSScore)
    owasp_category: str = ""
    cwe_id: str = ""

    def get_priority_label(self) -> str:
        if self.priority == Priority.VARIES:
            return "Varies"
        return f"P{self.priority.value}"

    def get_full_classification(self) -> str:
        parts = [self.category, self.subcategory]
        if self.variant:
            parts.append(self.variant)
        return " > ".join(parts)


# =============================================================================
# VRT MAPPING DATABASE
# =============================================================================
# Maps vulnerability types to Bugcrowd VRT classifications
# Focus on high-value bugs: AUTHZ, IDOR, RCE, SQLi, XSS, SSRF, SSTI

VRT_DATABASE: Dict[str, VRTClassification] = {
    # =========================================================================
    # P1 - CRITICAL VULNERABILITIES (Immediate payout potential)
    # =========================================================================

    # SQL Injection - P1
    "sql_injection": VRTClassification(
        priority=Priority.P1,
        category="Server-Side Injection",
        subcategory="SQL Injection",
        variant="",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="H"),
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-89"
    ),

    # Remote Code Execution - P1
    "rce": VRTClassification(
        priority=Priority.P1,
        category="Server-Side Injection",
        subcategory="Remote Code Execution (RCE)",
        variant="",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H"),
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-94"
    ),

    # Command Injection - P1
    "command_injection": VRTClassification(
        priority=Priority.P1,
        category="Insecure OS/Firmware",
        subcategory="Command Injection",
        variant="",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H"),
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-78"
    ),

    # XXE - P1
    "xxe": VRTClassification(
        priority=Priority.P1,
        category="Server-Side Injection",
        subcategory="XML External Entity Injection (XXE)",
        variant="",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="U", confidentiality="H", integrity="L", availability="L"),
        owasp_category="A05:2021 - Security Misconfiguration",
        cwe_id="CWE-611"
    ),

    # Local File Inclusion - P1
    "lfi": VRTClassification(
        priority=Priority.P1,
        category="Server-Side Injection",
        subcategory="File Inclusion",
        variant="Local",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="U", confidentiality="H", integrity="L", availability="N"),
        owasp_category="A01:2021 - Broken Access Control",
        cwe_id="CWE-98"
    ),

    # Authentication Bypass - P1
    "auth_bypass": VRTClassification(
        priority=Priority.P1,
        category="Broken Authentication and Session Management",
        subcategory="Authentication Bypass",
        variant="",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="N"),
        owasp_category="A07:2021 - Identification and Authentication Failures",
        cwe_id="CWE-287"
    ),

    # IDOR - Modify/View Sensitive (Iterable) - P1
    "idor_sensitive_iterable": VRTClassification(
        priority=Priority.P1,
        category="Broken Access Control (BAC)",
        subcategory="Insecure Direct Object References (IDOR)",
        variant="Modify/View Sensitive Information (Iterable Object Identifiers)",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="L",
                       user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="N"),
        owasp_category="A01:2021 - Broken Access Control",
        cwe_id="CWE-639"
    ),

    # Admin Portal Exposed - P1
    "admin_portal_exposed": VRTClassification(
        priority=Priority.P1,
        category="Server Security Misconfiguration",
        subcategory="Exposed Portal",
        variant="Admin Portal",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="L"),
        owasp_category="A05:2021 - Security Misconfiguration",
        cwe_id="CWE-200"
    ),

    # Default Credentials - P1
    "default_credentials": VRTClassification(
        priority=Priority.P1,
        category="Server Security Misconfiguration",
        subcategory="Using Default Credentials",
        variant="",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="H"),
        owasp_category="A07:2021 - Identification and Authentication Failures",
        cwe_id="CWE-798"
    ),

    # Secrets Disclosure (Public Asset) - P1
    "secrets_disclosure_public": VRTClassification(
        priority=Priority.P1,
        category="Sensitive Data Exposure",
        subcategory="Disclosure of Secrets",
        variant="For Publicly Accessible Asset",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="U", confidentiality="H", integrity="N", availability="N"),
        owasp_category="A02:2021 - Cryptographic Failures",
        cwe_id="CWE-200"
    ),

    # =========================================================================
    # P2 - HIGH VULNERABILITIES (Strong payout potential)
    # =========================================================================

    # SSRF - Internal High Impact - P2
    "ssrf_high_impact": VRTClassification(
        priority=Priority.P2,
        category="Server Security Misconfiguration",
        subcategory="Server-Side Request Forgery (SSRF)",
        variant="Internal High Impact",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="C", confidentiality="H", integrity="L", availability="N"),
        owasp_category="A10:2021 - Server-Side Request Forgery",
        cwe_id="CWE-918"
    ),

    # Stored XSS - Non-Privileged to Anyone - P2
    "stored_xss": VRTClassification(
        priority=Priority.P2,
        category="Cross-Site Scripting (XSS)",
        subcategory="Stored",
        variant="Non-Privileged User to Anyone",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="L",
                       user_interaction="R", scope="C", confidentiality="L", integrity="L", availability="N"),
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-79"
    ),

    # IDOR - Modify Sensitive (Iterable) - P2
    "idor_modify_iterable": VRTClassification(
        priority=Priority.P2,
        category="Broken Access Control (BAC)",
        subcategory="Insecure Direct Object References (IDOR)",
        variant="Modify Sensitive Information (Iterable Object Identifiers)",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="L",
                       user_interaction="N", scope="U", confidentiality="N", integrity="H", availability="N"),
        owasp_category="A01:2021 - Broken Access Control",
        cwe_id="CWE-639"
    ),

    # Application-Wide CSRF - P2
    "csrf_application_wide": VRTClassification(
        priority=Priority.P2,
        category="Cross-Site Request Forgery (CSRF)",
        subcategory="Application-Wide",
        variant="",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="R", scope="U", confidentiality="N", integrity="H", availability="N"),
        owasp_category="A01:2021 - Broken Access Control",
        cwe_id="CWE-352"
    ),

    # OAuth Account Takeover - P2
    "oauth_ato": VRTClassification(
        priority=Priority.P2,
        category="Server Security Misconfiguration",
        subcategory="OAuth Misconfiguration",
        variant="Account Takeover",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="R", scope="U", confidentiality="H", integrity="H", availability="N"),
        owasp_category="A07:2021 - Identification and Authentication Failures",
        cwe_id="CWE-287"
    ),

    # =========================================================================
    # P3 - MEDIUM VULNERABILITIES (Moderate payout potential)
    # =========================================================================

    # Reflected XSS - Non-Self - P3
    "reflected_xss": VRTClassification(
        priority=Priority.P3,
        category="Cross-Site Scripting (XSS)",
        subcategory="Reflected",
        variant="Non-Self",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="R", scope="C", confidentiality="L", integrity="L", availability="N"),
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-79"
    ),

    # SSRF - Internal Scan / Medium Impact - P3
    "ssrf_medium_impact": VRTClassification(
        priority=Priority.P3,
        category="Server Security Misconfiguration",
        subcategory="Server-Side Request Forgery (SSRF)",
        variant="Internal Scan and/or Medium Impact",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="U", confidentiality="L", integrity="N", availability="N"),
        owasp_category="A10:2021 - Server-Side Request Forgery",
        cwe_id="CWE-918"
    ),

    # IDOR - View Sensitive (Iterable) - P3
    "idor_view_iterable": VRTClassification(
        priority=Priority.P3,
        category="Broken Access Control (BAC)",
        subcategory="Insecure Direct Object References (IDOR)",
        variant="View Sensitive Information (Iterable Object Identifiers)",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="L",
                       user_interaction="N", scope="U", confidentiality="H", integrity="N", availability="N"),
        owasp_category="A01:2021 - Broken Access Control",
        cwe_id="CWE-639"
    ),

    # CRLF Injection - P3
    "crlf_injection": VRTClassification(
        priority=Priority.P3,
        category="Server-Side Injection",
        subcategory="HTTP Response Manipulation",
        variant="Response Splitting (CRLF)",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="R", scope="U", confidentiality="L", integrity="L", availability="N"),
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-113"
    ),

    # 2FA Bypass - P3
    "2fa_bypass": VRTClassification(
        priority=Priority.P3,
        category="Broken Authentication and Session Management",
        subcategory="Second Factor Authentication (2FA) Bypass",
        variant="",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="L",
                       user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="N"),
        owasp_category="A07:2021 - Identification and Authentication Failures",
        cwe_id="CWE-287"
    ),

    # Subdomain Takeover - P3
    "subdomain_takeover": VRTClassification(
        priority=Priority.P3,
        category="Server Security Misconfiguration",
        subcategory="Misconfigured DNS",
        variant="Subdomain Takeover",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="U", confidentiality="N", integrity="L", availability="N"),
        owasp_category="A05:2021 - Security Misconfiguration",
        cwe_id="CWE-200"
    ),

    # =========================================================================
    # P2 - HIGH VULNERABILITIES (Significant payout potential)
    # =========================================================================

    # SSTI - P2 (Confirmed template execution is high risk - trivial path to RCE)
    "ssti_basic": VRTClassification(
        priority=Priority.P2,
        category="Server-Side Injection",
        subcategory="Server-Side Template Injection (SSTI)",
        variant="Confirmed Template Execution",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H"),
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-94"
    ),

    # =========================================================================
    # P4 - LOW VULNERABILITIES (Minor payout potential)
    # =========================================================================

    # Open Redirect GET-Based - P4
    "open_redirect": VRTClassification(
        priority=Priority.P4,
        category="Unvalidated Redirects and Forwards",
        subcategory="Open Redirect",
        variant="GET-Based",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="R", scope="U", confidentiality="N", integrity="L", availability="N"),
        owasp_category="A01:2021 - Broken Access Control",
        cwe_id="CWE-601"
    ),

    # IDOR - Complex Object IDs - P4
    "idor_complex": VRTClassification(
        priority=Priority.P4,
        category="Broken Access Control (BAC)",
        subcategory="Insecure Direct Object References (IDOR)",
        variant="Modify/View Sensitive Information (Complex Object Identifiers GUID/UUID)",
        cvss=CVSSScore(attack_vector="N", attack_complexity="H", privileges_required="L",
                       user_interaction="N", scope="U", confidentiality="L", integrity="L", availability="N"),
        owasp_category="A01:2021 - Broken Access Control",
        cwe_id="CWE-639"
    ),

    # Clickjacking Sensitive Action - P4
    "clickjacking_sensitive": VRTClassification(
        priority=Priority.P4,
        category="Server Security Misconfiguration",
        subcategory="Clickjacking",
        variant="Sensitive Click-Based Action",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="R", scope="U", confidentiality="N", integrity="L", availability="N"),
        owasp_category="A05:2021 - Security Misconfiguration",
        cwe_id="CWE-1021"
    ),

    # Missing Secure Cookie Flag - P4
    "missing_secure_cookie": VRTClassification(
        priority=Priority.P4,
        category="Server Security Misconfiguration",
        subcategory="Missing Secure or HTTPOnly Cookie Flag",
        variant="Session Token",
        cvss=CVSSScore(attack_vector="N", attack_complexity="H", privileges_required="N",
                       user_interaction="R", scope="U", confidentiality="L", integrity="N", availability="N"),
        owasp_category="A05:2021 - Security Misconfiguration",
        cwe_id="CWE-614"
    ),

    # =========================================================================
    # VARIES - Context-dependent (requires manual assessment)
    # =========================================================================

    "privilege_escalation": VRTClassification(
        priority=Priority.VARIES,
        category="Broken Access Control (BAC)",
        subcategory="Privilege Escalation",
        variant="",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="L",
                       user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="N"),
        owasp_category="A01:2021 - Broken Access Control",
        cwe_id="CWE-269"
    ),

    "path_traversal": VRTClassification(
        priority=Priority.VARIES,
        category="Server Security Misconfiguration",
        subcategory="Path Traversal",
        variant="",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="U", confidentiality="H", integrity="N", availability="N"),
        owasp_category="A01:2021 - Broken Access Control",
        cwe_id="CWE-22"
    ),

    "race_condition": VRTClassification(
        priority=Priority.VARIES,
        category="Server Security Misconfiguration",
        subcategory="Race Condition",
        variant="",
        cvss=CVSSScore(attack_vector="N", attack_complexity="H", privileges_required="L",
                       user_interaction="N", scope="U", confidentiality="L", integrity="L", availability="N"),
        owasp_category="A04:2021 - Insecure Design",
        cwe_id="CWE-362"
    ),

    "cors_misconfiguration": VRTClassification(
        priority=Priority.VARIES,
        category="Server Security Misconfiguration",
        subcategory="Unsafe Cross-Origin Resource Sharing",
        variant="",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="R", scope="U", confidentiality="L", integrity="L", availability="N"),
        owasp_category="A05:2021 - Security Misconfiguration",
        cwe_id="CWE-942"
    ),

    # =========================================================================
    # P4/INFO - Low severity informational findings
    # =========================================================================

    # Method Disclosure - P4/Info (OPTIONS reveals allowed methods)
    "method_disclosure": VRTClassification(
        priority=Priority.P4,
        category="Server Security Misconfiguration",
        subcategory="HTTP Method Disclosure",
        variant="OPTIONS Method Enabled",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="U", confidentiality="L", integrity="N", availability="N"),
        owasp_category="A05:2021 - Security Misconfiguration",
        cwe_id="CWE-749"
    ),

    # HTTP Method Tampering - P3 (if PUT/DELETE actually work)
    "http_method_tampering": VRTClassification(
        priority=Priority.P3,
        category="Server Security Misconfiguration",
        subcategory="HTTP Method Tampering",
        variant="Dangerous Methods Allowed",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="U", confidentiality="N", integrity="L", availability="L"),
        owasp_category="A05:2021 - Security Misconfiguration",
        cwe_id="CWE-650"
    ),

    # Header-based Access Bypass - P2 (serious if confirmed)
    "header_bypass": VRTClassification(
        priority=Priority.P2,
        category="Broken Access Control (BAC)",
        subcategory="Header-Based Authorization Bypass",
        variant="",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="N"),
        owasp_category="A01:2021 - Broken Access Control",
        cwe_id="CWE-287"
    ),

    # Path Traversal Bypass - P2 (serious if confirmed)
    "path_bypass": VRTClassification(
        priority=Priority.P2,
        category="Broken Access Control (BAC)",
        subcategory="Path Traversal Authorization Bypass",
        variant="",
        cvss=CVSSScore(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="U", confidentiality="H", integrity="L", availability="N"),
        owasp_category="A01:2021 - Broken Access Control",
        cwe_id="CWE-22"
    ),
}


class VRTClassifier:
    """Classifies vulnerabilities according to Bugcrowd VRT"""

    # Mapping from common vulnerability names to VRT keys
    VULN_TYPE_MAPPING = {
        # SQL Injection variants
        "sql injection": "sql_injection",
        "sqli": "sql_injection",
        "sql_injection": "sql_injection",
        "blind sql injection": "sql_injection",
        "error-based sql injection": "sql_injection",
        "time-based sql injection": "sql_injection",
        "boolean-based sql injection": "sql_injection",

        # RCE/Command Injection
        "remote code execution": "rce",
        "rce": "rce",
        "code execution": "rce",
        "command injection": "command_injection",
        "os command injection": "command_injection",
        "shell injection": "command_injection",

        # XSS variants
        "cross-site scripting": "reflected_xss",
        "xss": "reflected_xss",
        "reflected xss": "reflected_xss",
        "stored xss": "stored_xss",
        "persistent xss": "stored_xss",
        "dom xss": "reflected_xss",

        # SSTI
        "server-side template injection": "ssti_basic",
        "ssti": "ssti_basic",
        "template injection": "ssti_basic",

        # SSRF
        "server-side request forgery": "ssrf_medium_impact",
        "ssrf": "ssrf_medium_impact",
        "ssrf_high": "ssrf_high_impact",
        "ssrf_cloud_metadata": "ssrf_high_impact",

        # XXE
        "xml external entity": "xxe",
        "xxe": "xxe",
        "xxe injection": "xxe",

        # LFI/Path Traversal
        "local file inclusion": "lfi",
        "lfi": "lfi",
        "file inclusion": "lfi",
        "path traversal": "path_traversal",
        "directory traversal": "path_traversal",

        # IDOR
        "idor": "idor_view_iterable",
        "insecure direct object reference": "idor_view_iterable",
        "broken object level authorization": "idor_view_iterable",
        "bola": "idor_view_iterable",

        # Authentication
        "authentication bypass": "auth_bypass",
        "auth bypass": "auth_bypass",
        "2fa bypass": "2fa_bypass",
        "mfa bypass": "2fa_bypass",

        # CSRF
        "csrf": "csrf_application_wide",
        "cross-site request forgery": "csrf_application_wide",

        # CRLF
        "crlf injection": "crlf_injection",
        "http response splitting": "crlf_injection",
        "header injection": "crlf_injection",

        # Open Redirect
        "open redirect": "open_redirect",
        "url redirect": "open_redirect",
        "unvalidated redirect": "open_redirect",

        # CORS
        "cors": "cors_misconfiguration",
        "cors misconfiguration": "cors_misconfiguration",

        # Others
        "subdomain takeover": "subdomain_takeover",
        "clickjacking": "clickjacking_sensitive",
        "privilege escalation": "privilege_escalation",
        "race condition": "race_condition",
        "default credentials": "default_credentials",
        "secrets disclosure": "secrets_disclosure_public",

        # BAC/Method findings (info-level)
        "method disclosure": "method_disclosure",
        "http method tampering": "http_method_tampering",
        "header-based access bypass": "header_bypass",
        "path traversal access bypass": "path_bypass",
        "options method enabled": "method_disclosure",
    }

    @classmethod
    def classify(cls, vuln_type: str, evidence: str = "", severity: str = "") -> Optional[VRTClassification]:
        """
        Classify a vulnerability according to Bugcrowd VRT.

        Args:
            vuln_type: The type/name of the vulnerability
            evidence: Evidence string that may help refine classification
            severity: Original severity rating

        Returns:
            VRTClassification object or None if not classifiable
        """
        vuln_lower = vuln_type.lower().strip()

        # Direct lookup
        if vuln_lower in VRT_DATABASE:
            return VRT_DATABASE[vuln_lower]

        # Mapping lookup
        for pattern, vrt_key in cls.VULN_TYPE_MAPPING.items():
            if pattern in vuln_lower:
                classification = VRT_DATABASE.get(vrt_key)
                if classification:
                    # Refine based on evidence/severity
                    return cls._refine_classification(classification, vuln_type, evidence, severity)

        # Fuzzy matching for common patterns
        classification = cls._fuzzy_match(vuln_lower, evidence, severity)
        if classification:
            return classification

        return None

    @classmethod
    def _refine_classification(cls, base: VRTClassification, vuln_type: str,
                               evidence: str, severity: str) -> VRTClassification:
        """Refine classification based on additional context"""
        vuln_lower = vuln_type.lower()
        evidence_lower = evidence.lower() if evidence else ""

        # SSRF refinement - upgrade to P2 if cloud metadata or high impact
        if base.subcategory == "Server-Side Request Forgery (SSRF)":
            if any(x in evidence_lower for x in ["metadata", "169.254", "cloud", "aws", "gcp", "azure", "iam", "credentials"]):
                return VRT_DATABASE["ssrf_high_impact"]

        # SSTI refinement - if RCE proven, upgrade to P1
        if "ssti" in vuln_lower or "template injection" in vuln_lower:
            if any(x in evidence_lower for x in ["rce", "code execution", "shell", "system command"]):
                return VRT_DATABASE["rce"]

        # XSS refinement - stored vs reflected
        if "xss" in vuln_lower or "cross-site scripting" in vuln_lower:
            if "stored" in vuln_lower or "persistent" in vuln_lower:
                return VRT_DATABASE["stored_xss"]
            return VRT_DATABASE["reflected_xss"]

        # IDOR refinement based on impact
        if "idor" in vuln_lower:
            if "modify" in vuln_lower or "write" in evidence_lower or "delete" in evidence_lower:
                if severity.lower() == "critical":
                    return VRT_DATABASE["idor_sensitive_iterable"]
                return VRT_DATABASE["idor_modify_iterable"]
            return VRT_DATABASE["idor_view_iterable"]

        return base

    @classmethod
    def _fuzzy_match(cls, vuln_type: str, evidence: str, severity: str) -> Optional[VRTClassification]:
        """Fuzzy matching for vulnerabilities not in the mapping"""

        # Check for injection patterns
        if "injection" in vuln_type:
            if "sql" in vuln_type:
                return VRT_DATABASE["sql_injection"]
            if "command" in vuln_type or "os" in vuln_type:
                return VRT_DATABASE["command_injection"]
            if "template" in vuln_type:
                return VRT_DATABASE["ssti_basic"]
            if "xml" in vuln_type:
                return VRT_DATABASE["xxe"]
            if "ldap" in vuln_type:
                return VRT_DATABASE["sql_injection"]  # Similar severity

        # Check for access control patterns
        if any(x in vuln_type for x in ["access control", "authorization", "authz", "privilege"]):
            return VRT_DATABASE["privilege_escalation"]

        # Check for authentication patterns
        if any(x in vuln_type for x in ["authentication", "login", "password", "credential"]):
            if "bypass" in vuln_type:
                return VRT_DATABASE["auth_bypass"]
            if "default" in vuln_type:
                return VRT_DATABASE["default_credentials"]

        return None

    @classmethod
    def should_report(cls, classification: VRTClassification, has_chain: bool = False) -> bool:
        """
        Determine if a vulnerability should be reported based on VRT priority.
        P5 vulnerabilities are excluded unless they have a proven chain to P4+.

        Args:
            classification: The VRT classification
            has_chain: Whether this vuln is part of an exploit chain

        Returns:
            True if the vulnerability should be reported
        """
        if classification.priority == Priority.P5:
            return has_chain  # Only report P5 if proven chainable
        return True

    @classmethod
    def get_report_title(cls, classification: VRTClassification,
                         url: str, parameter: str = "") -> str:
        """
        Generate a Bugcrowd-style report title.

        Format: "[VRT Category] [Vulnerability Type] in [endpoint] via [parameter]"
        """
        param_str = f" via parameter [{parameter}]" if parameter and parameter != "N/A" else ""
        return f"{classification.subcategory} in [{url}]{param_str}"

    @classmethod
    def get_impact_statement(cls, classification: VRTClassification) -> str:
        """Generate impact statement based on VRT classification"""

        impact_templates = {
            Priority.P1: """**CRITICAL IMPACT**: This vulnerability allows an attacker to {action}.
Exploitation requires no authentication and can be performed remotely.
This issue poses an immediate and severe risk to the confidentiality, integrity, and/or availability of the application and its data.

**Business Impact**:
- Complete compromise of affected systems
- Potential data breach affecting all users
- Regulatory compliance violations (GDPR, PCI-DSS, HIPAA)
- Significant reputational damage""",

            Priority.P2: """**HIGH IMPACT**: This vulnerability allows an attacker to {action}.
Successful exploitation could lead to significant unauthorized access or data exposure.

**Business Impact**:
- Unauthorized access to sensitive user data
- Potential for account takeover attacks
- Privacy violations affecting multiple users
- Moderate reputational damage""",

            Priority.P3: """**MEDIUM IMPACT**: This vulnerability allows an attacker to {action}.
Exploitation requires some user interaction or specific conditions.

**Business Impact**:
- Potential for targeted attacks against specific users
- Limited data exposure or session hijacking
- Compliance concerns""",

            Priority.P4: """**LOW IMPACT**: This vulnerability allows an attacker to {action}.
Exploitation is limited in scope or requires significant user interaction.

**Business Impact**:
- Limited security impact
- May be used as part of a larger attack chain
- Best practice violation""",
        }

        # Action descriptions by vulnerability type
        action_map = {
            "SQL Injection": "execute arbitrary SQL queries, potentially extracting, modifying, or deleting database contents",
            "Remote Code Execution (RCE)": "execute arbitrary code on the server, leading to complete system compromise",
            "Command Injection": "execute arbitrary operating system commands on the server",
            "XML External Entity Injection (XXE)": "read arbitrary files from the server and potentially achieve SSRF or DoS",
            "File Inclusion": "read arbitrary files from the server filesystem, potentially including sensitive configuration files",
            "Authentication Bypass": "bypass authentication mechanisms and gain unauthorized access to protected resources",
            "Server-Side Request Forgery (SSRF)": "make the server perform requests to internal resources, potentially accessing cloud metadata or internal services",
            "Insecure Direct Object References (IDOR)": "access or modify data belonging to other users by manipulating object identifiers",
            "Cross-Site Scripting (XSS)": "inject malicious scripts that execute in victims' browsers, potentially stealing session tokens or performing actions on their behalf",
            "Server-Side Template Injection (SSTI)": "inject template code that executes on the server, potentially leading to RCE",
            "HTTP Response Manipulation": "inject headers into HTTP responses, potentially enabling XSS or cache poisoning",
            "Open Redirect": "redirect users to malicious websites, potentially enabling phishing attacks",
        }

        action = action_map.get(classification.subcategory, "compromise the security of the application")
        template = impact_templates.get(classification.priority, impact_templates[Priority.P4])

        return template.format(action=action)


def classify_finding(finding: dict) -> dict:
    """
    Classify a vulnerability finding and enrich it with VRT data.

    Args:
        finding: The original finding dictionary

    Returns:
        Enriched finding with VRT classification, CVSS score, and Bugcrowd-style formatting
    """
    vuln_type = finding.get('vuln_type', finding.get('type', 'Unknown'))
    evidence = finding.get('evidence', finding.get('description', ''))
    severity = finding.get('severity', 'Medium')
    url = finding.get('url', finding.get('host', ''))
    parameter = finding.get('parameter', '')

    # Get VRT classification
    classification = VRTClassifier.classify(vuln_type, evidence, severity)

    if not classification:
        # Create a default classification for unknown types
        classification = VRTClassification(
            priority=Priority.VARIES,
            category="Uncategorized",
            subcategory=vuln_type,
            variant="",
            cvss=CVSSScore(),
            cwe_id=finding.get('cwe', '')
        )

    # Check if should be reported (filter P5)
    if not VRTClassifier.should_report(classification):
        return None  # Filter out P5 vulnerabilities

    # Enrich finding
    enriched = finding.copy()
    enriched.update({
        # VRT Classification
        'vrt_priority': classification.get_priority_label(),
        'vrt_category': classification.category,
        'vrt_subcategory': classification.subcategory,
        'vrt_variant': classification.variant,
        'vrt_full_classification': classification.get_full_classification(),

        # CVSS Score
        'cvss_score': classification.cvss.calculate_base_score(),
        'cvss_severity': classification.cvss.get_severity_rating(),
        'cvss_vector': classification.cvss.get_vector_string(),

        # Normalize severity to lowercase for consistent counting
        'severity': finding.get('severity', 'info').lower(),

        # OWASP & CWE
        'owasp_category': classification.owasp_category or finding.get('owasp', ''),
        'cwe': classification.cwe_id or finding.get('cwe', ''),

        # Bugcrowd-style report
        'report_title': VRTClassifier.get_report_title(classification, url, parameter),
        'impact_statement': VRTClassifier.get_impact_statement(classification),
    })

    return enriched


def filter_and_classify_findings(findings: List[dict]) -> List[dict]:
    """
    Filter and classify a list of findings according to Bugcrowd VRT.
    Removes P5 informational vulnerabilities and false positives (3xx, 4xx responses).

    CRITICAL: Only 200 OK responses are valid findings unless proven to chain.

    Args:
        findings: List of finding dictionaries

    Returns:
        Filtered and enriched list of findings
    """
    classified_findings = []

    # Ensure findings is a list
    if not isinstance(findings, list):
        return classified_findings

    for finding in findings:
        # Skip malformed findings
        if not isinstance(finding, dict):
            continue

        # CRITICAL: Filter out false positives based on status code
        status_code = finding.get('status_code', 200)

        # Convert status_code to int if it's a string
        if isinstance(status_code, str):
            if status_code.isdigit():
                status_code = int(status_code)
            elif status_code == 'N/A':
                status_code = 0  # Unknown status
            else:
                status_code = 0

        # Filter out 3xx (redirects) and 4xx (client errors) - these are false positives
        # Only 200 OK responses should be reported unless proven chainable
        if status_code >= 300 and status_code < 500:
            # Check if this finding has proven chaining capability
            has_chain = finding.get('has_exploit_chain', False)
            chain_evidence = finding.get('chain_evidence', '')

            if not has_chain and not chain_evidence:
                # This is a false positive - skip it
                continue

        enriched = classify_finding(finding)
        if enriched:  # None means filtered out (P5)
            classified_findings.append(enriched)

    # Sort by priority (P1 first) then by CVSS score
    def sort_key(f):
        priority_order = {'P1': 1, 'P2': 2, 'P3': 3, 'P4': 4, 'Varies': 5}
        priority = priority_order.get(f.get('vrt_priority', 'Varies'), 5)
        cvss = f.get('cvss_score', 0)
        return (priority, -cvss)

    classified_findings.sort(key=sort_key)

    return classified_findings
