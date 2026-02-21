"""
ReconX Event Correlation Engine

A sophisticated attack chain detection and correlation system that combines:
- Lockheed Martin Cyber Kill Chain (7 phases)
- MITRE ATT&CK Framework (tactics, techniques, procedures)
- PTES (Penetration Testing Execution Standard)
- NIST SP 800-115 Technical Guide to Security Testing
- OWASP Testing Guide v4.2

This module provides:
1. Event Correlation - Links related findings across modules
2. Attack Chain Detection - Identifies multi-stage attack patterns
3. Vulnerability Chaining - Maps exploit paths through combined vulnerabilities
4. Kill Chain Progression - Tracks adversary advancement through phases
5. Risk Amplification - Calculates compound risk from chained vulnerabilities

Industry References:
- Hutchins, E., Cloppert, M., Amin, R. (2011). "Intelligence-Driven Computer
  Network Defense Informed by Analysis of Adversary Campaigns and Intrusion
  Kill Chains." Lockheed Martin.
- MITRE ATT&CK Design and Philosophy (March 2020)
- NIST SP 800-115: Technical Guide to Information Security Testing and Assessment
- PTES Technical Guidelines: http://www.pentest-standard.org/
- OWASP Web Security Testing Guide (WSTG)

Author: ReconX Framework
Version: 2.0
"""

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

# Import existing methodology
try:
    from .methodology import (
        ATTACK_PHASES,  # noqa: F401
        MITRE_TECHNIQUES,  # noqa: F401
        MODULE_METHODOLOGY_MAP,  # noqa: F401
        OWASP_TOP_10_2021,  # noqa: F401
        MitreAttackTactic,  # noqa: F401
        MitreTechnique,  # noqa: F401
        enrich_finding_with_methodology,  # noqa: F401
        get_techniques_for_module,  # noqa: F401
    )
except ImportError:
    from methodology import (
        MITRE_TECHNIQUES,
        MODULE_METHODOLOGY_MAP,
        MitreAttackTactic,
    )


# =============================================================================
# CYBER KILL CHAIN (Lockheed Martin, 2011)
# =============================================================================

class CyberKillChainPhase(Enum):
    """
    Lockheed Martin Cyber Kill Chain - 7 Phases

    The Intrusion Kill Chain framework describes the stages of a cyber attack,
    providing defenders with insight into adversary actions and enabling
    courses of action at each phase.

    Reference: "Intelligence-Driven Computer Network Defense" (Hutchins et al., 2011)
    """
    RECONNAISSANCE = 1      # Target identification and research
    WEAPONIZATION = 2       # Creating attack vectors
    DELIVERY = 3            # Transmitting weapon to target
    EXPLOITATION = 4        # Exploiting vulnerability
    INSTALLATION = 5        # Installing persistent access
    COMMAND_CONTROL = 6     # Establishing C2 channel
    ACTIONS_ON_OBJECTIVES = 7  # Mission completion


@dataclass
class KillChainMapping:
    """Maps a finding to Cyber Kill Chain phase with MITRE ATT&CK alignment"""
    phase: CyberKillChainPhase
    mitre_tactics: List[MitreAttackTactic]
    description: str
    indicators: List[str]  # Observable indicators
    defensive_actions: List[str]  # Recommended defensive measures


# Comprehensive Kill Chain to MITRE ATT&CK mapping
KILL_CHAIN_MITRE_MAPPING: Dict[CyberKillChainPhase, KillChainMapping] = {
    CyberKillChainPhase.RECONNAISSANCE: KillChainMapping(
        phase=CyberKillChainPhase.RECONNAISSANCE,
        mitre_tactics=[MitreAttackTactic.RECONNAISSANCE],
        description="Adversary identifies and researches targets using OSINT, scanning, and social engineering",
        indicators=[
            "Port/vulnerability scans from external IPs",
            "Increased DNS queries",
            "Social media profiling activity",
            "Website scraping patterns",
            "Email harvesting attempts",
        ],
        defensive_actions=[
            "Web application firewalls",
            "Rate limiting on public APIs",
            "Minimize information disclosure",
            "Employee security awareness",
            "WHOIS privacy protection",
        ]
    ),
    CyberKillChainPhase.WEAPONIZATION: KillChainMapping(
        phase=CyberKillChainPhase.WEAPONIZATION,
        mitre_tactics=[MitreAttackTactic.RESOURCE_DEVELOPMENT],
        description="Adversary creates or acquires tools for the attack",
        indicators=[
            "Lookalike domain registrations",
            "Phishing infrastructure setup",
            "Malware compilation activity",
            "Exploit kit customization",
        ],
        defensive_actions=[
            "Threat intelligence monitoring",
            "Brand protection services",
            "Typosquatting detection",
            "Subdomain takeover monitoring",
        ]
    ),
    CyberKillChainPhase.DELIVERY: KillChainMapping(
        phase=CyberKillChainPhase.DELIVERY,
        mitre_tactics=[MitreAttackTactic.INITIAL_ACCESS],
        description="Adversary transmits weapon to target environment",
        indicators=[
            "Phishing emails with links/attachments",
            "Drive-by download attempts",
            "Exploitation of public-facing apps",
            "Social engineering attempts",
            "Malicious file uploads",
        ],
        defensive_actions=[
            "Email security gateways",
            "Web filtering",
            "Input validation",
            "File upload restrictions",
            "User awareness training",
        ]
    ),
    CyberKillChainPhase.EXPLOITATION: KillChainMapping(
        phase=CyberKillChainPhase.EXPLOITATION,
        mitre_tactics=[MitreAttackTactic.INITIAL_ACCESS, MitreAttackTactic.EXECUTION],
        description="Adversary exploits vulnerability to execute code",
        indicators=[
            "SQL injection attempts",
            "Command injection patterns",
            "Deserialization attacks",
            "Template injection",
            "XSS exploitation",
        ],
        defensive_actions=[
            "Input validation",
            "Output encoding",
            "Parameterized queries",
            "Least privilege principle",
            "WAF rules",
        ]
    ),
    CyberKillChainPhase.INSTALLATION: KillChainMapping(
        phase=CyberKillChainPhase.INSTALLATION,
        mitre_tactics=[MitreAttackTactic.PERSISTENCE, MitreAttackTactic.PRIVILEGE_ESCALATION],
        description="Adversary installs persistent access mechanism",
        indicators=[
            "Web shell uploads",
            "Backdoor installation",
            "Scheduled task creation",
            "Service modification",
            "Account creation",
        ],
        defensive_actions=[
            "File integrity monitoring",
            "Endpoint detection",
            "Privileged access management",
            "Application whitelisting",
        ]
    ),
    CyberKillChainPhase.COMMAND_CONTROL: KillChainMapping(
        phase=CyberKillChainPhase.COMMAND_CONTROL,
        mitre_tactics=[MitreAttackTactic.DEFENSE_EVASION],
        description="Adversary establishes command and control channel",
        indicators=[
            "Unusual outbound connections",
            "DNS tunneling",
            "Encrypted traffic to suspicious domains",
            "Beaconing patterns",
        ],
        defensive_actions=[
            "Network segmentation",
            "Egress filtering",
            "DNS monitoring",
            "SSL/TLS inspection",
        ]
    ),
    CyberKillChainPhase.ACTIONS_ON_OBJECTIVES: KillChainMapping(
        phase=CyberKillChainPhase.ACTIONS_ON_OBJECTIVES,
        mitre_tactics=[
            MitreAttackTactic.CREDENTIAL_ACCESS,
            MitreAttackTactic.DISCOVERY,
            MitreAttackTactic.LATERAL_MOVEMENT,
            MitreAttackTactic.COLLECTION,
            MitreAttackTactic.EXFILTRATION,
            MitreAttackTactic.IMPACT
        ],
        description="Adversary achieves their objectives (data theft, disruption, etc.)",
        indicators=[
            "Bulk data access",
            "Credential dumping",
            "Lateral movement",
            "Data exfiltration",
            "System modification",
        ],
        defensive_actions=[
            "Data loss prevention",
            "User behavior analytics",
            "Network segmentation",
            "Encryption at rest",
            "Backup and recovery",
        ]
    ),
}


# =============================================================================
# VULNERABILITY CHAIN PATTERNS
# =============================================================================

class VulnerabilityChainType(Enum):
    """Types of vulnerability chains based on exploitation patterns"""
    SEQUENTIAL = auto()      # A -> B -> C (linear progression)
    PARALLEL = auto()        # A + B -> C (combined exploitation)
    AMPLIFICATION = auto()   # A enhances B (risk amplification)
    PREREQUISITE = auto()    # A enables B (dependency chain)
    PIVOT = auto()           # A -> [internal] -> B (network pivot)


@dataclass
class VulnerabilityChainPattern:
    """
    Defines a known vulnerability chain pattern.

    Based on real-world attack chains documented in:
    - MITRE ATT&CK Campaigns
    - Bug bounty reports (HackerOne, Bugcrowd)
    - CVE chain analysis
    - Penetration testing methodologies
    """
    id: str
    name: str
    chain_type: VulnerabilityChainType
    description: str
    source_vulns: List[str]  # VRT/CWE identifiers
    target_vulns: List[str]  # VRT/CWE identifiers
    kill_chain_phases: List[CyberKillChainPhase]
    mitre_techniques: List[str]
    severity_multiplier: float  # Risk amplification factor
    real_world_examples: List[str]


# Common vulnerability chain patterns from industry research
VULNERABILITY_CHAIN_PATTERNS: List[VulnerabilityChainPattern] = [
    # ==========================================================================
    # RECONNAISSANCE -> EXPLOITATION CHAINS
    # ==========================================================================
    VulnerabilityChainPattern(
        id="CHAIN-001",
        name="Information Disclosure to Authentication Bypass",
        chain_type=VulnerabilityChainType.PREREQUISITE,
        description="Exposed credentials or configuration leads to unauthorized access",
        source_vulns=["sensitive_data_exposure", "information_disclosure", "CWE-200"],
        target_vulns=["authentication_bypass", "broken_authentication", "CWE-287"],
        kill_chain_phases=[CyberKillChainPhase.RECONNAISSANCE, CyberKillChainPhase.EXPLOITATION],
        mitre_techniques=["T1552", "T1078"],
        severity_multiplier=1.5,
        real_world_examples=[
            "Exposed .git directory reveals API keys -> Account takeover",
            "Leaked credentials in JS files -> Admin panel access",
            "Debug endpoint reveals session tokens -> Session hijacking",
        ]
    ),
    VulnerabilityChainPattern(
        id="CHAIN-002",
        name="Subdomain Takeover to Phishing",
        chain_type=VulnerabilityChainType.SEQUENTIAL,
        description="Dangling DNS enables credential harvesting phishing",
        source_vulns=["subdomain_takeover", "CWE-284"],
        target_vulns=["phishing", "credential_theft"],
        kill_chain_phases=[
            CyberKillChainPhase.WEAPONIZATION,
            CyberKillChainPhase.DELIVERY,
        ],
        mitre_techniques=["T1584.001", "T1566"],
        severity_multiplier=1.8,
        real_world_examples=[
            "Unclaimed S3 bucket on subdomain -> Brand impersonation",
            "Dangling CNAME -> Credential harvesting page",
        ]
    ),

    # ==========================================================================
    # INJECTION -> LATERAL MOVEMENT CHAINS
    # ==========================================================================
    VulnerabilityChainPattern(
        id="CHAIN-003",
        name="SSRF to Internal Service Compromise",
        chain_type=VulnerabilityChainType.PIVOT,
        description="SSRF enables access to internal services and metadata",
        source_vulns=["ssrf", "CWE-918"],
        target_vulns=["internal_service_access", "cloud_metadata", "CWE-284"],
        kill_chain_phases=[
            CyberKillChainPhase.EXPLOITATION,
            CyberKillChainPhase.ACTIONS_ON_OBJECTIVES,
        ],
        mitre_techniques=["T1190", "T1078.004", "T1530"],
        severity_multiplier=2.0,
        real_world_examples=[
            "SSRF -> AWS metadata endpoint -> IAM credentials",
            "SSRF -> Internal admin panel without auth",
            "SSRF -> Redis/Memcached -> RCE via deserialization",
        ]
    ),
    VulnerabilityChainPattern(
        id="CHAIN-004",
        name="SQL Injection to Data Exfiltration",
        chain_type=VulnerabilityChainType.SEQUENTIAL,
        description="SQLi enables database access leading to mass data theft",
        source_vulns=["sql_injection", "CWE-89"],
        target_vulns=["data_breach", "credential_theft", "CWE-312"],
        kill_chain_phases=[
            CyberKillChainPhase.EXPLOITATION,
            CyberKillChainPhase.ACTIONS_ON_OBJECTIVES,
        ],
        mitre_techniques=["T1190", "T1005", "T1567"],
        severity_multiplier=2.5,
        real_world_examples=[
            "Boolean-blind SQLi -> Full database dump",
            "UNION SQLi -> Password hash extraction",
            "Time-based SQLi -> Sensitive PII exfiltration",
        ]
    ),
    VulnerabilityChainPattern(
        id="CHAIN-005",
        name="Template Injection to Remote Code Execution",
        chain_type=VulnerabilityChainType.AMPLIFICATION,
        description="SSTI escalates to full server compromise",
        source_vulns=["ssti", "template_injection", "CWE-1336"],
        target_vulns=["rce", "command_injection", "CWE-78"],
        kill_chain_phases=[
            CyberKillChainPhase.EXPLOITATION,
            CyberKillChainPhase.INSTALLATION,
        ],
        mitre_techniques=["T1190", "T1059"],
        severity_multiplier=2.0,
        real_world_examples=[
            "Jinja2 SSTI -> subprocess.Popen RCE",
            "Twig SSTI -> system() execution",
            "Freemarker SSTI -> Runtime.exec()",
        ]
    ),

    # ==========================================================================
    # ACCESS CONTROL -> PRIVILEGE ESCALATION CHAINS
    # ==========================================================================
    VulnerabilityChainPattern(
        id="CHAIN-006",
        name="IDOR to Privilege Escalation",
        chain_type=VulnerabilityChainType.SEQUENTIAL,
        description="IDOR enables access to admin functionality or sensitive data",
        source_vulns=["idor", "bola", "CWE-639"],
        target_vulns=["privilege_escalation", "CWE-269"],
        kill_chain_phases=[
            CyberKillChainPhase.EXPLOITATION,
            CyberKillChainPhase.ACTIONS_ON_OBJECTIVES,
        ],
        mitre_techniques=["T1068", "T1548"],
        severity_multiplier=1.5,
        real_world_examples=[
            "User ID manipulation -> Access other users' data",
            "Order ID tampering -> View/modify others' orders",
            "Admin user_id reference -> Privilege escalation",
        ]
    ),
    VulnerabilityChainPattern(
        id="CHAIN-007",
        name="JWT Vulnerability to Account Takeover",
        chain_type=VulnerabilityChainType.SEQUENTIAL,
        description="JWT weaknesses enable authentication bypass",
        source_vulns=["jwt_none_alg", "jwt_weak_secret", "CWE-347"],
        target_vulns=["authentication_bypass", "account_takeover", "CWE-287"],
        kill_chain_phases=[
            CyberKillChainPhase.EXPLOITATION,
            CyberKillChainPhase.ACTIONS_ON_OBJECTIVES,
        ],
        mitre_techniques=["T1078", "T1539"],
        severity_multiplier=2.0,
        real_world_examples=[
            "alg:none bypass -> Arbitrary user impersonation",
            "Weak JWT secret cracking -> Admin token forgery",
            "JWT key confusion -> Role elevation",
        ]
    ),

    # ==========================================================================
    # CLIENT-SIDE -> SERVER-SIDE CHAINS
    # ==========================================================================
    VulnerabilityChainPattern(
        id="CHAIN-008",
        name="XSS to Session Hijacking",
        chain_type=VulnerabilityChainType.SEQUENTIAL,
        description="XSS enables session theft and account takeover",
        source_vulns=["xss_stored", "xss_reflected", "CWE-79"],
        target_vulns=["session_hijacking", "account_takeover", "CWE-384"],
        kill_chain_phases=[
            CyberKillChainPhase.DELIVERY,
            CyberKillChainPhase.EXPLOITATION,
        ],
        mitre_techniques=["T1189", "T1539"],
        severity_multiplier=1.5,
        real_world_examples=[
            "Stored XSS -> Admin session theft",
            "Reflected XSS with CSRF -> State-changing actions",
            "DOM XSS -> Credential harvesting",
        ]
    ),
    VulnerabilityChainPattern(
        id="CHAIN-009",
        name="CORS Misconfiguration to Data Theft",
        chain_type=VulnerabilityChainType.SEQUENTIAL,
        description="CORS bypass enables cross-origin data exfiltration",
        source_vulns=["cors_misconfiguration", "CWE-942"],
        target_vulns=["data_theft", "credential_theft"],
        kill_chain_phases=[
            CyberKillChainPhase.EXPLOITATION,
            CyberKillChainPhase.ACTIONS_ON_OBJECTIVES,
        ],
        mitre_techniques=["T1189", "T1005"],
        severity_multiplier=1.3,
        real_world_examples=[
            "Origin reflection -> API key theft",
            "Null origin allowed -> Sandboxed iframe attack",
            "Wildcard with credentials -> Session data theft",
        ]
    ),

    # ==========================================================================
    # SUPPLY CHAIN / THIRD-PARTY CHAINS
    # ==========================================================================
    VulnerabilityChainPattern(
        id="CHAIN-010",
        name="Dependency Vulnerability to RCE",
        chain_type=VulnerabilityChainType.AMPLIFICATION,
        description="Vulnerable component enables server compromise",
        source_vulns=["outdated_component", "vulnerable_dependency", "CWE-1104"],
        target_vulns=["rce", "CWE-94"],
        kill_chain_phases=[
            CyberKillChainPhase.WEAPONIZATION,
            CyberKillChainPhase.EXPLOITATION,
        ],
        mitre_techniques=["T1195.001", "T1190"],
        severity_multiplier=2.0,
        real_world_examples=[
            "Log4Shell (CVE-2021-44228) -> RCE via log injection",
            "Spring4Shell (CVE-2022-22965) -> RCE",
            "Prototype pollution -> RCE via gadget chain",
        ]
    ),
    VulnerabilityChainPattern(
        id="CHAIN-011",
        name="Open Redirect to OAuth Token Theft",
        chain_type=VulnerabilityChainType.SEQUENTIAL,
        description="Open redirect enables OAuth authorization code interception",
        source_vulns=["open_redirect", "CWE-601"],
        target_vulns=["oauth_token_theft", "account_takeover", "CWE-287"],
        kill_chain_phases=[
            CyberKillChainPhase.DELIVERY,
            CyberKillChainPhase.EXPLOITATION,
        ],
        mitre_techniques=["T1566.002", "T1078"],
        severity_multiplier=1.8,
        real_world_examples=[
            "OAuth redirect_uri bypass -> Authorization code theft",
            "Open redirect in callback -> Token interception",
        ]
    ),

    # ==========================================================================
    # CONFIGURATION -> EXPLOITATION CHAINS
    # ==========================================================================
    VulnerabilityChainPattern(
        id="CHAIN-012",
        name="Security Header Missing to Attack Enablement",
        chain_type=VulnerabilityChainType.PREREQUISITE,
        description="Missing security headers enable various attacks",
        source_vulns=["missing_csp", "missing_xfo", "CWE-1021"],
        target_vulns=["xss", "clickjacking", "CWE-79", "CWE-1021"],
        kill_chain_phases=[
            CyberKillChainPhase.RECONNAISSANCE,
            CyberKillChainPhase.EXPLOITATION,
        ],
        mitre_techniques=["T1592.002", "T1189"],
        severity_multiplier=1.2,
        real_world_examples=[
            "Missing CSP -> XSS payload execution",
            "Missing X-Frame-Options -> Clickjacking attack",
        ]
    ),
    VulnerabilityChainPattern(
        id="CHAIN-013",
        name="Debug Endpoint to Information Disclosure",
        chain_type=VulnerabilityChainType.SEQUENTIAL,
        description="Exposed debug endpoints leak sensitive information",
        source_vulns=["debug_endpoint_exposed", "CWE-489"],
        target_vulns=["information_disclosure", "credential_exposure", "CWE-200"],
        kill_chain_phases=[
            CyberKillChainPhase.RECONNAISSANCE,
            CyberKillChainPhase.EXPLOITATION,
        ],
        mitre_techniques=["T1592.002", "T1552"],
        severity_multiplier=1.5,
        real_world_examples=[
            "Django DEBUG=True -> Settings/secrets exposure",
            "Spring Actuator -> Environment variables leak",
            "PHP phpinfo() -> Configuration disclosure",
        ]
    ),
]


# =============================================================================
# CORRELATED EVENT (FINDING)
# =============================================================================

@dataclass
class CorrelatedEvent:
    """
    A security finding enriched with correlation data.

    Combines:
    - Original finding data
    - MITRE ATT&CK mapping
    - Cyber Kill Chain phase
    - OWASP classification
    - Chain relationships
    """
    id: str
    timestamp: datetime
    module: str
    finding_type: str
    severity: str
    url: str
    evidence: Dict[str, Any]

    # Framework mappings
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactic: Optional[MitreAttackTactic] = None
    kill_chain_phase: Optional[CyberKillChainPhase] = None
    owasp_category: Optional[str] = None
    cwe_ids: List[str] = field(default_factory=list)

    # Correlation data
    related_events: List[str] = field(default_factory=list)
    chain_patterns: List[str] = field(default_factory=list)
    is_chain_start: bool = False
    is_chain_end: bool = False

    # Risk scoring
    base_cvss: float = 0.0
    chain_multiplier: float = 1.0

    @property
    def effective_risk(self) -> float:
        """Chain-adjusted risk score — recalculated when chain_multiplier changes."""
        return self.base_cvss * self.chain_multiplier


# =============================================================================
# ATTACK CHAIN
# =============================================================================

@dataclass
class AttackChain:
    """
    Represents a detected attack chain - a sequence of correlated vulnerabilities
    that together enable a more significant attack.

    Based on research from:
    - MITRE ATT&CK Chains
    - Real-world APT campaign analysis
    - Bug bounty impact chains
    """
    id: str
    name: str
    description: str
    events: List[CorrelatedEvent]
    pattern: Optional[VulnerabilityChainPattern] = None
    kill_chain_progression: List[CyberKillChainPhase] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    # Impact assessment
    combined_severity: str = "info"
    risk_score: float = 0.0
    business_impact: str = ""
    exploitability: str = ""

    # Evidence
    attack_narrative: str = ""
    remediation_priority: int = 0

    def calculate_combined_severity(self) -> str:
        """
        Calculate combined severity based on chain composition.

        Uses a weighted approach where:
        - Chain length increases severity
        - Kill chain progression increases severity
        - Pattern multiplier amplifies risk
        """
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2,
            'info': 1
        }

        # Base score from individual findings
        total_weight = sum(
            severity_weights.get(e.severity.lower(), 1)
            for e in self.events
        )

        # Apply chain length bonus (more steps = more sophisticated = higher risk)
        chain_bonus = min(len(self.events) * 0.5, 3.0)

        # Apply kill chain progression bonus
        kc_phases = len(set(self.kill_chain_progression))
        kc_bonus = kc_phases * 0.75

        # Apply pattern multiplier if matched
        pattern_mult = self.pattern.severity_multiplier if self.pattern else 1.0

        # Calculate final weighted score
        final_score = (total_weight + chain_bonus + kc_bonus) * pattern_mult

        # Map back to severity
        if final_score >= 15:
            return 'critical'
        elif final_score >= 10:
            return 'high'
        elif final_score >= 5:
            return 'medium'
        elif final_score >= 2:
            return 'low'
        return 'info'

    def generate_attack_narrative(self) -> str:
        """Generate a human-readable attack narrative for the chain"""
        if not self.events:
            return "No events in chain."

        narrative_parts = [
            f"**Attack Chain: {self.name}**\n",
            f"_{self.description}_\n",
            "\n**Attack Progression:**\n"
        ]

        for i, event in enumerate(self.events, 1):
            phase = event.kill_chain_phase.name if event.kill_chain_phase else "Unknown"
            narrative_parts.append(
                f"{i}. [{phase}] {event.finding_type} at `{event.url}`\n"
                f"   - MITRE: {', '.join(event.mitre_techniques[:3])}\n"
            )

        if self.pattern:
            narrative_parts.append(f"\n**Pattern Match:** {self.pattern.name}\n")
            narrative_parts.append("**Real-World Examples:**\n")
            for example in self.pattern.real_world_examples[:2]:
                narrative_parts.append(f"  - {example}\n")

        narrative_parts.append(f"\n**Combined Severity:** {self.combined_severity.upper()}\n")
        narrative_parts.append(f"**Risk Score:** {self.risk_score:.1f}/10\n")

        return ''.join(narrative_parts)


# =============================================================================
# EVENT CORRELATION ENGINE
# =============================================================================

class EventCorrelationEngine:
    """
    Main correlation engine that processes security findings and identifies
    attack chains, vulnerability relationships, and risk amplification.

    Architecture based on:
    - SIEM correlation patterns
    - Attack graph generation algorithms
    - Threat modeling frameworks (STRIDE, PASTA)

    Industry Tools Integration:
    - Compatible with MITRE ATT&CK Navigator export
    - Maps to Nuclei finding format
    - Supports Bugcrowd VRT classification
    """

    def __init__(self):
        self.events: List[CorrelatedEvent] = []
        self.chains: List[AttackChain] = []
        self.event_index: Dict[str, CorrelatedEvent] = {}

        # Indexes for fast correlation
        self.events_by_url: Dict[str, List[CorrelatedEvent]] = defaultdict(list)
        self.events_by_type: Dict[str, List[CorrelatedEvent]] = defaultdict(list)
        self.events_by_phase: Dict[CyberKillChainPhase, List[CorrelatedEvent]] = defaultdict(list)
        self.events_by_technique: Dict[str, List[CorrelatedEvent]] = defaultdict(list)

        # Chain patterns for matching
        self.chain_patterns = VULNERABILITY_CHAIN_PATTERNS

        # Statistics
        self.stats = {
            'total_events': 0,
            'chains_detected': 0,
            'risk_amplifications': 0,
            'kill_chain_coverage': set(),
        }

    def _generate_event_id(self, finding: Dict) -> str:
        """Generate unique ID for a finding"""
        content = json.dumps(finding, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _map_to_kill_chain(self, mitre_tactics: List[MitreAttackTactic]) -> CyberKillChainPhase:
        """Map MITRE tactics to Cyber Kill Chain phase"""
        tactic_to_phase = {
            MitreAttackTactic.RECONNAISSANCE: CyberKillChainPhase.RECONNAISSANCE,
            MitreAttackTactic.RESOURCE_DEVELOPMENT: CyberKillChainPhase.WEAPONIZATION,
            MitreAttackTactic.INITIAL_ACCESS: CyberKillChainPhase.DELIVERY,
            MitreAttackTactic.EXECUTION: CyberKillChainPhase.EXPLOITATION,
            MitreAttackTactic.PERSISTENCE: CyberKillChainPhase.INSTALLATION,
            MitreAttackTactic.PRIVILEGE_ESCALATION: CyberKillChainPhase.INSTALLATION,
            MitreAttackTactic.DEFENSE_EVASION: CyberKillChainPhase.COMMAND_CONTROL,
            MitreAttackTactic.CREDENTIAL_ACCESS: CyberKillChainPhase.ACTIONS_ON_OBJECTIVES,
            MitreAttackTactic.DISCOVERY: CyberKillChainPhase.RECONNAISSANCE,
            MitreAttackTactic.LATERAL_MOVEMENT: CyberKillChainPhase.ACTIONS_ON_OBJECTIVES,
            MitreAttackTactic.COLLECTION: CyberKillChainPhase.ACTIONS_ON_OBJECTIVES,
            MitreAttackTactic.EXFILTRATION: CyberKillChainPhase.ACTIONS_ON_OBJECTIVES,
            MitreAttackTactic.IMPACT: CyberKillChainPhase.ACTIONS_ON_OBJECTIVES,
        }

        # Return the highest phase (most progressed in kill chain)
        phases = [tactic_to_phase.get(t) for t in mitre_tactics if t in tactic_to_phase]
        if phases:
            return max(phases, key=lambda p: p.value)
        return CyberKillChainPhase.RECONNAISSANCE

    def _map_finding_to_mitre(self, finding: Dict, module: str) -> Tuple[List[str], Optional[MitreAttackTactic]]:
        """Map a finding to MITRE ATT&CK techniques"""
        techniques = []
        tactic = None

        # Get module mapping
        module_map = MODULE_METHODOLOGY_MAP.get(module, {})
        if module_map:
            techniques.extend(module_map.get('mitre_techniques', []))

        # Map by finding type
        finding_type = finding.get('type', finding.get('vuln_type', '')).lower()

        type_to_technique = {
            'sql_injection': ['T1190'],
            'sqli': ['T1190'],
            'xss': ['T1189', 'T1203'],
            'cross_site_scripting': ['T1189', 'T1203'],
            'command_injection': ['T1190', 'T1059'],
            'cmdi': ['T1190', 'T1059'],
            'ssrf': ['T1190', 'T1567'],
            'server_side_request_forgery': ['T1190', 'T1567'],
            'ssti': ['T1190', 'T1059'],
            'template_injection': ['T1190', 'T1059'],
            'idor': ['T1068', 'T1078'],
            'bac': ['T1068', 'T1548'],
            'broken_access_control': ['T1068', 'T1548'],
            'jwt': ['T1078', 'T1539'],
            'cors': ['T1189', 'T1068'],
            'open_redirect': ['T1566.002'],
            'information_disclosure': ['T1592.002', 'T1552'],
            'sensitive_data': ['T1552', 'T1589.001'],
            'subdomain_takeover': ['T1584.001'],
            'default_credentials': ['T1078.001'],
            'weak_password': ['T1110'],
            'rce': ['T1190', 'T1059'],
            'lfi': ['T1005', 'T1083'],
            'path_traversal': ['T1083', 'T1005'],
            'xxe': ['T1190'],
            'deserialization': ['T1190'],
        }

        additional_techniques = type_to_technique.get(finding_type, [])
        techniques.extend(additional_techniques)

        # Deduplicate while preserving order
        seen = set()
        techniques = [t for t in techniques if not (t in seen or seen.add(t))]

        # Determine primary tactic
        if techniques:
            first_tech = techniques[0]
            if first_tech in MITRE_TECHNIQUES:
                tactic = MITRE_TECHNIQUES[first_tech].tactic

        return techniques, tactic

    def _map_to_owasp(self, finding: Dict) -> Optional[str]:
        """Map finding to OWASP Top 10 category"""
        finding_type = finding.get('type', finding.get('vuln_type', '')).lower()

        type_to_owasp = {
            'sql_injection': 'A03',
            'sqli': 'A03',
            'xss': 'A03',
            'command_injection': 'A03',
            'ssti': 'A03',
            'ssrf': 'A10',
            'idor': 'A01',
            'bac': 'A01',
            'broken_access_control': 'A01',
            'cors': 'A01',
            'jwt': 'A07',
            'authentication': 'A07',
            'session': 'A07',
            'sensitive_data': 'A02',
            'information_disclosure': 'A05',
            'misconfiguration': 'A05',
            'outdated_component': 'A06',
            'deserialization': 'A08',
            'xxe': 'A03',
        }

        return type_to_owasp.get(finding_type)

    def _extract_cwe(self, finding: Dict) -> List[str]:
        """Extract CWE identifiers from finding"""
        cwes = []

        # Direct CWE field
        if 'cwe' in finding:
            cwe = finding['cwe']
            if isinstance(cwe, list):
                cwes.extend(cwe)
            else:
                cwes.append(cwe)

        # CWE in classification
        if 'classification' in finding:
            cls = finding['classification']
            if isinstance(cls, dict) and 'cwe' in cls:
                cwes.append(cls['cwe'])

        # Normalize CWE format
        normalized = []
        for cwe in cwes:
            if isinstance(cwe, int):
                normalized.append(f"CWE-{cwe}")
            elif isinstance(cwe, str):
                if not cwe.startswith('CWE-'):
                    cwe = f"CWE-{cwe}"
                normalized.append(cwe)

        return list(set(normalized))

    def ingest_finding(self, finding: Dict, module: str) -> CorrelatedEvent:
        """
        Process a raw finding and create a correlated event.

        Args:
            finding: Raw finding dictionary from scanner module
            module: Name of the module that produced the finding

        Returns:
            CorrelatedEvent with full correlation data
        """
        # Generate unique ID
        event_id = self._generate_event_id(finding)

        # Check for duplicate
        if event_id in self.event_index:
            return self.event_index[event_id]

        # Extract base data
        finding_type = finding.get('type', finding.get('vuln_type', 'unknown'))
        severity = finding.get('severity', 'info').lower()
        url = finding.get('url', finding.get('host', ''))

        # Map to frameworks
        mitre_techniques, mitre_tactic = self._map_finding_to_mitre(finding, module)
        owasp_category = self._map_to_owasp(finding)
        cwe_ids = self._extract_cwe(finding)

        # Determine kill chain phase
        kill_chain_phase = None
        if mitre_tactic:
            kill_chain_phase = self._map_to_kill_chain([mitre_tactic])

        # Calculate base CVSS
        cvss_map = {'critical': 9.5, 'high': 7.5, 'medium': 5.0, 'low': 3.0, 'info': 1.0}
        base_cvss = finding.get('cvss_score', cvss_map.get(severity, 1.0))

        # Create correlated event
        event = CorrelatedEvent(
            id=event_id,
            timestamp=datetime.now(),
            module=module,
            finding_type=finding_type,
            severity=severity,
            url=url,
            evidence=finding,
            mitre_techniques=mitre_techniques,
            mitre_tactic=mitre_tactic,
            kill_chain_phase=kill_chain_phase,
            owasp_category=owasp_category,
            cwe_ids=cwe_ids,
            base_cvss=base_cvss,
        )

        # Index the event
        self.events.append(event)
        self.event_index[event_id] = event
        self.events_by_url[url].append(event)
        self.events_by_type[finding_type.lower()].append(event)

        if kill_chain_phase:
            self.events_by_phase[kill_chain_phase].append(event)
            self.stats['kill_chain_coverage'].add(kill_chain_phase)

        for technique in mitre_techniques:
            self.events_by_technique[technique].append(event)

        self.stats['total_events'] += 1

        return event

    def ingest_module_results(self, module_name: str, results: Dict) -> List[CorrelatedEvent]:
        """
        Ingest all findings from a module's results.

        Args:
            module_name: Name of the scanner module
            results: Module results dictionary

        Returns:
            List of created CorrelatedEvents
        """
        events = []

        # Handle different result formats
        findings = []
        if isinstance(results, dict):
            # Try common finding locations
            findings = results.get('vulnerabilities',
                       results.get('findings',
                       results.get('results', [])))
        elif isinstance(results, list):
            findings = results

        for finding in findings:
            if isinstance(finding, dict):
                event = self.ingest_finding(finding, module_name)
                events.append(event)

        return events

    def correlate_by_url(self) -> List[Tuple[str, List[CorrelatedEvent]]]:
        """
        Find events affecting the same URL/endpoint.

        Multiple vulnerabilities on the same endpoint often indicate
        deeper issues and potential attack chain opportunities.
        """
        correlated = []

        for url, events in self.events_by_url.items():
            if len(events) > 1:
                # Sort by kill chain phase progression
                events_sorted = sorted(
                    events,
                    key=lambda e: e.kill_chain_phase.value if e.kill_chain_phase else 0
                )
                correlated.append((url, events_sorted))

                # Link events
                for i, event in enumerate(events_sorted):
                    event.related_events = [e.id for e in events_sorted if e.id != event.id]

        return correlated

    def correlate_by_kill_chain(self) -> Dict[CyberKillChainPhase, List[CorrelatedEvent]]:
        """
        Group events by kill chain phase to show attack progression.
        """
        return dict(self.events_by_phase)

    def detect_chains(self) -> List[AttackChain]:
        """
        Detect vulnerability chains by matching against known patterns.

        This is the core chain detection algorithm that:
        1. Matches events against known chain patterns
        2. Validates temporal and logical relationships
        3. Calculates combined risk scores
        4. Generates attack narratives
        """
        detected_chains = []

        for pattern in self.chain_patterns:
            # Find source events matching pattern
            source_events = []
            for source_vuln in pattern.source_vulns:
                source_vuln_lower = source_vuln.lower()

                # Check by type
                if source_vuln_lower in self.events_by_type:
                    source_events.extend(self.events_by_type[source_vuln_lower])

                # Check by CWE
                for event in self.events:
                    if source_vuln in event.cwe_ids:
                        if event not in source_events:
                            source_events.append(event)

            # Find target events matching pattern
            target_events = []
            for target_vuln in pattern.target_vulns:
                target_vuln_lower = target_vuln.lower()

                if target_vuln_lower in self.events_by_type:
                    target_events.extend(self.events_by_type[target_vuln_lower])

                for event in self.events:
                    if target_vuln in event.cwe_ids:
                        if event not in target_events:
                            target_events.append(event)

            # Check for chain matches
            if source_events and target_events:
                # Create chain for each valid source-target combination
                for source in source_events[:5]:  # Limit to prevent explosion
                    for target in target_events[:5]:
                        if source.id != target.id:
                            # Validate chain (same target scope)
                            same_domain = self._same_domain(source.url, target.url)
                            if same_domain or pattern.chain_type == VulnerabilityChainType.PIVOT:
                                chain = self._create_chain(
                                    source, target, pattern
                                )
                                detected_chains.append(chain)

                                # Update event flags
                                source.is_chain_start = True
                                target.is_chain_end = True
                                source.chain_patterns.append(pattern.id)
                                target.chain_patterns.append(pattern.id)

                                # Apply risk amplification
                                source.chain_multiplier = pattern.severity_multiplier
                                target.chain_multiplier = pattern.severity_multiplier

                                self.stats['risk_amplifications'] += 1

        # Also detect implicit chains from URL correlation
        url_chains = self._detect_url_based_chains()
        detected_chains.extend(url_chains)

        self.chains = detected_chains
        self.stats['chains_detected'] = len(detected_chains)

        return detected_chains

    def _same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs are on the same domain"""
        from urllib.parse import urlparse

        # Multi-part TLDs where the second-to-last segment is part of the TLD
        _MP_TLDS = {'co', 'com', 'org', 'net', 'edu', 'gov', 'ac', 'or', 'ne'}

        def _base_domain(netloc: str) -> str:
            # Strip port
            host = netloc.split(':')[0]
            parts = host.split('.')
            if len(parts) >= 3 and parts[-2] in _MP_TLDS:
                return '.'.join(parts[-3:])
            return '.'.join(parts[-2:]) if len(parts) >= 2 else host

        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc
            return _base_domain(domain1) == _base_domain(domain2)
        except Exception:
            return False

    def _create_chain(
        self,
        source: CorrelatedEvent,
        target: CorrelatedEvent,
        pattern: VulnerabilityChainPattern
    ) -> AttackChain:
        """Create an attack chain from matched events"""
        chain_id = f"chain-{source.id[:8]}-{target.id[:8]}"

        # Collect kill chain phases
        phases = []
        if source.kill_chain_phase:
            phases.append(source.kill_chain_phase)
        if target.kill_chain_phase:
            phases.append(target.kill_chain_phase)
        phases.extend(pattern.kill_chain_phases)
        phases = list(dict.fromkeys(phases))  # Dedupe while preserving order

        # Collect MITRE techniques
        techniques = list(set(
            source.mitre_techniques +
            target.mitre_techniques +
            pattern.mitre_techniques
        ))

        chain = AttackChain(
            id=chain_id,
            name=pattern.name,
            description=pattern.description,
            events=[source, target],
            pattern=pattern,
            kill_chain_progression=phases,
            mitre_techniques=techniques,
        )

        # Calculate severity and risk
        chain.combined_severity = chain.calculate_combined_severity()
        chain.risk_score = (source.base_cvss + target.base_cvss) * pattern.severity_multiplier / 2
        chain.risk_score = min(10.0, chain.risk_score)  # Cap at 10

        # Generate narrative
        chain.attack_narrative = chain.generate_attack_narrative()

        # Set remediation priority (1 = highest)
        severity_priority = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}
        chain.remediation_priority = severity_priority.get(chain.combined_severity, 5)

        return chain

    def _detect_url_based_chains(self) -> List[AttackChain]:
        """Detect chains based on URL correlation (multiple vulns on same endpoint)"""
        chains = []

        for url, events in self.events_by_url.items():
            if len(events) >= 2:
                # Sort by kill chain progression
                sorted_events = sorted(
                    events,
                    key=lambda e: e.kill_chain_phase.value if e.kill_chain_phase else 0
                )

                # Check for meaningful progression
                phases = [e.kill_chain_phase for e in sorted_events if e.kill_chain_phase]
                if len(set(phases)) >= 2:  # Multiple kill chain phases
                    chain = AttackChain(
                        id=f"url-chain-{hashlib.sha256(url.encode()).hexdigest()[:8]}",
                        name="Multi-Vulnerability Attack Surface",
                        description=f"Multiple vulnerabilities detected on {url} enabling attack chain",
                        events=sorted_events,
                        kill_chain_progression=phases,
                        mitre_techniques=list(set(
                            tech for e in sorted_events for tech in e.mitre_techniques
                        )),
                    )
                    chain.combined_severity = chain.calculate_combined_severity()
                    chain.risk_score = sum(e.base_cvss for e in sorted_events) / len(sorted_events)
                    chain.attack_narrative = chain.generate_attack_narrative()
                    chains.append(chain)

        return chains

    def get_attack_surface_summary(self) -> Dict:
        """
        Generate comprehensive attack surface summary.

        Returns:
            Dictionary with:
            - Kill chain coverage analysis
            - MITRE technique distribution
            - Chain statistics
            - Risk heat map data
        """
        return {
            'total_events': self.stats['total_events'],
            'chains_detected': self.stats['chains_detected'],
            'risk_amplifications': self.stats['risk_amplifications'],
            'kill_chain_coverage': {
                phase.name: len(self.events_by_phase.get(phase, []))
                for phase in CyberKillChainPhase
            },
            'mitre_technique_distribution': {
                tech: len(events)
                for tech, events in sorted(
                    self.events_by_technique.items(),
                    key=lambda x: -len(x[1])
                )[:20]  # Top 20 techniques
            },
            'severity_distribution': self._get_severity_distribution(),
            'highest_risk_chains': self._get_highest_risk_chains(5),
            'recommended_actions': self._generate_recommendations(),
        }

    def _get_severity_distribution(self) -> Dict[str, int]:
        """Get distribution of findings by severity"""
        dist = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for event in self.events:
            sev = event.severity.lower()
            if sev in dist:
                dist[sev] += 1
        return dist

    def _get_highest_risk_chains(self, n: int = 5) -> List[Dict]:
        """Get top N highest risk chains"""
        sorted_chains = sorted(
            self.chains,
            key=lambda c: c.risk_score,
            reverse=True
        )

        return [
            {
                'id': chain.id,
                'name': chain.name,
                'severity': chain.combined_severity,
                'risk_score': chain.risk_score,
                'event_count': len(chain.events),
                'kill_chain_phases': [p.name for p in chain.kill_chain_progression],
            }
            for chain in sorted_chains[:n]
        ]

    def _generate_recommendations(self) -> List[Dict]:
        """Generate prioritized security recommendations"""
        recommendations = []

        # Based on kill chain coverage
        if CyberKillChainPhase.RECONNAISSANCE in self.stats['kill_chain_coverage']:
            recommendations.append({
                'priority': 'high',
                'category': 'Information Disclosure',
                'action': 'Review and minimize exposed information',
                'rationale': 'Reconnaissance findings indicate attackers can gather targeting information'
            })

        if CyberKillChainPhase.EXPLOITATION in self.stats['kill_chain_coverage']:
            recommendations.append({
                'priority': 'critical',
                'category': 'Vulnerability Remediation',
                'action': 'Patch exploitable vulnerabilities immediately',
                'rationale': 'Exploitation-phase findings indicate active attack vectors'
            })

        # Based on chains
        if self.stats['chains_detected'] > 0:
            recommendations.append({
                'priority': 'critical',
                'category': 'Attack Chain Mitigation',
                'action': 'Address vulnerability chains to prevent compound attacks',
                'rationale': f'{self.stats["chains_detected"]} attack chains detected amplify individual risks'
            })

        # Based on technique frequency
        common_techniques = sorted(
            self.events_by_technique.items(),
            key=lambda x: -len(x[1])
        )[:3]

        for tech, events in common_techniques:
            if tech in MITRE_TECHNIQUES:
                technique = MITRE_TECHNIQUES[tech]
                recommendations.append({
                    'priority': 'medium',
                    'category': f'MITRE {tech}',
                    'action': f'Implement controls for {technique.name}',
                    'rationale': f'{len(events)} findings map to this technique'
                })

        return recommendations

    def export_mitre_navigator(self) -> Dict:
        """
        Export findings to MITRE ATT&CK Navigator format.

        Returns:
            Dictionary compatible with ATT&CK Navigator JSON layer format
        """
        techniques = []

        for tech_id, events in self.events_by_technique.items():
            # Calculate score based on findings (max 100)
            score = min(len(events) * 10, 100)

            # Color based on severity
            max_severity = max(
                (e.severity for e in events),
                key=lambda s: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}.get(s, 0)
            )

            color_map = {
                'critical': '#c62828',
                'high': '#d84315',
                'medium': '#f9a825',
                'low': '#388e3c',
                'info': '#1565c0'
            }

            techniques.append({
                'techniqueID': tech_id,
                'score': score,
                'color': color_map.get(max_severity, '#1565c0'),
                'comment': f'{len(events)} findings',
                'enabled': True,
                'showSubtechniques': True,
            })

        return {
            'name': 'ReconX Findings',
            'version': '4.5',
            'domain': 'enterprise-attack',
            'description': 'Security assessment findings mapped to MITRE ATT&CK',
            'techniques': techniques,
            'gradient': {
                'colors': ['#1565c0', '#f9a825', '#c62828'],
                'minValue': 0,
                'maxValue': 100,
            },
            'legendItems': [
                {'label': 'Info', 'color': '#1565c0'},
                {'label': 'Low', 'color': '#388e3c'},
                {'label': 'Medium', 'color': '#f9a825'},
                {'label': 'High', 'color': '#d84315'},
                {'label': 'Critical', 'color': '#c62828'},
            ],
            'showTacticRowBackground': True,
            'tacticRowBackground': '#282828',
            'selectTechniquesAcrossTactics': True,
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def correlate_scan_results(scan_results: Dict) -> EventCorrelationEngine:
    """
    Convenience function to correlate all findings from a scan.

    Args:
        scan_results: Complete scan results dictionary from ReconEngine

    Returns:
        Configured EventCorrelationEngine with all findings processed
    """
    engine = EventCorrelationEngine()

    # Ensure scan_results is a dict
    if not isinstance(scan_results, dict):
        return engine

    modules = scan_results.get('modules', {})

    # Ensure modules is a dict before iterating
    if not isinstance(modules, dict):
        return engine

    for module_name, module_data in modules.items():
        # Skip if module_data is not a dict (e.g., failed modules may be strings)
        if not isinstance(module_data, dict):
            continue
        # Skip failed modules
        if module_data.get('status') == 'failed':
            continue
        # Get data if available
        data = module_data.get('data')
        if data and isinstance(data, dict):
            engine.ingest_module_results(module_name, data)

    # Run correlation
    engine.correlate_by_url()
    engine.detect_chains()

    return engine


def get_kill_chain_summary(engine: EventCorrelationEngine) -> str:
    """Generate a formatted kill chain summary"""
    lines = [
        "╔══════════════════════════════════════════════════════════════════╗",
        "║           CYBER KILL CHAIN ANALYSIS                              ║",
        "╚══════════════════════════════════════════════════════════════════╝",
        ""
    ]

    for phase in CyberKillChainPhase:
        events = engine.events_by_phase.get(phase, [])
        mapping = KILL_CHAIN_MITRE_MAPPING[phase]

        status = "✓" if events else "○"
        count = len(events)

        lines.append(f"  {status} Phase {phase.value}: {phase.name}")
        lines.append(f"    └─ {mapping.description}")
        lines.append(f"    └─ Findings: {count}")

        if events:
            for event in events[:3]:  # Show first 3
                lines.append(f"       • {event.finding_type} at {event.url[:50]}...")
            if len(events) > 3:
                lines.append(f"       ... and {len(events) - 3} more")
        lines.append("")

    return '\n'.join(lines)


# =============================================================================
# EXPORT
# =============================================================================

__all__ = [
    # Kill Chain
    'CyberKillChainPhase',
    'KillChainMapping',
    'KILL_CHAIN_MITRE_MAPPING',

    # Vulnerability Chains
    'VulnerabilityChainType',
    'VulnerabilityChainPattern',
    'VULNERABILITY_CHAIN_PATTERNS',

    # Events and Chains
    'CorrelatedEvent',
    'AttackChain',

    # Engine
    'EventCorrelationEngine',

    # Convenience
    'correlate_scan_results',
    'get_kill_chain_summary',
]
