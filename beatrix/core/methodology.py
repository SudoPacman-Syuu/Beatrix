"""
ReconX Security Testing Methodology Framework

Aligns with:
- MITRE ATT&CK Framework (https://attack.mitre.org/)
- OWASP Testing Guide v4.2
- PTES (Penetration Testing Execution Standard)
- NIST SP 800-115 Technical Guide

This module provides structured attack phases and technique mappings
for comprehensive, industry-standard security assessments.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

# =============================================================================
# MITRE ATT&CK TECHNIQUE MAPPINGS (Web Application Focused)
# =============================================================================

class MitreAttackTactic(Enum):
    """MITRE ATT&CK Tactics relevant to web application testing"""
    RECONNAISSANCE = "TA0043"      # Gathering information
    RESOURCE_DEVELOPMENT = "TA0042"  # Establishing resources
    INITIAL_ACCESS = "TA0001"      # Getting into the network
    EXECUTION = "TA0002"           # Running malicious code
    PERSISTENCE = "TA0003"         # Maintaining foothold
    PRIVILEGE_ESCALATION = "TA0004"  # Gaining higher-level permissions
    DEFENSE_EVASION = "TA0005"     # Avoiding detection
    CREDENTIAL_ACCESS = "TA0006"   # Stealing credentials
    DISCOVERY = "TA0007"           # Learning about the environment
    LATERAL_MOVEMENT = "TA0008"    # Moving through environment
    COLLECTION = "TA0009"          # Gathering data of interest
    EXFILTRATION = "TA0010"        # Stealing data
    IMPACT = "TA0040"              # Manipulate, interrupt, destroy


@dataclass
class MitreTechnique:
    """MITRE ATT&CK Technique definition"""
    id: str                        # e.g., T1190
    name: str
    tactic: MitreAttackTactic
    description: str
    detection_methods: List[str] = field(default_factory=list)
    owasp_mapping: List[str] = field(default_factory=list)  # OWASP Top 10 mapping
    cwe_mapping: List[str] = field(default_factory=list)    # CWE IDs


# MITRE ATT&CK Techniques mapped to web application attacks
# Complete mapping for TA0043 (Reconnaissance), TA0042 (Resource Development), TA0001 (Initial Access)
MITRE_TECHNIQUES = {
    # ==========================================================================
    # TA0043: RECONNAISSANCE (11 Techniques)
    # ==========================================================================

    # T1595 - Active Scanning
    "T1595": MitreTechnique(
        id="T1595",
        name="Active Scanning",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Adversaries may execute active reconnaissance scans to gather information",
        detection_methods=["Port scanning", "Web service enumeration", "Vulnerability scanning"],
        owasp_mapping=["WSTG-INFO-01", "WSTG-INFO-02"],
        cwe_mapping=[]
    ),
    "T1595.001": MitreTechnique(
        id="T1595.001",
        name="Active Scanning: Scanning IP Blocks",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Scan victim IP blocks to gather information about network infrastructure",
        detection_methods=["IP range scanning", "CIDR enumeration", "Network mapping"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=[]
    ),
    "T1595.002": MitreTechnique(
        id="T1595.002",
        name="Active Scanning: Vulnerability Scanning",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Scan victims for vulnerabilities that can be used during targeting",
        detection_methods=["CVE scanning", "Service version detection", "Nuclei templates"],
        owasp_mapping=["WSTG-INFO-02", "WSTG-CONF-01"],
        cwe_mapping=["CWE-200"]
    ),
    "T1595.003": MitreTechnique(
        id="T1595.003",
        name="Active Scanning: Wordlist Scanning",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Iteratively probe infrastructure using brute-forcing and crawling",
        detection_methods=["Directory brute-force", "File enumeration", "Endpoint discovery"],
        owasp_mapping=["WSTG-INFO-04", "WSTG-CONF-05"],
        cwe_mapping=["CWE-425"]
    ),

    # T1592 - Gather Victim Host Information
    "T1592": MitreTechnique(
        id="T1592",
        name="Gather Victim Host Information",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather information about victim hosts including software/hardware configurations",
        detection_methods=["Technology fingerprinting", "Version detection", "Header analysis"],
        owasp_mapping=["WSTG-INFO-02", "WSTG-INFO-08"],
        cwe_mapping=["CWE-200"]
    ),
    "T1592.001": MitreTechnique(
        id="T1592.001",
        name="Gather Victim Host Information: Hardware",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather information about victim host hardware",
        detection_methods=["Server headers", "Infrastructure fingerprinting"],
        owasp_mapping=["WSTG-INFO-02"],
        cwe_mapping=["CWE-200"]
    ),
    "T1592.002": MitreTechnique(
        id="T1592.002",
        name="Gather Victim Host Information: Software",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather information about installed software including types and versions",
        detection_methods=["Web server fingerprinting", "CMS detection", "Framework identification"],
        owasp_mapping=["WSTG-INFO-02", "WSTG-INFO-08", "WSTG-INFO-09"],
        cwe_mapping=["CWE-200"]
    ),
    "T1592.003": MitreTechnique(
        id="T1592.003",
        name="Gather Victim Host Information: Firmware",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather information about host firmware (IoT/embedded devices)",
        detection_methods=["Firmware version detection", "Device identification"],
        owasp_mapping=["WSTG-INFO-02"],
        cwe_mapping=["CWE-200"]
    ),
    "T1592.004": MitreTechnique(
        id="T1592.004",
        name="Gather Victim Host Information: Client Configurations",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather information about client configurations (OS, browser, plugins)",
        detection_methods=["User-Agent analysis", "JavaScript fingerprinting", "Client detection"],
        owasp_mapping=["WSTG-INFO-02"],
        cwe_mapping=["CWE-200"]
    ),

    # T1589 - Gather Victim Identity Information
    "T1589": MitreTechnique(
        id="T1589",
        name="Gather Victim Identity Information",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather information about victim identities for targeting",
        detection_methods=["Email harvesting", "Employee enumeration", "Social engineering recon"],
        owasp_mapping=["WSTG-INFO-03", "WSTG-IDNT-01"],
        cwe_mapping=["CWE-200"]
    ),
    "T1589.001": MitreTechnique(
        id="T1589.001",
        name="Gather Victim Identity Information: Credentials",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather credentials from breaches, leaks, or other sources",
        detection_methods=["Breach monitoring", "Credential leak detection", "Dark web monitoring"],
        owasp_mapping=["WSTG-ATHN-07"],
        cwe_mapping=["CWE-200", "CWE-312"]
    ),
    "T1589.002": MitreTechnique(
        id="T1589.002",
        name="Gather Victim Identity Information: Email Addresses",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather email addresses for phishing or account enumeration",
        detection_methods=["Email harvesting", "Contact page scraping", "WHOIS data"],
        owasp_mapping=["WSTG-INFO-03", "WSTG-IDNT-02"],
        cwe_mapping=["CWE-200"]
    ),
    "T1589.003": MitreTechnique(
        id="T1589.003",
        name="Gather Victim Identity Information: Employee Names",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather employee names for social engineering or credential guessing",
        detection_methods=["LinkedIn scraping", "About page analysis", "Staff directory enumeration"],
        owasp_mapping=["WSTG-INFO-03"],
        cwe_mapping=["CWE-200"]
    ),

    # T1590 - Gather Victim Network Information
    "T1590": MitreTechnique(
        id="T1590",
        name="Gather Victim Network Information",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather information about victim network infrastructure",
        detection_methods=["DNS enumeration", "Network mapping", "ASN analysis"],
        owasp_mapping=["WSTG-INFO-01", "WSTG-CONF-05"],
        cwe_mapping=["CWE-200"]
    ),
    "T1590.001": MitreTechnique(
        id="T1590.001",
        name="Gather Victim Network Information: Domain Properties",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather information about domain registration and properties",
        detection_methods=["WHOIS lookup", "Domain history", "Registrar analysis"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=["CWE-200"]
    ),
    "T1590.002": MitreTechnique(
        id="T1590.002",
        name="Gather Victim Network Information: DNS",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather DNS records including subdomains, mail servers, nameservers",
        detection_methods=["DNS enumeration", "Zone transfer", "Subdomain brute-force"],
        owasp_mapping=["WSTG-INFO-01", "WSTG-CONF-05"],
        cwe_mapping=["CWE-200"]
    ),
    "T1590.003": MitreTechnique(
        id="T1590.003",
        name="Gather Victim Network Information: Network Trust Dependencies",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Identify third-party organizations with network access",
        detection_methods=["Third-party service detection", "Integration analysis", "Vendor identification"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=["CWE-200"]
    ),
    "T1590.004": MitreTechnique(
        id="T1590.004",
        name="Gather Victim Network Information: Network Topology",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather information about network topology and infrastructure",
        detection_methods=["Traceroute", "Network mapping", "Infrastructure fingerprinting"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=["CWE-200"]
    ),
    "T1590.005": MitreTechnique(
        id="T1590.005",
        name="Gather Victim Network Information: IP Addresses",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather victim IP addresses including origin IPs behind CDN/WAF",
        detection_methods=["Origin IP discovery", "DNS history", "SSL certificate analysis"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=["CWE-200"]
    ),
    "T1590.006": MitreTechnique(
        id="T1590.006",
        name="Gather Victim Network Information: Network Security Appliances",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather information about WAFs, firewalls, and security appliances",
        detection_methods=["WAF detection", "CDN identification", "Security header analysis"],
        owasp_mapping=["WSTG-INFO-02", "WSTG-CONF-05"],
        cwe_mapping=["CWE-200"]
    ),

    # T1591 - Gather Victim Org Information
    "T1591": MitreTechnique(
        id="T1591",
        name="Gather Victim Org Information",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather information about the victim organization structure",
        detection_methods=["Organization profiling", "Business intelligence", "OSINT"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=["CWE-200"]
    ),
    "T1591.001": MitreTechnique(
        id="T1591.001",
        name="Gather Victim Org Information: Physical Locations",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Gather physical location information about target organization",
        detection_methods=["Geolocation", "Office location enumeration"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=["CWE-200"]
    ),
    "T1591.002": MitreTechnique(
        id="T1591.002",
        name="Gather Victim Org Information: Business Relationships",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Identify business partners, vendors, and third-party relationships",
        detection_methods=["Third-party detection", "Partner enumeration", "Supply chain mapping"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=["CWE-200"]
    ),
    "T1591.003": MitreTechnique(
        id="T1591.003",
        name="Gather Victim Org Information: Business Tempo",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Identify business operations timing and patterns",
        detection_methods=["Operations timing", "Business hours analysis"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=[]
    ),
    "T1591.004": MitreTechnique(
        id="T1591.004",
        name="Gather Victim Org Information: Identify Roles",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Identify key personnel and their roles within the organization",
        detection_methods=["Role enumeration", "Admin detection", "Privilege mapping"],
        owasp_mapping=["WSTG-INFO-03", "WSTG-IDNT-01"],
        cwe_mapping=["CWE-200"]
    ),

    # T1598 - Phishing for Information
    "T1598": MitreTechnique(
        id="T1598",
        name="Phishing for Information",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Send phishing messages to elicit sensitive information",
        detection_methods=["Phishing detection", "Social engineering awareness"],
        owasp_mapping=["WSTG-CLNT-04"],
        cwe_mapping=["CWE-1004"]
    ),
    "T1598.001": MitreTechnique(
        id="T1598.001",
        name="Phishing for Information: Spearphishing Service",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Use third-party services to send spearphishing messages",
        detection_methods=["Service-based phishing detection"],
        owasp_mapping=["WSTG-CLNT-04"],
        cwe_mapping=["CWE-1004"]
    ),
    "T1598.002": MitreTechnique(
        id="T1598.002",
        name="Phishing for Information: Spearphishing Attachment",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Send spearphishing emails with malicious attachments",
        detection_methods=["Attachment analysis", "Malware detection"],
        owasp_mapping=["WSTG-CLNT-04"],
        cwe_mapping=["CWE-1004"]
    ),
    "T1598.003": MitreTechnique(
        id="T1598.003",
        name="Phishing for Information: Spearphishing Link",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Send spearphishing emails with malicious links",
        detection_methods=["Link analysis", "Phishing page detection", "URL scanning"],
        owasp_mapping=["WSTG-CLNT-04"],
        cwe_mapping=["CWE-601"]
    ),
    "T1598.004": MitreTechnique(
        id="T1598.004",
        name="Phishing for Information: Spearphishing Voice",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Use voice communications for social engineering",
        detection_methods=["Vishing awareness"],
        owasp_mapping=[],
        cwe_mapping=[]
    ),

    # T1597 - Search Closed Sources
    "T1597": MitreTechnique(
        id="T1597",
        name="Search Closed Sources",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Search paid or private sources for victim information",
        detection_methods=["Threat intelligence", "Dark web monitoring"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=[]
    ),
    "T1597.001": MitreTechnique(
        id="T1597.001",
        name="Search Closed Sources: Threat Intel Vendors",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Search threat intelligence vendor data for victim information",
        detection_methods=["Threat intel integration", "IOC correlation"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=[]
    ),
    "T1597.002": MitreTechnique(
        id="T1597.002",
        name="Search Closed Sources: Purchase Technical Data",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Purchase technical information from underground sources",
        detection_methods=["Dark web monitoring"],
        owasp_mapping=[],
        cwe_mapping=[]
    ),

    # T1596 - Search Open Technical Databases
    "T1596": MitreTechnique(
        id="T1596",
        name="Search Open Technical Databases",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Search freely available technical databases for victim information",
        detection_methods=["OSINT databases", "Public records search"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=[]
    ),
    "T1596.001": MitreTechnique(
        id="T1596.001",
        name="Search Open Technical Databases: DNS/Passive DNS",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Search DNS and passive DNS data for victim information",
        detection_methods=["Passive DNS lookup", "Historical DNS", "DNS intelligence"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=[]
    ),
    "T1596.002": MitreTechnique(
        id="T1596.002",
        name="Search Open Technical Databases: WHOIS",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Search WHOIS data for domain registration information",
        detection_methods=["WHOIS lookup", "Registrant analysis"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=[]
    ),
    "T1596.003": MitreTechnique(
        id="T1596.003",
        name="Search Open Technical Databases: Digital Certificates",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Search certificate transparency logs for certificates",
        detection_methods=["crt.sh lookup", "Certificate analysis", "CT log monitoring"],
        owasp_mapping=["WSTG-INFO-01", "WSTG-CRYP-01"],
        cwe_mapping=[]
    ),
    "T1596.004": MitreTechnique(
        id="T1596.004",
        name="Search Open Technical Databases: CDNs",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Search CDN data for origin server information",
        detection_methods=["CDN detection", "Origin discovery", "Cache analysis"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=[]
    ),
    "T1596.005": MitreTechnique(
        id="T1596.005",
        name="Search Open Technical Databases: Scan Databases",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Search public scan databases like Shodan, Censys",
        detection_methods=["Shodan search", "Censys search", "Internet scan databases"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=[]
    ),

    # T1593 - Search Open Websites/Domains
    "T1593": MitreTechnique(
        id="T1593",
        name="Search Open Websites/Domains",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Search freely available websites for victim information",
        detection_methods=["OSINT", "Web scraping", "Social media analysis"],
        owasp_mapping=["WSTG-INFO-01", "WSTG-INFO-05"],
        cwe_mapping=["CWE-200"]
    ),
    "T1593.001": MitreTechnique(
        id="T1593.001",
        name="Search Open Websites/Domains: Social Media",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Search social media for organizational information",
        detection_methods=["Social media scraping", "LinkedIn analysis", "Twitter/X OSINT"],
        owasp_mapping=["WSTG-INFO-01"],
        cwe_mapping=["CWE-200"]
    ),
    "T1593.002": MitreTechnique(
        id="T1593.002",
        name="Search Open Websites/Domains: Search Engines",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Use search engines to discover victim information",
        detection_methods=["Google dorking", "Bing search", "Search engine OSINT"],
        owasp_mapping=["WSTG-INFO-01", "WSTG-INFO-05"],
        cwe_mapping=["CWE-200"]
    ),
    "T1593.003": MitreTechnique(
        id="T1593.003",
        name="Search Open Websites/Domains: Code Repositories",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Search public code repositories for secrets and information",
        detection_methods=["GitHub search", "GitLab analysis", "Secret scanning"],
        owasp_mapping=["WSTG-INFO-01", "WSTG-INFO-05"],
        cwe_mapping=["CWE-200", "CWE-312", "CWE-798"]
    ),

    # T1594 - Search Victim-Owned Websites
    "T1594": MitreTechnique(
        id="T1594",
        name="Search Victim-Owned Websites",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Search websites owned by the victim for information",
        detection_methods=["Web crawling", "Content analysis", "Site mapping"],
        owasp_mapping=["WSTG-INFO-03", "WSTG-INFO-04", "WSTG-INFO-05"],
        cwe_mapping=["CWE-200"]
    ),

    # T1681 - Search Threat Vendor Data
    "T1681": MitreTechnique(
        id="T1681",
        name="Search Threat Vendor Data",
        tactic=MitreAttackTactic.RECONNAISSANCE,
        description="Search threat intelligence for information about adversary campaigns",
        detection_methods=["Threat intel correlation", "Campaign analysis"],
        owasp_mapping=[],
        cwe_mapping=[]
    ),

    # ==========================================================================
    # TA0042: RESOURCE DEVELOPMENT (8 Techniques)
    # ==========================================================================

    # T1650 - Acquire Access
    "T1650": MitreTechnique(
        id="T1650",
        name="Acquire Access",
        tactic=MitreAttackTactic.RESOURCE_DEVELOPMENT,
        description="Purchase or acquire existing access to target systems",
        detection_methods=["Access broker monitoring", "Credential market monitoring"],
        owasp_mapping=[],
        cwe_mapping=[]
    ),

    # T1583 - Acquire Infrastructure
    "T1583": MitreTechnique(
        id="T1583",
        name="Acquire Infrastructure",
        tactic=MitreAttackTactic.RESOURCE_DEVELOPMENT,
        description="Buy, lease, or obtain infrastructure for operations",
        detection_methods=["Malicious infrastructure detection", "Domain reputation"],
        owasp_mapping=[],
        cwe_mapping=[]
    ),
    "T1583.001": MitreTechnique(
        id="T1583.001",
        name="Acquire Infrastructure: Domains",
        tactic=MitreAttackTactic.RESOURCE_DEVELOPMENT,
        description="Acquire domains for malicious operations",
        detection_methods=["Typosquatting detection", "Lookalike domain monitoring"],
        owasp_mapping=["WSTG-CLNT-04"],
        cwe_mapping=[]
    ),
    "T1583.006": MitreTechnique(
        id="T1583.006",
        name="Acquire Infrastructure: Web Services",
        tactic=MitreAttackTactic.RESOURCE_DEVELOPMENT,
        description="Register for web services for malicious operations",
        detection_methods=["Third-party service abuse detection"],
        owasp_mapping=[],
        cwe_mapping=[]
    ),

    # T1586 - Compromise Accounts
    "T1586": MitreTechnique(
        id="T1586",
        name="Compromise Accounts",
        tactic=MitreAttackTactic.RESOURCE_DEVELOPMENT,
        description="Compromise existing accounts for operations",
        detection_methods=["Account takeover detection", "Credential stuffing detection"],
        owasp_mapping=["WSTG-ATHN-07"],
        cwe_mapping=["CWE-287"]
    ),

    # T1584 - Compromise Infrastructure
    "T1584": MitreTechnique(
        id="T1584",
        name="Compromise Infrastructure",
        tactic=MitreAttackTactic.RESOURCE_DEVELOPMENT,
        description="Compromise third-party infrastructure for operations",
        detection_methods=["Subdomain takeover", "DNS hijacking detection"],
        owasp_mapping=["WSTG-CONF-10"],
        cwe_mapping=["CWE-284"]
    ),
    "T1584.001": MitreTechnique(
        id="T1584.001",
        name="Compromise Infrastructure: Domains",
        tactic=MitreAttackTactic.RESOURCE_DEVELOPMENT,
        description="Hijack domains or subdomains for malicious use",
        detection_methods=["Subdomain takeover detection", "Dangling DNS detection"],
        owasp_mapping=["WSTG-CONF-10"],
        cwe_mapping=["CWE-284"]
    ),

    # T1587 - Develop Capabilities
    "T1587": MitreTechnique(
        id="T1587",
        name="Develop Capabilities",
        tactic=MitreAttackTactic.RESOURCE_DEVELOPMENT,
        description="Build capabilities including malware and exploits",
        detection_methods=["Malware analysis", "Exploit detection"],
        owasp_mapping=[],
        cwe_mapping=[]
    ),
    "T1587.004": MitreTechnique(
        id="T1587.004",
        name="Develop Capabilities: Exploits",
        tactic=MitreAttackTactic.RESOURCE_DEVELOPMENT,
        description="Develop exploits for vulnerabilities",
        detection_methods=["Exploit detection", "Vulnerability correlation"],
        owasp_mapping=[],
        cwe_mapping=[]
    ),

    # T1585 - Establish Accounts
    "T1585": MitreTechnique(
        id="T1585",
        name="Establish Accounts",
        tactic=MitreAttackTactic.RESOURCE_DEVELOPMENT,
        description="Create and cultivate accounts for operations",
        detection_methods=["Fake account detection", "Bot detection"],
        owasp_mapping=["WSTG-IDNT-01"],
        cwe_mapping=[]
    ),

    # T1588 - Obtain Capabilities
    "T1588": MitreTechnique(
        id="T1588",
        name="Obtain Capabilities",
        tactic=MitreAttackTactic.RESOURCE_DEVELOPMENT,
        description="Buy, steal, or download capabilities for operations",
        detection_methods=["Malware detection", "Exploit detection"],
        owasp_mapping=[],
        cwe_mapping=[]
    ),
    "T1588.005": MitreTechnique(
        id="T1588.005",
        name="Obtain Capabilities: Exploits",
        tactic=MitreAttackTactic.RESOURCE_DEVELOPMENT,
        description="Obtain exploits from various sources",
        detection_methods=["Known exploit detection", "CVE correlation"],
        owasp_mapping=["WSTG-CONF-01"],
        cwe_mapping=[]
    ),
    "T1588.006": MitreTechnique(
        id="T1588.006",
        name="Obtain Capabilities: Vulnerabilities",
        tactic=MitreAttackTactic.RESOURCE_DEVELOPMENT,
        description="Acquire vulnerability information for targeting",
        detection_methods=["Vulnerability scanning", "CVE monitoring"],
        owasp_mapping=["WSTG-INFO-02"],
        cwe_mapping=[]
    ),

    # T1608 - Stage Capabilities
    "T1608": MitreTechnique(
        id="T1608",
        name="Stage Capabilities",
        tactic=MitreAttackTactic.RESOURCE_DEVELOPMENT,
        description="Upload, install, or set up capabilities for use",
        detection_methods=["Malicious content detection", "Staged payload detection"],
        owasp_mapping=[],
        cwe_mapping=[]
    ),
    "T1608.004": MitreTechnique(
        id="T1608.004",
        name="Stage Capabilities: Drive-by Target",
        tactic=MitreAttackTactic.RESOURCE_DEVELOPMENT,
        description="Prepare infrastructure for drive-by compromise",
        detection_methods=["Malicious script detection", "Exploit kit detection"],
        owasp_mapping=["WSTG-CLNT-01"],
        cwe_mapping=["CWE-79"]
    ),
    "T1608.005": MitreTechnique(
        id="T1608.005",
        name="Stage Capabilities: Link Target",
        tactic=MitreAttackTactic.RESOURCE_DEVELOPMENT,
        description="Set up resources for malicious links",
        detection_methods=["Phishing page detection", "Malicious link analysis"],
        owasp_mapping=["WSTG-CLNT-04"],
        cwe_mapping=["CWE-601"]
    ),

    # ==========================================================================
    # TA0001: INITIAL ACCESS (11 Techniques)
    # ==========================================================================

    # T1659 - Content Injection
    "T1659": MitreTechnique(
        id="T1659",
        name="Content Injection",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Gain access by injecting malicious content into network traffic",
        detection_methods=["MITM detection", "Content integrity verification"],
        owasp_mapping=["WSTG-CRYP-01"],
        cwe_mapping=["CWE-319"]
    ),

    # T1189 - Drive-by Compromise
    "T1189": MitreTechnique(
        id="T1189",
        name="Drive-by Compromise",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Gain access through visiting a malicious website",
        detection_methods=["XSS detection", "Malicious script analysis", "DOM manipulation"],
        owasp_mapping=["WSTG-CLNT-01", "WSTG-CLNT-02"],
        cwe_mapping=["CWE-79"]
    ),

    # T1190 - Exploit Public-Facing Application (PRIMARY FOCUS)
    "T1190": MitreTechnique(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Exploit vulnerabilities in public-facing applications for access",
        detection_methods=["SQL Injection", "Command Injection", "RCE", "SSRF", "XXE", "SSTI", "Deserialization"],
        owasp_mapping=["A03:2021-Injection", "A08:2021-Software and Data Integrity Failures"],
        cwe_mapping=["CWE-89", "CWE-78", "CWE-94", "CWE-918", "CWE-611", "CWE-502", "CWE-22", "CWE-1336"]
    ),

    # T1133 - External Remote Services
    "T1133": MitreTechnique(
        id="T1133",
        name="External Remote Services",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Leverage external-facing remote services for access",
        detection_methods=["Exposed service detection", "Admin panel discovery", "VPN/RDP enumeration"],
        owasp_mapping=["WSTG-CONF-01", "WSTG-CONF-05"],
        cwe_mapping=["CWE-284"]
    ),

    # T1200 - Hardware Additions
    "T1200": MitreTechnique(
        id="T1200",
        name="Hardware Additions",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Introduce hardware to gain access (physical vector)",
        detection_methods=["Physical security"],
        owasp_mapping=[],
        cwe_mapping=[]
    ),

    # T1566 - Phishing
    "T1566": MitreTechnique(
        id="T1566",
        name="Phishing",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Send phishing messages to gain access to systems",
        detection_methods=["Phishing page detection", "OAuth abuse", "Session hijacking"],
        owasp_mapping=["WSTG-CLNT-04"],
        cwe_mapping=["CWE-1004"]
    ),
    "T1566.001": MitreTechnique(
        id="T1566.001",
        name="Phishing: Spearphishing Attachment",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Send emails with malicious attachments",
        detection_methods=["File upload analysis", "Malware scanning"],
        owasp_mapping=["WSTG-BUSL-08"],
        cwe_mapping=["CWE-434"]
    ),
    "T1566.002": MitreTechnique(
        id="T1566.002",
        name="Phishing: Spearphishing Link",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Send emails with malicious links",
        detection_methods=["Open redirect detection", "URL analysis"],
        owasp_mapping=["WSTG-CLNT-04"],
        cwe_mapping=["CWE-601"]
    ),
    "T1566.003": MitreTechnique(
        id="T1566.003",
        name="Phishing: Spearphishing via Service",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Use third-party services for phishing",
        detection_methods=["OAuth abuse detection", "Third-party integration analysis"],
        owasp_mapping=["WSTG-CLNT-04"],
        cwe_mapping=["CWE-287"]
    ),

    # T1091 - Replication Through Removable Media
    "T1091": MitreTechnique(
        id="T1091",
        name="Replication Through Removable Media",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Move onto systems via removable media",
        detection_methods=["Physical security"],
        owasp_mapping=[],
        cwe_mapping=[]
    ),

    # T1195 - Supply Chain Compromise
    "T1195": MitreTechnique(
        id="T1195",
        name="Supply Chain Compromise",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Manipulate products or delivery mechanisms",
        detection_methods=["Third-party analysis", "Dependency scanning"],
        owasp_mapping=["A06:2021-Vulnerable and Outdated Components"],
        cwe_mapping=["CWE-1104"]
    ),
    "T1195.001": MitreTechnique(
        id="T1195.001",
        name="Supply Chain Compromise: Software Dependencies",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Compromise software dependencies and development tools",
        detection_methods=["Dependency confusion detection", "Package analysis", "SCA"],
        owasp_mapping=["A06:2021-Vulnerable and Outdated Components"],
        cwe_mapping=["CWE-1104"]
    ),
    "T1195.002": MitreTechnique(
        id="T1195.002",
        name="Supply Chain Compromise: Software Supply Chain",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Compromise software prior to customer receipt",
        detection_methods=["Third-party script analysis", "Integrity verification"],
        owasp_mapping=["A08:2021-Software and Data Integrity Failures"],
        cwe_mapping=["CWE-494"]
    ),

    # T1199 - Trusted Relationship
    "T1199": MitreTechnique(
        id="T1199",
        name="Trusted Relationship",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Breach organizations with trusted access to target",
        detection_methods=["Third-party integration audit", "API key exposure", "OAuth analysis"],
        owasp_mapping=["WSTG-CONF-06"],
        cwe_mapping=["CWE-284"]
    ),

    # T1078 - Valid Accounts (HIGH PRIORITY)
    "T1078": MitreTechnique(
        id="T1078",
        name="Valid Accounts",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Use valid credentials to gain initial access",
        detection_methods=["Credential stuffing", "Default credentials", "Weak passwords", "Brute force"],
        owasp_mapping=["A07:2021-Identification and Authentication Failures"],
        cwe_mapping=["CWE-287", "CWE-798", "CWE-521", "CWE-307"]
    ),
    "T1078.001": MitreTechnique(
        id="T1078.001",
        name="Valid Accounts: Default Accounts",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Use default account credentials",
        detection_methods=["Default credential testing", "Factory password detection"],
        owasp_mapping=["A07:2021-Identification and Authentication Failures", "WSTG-ATHN-02"],
        cwe_mapping=["CWE-798"]
    ),
    "T1078.002": MitreTechnique(
        id="T1078.002",
        name="Valid Accounts: Domain Accounts",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Use domain account credentials",
        detection_methods=["User enumeration", "Account brute force"],
        owasp_mapping=["A07:2021-Identification and Authentication Failures"],
        cwe_mapping=["CWE-287"]
    ),
    "T1078.003": MitreTechnique(
        id="T1078.003",
        name="Valid Accounts: Local Accounts",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Use local account credentials",
        detection_methods=["Local user enumeration", "Brute force protection testing"],
        owasp_mapping=["A07:2021-Identification and Authentication Failures"],
        cwe_mapping=["CWE-287", "CWE-307"]
    ),
    "T1078.004": MitreTechnique(
        id="T1078.004",
        name="Valid Accounts: Cloud Accounts",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Use cloud account credentials",
        detection_methods=["Cloud misconfiguration", "IAM analysis", "API key exposure"],
        owasp_mapping=["A05:2021-Security Misconfiguration"],
        cwe_mapping=["CWE-287", "CWE-284"]
    ),

    # T1669 - Wi-Fi Networks
    "T1669": MitreTechnique(
        id="T1669",
        name="Wi-Fi Networks",
        tactic=MitreAttackTactic.INITIAL_ACCESS,
        description="Gain access through wireless networks",
        detection_methods=["Network layer testing"],
        owasp_mapping=[],
        cwe_mapping=[]
    ),

    # ==========================================================================
    # ADDITIONAL TECHNIQUES (Post-Initial Access - For reference)
    # ==========================================================================

    # EXECUTION
    "T1059": MitreTechnique(
        id="T1059",
        name="Command and Scripting Interpreter",
        tactic=MitreAttackTactic.EXECUTION,
        description="Adversaries may abuse command and script interpreters",
        detection_methods=["Command injection", "Code injection", "Template injection"],
        owasp_mapping=["A03:2021-Injection"],
        cwe_mapping=["CWE-78", "CWE-94", "CWE-1336"]
    ),
    "T1203": MitreTechnique(
        id="T1203",
        name="Exploitation for Client Execution",
        tactic=MitreAttackTactic.EXECUTION,
        description="Adversaries may exploit software vulnerabilities in client applications",
        detection_methods=["XSS", "DOM manipulation", "JavaScript injection"],
        owasp_mapping=["A03:2021-Injection"],
        cwe_mapping=["CWE-79"]
    ),

    # PRIVILEGE ESCALATION
    "T1068": MitreTechnique(
        id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic=MitreAttackTactic.PRIVILEGE_ESCALATION,
        description="Adversaries may exploit software vulnerabilities to escalate privileges",
        detection_methods=["Vertical privilege escalation", "IDOR", "JWT manipulation", "Role bypass"],
        owasp_mapping=["A01:2021-Broken Access Control"],
        cwe_mapping=["CWE-269", "CWE-639", "CWE-862"]
    ),
    "T1548": MitreTechnique(
        id="T1548",
        name="Abuse Elevation Control Mechanism",
        tactic=MitreAttackTactic.PRIVILEGE_ESCALATION,
        description="Adversaries may abuse elevation control mechanisms",
        detection_methods=["Sudo abuse", "SetUID abuse", "Authorization bypass"],
        owasp_mapping=["A01:2021-Broken Access Control"],
        cwe_mapping=["CWE-284"]
    ),

    # CREDENTIAL ACCESS
    "T1110": MitreTechnique(
        id="T1110",
        name="Brute Force",
        tactic=MitreAttackTactic.CREDENTIAL_ACCESS,
        description="Adversaries may use brute force techniques to gain access",
        detection_methods=["Password spraying", "Credential stuffing", "Dictionary attacks"],
        owasp_mapping=["A07:2021-Identification and Authentication Failures"],
        cwe_mapping=["CWE-307", "CWE-521"]
    ),
    "T1552": MitreTechnique(
        id="T1552",
        name="Unsecured Credentials",
        tactic=MitreAttackTactic.CREDENTIAL_ACCESS,
        description="Adversaries may search for unsecured credentials",
        detection_methods=["Hardcoded credentials", "Exposed secrets", "API keys in source"],
        owasp_mapping=["A02:2021-Cryptographic Failures", "A05:2021-Security Misconfiguration"],
        cwe_mapping=["CWE-798", "CWE-312", "CWE-319"]
    ),
    "T1539": MitreTechnique(
        id="T1539",
        name="Steal Web Session Cookie",
        tactic=MitreAttackTactic.CREDENTIAL_ACCESS,
        description="Adversaries may steal web session cookies",
        detection_methods=["Session hijacking", "Cookie theft via XSS", "Session fixation"],
        owasp_mapping=["A07:2021-Identification and Authentication Failures"],
        cwe_mapping=["CWE-384", "CWE-614", "CWE-1004"]
    ),

    # DISCOVERY
    "T1087": MitreTechnique(
        id="T1087",
        name="Account Discovery",
        tactic=MitreAttackTactic.DISCOVERY,
        description="Adversaries may attempt to get a listing of accounts",
        detection_methods=["User enumeration", "Email enumeration", "Username harvesting"],
        owasp_mapping=["A07:2021-Identification and Authentication Failures"],
        cwe_mapping=["CWE-203", "CWE-204"]
    ),
    "T1083": MitreTechnique(
        id="T1083",
        name="File and Directory Discovery",
        tactic=MitreAttackTactic.DISCOVERY,
        description="Adversaries may enumerate files and directories",
        detection_methods=["Directory traversal", "Forced browsing", "Backup file discovery"],
        owasp_mapping=["A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"],
        cwe_mapping=["CWE-22", "CWE-425", "CWE-530"]
    ),

    # COLLECTION
    "T1005": MitreTechnique(
        id="T1005",
        name="Data from Local System",
        tactic=MitreAttackTactic.COLLECTION,
        description="Adversaries may search local system sources for data",
        detection_methods=["LFI", "Path traversal", "Arbitrary file read"],
        owasp_mapping=["A01:2021-Broken Access Control"],
        cwe_mapping=["CWE-22", "CWE-98"]
    ),
    "T1530": MitreTechnique(
        id="T1530",
        name="Data from Cloud Storage",
        tactic=MitreAttackTactic.COLLECTION,
        description="Adversaries may access data from cloud storage",
        detection_methods=["S3 bucket enumeration", "Azure blob access", "GCP storage access"],
        owasp_mapping=["A05:2021-Security Misconfiguration"],
        cwe_mapping=["CWE-284", "CWE-732"]
    ),

    # EXFILTRATION
    "T1567": MitreTechnique(
        id="T1567",
        name="Exfiltration Over Web Service",
        tactic=MitreAttackTactic.EXFILTRATION,
        description="Adversaries may use web services to exfiltrate data",
        detection_methods=["SSRF to external services", "Data exfil via DNS", "Webhook abuse"],
        owasp_mapping=["A10:2021-Server-Side Request Forgery"],
        cwe_mapping=["CWE-918"]
    ),
}


# =============================================================================
# OWASP TOP 10 (2021) MAPPING
# =============================================================================

@dataclass
class OWASPCategory:
    """OWASP Top 10 Category"""
    id: str                        # e.g., A01:2021
    name: str
    description: str
    cwe_mapping: List[str]         # CWE IDs
    mitre_techniques: List[str]    # MITRE ATT&CK technique IDs
    test_cases: List[str]          # Specific test cases


OWASP_TOP_10_2021 = {
    "A01": OWASPCategory(
        id="A01:2021",
        name="Broken Access Control",
        description="Access control enforces policy such that users cannot act outside of their intended permissions",
        cwe_mapping=["CWE-200", "CWE-201", "CWE-352", "CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863", "CWE-22"],
        mitre_techniques=["T1068", "T1548", "T1083", "T1005"],
        test_cases=[
            "IDOR - Access other users' data by changing ID",
            "Vertical privilege escalation - Access admin functions as user",
            "Horizontal privilege escalation - Access user1's data as user2",
            "Missing function level access control",
            "CORS misconfiguration",
            "Path traversal",
            "Forced browsing to unauthorized pages",
            "JWT manipulation (alg:none, signature bypass)",
            "Metadata/header manipulation for privilege escalation",
            "Method tampering (POST vs PUT vs DELETE)",
        ]
    ),
    "A02": OWASPCategory(
        id="A02:2021",
        name="Cryptographic Failures",
        description="Failures related to cryptography which often lead to exposure of sensitive data",
        cwe_mapping=["CWE-259", "CWE-327", "CWE-328", "CWE-330", "CWE-311", "CWE-312", "CWE-319", "CWE-326"],
        mitre_techniques=["T1552", "T1539"],
        test_cases=[
            "Sensitive data transmitted over HTTP (not HTTPS)",
            "Weak TLS/SSL configuration",
            "Sensitive data in URL parameters",
            "Weak password hashing algorithms",
            "Predictable cryptographic keys",
            "Missing encryption for sensitive data at rest",
            "Hardcoded secrets and API keys",
            "Sensitive data in client-side storage",
        ]
    ),
    "A03": OWASPCategory(
        id="A03:2021",
        name="Injection",
        description="User-supplied data is not validated, filtered, or sanitized by the application",
        cwe_mapping=["CWE-79", "CWE-89", "CWE-78", "CWE-94", "CWE-917", "CWE-1336", "CWE-611", "CWE-918"],
        mitre_techniques=["T1190", "T1059", "T1203"],
        test_cases=[
            "SQL Injection - Error-based, UNION, Blind, Time-based",
            "NoSQL Injection - MongoDB, CouchDB operators",
            "Command Injection - OS command execution",
            "LDAP Injection",
            "XPath Injection",
            "XML External Entity (XXE)",
            "Server-Side Template Injection (SSTI)",
            "Expression Language Injection",
            "Cross-Site Scripting (XSS) - Reflected, Stored, DOM-based",
            "Header Injection (CRLF)",
        ]
    ),
    "A04": OWASPCategory(
        id="A04:2021",
        name="Insecure Design",
        description="Missing or ineffective control design",
        cwe_mapping=["CWE-209", "CWE-256", "CWE-501", "CWE-522", "CWE-656", "CWE-799", "CWE-840", "CWE-841"],
        mitre_techniques=["T1190"],
        test_cases=[
            "Missing rate limiting on sensitive operations",
            "Lack of account lockout mechanism",
            "Insufficient anti-automation controls",
            "Business logic flaws",
            "Missing security controls in design",
            "Trust boundary violations",
        ]
    ),
    "A05": OWASPCategory(
        id="A05:2021",
        name="Security Misconfiguration",
        description="Application is missing appropriate security hardening or has improperly configured permissions",
        cwe_mapping=["CWE-16", "CWE-611", "CWE-200", "CWE-1004"],
        mitre_techniques=["T1592", "T1552", "T1530"],
        test_cases=[
            "Default credentials",
            "Unnecessary features enabled",
            "Error messages revealing sensitive info",
            "Missing security headers",
            "Directory listing enabled",
            "Backup files exposed",
            "Outdated software with known vulnerabilities",
            "Debug endpoints exposed",
            "Verbose error messages",
            "Cloud storage misconfiguration",
        ]
    ),
    "A06": OWASPCategory(
        id="A06:2021",
        name="Vulnerable and Outdated Components",
        description="Using components with known vulnerabilities",
        cwe_mapping=["CWE-1104"],
        mitre_techniques=["T1190"],
        test_cases=[
            "Outdated JavaScript libraries with known CVEs",
            "Unpatched server software",
            "Outdated CMS/framework versions",
            "Components with known vulnerabilities",
            "Dependency confusion attacks",
        ]
    ),
    "A07": OWASPCategory(
        id="A07:2021",
        name="Identification and Authentication Failures",
        description="Authentication and session management vulnerabilities",
        cwe_mapping=["CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-295", "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306", "CWE-307", "CWE-346", "CWE-384", "CWE-521", "CWE-613", "CWE-620", "CWE-640", "CWE-798", "CWE-940", "CWE-1216"],
        mitre_techniques=["T1078", "T1110", "T1539", "T1087"],
        test_cases=[
            "Weak password policy",
            "Missing brute force protection",
            "Credential stuffing possible",
            "Weak session management",
            "Session fixation",
            "Session not invalidated on logout",
            "Password reset weaknesses",
            "User enumeration",
            "MFA bypass",
            "JWT vulnerabilities",
        ]
    ),
    "A08": OWASPCategory(
        id="A08:2021",
        name="Software and Data Integrity Failures",
        description="Code and infrastructure that does not protect against integrity violations",
        cwe_mapping=["CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565", "CWE-784", "CWE-829", "CWE-830", "CWE-913"],
        mitre_techniques=["T1190"],
        test_cases=[
            "Insecure deserialization",
            "CI/CD pipeline vulnerabilities",
            "Unsigned or unchecked updates",
            "Mass assignment vulnerabilities",
            "Prototype pollution",
            "Object injection",
        ]
    ),
    "A09": OWASPCategory(
        id="A09:2021",
        name="Security Logging and Monitoring Failures",
        description="Insufficient logging and monitoring",
        cwe_mapping=["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        mitre_techniques=["T1562"],  # Impair Defenses
        test_cases=[
            "Missing audit logging",
            "Logs not monitored for suspicious activity",
            "Sensitive data in logs",
            "Log injection possible",
        ]
    ),
    "A10": OWASPCategory(
        id="A10:2021",
        name="Server-Side Request Forgery (SSRF)",
        description="Web application fetches a remote resource without validating the user-supplied URL",
        cwe_mapping=["CWE-918"],
        mitre_techniques=["T1567", "T1190"],
        test_cases=[
            "SSRF to internal services",
            "SSRF to cloud metadata endpoints",
            "SSRF via URL parameters",
            "SSRF via file upload",
            "Blind SSRF",
            "SSRF with protocol handlers",
        ]
    ),
}


# =============================================================================
# ATTACK PHASES (PTES Aligned)
# =============================================================================

@dataclass
class AttackPhase:
    """Security testing phase definition"""
    id: int
    name: str
    description: str
    mitre_tactics: List[MitreAttackTactic]
    objectives: List[str]
    tools: List[str]
    output_artifacts: List[str]


ATTACK_PHASES = [
    AttackPhase(
        id=1,
        name="Reconnaissance",
        description="Gather information about the target to understand attack surface",
        mitre_tactics=[MitreAttackTactic.RECONNAISSANCE],
        objectives=[
            "Identify all subdomains and assets",
            "Enumerate web technologies and versions",
            "Discover entry points and attack surface",
            "Identify potential vulnerabilities from version info",
            "Map application structure and functionality",
        ],
        tools=["subfinder", "amass", "httpx", "whatweb", "wappalyzer", "nmap"],
        output_artifacts=["subdomains.txt", "live_hosts.json", "technologies.json", "endpoints.txt"]
    ),
    AttackPhase(
        id=2,
        name="Discovery",
        description="Active enumeration of application functionality and hidden content",
        mitre_tactics=[MitreAttackTactic.DISCOVERY],
        objectives=[
            "Crawl and map all application pages",
            "Discover hidden directories and files",
            "Identify API endpoints",
            "Extract JavaScript files and analyze",
            "Find backup files and sensitive data",
        ],
        tools=["gospider", "hakrawler", "katana", "ffuf", "dirsearch", "gau"],
        output_artifacts=["crawl_results.json", "directories.txt", "js_files.txt", "api_endpoints.json"]
    ),
    AttackPhase(
        id=3,
        name="Vulnerability Analysis",
        description="Identify and verify security vulnerabilities",
        mitre_tactics=[MitreAttackTactic.INITIAL_ACCESS, MitreAttackTactic.EXECUTION],
        objectives=[
            "Test for injection vulnerabilities (SQLi, XSS, CMDi)",
            "Identify authentication weaknesses",
            "Test access control mechanisms",
            "Check for misconfigurations",
            "Analyze cryptographic implementations",
        ],
        tools=["nuclei", "sqlmap", "dalfox", "commix", "jwt_tool"],
        output_artifacts=["vulnerabilities.json", "injection_findings.json", "auth_issues.json"]
    ),
    AttackPhase(
        id=4,
        name="Exploitation",
        description="Verify and demonstrate vulnerability impact",
        mitre_tactics=[MitreAttackTactic.PRIVILEGE_ESCALATION, MitreAttackTactic.CREDENTIAL_ACCESS],
        objectives=[
            "Confirm vulnerabilities are exploitable",
            "Demonstrate actual impact",
            "Test privilege escalation paths",
            "Attempt credential access",
            "Document proof of concept",
        ],
        tools=["burp_suite", "sqlmap", "metasploit", "custom_scripts"],
        output_artifacts=["exploitation_log.json", "poc_evidence/", "credentials_found.txt"]
    ),
    AttackPhase(
        id=5,
        name="Post-Exploitation",
        description="Assess impact of successful exploitation",
        mitre_tactics=[MitreAttackTactic.COLLECTION, MitreAttackTactic.EXFILTRATION],
        objectives=[
            "Determine data access achieved",
            "Identify lateral movement opportunities",
            "Assess full impact scope",
            "Document business impact",
        ],
        tools=["custom_scripts", "manual_analysis"],
        output_artifacts=["impact_assessment.json", "data_access_scope.json"]
    ),
    AttackPhase(
        id=6,
        name="Reporting",
        description="Document findings and provide remediation guidance",
        mitre_tactics=[],
        objectives=[
            "Document all findings with evidence",
            "Provide CVSS/severity ratings",
            "Include remediation recommendations",
            "Create executive summary",
            "Map to MITRE ATT&CK and OWASP",
        ],
        tools=["report_generator"],
        output_artifacts=["report.json", "report.html", "report.pdf"]
    ),
]


# =============================================================================
# SCANNER MODULE TO METHODOLOGY MAPPING
# =============================================================================

MODULE_METHODOLOGY_MAP = {
    # ==========================================================================
    # RECONNAISSANCE PHASE (TA0043)
    # ==========================================================================
    "subdomain": {
        "phase": 1,
        "mitre_techniques": ["T1595.001", "T1596.001", "T1596.002", "T1596.003"],
        "owasp_categories": [],
        "description": "Subdomain enumeration via DNS, CT logs, and passive sources",
    },
    "subdomain_enum": {
        "phase": 1,
        "mitre_techniques": ["T1595.001", "T1596.001", "T1596.003"],
        "owasp_categories": [],
        "description": "Subdomain enumeration using subfinder, amass",
    },
    "dnsenum": {
        "phase": 1,
        "mitre_techniques": ["T1590.001", "T1590.002", "T1596.001", "T1596.002"],
        "owasp_categories": [],
        "description": "DNS enumeration, zone transfer, and WHOIS analysis",
    },
    "probe": {
        "phase": 1,
        "mitre_techniques": ["T1592.002", "T1592.004", "T1590.006"],
        "owasp_categories": ["A05"],
        "description": "HTTP probing, technology fingerprinting, WAF detection",
    },
    "http_prober": {
        "phase": 1,
        "mitre_techniques": ["T1592.002", "T1590.006"],
        "owasp_categories": ["A05"],
        "description": "HTTP service detection and technology fingerprinting",
    },
    "portscan": {
        "phase": 1,
        "mitre_techniques": ["T1595.001", "T1595.002"],
        "owasp_categories": [],
        "description": "Port scanning and service discovery",
    },
    "origin_ip": {
        "phase": 1,
        "mitre_techniques": ["T1590.005", "T1590.006", "T1596.003", "T1596.004", "T1596.005"],
        "owasp_categories": [],
        "description": "Origin IP discovery behind CDN/WAF",
    },

    # ==========================================================================
    # DISCOVERY PHASE (Content Discovery)
    # ==========================================================================
    "crawler": {
        "phase": 2,
        "mitre_techniques": ["T1594", "T1083"],
        "owasp_categories": [],
        "description": "Web crawling and site mapping",
    },
    "web_crawler": {
        "phase": 2,
        "mitre_techniques": ["T1594", "T1593.002"],
        "owasp_categories": [],
        "description": "Comprehensive web crawling and content discovery",
    },
    "dirscan": {
        "phase": 2,
        "mitre_techniques": ["T1595.003", "T1083"],
        "owasp_categories": ["A01", "A05"],
        "description": "Directory and file brute forcing",
    },
    "jsrecon": {
        "phase": 2,
        "mitre_techniques": ["T1594", "T1593.003", "T1592.002", "T1552"],
        "owasp_categories": ["A02", "A05"],
        "description": "JavaScript analysis for endpoints, secrets, and vulnerabilities",
    },
    "force_browsing": {
        "phase": 2,
        "mitre_techniques": ["T1595.003", "T1083"],
        "owasp_categories": ["A01", "A05"],
        "description": "Forced browsing for hidden resources",
    },
    "sensitive_data": {
        "phase": 2,
        "mitre_techniques": ["T1589.001", "T1589.002", "T1593.003", "T1552"],
        "owasp_categories": ["A02", "A05"],
        "description": "Sensitive data and credential exposure detection",
    },
    "parameter_discovery": {
        "phase": 2,
        "mitre_techniques": ["T1594", "T1595.003"],
        "owasp_categories": [],
        "description": "Parameter and endpoint discovery",
    },

    # ==========================================================================
    # VULNERABILITY ANALYSIS PHASE (TA0001 - Initial Access Testing)
    # ==========================================================================
    "injection": {
        "phase": 3,
        "mitre_techniques": ["T1190", "T1059"],
        "owasp_categories": ["A03"],
        "description": "Injection vulnerability testing (SQLi, XSS, CMDi, SSTI)",
    },
    "advanced_fuzzer": {
        "phase": 3,
        "mitre_techniques": ["T1190", "T1059"],
        "owasp_categories": ["A03", "A10"],
        "description": "Advanced fuzzing for SQLi, CMDi, SSTI, SSRF, XSS",
    },
    "sqli": {
        "phase": 3,
        "mitre_techniques": ["T1190"],
        "owasp_categories": ["A03"],
        "description": "SQL injection detection and exploitation",
    },
    "xss": {
        "phase": 3,
        "mitre_techniques": ["T1189", "T1203"],
        "owasp_categories": ["A03"],
        "description": "Cross-Site Scripting detection",
    },
    "cors": {
        "phase": 3,
        "mitre_techniques": ["T1189", "T1068"],
        "owasp_categories": ["A01", "A05"],
        "description": "CORS misconfiguration testing",
    },
    "api": {
        "phase": 3,
        "mitre_techniques": ["T1190", "T1078", "T1068"],
        "owasp_categories": ["A01"],
        "description": "API access control and security testing",
    },
    "api_access": {
        "phase": 3,
        "mitre_techniques": ["T1190", "T1078", "T1199"],
        "owasp_categories": ["A01", "A07"],
        "description": "API access control comprehensive testing",
    },
    "idor": {
        "phase": 3,
        "mitre_techniques": ["T1078", "T1068"],
        "owasp_categories": ["A01"],
        "description": "Insecure Direct Object Reference testing",
    },
    "bac": {
        "phase": 3,
        "mitre_techniques": ["T1078", "T1068", "T1548"],
        "owasp_categories": ["A01"],
        "description": "Broken Access Control comprehensive testing",
    },
    "bac_scanner": {
        "phase": 3,
        "mitre_techniques": ["T1078", "T1068", "T1548"],
        "owasp_categories": ["A01"],
        "description": "Broken Access Control scanning",
    },
    "jwt": {
        "phase": 3,
        "mitre_techniques": ["T1078", "T1539", "T1068"],
        "owasp_categories": ["A01", "A07"],
        "description": "JWT security analysis and manipulation",
    },
    "jwt_analyzer": {
        "phase": 3,
        "mitre_techniques": ["T1078", "T1539"],
        "owasp_categories": ["A01", "A07"],
        "description": "JWT token analysis and vulnerability testing",
    },
    "sensitive": {
        "phase": 3,
        "mitre_techniques": ["T1552", "T1589.001"],
        "owasp_categories": ["A02", "A05"],
        "description": "Sensitive data exposure detection",
    },
    "vuln": {
        "phase": 3,
        "mitre_techniques": ["T1190", "T1588.005", "T1588.006"],
        "owasp_categories": ["A06"],
        "description": "Known vulnerability scanning (CVEs)",
    },
    "vuln_scanner": {
        "phase": 3,
        "mitre_techniques": ["T1190", "T1595.002"],
        "owasp_categories": ["A06"],
        "description": "Vulnerability scanning and CVE detection",
    },
    "nuclei": {
        "phase": 3,
        "mitre_techniques": ["T1190", "T1595.002", "T1588.005"],
        "owasp_categories": ["A01", "A03", "A05", "A06"],
        "description": "Template-based vulnerability scanning",
    },

    # ==========================================================================
    # RESOURCE DEVELOPMENT AWARENESS (TA0042 - Detection Focus)
    # ==========================================================================
    "subdomain_takeover": {
        "phase": 3,
        "mitre_techniques": ["T1584.001"],
        "owasp_categories": ["A05"],
        "description": "Subdomain takeover vulnerability detection",
    },
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_techniques_for_module(module_name: str) -> List[MitreTechnique]:
    """Get MITRE ATT&CK techniques for a scanner module"""
    mapping = MODULE_METHODOLOGY_MAP.get(module_name, {})
    technique_ids = mapping.get("mitre_techniques", [])
    return [MITRE_TECHNIQUES[tid] for tid in technique_ids if tid in MITRE_TECHNIQUES]


def get_owasp_categories_for_module(module_name: str) -> List[OWASPCategory]:
    """Get OWASP categories for a scanner module"""
    mapping = MODULE_METHODOLOGY_MAP.get(module_name, {})
    category_ids = mapping.get("owasp_categories", [])
    return [OWASP_TOP_10_2021[cid] for cid in category_ids if cid in OWASP_TOP_10_2021]


def get_phase_for_module(module_name: str) -> Optional[AttackPhase]:
    """Get attack phase for a scanner module"""
    mapping = MODULE_METHODOLOGY_MAP.get(module_name, {})
    phase_id = mapping.get("phase")
    if phase_id:
        return next((p for p in ATTACK_PHASES if p.id == phase_id), None)
    return None


def get_test_cases_for_owasp(category_id: str) -> List[str]:
    """Get test cases for an OWASP category"""
    category = OWASP_TOP_10_2021.get(category_id)
    return category.test_cases if category else []


def enrich_finding_with_methodology(finding: dict) -> dict:
    """Enrich a finding with MITRE ATT&CK and OWASP mappings"""
    enriched = finding.copy()

    # Map CWE to MITRE techniques
    cwe = finding.get("cwe", "")
    if cwe:
        for tid, technique in MITRE_TECHNIQUES.items():
            if cwe in technique.cwe_mapping:
                enriched.setdefault("mitre_techniques", []).append({
                    "id": technique.id,
                    "name": technique.name,
                    "tactic": technique.tactic.name
                })

        # Map CWE to OWASP
        for oid, category in OWASP_TOP_10_2021.items():
            if cwe in category.cwe_mapping:
                enriched.setdefault("owasp_categories", []).append({
                    "id": category.id,
                    "name": category.name
                })

    return enriched


# =============================================================================
# EXPORT
# =============================================================================

__all__ = [
    'MitreAttackTactic',
    'MitreTechnique',
    'MITRE_TECHNIQUES',
    'OWASPCategory',
    'OWASP_TOP_10_2021',
    'AttackPhase',
    'ATTACK_PHASES',
    'MODULE_METHODOLOGY_MAP',
    'get_techniques_for_module',
    'get_owasp_categories_for_module',
    'get_phase_for_module',
    'get_test_cases_for_owasp',
    'enrich_finding_with_methodology',
]
