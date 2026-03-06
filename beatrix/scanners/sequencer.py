"""
BEATRIX Token Sequencer

Inspired by Burp Suite's Sequencer tool.

Collects a sample of tokens (session IDs, CSRF tokens, any tracked value)
and performs statistical analysis to evaluate randomness quality.

Tests performed:
    ┌──────────────────────┐
    │ FIPS 140-2 Suite     │  Monobit, Poker, Runs, Long Runs
    ├──────────────────────┤
    │ Shannon Entropy      │  Bits of entropy per character
    ├──────────────────────┤
    │ Chi-Squared (χ²)     │  Uniform character distribution test
    ├──────────────────────┤
    │ Serial Correlation   │  Adjacent character correlation
    ├──────────────────────┤
    │ Character Frequency  │  Distribution analysis per position
    ├──────────────────────┤
    │ Overall Rating       │  EXCELLENT / GOOD / POOR / FAILED
    └──────────────────────┘

A token with low entropy or high serial correlation may be predictable,
allowing session hijacking or CSRF bypass.

Reference: https://portswigger.net/burp/documentation/desktop/tools/sequencer
CWE:       CWE-330 (Use of Insufficiently Random Values)
"""

import asyncio
import hashlib
import logging
import math
import re
import string
import time
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum, auto
from http.cookiejar import CookieJar
from typing import Any, AsyncIterator, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from beatrix.core.types import Confidence, Finding, Severity
from .base import BaseScanner, ScanContext

logger = logging.getLogger("beatrix.scanners.sequencer")


# =============================================================================
# ANALYSIS DATA MODELS
# =============================================================================

class RandomnessRating(Enum):
    EXCELLENT = auto()  # >= 7.5 bits/char, passes all tests
    GOOD = auto()       # >= 6.0 bits/char, passes most tests
    REASONABLE = auto() # >= 4.5 bits/char, some concerns
    POOR = auto()       # >= 3.0 bits/char, predictability risk
    FAILED = auto()     # < 3.0 bits/char, trivially predictable


@dataclass
class TokenAnalysis:
    """Complete statistical analysis of a set of tokens."""
    token_name: str
    source: str                # "cookie", "header", "body"
    sample_size: int
    token_length_mean: float
    token_length_std: float
    charset_size: int
    charset: str
    shannon_entropy: float     # bits per character
    max_entropy: float         # theoretical max for this charset
    entropy_ratio: float       # shannon / max (0.0 - 1.0)
    chi_squared: float
    chi_squared_p_value: float
    serial_correlation: float
    char_frequency: Dict[str, float] = field(default_factory=dict)
    position_entropy: List[float] = field(default_factory=list)
    monobit_pass: bool = True
    poker_pass: bool = True
    runs_pass: bool = True
    long_run_pass: bool = True
    rating: RandomnessRating = RandomnessRating.GOOD
    notes: List[str] = field(default_factory=list)


# =============================================================================
# STATISTICAL FUNCTIONS
# =============================================================================

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
        if count > 0
    )


def chi_squared_test(data: str, expected_charset: str) -> Tuple[float, float]:
    """
    Chi-squared test for uniform character distribution.
    Returns (chi2_statistic, p_value_approximation).
    """
    if not data or not expected_charset:
        return 0.0, 1.0

    freq = Counter(data)
    n = len(data)
    k = len(expected_charset)
    expected = n / k

    chi2 = sum(
        ((freq.get(c, 0) - expected) ** 2) / expected
        for c in expected_charset
    )

    # Approximate p-value using Wilson-Hilferty transformation
    df = k - 1
    if df <= 0:
        return chi2, 1.0

    z = ((chi2 / df) ** (1 / 3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))

    # Standard normal CDF approximation
    p_value = 0.5 * (1 + math.erf(-z / math.sqrt(2)))

    return chi2, max(0.0, min(1.0, p_value))


def serial_correlation(data: str) -> float:
    """
    Calculate serial correlation coefficient between adjacent characters.
    Returns value between -1 and 1. Values close to 0 indicate good randomness.
    """
    if len(data) < 3:
        return 0.0

    values = [ord(c) for c in data]
    n = len(values)
    mean = sum(values) / n

    numerator = sum(
        (values[i] - mean) * (values[i + 1] - mean)
        for i in range(n - 1)
    )
    denominator = sum((v - mean) ** 2 for v in values)

    if denominator == 0:
        return 1.0  # All same character — perfectly correlated

    return numerator / denominator


def monobit_test(bits: str) -> bool:
    """FIPS 140-2 Monobit test: count of 1s should be ~50%."""
    if len(bits) < 20:
        return True  # Not enough data
    ones = bits.count("1")
    n = len(bits)
    # For FIPS 140-2: 9725 < ones < 10275 for 20000 bits
    # For our purposes, use proportional bounds (40%-60%)
    ratio = ones / n
    return 0.4 < ratio < 0.6


def poker_test(bits: str, m: int = 4) -> bool:
    """FIPS 140-2 Poker test: divide into m-bit groups, check uniformity."""
    if len(bits) < 20:
        return True
    n_groups = len(bits) // m
    groups = [bits[i * m:(i + 1) * m] for i in range(n_groups)]
    freq = Counter(groups)
    k = 2 ** m
    chi2 = (k / n_groups) * sum(f ** 2 for f in freq.values()) - n_groups
    # Chi-squared critical value for df=15 at p=0.01 is ~30.578
    return chi2 < 30.578


def runs_test(bits: str) -> bool:
    """FIPS 140-2 Runs test: runs of consecutive 0s/1s should be balanced."""
    if len(bits) < 20:
        return True
    runs = 1
    for i in range(1, len(bits)):
        if bits[i] != bits[i - 1]:
            runs += 1
    n = len(bits)
    ones = bits.count("1")
    zeros = n - ones
    if ones == 0 or zeros == 0:
        return False
    expected = (2 * ones * zeros) / n + 1
    variance = (2 * ones * zeros * (2 * ones * zeros - n)) / (n * n * (n - 1))
    if variance <= 0:
        return False
    z = (runs - expected) / math.sqrt(variance)
    return abs(z) < 2.576  # 99% confidence interval


def longest_run(bits: str) -> int:
    """Find the longest run of consecutive identical bits."""
    if not bits:
        return 0
    max_run = 1
    current_run = 1
    for i in range(1, len(bits)):
        if bits[i] == bits[i - 1]:
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            current_run = 1
    return max_run


def to_bits(data: str) -> str:
    """Convert a string to its binary representation."""
    return "".join(format(ord(c), "08b") for c in data)


# =============================================================================
# SCANNER
# =============================================================================

class SequencerScanner(BaseScanner):
    """
    Token randomness analyzer.

    Collects a sample of tokens from cookies, headers, and form fields,
    then performs statistical analysis to determine if they are
    sufficiently random to resist prediction attacks.
    """

    name = "sequencer"
    description = "Token randomness analysis (Sequencer)"
    version = "1.0.0"
    checks = ["token_randomness", "session_predictability"]
    owasp_category = "A02:2021"  # Cryptographic Failures
    mitre_technique = "T1539"     # Steal Web Session Cookie

    # Token name patterns that indicate security-critical tokens
    CRITICAL_TOKEN_PATTERNS = [
        r"sess", r"session", r"sid", r"token", r"csrf", r"xsrf",
        r"auth", r"jwt", r"api.?key", r"nonce", r"otp", r"reset",
        r"confirm", r"verify", r"invite",
    ]

    # Cookie names that are NOT tokens (ignore these)
    NON_TOKEN_NAMES = {
        "theme", "lang", "locale", "timezone", "tz", "currency",
        "consent", "gdpr", "cookie_consent", "accepted",
        "utm_source", "utm_medium", "utm_campaign", "utm_content",
        "_ga", "_gid", "_gat", "_fbp", "_fbc",
        "__cf_bm", "_cfuvid", "cf_clearance",
    }

    def __init__(self, config=None):
        super().__init__(config)
        self.sample_size = self.config.get("sequencer_samples", 50)
        self.min_token_length = self.config.get("min_token_length", 8)

    def _is_token_name(self, name: str) -> bool:
        """Check if a cookie/header name likely represents a security token."""
        name_lower = name.lower()
        if name_lower in self.NON_TOKEN_NAMES:
            return False
        for pattern in self.CRITICAL_TOKEN_PATTERNS:
            if re.search(pattern, name_lower):
                return True
        return False

    def _detect_charset(self, tokens: List[str]) -> str:
        """Determine the character set used by a collection of tokens."""
        all_chars = set("".join(tokens))
        if all_chars <= set(string.hexdigits):
            return string.hexdigits[:16]  # lowercase hex
        if all_chars <= set(string.ascii_lowercase + string.digits):
            return string.ascii_lowercase + string.digits
        if all_chars <= set(string.ascii_letters + string.digits):
            return string.ascii_letters + string.digits
        # Base64-like
        if all_chars <= set(string.ascii_letters + string.digits + "+/=_-"):
            return string.ascii_letters + string.digits + "+/=_-"
        return "".join(sorted(all_chars))

    def _analyze_tokens(
        self, tokens: List[str], token_name: str, source: str
    ) -> TokenAnalysis:
        """Perform full statistical analysis on a collection of tokens."""
        if not tokens:
            return TokenAnalysis(
                token_name=token_name, source=source, sample_size=0,
                token_length_mean=0, token_length_std=0, charset_size=0,
                charset="", shannon_entropy=0, max_entropy=0,
                entropy_ratio=0, chi_squared=0, chi_squared_p_value=1,
                serial_correlation=0, rating=RandomnessRating.FAILED,
            )

        # Length statistics
        lengths = [len(t) for t in tokens]
        mean_len = sum(lengths) / len(lengths)
        std_len = (
            math.sqrt(sum((l - mean_len) ** 2 for l in lengths) / len(lengths))
            if len(lengths) > 1
            else 0
        )

        # Concatenate all tokens for analysis
        combined = "".join(tokens)
        charset = self._detect_charset(tokens)
        charset_size = len(set(charset))

        # Shannon entropy
        ent = shannon_entropy(combined)
        max_ent = math.log2(charset_size) if charset_size > 1 else 0
        ent_ratio = ent / max_ent if max_ent > 0 else 0

        # Chi-squared
        chi2, chi2_p = chi_squared_test(combined, charset)

        # Serial correlation
        sc = serial_correlation(combined)

        # Character frequency
        freq = Counter(combined)
        total = len(combined)
        char_freq = {c: count / total for c, count in freq.most_common(20)}

        # Per-position entropy
        pos_entropy = []
        max_pos = min(int(mean_len), 64)
        for pos in range(max_pos):
            pos_chars = "".join(t[pos] for t in tokens if len(t) > pos)
            if pos_chars:
                pos_entropy.append(shannon_entropy(pos_chars))

        # FIPS-style tests on binary representation
        bits = to_bits(combined)
        mb_pass = monobit_test(bits)
        pk_pass = poker_test(bits)
        rn_pass = runs_test(bits)
        lr = longest_run(bits)
        lr_pass = lr < 34  # FIPS 140-2: no run > 33

        # Build notes
        notes = []
        if std_len > 2:
            notes.append(f"Variable token length (σ={std_len:.1f}) — often indicates weak generation")
        if ent_ratio < 0.7:
            notes.append(f"Low entropy ratio ({ent_ratio:.2f}) — using only {ent_ratio*100:.0f}% of available character space")
        if abs(sc) > 0.1:
            notes.append(f"Serial correlation {sc:.3f} — adjacent characters are correlated")
        if chi2_p < 0.01:
            notes.append(f"Chi-squared test FAILED (p={chi2_p:.4f}) — non-uniform character distribution")
        if not mb_pass:
            notes.append("Monobit test FAILED — bit distribution not 50/50")
        if not pk_pass:
            notes.append("Poker test FAILED — bit groups not uniformly distributed")
        if not rn_pass:
            notes.append("Runs test FAILED — suspicious patterns in bit sequences")
        if not lr_pass:
            notes.append(f"Long run detected ({lr} consecutive bits) — possible pattern")

        # Weak positions (low entropy per position)
        weak_positions = [
            i for i, e in enumerate(pos_entropy)
            if e < 2.0 and i < max_pos
        ]
        if weak_positions:
            notes.append(
                f"Low entropy at positions {weak_positions[:5]} — "
                f"possible timestamp or counter component"
            )

        # Determine overall rating
        rating = self._rate_randomness(
            ent, ent_ratio, sc, chi2_p, mb_pass, pk_pass, rn_pass, lr_pass
        )

        return TokenAnalysis(
            token_name=token_name,
            source=source,
            sample_size=len(tokens),
            token_length_mean=mean_len,
            token_length_std=std_len,
            charset_size=charset_size,
            charset=charset[:30] + ("..." if len(charset) > 30 else ""),
            shannon_entropy=ent,
            max_entropy=max_ent,
            entropy_ratio=ent_ratio,
            chi_squared=chi2,
            chi_squared_p_value=chi2_p,
            serial_correlation=sc,
            char_frequency=char_freq,
            position_entropy=pos_entropy,
            monobit_pass=mb_pass,
            poker_pass=pk_pass,
            runs_pass=rn_pass,
            long_run_pass=lr_pass,
            rating=rating,
            notes=notes,
        )

    @staticmethod
    def _rate_randomness(
        entropy: float,
        entropy_ratio: float,
        serial_corr: float,
        chi2_p: float,
        monobit: bool,
        poker: bool,
        runs: bool,
        long_run: bool,
    ) -> RandomnessRating:
        """Assign an overall randomness rating based on all test results."""
        fips_failures = sum(1 for t in [monobit, poker, runs, long_run] if not t)

        if entropy_ratio >= 0.9 and abs(serial_corr) < 0.05 and fips_failures == 0 and chi2_p >= 0.01:
            return RandomnessRating.EXCELLENT
        if entropy_ratio >= 0.75 and abs(serial_corr) < 0.1 and fips_failures <= 1:
            return RandomnessRating.GOOD
        if entropy_ratio >= 0.6 and abs(serial_corr) < 0.2 and fips_failures <= 2:
            return RandomnessRating.REASONABLE
        if entropy_ratio >= 0.4:
            return RandomnessRating.POOR
        return RandomnessRating.FAILED

    # ─────────────────────────────────────────────────────────────────────
    # TOKEN COLLECTION
    # ─────────────────────────────────────────────────────────────────────

    async def _collect_tokens(
        self, url: str, context: ScanContext
    ) -> Dict[str, Dict[str, List[str]]]:
        """
        Collect token samples by making repeated requests.
        Returns: {token_name: {"source": source_type, "values": [...]}}
        """
        tokens: Dict[str, Dict[str, List[str]]] = {}

        for i in range(self.sample_size):
            try:
                resp = await self.get(url)
            except Exception:
                continue

            # Extract cookies
            for cookie_header in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]:
                if not cookie_header:
                    continue
                parts = cookie_header.split(";")[0]
                if "=" not in parts:
                    continue
                name, value = parts.split("=", 1)
                name = name.strip()
                value = value.strip()
                if len(value) < self.min_token_length:
                    continue
                if name.lower() in self.NON_TOKEN_NAMES:
                    continue
                if name not in tokens:
                    tokens[name] = {"source": "cookie", "values": []}
                tokens[name]["values"].append(value)

            # Extract security headers (CSRF tokens, etc.)
            for header_name in ["x-csrf-token", "x-xsrf-token", "x-request-id"]:
                value = resp.headers.get(header_name, "")
                if value and len(value) >= self.min_token_length:
                    if header_name not in tokens:
                        tokens[header_name] = {"source": "header", "values": []}
                    tokens[header_name]["values"].append(value)

            # Rate limit: slight delay between requests
            if i % 10 == 9:
                await asyncio.sleep(0.2)

        return tokens

    # ─────────────────────────────────────────────────────────────────────
    # MAIN SCAN ENTRY POINT
    # ─────────────────────────────────────────────────────────────────────

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Collect tokens and analyze their randomness.
        """
        url = context.url
        logger.info(f"Sequencer: collecting {self.sample_size} samples from {url}")

        # Collect tokens
        token_data = await self._collect_tokens(url, context)

        if not token_data:
            logger.info("Sequencer: no tokens found to analyze")
            return

        # Analyze each token
        for token_name, data in token_data.items():
            values = data["values"]
            source = data["source"]

            if len(values) < 10:
                logger.info(
                    f"Sequencer: insufficient samples for {token_name} "
                    f"({len(values)}/{self.sample_size})"
                )
                continue

            # Check if all values are the same (static token — not random)
            unique_values = set(values)
            if len(unique_values) == 1:
                # Static token — only report if it's a security-critical name
                if self._is_token_name(token_name):
                    yield self.create_finding(
                        title=f"Static Token: {token_name}",
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        url=url,
                        description=(
                            f"The {source} `{token_name}` returns the same value "
                            f"across all {len(values)} requests. A static token "
                            f"provides no protection against replay or prediction "
                            f"attacks.\n\n"
                            f"**Token value:** `{values[0][:40]}...`\n"
                            f"**Source:** {source}"
                        ),
                        evidence=f"All {len(values)} samples identical: {values[0][:60]}",
                        cwe_id="CWE-330",
                        impact=(
                            "A static token can be trivially predicted by any "
                            "attacker who observes a single request. If this "
                            "is a session ID or CSRF token, it provides zero "
                            "protection against session hijacking or CSRF attacks."
                        ),
                        remediation=(
                            "Generate a fresh, cryptographically random token "
                            "for each session or request. Use a CSPRNG "
                            "(e.g., secrets.token_hex() in Python, "
                            "crypto.randomBytes() in Node.js)."
                        ),
                        references=[
                            "https://cwe.mitre.org/data/definitions/330.html",
                            "https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length",
                        ],
                    )
                continue

            # Full statistical analysis
            analysis = self._analyze_tokens(values, token_name, source)

            # Only report findings for tokens that show weakness
            if analysis.rating in (RandomnessRating.EXCELLENT, RandomnessRating.GOOD):
                logger.info(
                    f"Sequencer: {token_name} rated {analysis.rating.name} "
                    f"(entropy={analysis.shannon_entropy:.2f})"
                )
                continue

            # Map rating to severity
            severity_map = {
                RandomnessRating.REASONABLE: Severity.LOW,
                RandomnessRating.POOR: Severity.MEDIUM,
                RandomnessRating.FAILED: Severity.HIGH,
            }
            severity = severity_map.get(analysis.rating, Severity.INFO)

            # Only elevate if this is a security-critical token name
            is_critical = self._is_token_name(token_name)
            if not is_critical and severity == Severity.LOW:
                continue  # Don't report LOW for non-critical tokens

            # Build analysis summary
            fips_results = []
            for test_name, passed in [
                ("Monobit", analysis.monobit_pass),
                ("Poker", analysis.poker_pass),
                ("Runs", analysis.runs_pass),
                ("Long Run", analysis.long_run_pass),
            ]:
                fips_results.append(f"  - {test_name}: {'PASS' if passed else '**FAIL**'}")

            analysis_text = (
                f"**Token:** `{token_name}` ({source})\n"
                f"**Samples:** {analysis.sample_size}\n"
                f"**Token Length:** {analysis.token_length_mean:.0f} chars "
                f"(σ={analysis.token_length_std:.1f})\n"
                f"**Character Set:** {analysis.charset} ({analysis.charset_size} chars)\n\n"
                f"### Entropy\n"
                f"- Shannon entropy: **{analysis.shannon_entropy:.2f}** bits/char\n"
                f"- Maximum possible: {analysis.max_entropy:.2f} bits/char\n"
                f"- Entropy ratio: **{analysis.entropy_ratio:.1%}**\n\n"
                f"### Statistical Tests\n"
                f"- Chi-squared: χ²={analysis.chi_squared:.1f} (p={analysis.chi_squared_p_value:.4f})\n"
                f"- Serial correlation: **{analysis.serial_correlation:.4f}**\n"
                + "\n".join(fips_results) + "\n\n"
                f"### Rating: **{analysis.rating.name}**\n\n"
            )

            if analysis.notes:
                analysis_text += "### Issues Found\n"
                for note in analysis.notes:
                    analysis_text += f"- {note}\n"

            yield self.create_finding(
                title=f"Weak Token Randomness: {token_name} ({analysis.rating.name})",
                severity=severity,
                confidence=Confidence.FIRM if analysis.sample_size >= 30 else Confidence.TENTATIVE,
                url=url,
                description=(
                    f"Statistical analysis of {analysis.sample_size} samples of "
                    f"the `{token_name}` {source} reveals insufficient randomness.\n\n"
                    + analysis_text
                ),
                evidence=(
                    f"Shannon entropy: {analysis.shannon_entropy:.2f}/{analysis.max_entropy:.2f} "
                    f"({analysis.entropy_ratio:.1%}), "
                    f"serial correlation: {analysis.serial_correlation:.4f}, "
                    f"FIPS failures: "
                    + str(sum(1 for x in [analysis.monobit_pass, analysis.poker_pass,
                                          analysis.runs_pass, analysis.long_run_pass] if not x))
                ),
                cwe_id="CWE-330",
                impact=(
                    f"The {source} '{token_name}' has {analysis.rating.name.lower()} "
                    f"randomness quality. "
                    + (
                        "An attacker may be able to predict future token values "
                        "based on observed patterns, enabling session hijacking "
                        "or CSRF bypass."
                        if is_critical else
                        "While this token may not be directly security-critical, "
                        "weak randomness could indicate systemic issues in the "
                        "application's random number generation."
                    )
                ),
                remediation=(
                    "Use a cryptographically secure pseudorandom number generator "
                    "(CSPRNG) for all security-sensitive tokens:\n\n"
                    "- **Python:** `secrets.token_hex(32)` or `secrets.token_urlsafe(32)`\n"
                    "- **Node.js:** `crypto.randomBytes(32).toString('hex')`\n"
                    "- **Java:** `SecureRandom.getInstanceStrong()`\n"
                    "- **Go:** `crypto/rand.Read()`\n\n"
                    "Ensure tokens are at least 128 bits (16 bytes) long."
                ),
                references=[
                    "https://portswigger.net/burp/documentation/desktop/tools/sequencer",
                    "https://cwe.mitre.org/data/definitions/330.html",
                    "https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                ],
            )
