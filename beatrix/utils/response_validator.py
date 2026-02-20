"""
Response Validation Utility
Centralized validation for CDN soft-404 detection and response validation.
Created for remediation of false positive issues.
"""

import hashlib
import re
from typing import Dict, Optional, Set, Tuple
from urllib.parse import urlparse


class ResponseValidator:
    """
    Centralized response validation to detect CDN soft-404s and validate responses.

    CDN soft-404 problem: Many CDNs (Cloudflare, Akamai, etc.) return HTTP 200
    with HTML content for non-existent paths instead of 404. This causes
    vulnerability scanners to report false positives.
    """

    # Generic soft-404 indicators in page content
    SOFT_404_INDICATORS = [
        'page not found', 'not found', '404', 'error page',
        "we couldn't find", "doesn't exist", 'does not exist',
        'page you requested', 'no longer available',
        'moved or deleted', 'check the url', 'go back',
        'return to homepage', 'page is missing',
    ]

    # CDN-specific patterns (marketing/landing pages served for any path)
    CDN_LANDING_PATTERNS = [
        r'<nav[^>]*>.*?(home|about|contact|products|services).*?</nav>',
        r'<header[^>]*class=["\'][^"\']*hero[^"\']*["\']',
        r'<div[^>]*class=["\'][^"\']*landing[^"\']*["\']',
        r'<footer[^>]*>.*?©.*?</footer>',
        r'meta\s+name=["\']description["\']',
    ]

    # CDN header signatures
    CDN_HEADERS = {
        'cloudflare': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
        'akamai': ['x-akamai-transformed', 'akamai-origin-hop', 'x-akamai-request-id'],
        'cloudfront': ['x-amz-cf-id', 'x-amz-cf-pop', 'x-cache'],
        'fastly': ['x-served-by', 'x-cache', 'x-cache-hits', 'fastly-io-info'],
        'incapsula': ['x-iinfo', 'x-cdn'],
        'sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
        'varnish': ['x-varnish', 'via'],
    }

    def __init__(self):
        self.fingerprints: Dict[str, str] = {}  # hash -> first URL
        self.soft_404_hashes: Set[str] = set()
        self.baseline_response: Optional[dict] = None

    def reset(self):
        """Reset state for new target"""
        self.fingerprints.clear()
        self.soft_404_hashes.clear()
        self.baseline_response = None

    def fingerprint(self, body: str) -> str:
        """Generate fingerprint for response body"""
        # Normalize whitespace and extract key content
        normalized = ' '.join(body.split())
        return hashlib.md5(normalized.encode()).hexdigest()[:16]

    def detect_cdn(self, headers: dict) -> Optional[str]:
        """Detect which CDN is serving the response"""
        header_keys = [k.lower() for k in headers.keys()]

        for cdn, cdn_headers in self.CDN_HEADERS.items():
            if any(h.lower() in header_keys for h in cdn_headers):
                return cdn
        return None

    def is_html_response(self, body: str, headers: Optional[dict] = None) -> bool:
        """Check if response is HTML content"""
        if headers:
            content_type = headers.get('Content-Type', '').lower()
            if 'text/html' in content_type:
                return True

        body_lower = body.lower().strip()
        return (
            body_lower.startswith('<!doctype') or
            body_lower.startswith('<html') or
            '<head>' in body_lower or
            '</html>' in body_lower
        )

    def is_json_response(self, body: str, headers: Optional[dict] = None) -> bool:
        """Check if response is JSON content"""
        if headers:
            content_type = headers.get('Content-Type', '').lower()
            if 'application/json' in content_type:
                return True

        body_stripped = body.strip()
        return body_stripped.startswith(('{', '[')) and body_stripped.endswith(('}', ']'))

    def is_soft_404(self, body: str, headers: Optional[dict] = None) -> bool:
        """
        Detect if response is a soft-404 (200 OK but actually an error page).

        Returns True if the response appears to be a soft-404.
        """
        body_lower = body.lower()

        # Check for soft-404 text indicators
        if any(indicator in body_lower for indicator in self.SOFT_404_INDICATORS):
            return True

        # Check for generic CDN landing page patterns
        for pattern in self.CDN_LANDING_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                # Landing page served for API/file endpoints = soft-404
                return True

        return False

    def is_cdn_soft_404(self, body: str, headers: Optional[dict] = None, url: Optional[str] = None) -> bool:
        """
        Comprehensive CDN soft-404 detection.

        Combines multiple heuristics:
        1. CDN detection via headers
        2. HTML content for non-HTML expected endpoints
        3. Soft-404 text patterns
        4. Response fingerprinting (same response for different URLs)
        """
        # If we've seen this exact response for a different URL, it's a soft-404
        fp = self.fingerprint(body)
        if fp in self.soft_404_hashes:
            return True

        # Check if this fingerprint was seen for a different path
        if url and fp in self.fingerprints:
            first_url = self.fingerprints[fp]
            if self._urls_are_different_paths(url, first_url):
                self.soft_404_hashes.add(fp)
                return True

        if url:
            self.fingerprints[fp] = url

        # Check for soft-404 content patterns
        if self.is_soft_404(body, headers):
            return True

        # For API endpoints, HTML response = soft-404
        if url and self._is_api_endpoint(url):
            if self.is_html_response(body, headers):
                return True

        return False

    def _urls_are_different_paths(self, url1: str, url2: str) -> bool:
        """Check if two URLs have different paths (same host, different path)"""
        try:
            parsed1 = urlparse(url1)
            parsed2 = urlparse(url2)
            return parsed1.netloc == parsed2.netloc and parsed1.path != parsed2.path
        except Exception:
            return False

    def _is_api_endpoint(self, url: str) -> bool:
        """Check if URL appears to be an API endpoint"""
        api_patterns = ['/api/', '/v1/', '/v2/', '/graphql', '/rest/', '/json/']
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in api_patterns)

    def validate_api_response(self, body: str, headers: dict, url: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validate an API response is legitimate, not a CDN soft-404.

        Returns (is_valid, reason)
        """
        # Check content type
        content_type = headers.get('Content-Type', '').lower() if headers else ''

        # API should return JSON, not HTML
        if 'text/html' in content_type:
            return False, "API returned HTML content type"

        # Check if body is HTML (even without correct content-type)
        if self.is_html_response(body, headers):
            return False, "API response contains HTML content"

        # Check if JSON structure
        if not self.is_json_response(body, headers):
            return False, "API response is not valid JSON"

        # Check for soft-404 patterns in JSON
        body_lower = body.lower()
        if any(ind in body_lower for ind in ['not found', 'error', '404']):
            # Could be a JSON error response - check structure
            try:
                import json
                data = json.loads(body)
                if isinstance(data, dict):
                    error_keys = ['error', 'message', 'status', 'code']
                    if any(k in data for k in error_keys):
                        return False, "API returned error response"
            except Exception:
                pass

        return True, "Valid API response"

    def validate_admin_page(self, body: str, headers: dict, url: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validate that a page is actually an admin/dashboard page, not a generic page
        with common words that happen to include 'admin', 'dashboard', etc.

        Returns (is_valid_admin, reason)
        """
        content_type = headers.get('Content-Type', '').lower() if headers else ''

        # If JSON, check for admin-specific data structures
        if 'application/json' in content_type or self.is_json_response(body, headers):
            return self._validate_admin_json(body)

        # For HTML, require strong admin indicators
        return self._validate_admin_html(body)

    def _validate_admin_json(self, body: str) -> Tuple[bool, str]:
        """Validate JSON response contains admin-specific data"""
        try:
            import json
            data = json.loads(body)

            if isinstance(data, dict):
                # Strong admin indicators in JSON
                admin_keys = [
                    'users', 'permissions', 'roles', 'admin_settings',
                    'system_config', 'audit_log', 'server_status',
                    'database', 'api_keys', 'access_tokens'
                ]
                if any(k in data for k in admin_keys):
                    return True, "JSON contains admin data structures"

            return False, "JSON does not contain admin-specific data"
        except Exception:
            return False, "Invalid JSON response"

    def _validate_admin_html(self, body: str) -> Tuple[bool, str]:
        """Validate HTML page is actually an admin interface"""
        body_lower = body.lower()

        # Strong admin indicators - actual admin functionality, not just words
        strong_indicators = [
            # Admin forms and actions
            r'<form[^>]*action=["\'][^"\']*admin',
            r'<form[^>]*action=["\'][^"\']*delete',
            r'<form[^>]*action=["\'][^"\']*update',
            r'<input[^>]*name=["\']_?csrf',

            # Admin-specific UI elements
            r'admin[-_]?panel', r'admin[-_]?dashboard',
            r'user[-_]?management', r'system[-_]?configuration',
            r'database[-_]?backup', r'server[-_]?status',
            r'audit[-_]?log', r'access[-_]?control',

            # Admin-only actions visible
            r'delete\s+user', r'ban\s+user', r'edit\s+role',
            r'system\s+settings', r'site\s+configuration',
        ]

        for pattern in strong_indicators:
            if re.search(pattern, body_lower, re.IGNORECASE):
                return True, f"Found admin indicator: {pattern}"

        # Weak indicators that appear on many pages (NOT sufficient alone)
        weak_indicators = ['dashboard', 'admin', 'manage', 'settings', 'users', 'configuration']
        weak_matches = sum(1 for w in weak_indicators if w in body_lower)

        # Require multiple weak indicators AND absence of typical marketing content
        marketing_indicators = [
            'sign up', 'subscribe', 'newsletter', 'contact us',
            'our products', 'our services', 'testimonials', 'pricing'
        ]
        has_marketing = any(m in body_lower for m in marketing_indicators)

        if weak_matches >= 3 and not has_marketing:
            return True, "Multiple admin-related terms without marketing content"

        return False, "Page appears to be generic content, not actual admin interface"

    def set_baseline(self, body: str, status: int, headers: dict):
        """Set baseline response for comparison"""
        self.baseline_response = {
            'body_hash': self.fingerprint(body),
            'status': status,
            'length': len(body),
            'content_type': headers.get('Content-Type', '') if headers else ''
        }

    def matches_baseline(self, body: str, status: int, headers: Optional[dict] = None) -> bool:
        """Check if response matches baseline (likely soft-404)"""
        if not self.baseline_response:
            return False

        current_hash = self.fingerprint(body)

        # Same content hash = definitely matches
        if current_hash == self.baseline_response['body_hash']:
            return True

        # Similar length and same status could also indicate soft-404
        length_diff = abs(len(body) - self.baseline_response['length'])
        if status == self.baseline_response['status'] and length_diff < 100:
            return True

        return False


class ContentTypeValidator:
    """Validate content matches expected file/data types"""

    # Expected content patterns for sensitive files
    FILE_PATTERNS = {
        '.git/config': [r'\[core\]', r'\[remote', r'repositoryformatversion'],
        '.git/HEAD': [r'^ref: refs/', r'^[a-f0-9]{40}$'],
        '.env': [r'^[A-Z_]+=', r'DB_', r'API_KEY', r'SECRET'],
        'wp-config.php': [r"define\s*\(\s*['\"]DB_", r'WP_DEBUG'],
        '.htaccess': [r'RewriteEngine', r'RewriteRule', r'Deny from'],
        'web.config': [r'<configuration>', r'<system.webServer>'],
        'package.json': [r'"name":', r'"version":', r'"dependencies"'],
        'composer.json': [r'"require":', r'"autoload":'],
    }

    @classmethod
    def validate_file_content(cls, filename: str, content: str) -> Tuple[bool, str]:
        """
        Validate that file content matches expected format.

        Returns (is_valid, reason)
        """
        # Check if it's HTML (wrong for config files)
        if content.strip().lower().startswith(('<!doctype', '<html')):
            return False, "Content is HTML, not expected file format"

        # Check against known patterns
        for file_pattern, content_patterns in cls.FILE_PATTERNS.items():
            if file_pattern in filename.lower():
                for pattern in content_patterns:
                    if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                        return True, f"Content matches {file_pattern} format"
                return False, f"Content does not match expected {file_pattern} format"

        return True, "No specific validation rules for this file type"


# Global instance for convenience
response_validator = ResponseValidator()
content_validator = ContentTypeValidator()
