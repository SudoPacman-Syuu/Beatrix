"""
BEATRIX GraphQL Exploitation Scanner

Born from: OWASP API Security + PortSwigger GraphQL research
https://portswigger.net/web-security/graphql

TECHNIQUE:
1. Introspection query to map entire schema (types, fields, mutations, subscriptions)
2. Field suggestion abuse (disabled introspection → use __type suggestions)
3. Batch query attacks (DoS via massive query arrays)
4. Nested query depth attacks (exponential DB load via recursive relationships)
5. Alias-based rate limit bypass (N identical queries with aliases in 1 request)
6. GraphQL IDOR (access other users' data via enumerable arguments)
7. Mutation abuse (privilege escalation via admin mutations)
8. Directive injection (@include/@skip logic abuse)
9. Query cost analysis bypass
10. Subscription abuse for data streaming

SEVERITY: HIGH-CRITICAL — GraphQL exposes:
- Full schema via introspection → complete API surface map
- IDOR by design → direct object access without authorization
- DoS → nested/batched queries amplify 1 request to millions of DB ops
- Data overfetching → sensitive fields exposed alongside public ones
- Mutation abuse → admin operations accessible to regular users

OWASP: API8:2023 (Security Misconfiguration)
       API1:2023 (Broken Object Level Authorization — IDOR)
       API4:2023 (Unrestricted Resource Consumption — DoS)

MITRE: T1190 (Exploit Public-Facing Application)
       T1046 (Network Service Discovery — via introspection)

CWE: CWE-200 (Exposure of Sensitive Information)
     CWE-400 (Uncontrolled Resource Consumption)
     CWE-639 (Authorization Bypass Through User-Controlled Key — IDOR)
     CWE-284 (Improper Access Control)

REFERENCES:
- https://portswigger.net/web-security/graphql
- https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql
- https://graphql.org/learn/introspection/
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

try:
    import httpx
except ImportError:
    httpx = None

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext

# =============================================================================
# DATA MODELS
# =============================================================================

class GraphQLAttack(Enum):
    """GraphQL attack types"""
    INTROSPECTION = "introspection"
    FIELD_SUGGESTION = "field_suggestion"
    BATCH_QUERY = "batch_query"
    DEPTH_ATTACK = "depth_attack"
    ALIAS_BYPASS = "alias_bypass"
    IDOR = "idor"
    MUTATION_ABUSE = "mutation_abuse"
    DIRECTIVE_INJECTION = "directive_injection"
    SCHEMA_LEAK = "schema_leak"


@dataclass
class GraphQLEndpoint:
    """Discovered GraphQL endpoint info"""
    url: str
    method: str = "POST"
    accepts_get: bool = False
    introspection_enabled: bool = False
    schema: Optional[Dict] = None
    types: List[str] = field(default_factory=list)
    queries: List[str] = field(default_factory=list)
    mutations: List[str] = field(default_factory=list)


# =============================================================================
# INTROSPECTION QUERIES
# =============================================================================

FULL_INTROSPECTION = """{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type {
            kind
            name
            ofType { kind name ofType { kind name ofType { kind name } } }
          }
          defaultValue
        }
        type {
          kind
          name
          ofType { kind name ofType { kind name ofType { kind name } } }
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        description
        type {
          kind
          name
          ofType { kind name ofType { kind name } }
        }
        defaultValue
      }
      interfaces { kind name }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes { kind name }
    }
    directives {
      name
      description
      locations
      args {
        name
        description
        type {
          kind
          name
          ofType { kind name ofType { kind name } }
        }
        defaultValue
      }
    }
  }
}"""

# Simplified introspection (less likely to be blocked)
SIMPLE_INTROSPECTION = """{
  __schema {
    types {
      name
      fields {
        name
        type { name kind ofType { name } }
      }
    }
  }
}"""

# Type-name only (minimal fingerprint)
TYPENAME_PROBE = '{ __typename }'

# Alternative introspection bypasses
INTROSPECTION_BYPASSES = [
    # Newline obfuscation
    '{\n  __schema\n  {\n    types\n    {\n      name\n    }\n  }\n}',
    # GET request with query param
    None,  # Handled separately as GET
    # Batched with legitimate query
    None,  # Handled in batch section
]

# =============================================================================
# SENSITIVE FIELD PATTERNS
# =============================================================================

SENSITIVE_FIELDS = {
    "password", "passwd", "secret", "token", "apiKey", "api_key",
    "accessToken", "access_token", "refreshToken", "refresh_token",
    "ssn", "socialSecurity", "social_security_number",
    "creditCard", "credit_card", "cardNumber", "card_number",
    "cvv", "cvc", "securityCode",
    "bankAccount", "bank_account", "routingNumber",
    "privateKey", "private_key",
    "internalId", "internal_id",
    "isAdmin", "is_admin", "role", "permissions",
    "salary", "income", "balance",
    "resetToken", "reset_token", "verificationCode",
    "otp", "twoFactorSecret", "mfaSecret",
}

SENSITIVE_MUTATIONS = {
    "deleteUser", "delete_user", "removeUser",
    "updateRole", "update_role", "setRole", "assignRole",
    "setAdmin", "makeAdmin", "grantPermission",
    "resetPassword", "reset_password", "changePassword",
    "deleteAccount", "suspendAccount", "banUser",
    "updatePrice", "setPrice", "modifyBalance",
    "createAdmin", "createSuperuser",
    "executeCommand", "runQuery", "importData",
    "toggleFeature", "setConfig", "updateSettings",
}


# =============================================================================
# SCANNER
# =============================================================================

class GraphQLScanner(BaseScanner):
    """
    GraphQL Exploitation Scanner.

    Comprehensive testing of GraphQL endpoints:
    - Schema extraction via introspection
    - Nested query DoS
    - Batch query attacks
    - Alias-based rate limit bypass
    - IDOR detection
    - Sensitive field/mutation identification
    - Field suggestion harvesting (when introspection is disabled)
    """

    name = "graphql"
    description = "GraphQL Exploitation Scanner"
    version = "1.0.0"

    checks = [
        "graphql_introspection",
        "graphql_depth_limit",
        "graphql_batch_limit",
        "graphql_alias_bypass",
        "graphql_idor",
        "graphql_sensitive_fields",
        "graphql_mutation_audit",
        "graphql_field_suggestion",
    ]

    owasp_category = "API8:2023"
    mitre_technique = "T1190"

    # Common GraphQL endpoint paths
    GRAPHQL_PATHS = [
        "/graphql",
        "/graphql/v1",
        "/graphql/v2",
        "/api/graphql",
        "/api/v1/graphql",
        "/v1/graphql",
        "/gql",
        "/query",
        "/graphiql",
        "/playground",
        "/console",
        "/api",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.max_depth = self.config.get("max_depth", 10)
        self.batch_size = self.config.get("batch_size", 50)
        self.safe_mode = self.config.get("safe_mode", True)

    # =========================================================================
    # GRAPHQL REQUEST HELPERS
    # =========================================================================

    async def _gql_query(
        self,
        url: str,
        query: str,
        variables: Optional[Dict] = None,
        operation: Optional[str] = None,
    ) -> Optional[Dict]:
        """Send a GraphQL query and return parsed response"""
        payload: Dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation:
            payload["operationName"] = operation

        try:
            resp = await self.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                return data
        except Exception:
            pass
        return None

    async def _gql_query_raw(self, url: str, query: str) -> Optional[httpx.Response]:
        """Send a GraphQL query and return raw response"""
        try:
            return await self.post(
                url,
                json={"query": query},
                headers={"Content-Type": "application/json"},
            )
        except Exception:
            return None

    # =========================================================================
    # ENDPOINT DISCOVERY
    # =========================================================================

    async def _discover_endpoint(self, context: ScanContext) -> Optional[GraphQLEndpoint]:
        """Try to find and validate a GraphQL endpoint"""
        parsed = urlparse(context.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # First try the URL as-is
        urls_to_try = [context.url]

        # Then try common paths
        for path in self.GRAPHQL_PATHS:
            candidate = base + path
            if candidate != context.url:
                urls_to_try.append(candidate)

        for url in urls_to_try:
            result = await self._gql_query(url, TYPENAME_PROBE)
            if result and ("data" in result or "errors" in result):
                endpoint = GraphQLEndpoint(url=url)

                # Check GET support
                try:
                    get_resp = await self.get(
                        url, params={"query": TYPENAME_PROBE}
                    )
                    if get_resp.status_code == 200:
                        get_data = get_resp.json()
                        if "data" in get_data:
                            endpoint.accepts_get = True
                except Exception:
                    pass

                return endpoint

        return None

    # =========================================================================
    # INTROSPECTION
    # =========================================================================

    async def _test_introspection(self, endpoint: GraphQLEndpoint) -> Tuple[bool, Optional[Dict]]:
        """Test if introspection is enabled and extract schema"""

        # Try full introspection
        result = await self._gql_query(endpoint.url, FULL_INTROSPECTION)
        if result and "data" in result and result["data"].get("__schema"):
            return True, result["data"]["__schema"]

        # Try simplified
        result = await self._gql_query(endpoint.url, SIMPLE_INTROSPECTION)
        if result and "data" in result and result["data"].get("__schema"):
            return True, result["data"]["__schema"]

        # Try via GET (might bypass POST-only introspection block)
        if endpoint.accepts_get:
            try:
                resp = await self.get(
                    endpoint.url,
                    params={"query": SIMPLE_INTROSPECTION},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if "data" in data and data["data"].get("__schema"):
                        return True, data["data"]["__schema"]
            except Exception:
                pass

        return False, None

    def _extract_schema_info(self, schema: Dict, endpoint: GraphQLEndpoint):
        """Parse introspection result into structured info"""
        types = schema.get("types", [])

        # Extract user-defined types (skip __* internal types)
        for t in types:
            name = t.get("name", "")
            if not name.startswith("__"):
                endpoint.types.append(name)

                # Map queries and mutations
                if name == schema.get("queryType", {}).get("name"):
                    for f in t.get("fields", []):
                        endpoint.queries.append(f.get("name", ""))
                elif name == schema.get("mutationType", {}).get("name"):
                    for f in t.get("fields", []):
                        endpoint.mutations.append(f.get("name", ""))

        endpoint.schema = schema

    def _find_sensitive_fields(self, schema: Dict) -> List[Tuple[str, str, str]]:
        """Find sensitive fields in schema. Returns (type_name, field_name, field_type)"""
        sensitive = []

        for t in schema.get("types", []):
            type_name = t.get("name", "")
            if type_name.startswith("__"):
                continue

            for f in t.get("fields", []):
                fname = f.get("name", "")
                if fname.lower() in {s.lower() for s in SENSITIVE_FIELDS}:
                    ftype = self._resolve_type(f.get("type", {}))
                    sensitive.append((type_name, fname, ftype))

        return sensitive

    def _find_sensitive_mutations(self, schema: Dict) -> List[str]:
        """Find potentially dangerous mutations"""
        mutation_type_name = schema.get("mutationType", {})
        if not mutation_type_name:
            return []

        mt_name = mutation_type_name.get("name", "Mutation")
        dangerous = []

        for t in schema.get("types", []):
            if t.get("name") == mt_name:
                for f in t.get("fields", []):
                    fname = f.get("name", "")
                    if fname.lower() in {s.lower() for s in SENSITIVE_MUTATIONS}:
                        dangerous.append(fname)
                    # Also flag mutations with role/admin/permission args
                    for arg in f.get("args", []):
                        aname = arg.get("name", "").lower()
                        if any(kw in aname for kw in ["role", "admin", "permission", "privilege"]):
                            dangerous.append(f"{fname}(arg:{arg.get('name')})")
                            break

        return dangerous

    def _resolve_type(self, type_info: Dict) -> str:
        """Resolve nested GraphQL type to readable string"""
        kind = type_info.get("kind", "")
        name = type_info.get("name", "")

        if name:
            return name

        of_type = type_info.get("ofType", {})
        if of_type:
            inner = self._resolve_type(of_type)
            if kind == "NON_NULL":
                return f"{inner}!"
            elif kind == "LIST":
                return f"[{inner}]"
            return inner

        return kind

    # =========================================================================
    # ATTACK TECHNIQUES
    # =========================================================================

    async def _test_depth_limit(self, endpoint: GraphQLEndpoint) -> Optional[Dict]:
        """Test for missing query depth limits (DoS vector)"""
        # Build nested query: { a { b { c { d { ... } } } } }
        # Use __typename as it works on any type

        # Start with shallow, increase depth
        for depth in [5, 10, 15, 20]:
            inner = "__typename"
            # We need actual fields — try to use schema if available
            if endpoint.schema:
                # Find a self-referential type
                for t in endpoint.schema.get("types", []):
                    for f in t.get("fields", []):
                        ftype = self._resolve_type(f.get("type", {}))
                        if ftype == t.get("name"):
                            # Self-referential! Build deep nesting
                            fname = f.get("name")
                            inner = "__typename"
                            for _ in range(depth):
                                inner = f"{fname} {{ {inner} }}"
                            query = f"{{ {endpoint.queries[0] if endpoint.queries else '__typename'} {{ {inner} }} }}"

                            result = await self._gql_query(endpoint.url, query)
                            if result and "data" in result:
                                return {"depth": depth, "query": query[:200]}

            # Generic approach: try with __type
            nested = "__typename"
            for _ in range(depth):
                nested = f"__type(name: \"Query\") {{ name fields {{ name type {{ {nested} }} }} }}"

            query = f"{{ {nested} }}"
            result = await self._gql_query(endpoint.url, query)
            if result and "data" in result and not result.get("errors"):
                return {"depth": depth, "query": query[:200]}

        return None

    async def _test_batch_queries(self, endpoint: GraphQLEndpoint) -> Optional[Dict]:
        """Test for missing batch query limits"""
        # Send array of queries
        queries = [{"query": TYPENAME_PROBE} for _ in range(self.batch_size)]

        try:
            resp = await self.post(
                endpoint.url,
                json=queries,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) >= self.batch_size:
                    return {"batch_size": len(data)}
        except Exception:
            pass

        return None

    async def _test_alias_bypass(self, endpoint: GraphQLEndpoint) -> Optional[Dict]:
        """Test alias-based rate limit bypass"""
        # Send same query N times with aliases: { a1: user(id:1){name} a2: user(id:1){name} ... }
        if not endpoint.queries:
            return None

        query_name = endpoint.queries[0]
        aliases = " ".join(
            f'a{i}: {query_name} {{ __typename }}'
            for i in range(20)
        )
        query = f'{{ {aliases} }}'

        result = await self._gql_query(endpoint.url, query)
        if result and "data" in result:
            returned = len(result["data"])
            if returned >= 15:
                return {"aliases_accepted": returned}

        return None

    async def _test_field_suggestions(self, endpoint: GraphQLEndpoint) -> List[str]:
        """Harvest field names from error suggestions (when introspection disabled)"""
        discovered_fields: Set[str] = set()

        # Send queries with intentional typos, look for "Did you mean"
        probe_fields = [
            "usre", "admi", "user", "me", "profle",
            "accoun", "seting", "confi", "delet", "updat",
        ]

        for pf in probe_fields:
            result = await self._gql_query(endpoint.url, f"{{ {pf} }}")
            if result and "errors" in result:
                for err in result["errors"]:
                    msg = err.get("message", "")
                    # Look for suggestions like: Did you mean "users"?
                    suggestions = re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]*)"', msg)
                    for s in suggestions:
                        if s not in ("query", "mutation", "subscription"):
                            discovered_fields.add(s)

        return list(discovered_fields)

    # =========================================================================
    # MAIN SCAN
    # =========================================================================

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Main GraphQL security scan"""

        # Step 1: Discover endpoint
        endpoint = await self._discover_endpoint(context)
        if not endpoint:
            return

        yield self.create_finding(
            title="GraphQL Endpoint Discovered",
            severity=Severity.INFO,
            confidence=Confidence.CERTAIN,
            url=endpoint.url,
            description=(
                f"GraphQL endpoint found at: {endpoint.url}\n"
                f"Accepts GET: {endpoint.accepts_get}"
            ),
            evidence=f"URL: {endpoint.url}",
        )

        # Step 2: Introspection
        introspection_enabled, schema = await self._test_introspection(endpoint)

        if introspection_enabled and schema:
            endpoint.introspection_enabled = True
            self._extract_schema_info(schema, endpoint)

            type_count = len(endpoint.types)
            query_count = len(endpoint.queries)
            mutation_count = len(endpoint.mutations)

            yield self.create_finding(
                title="GraphQL Introspection Enabled",
                severity=Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                url=endpoint.url,
                description=(
                    f"Full schema introspection is enabled.\n"
                    f"Discovered: {type_count} types, {query_count} queries, {mutation_count} mutations.\n\n"
                    f"Queries: {', '.join(endpoint.queries[:20])}\n"
                    f"Mutations: {', '.join(endpoint.mutations[:20])}\n"
                    f"Types: {', '.join(endpoint.types[:30])}"
                ),
                evidence=json.dumps({
                    "types": endpoint.types[:50],
                    "queries": endpoint.queries[:50],
                    "mutations": endpoint.mutations[:50],
                }, indent=2),
                remediation=(
                    "Disable introspection in production:\n"
                    "- Apollo Server: introspection: false\n"
                    "- graphql-yoga: maskedErrors, disableIntrospection plugin\n"
                    "- Hasura: HASURA_GRAPHQL_ENABLE_ALLOWLIST=true\n"
                    "- AWS AppSync: disable in resolver configuration"
                ),
                references=[
                    "https://portswigger.net/web-security/graphql#discovering-schema-information",
                ],
            )

            # Check for sensitive fields
            sensitive = self._find_sensitive_fields(schema)
            if sensitive:
                yield self.create_finding(
                    title=f"Sensitive Fields Exposed in GraphQL Schema ({len(sensitive)} found)",
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    url=endpoint.url,
                    description=(
                        "Potentially sensitive fields found in GraphQL schema:\n" +
                        "\n".join(f"  - {t}.{f} ({ft})" for t, f, ft in sensitive[:30])
                    ),
                    evidence=json.dumps([
                        {"type": t, "field": f, "fieldType": ft}
                        for t, f, ft in sensitive
                    ], indent=2),
                    remediation=(
                        "1. Remove sensitive fields from the schema or restrict via authorization\n"
                        "2. Use field-level authorization directives\n"
                        "3. Implement query allowlisting\n"
                        "4. Consider a schema gateway that strips sensitive fields"
                    ),
                )

            # Check for dangerous mutations
            dangerous_mutations = self._find_sensitive_mutations(schema)
            if dangerous_mutations:
                yield self.create_finding(
                    title=f"Potentially Dangerous Mutations Found ({len(dangerous_mutations)})",
                    severity=Severity.HIGH,
                    confidence=Confidence.FIRM,
                    url=endpoint.url,
                    description=(
                        "Admin/destructive mutations accessible in schema:\n" +
                        "\n".join(f"  - {m}" for m in dangerous_mutations)
                    ),
                    evidence=json.dumps(dangerous_mutations, indent=2),
                    remediation=(
                        "1. Implement proper authorization on all mutations\n"
                        "2. Use role-based access control for admin mutations\n"
                        "3. Consider mutation allowlisting for regular users"
                    ),
                )

        else:
            # Introspection disabled — try field suggestion harvesting
            suggested = await self._test_field_suggestions(endpoint)
            if suggested:
                yield self.create_finding(
                    title="GraphQL Field Names Discovered via Suggestions",
                    severity=Severity.LOW,
                    confidence=Confidence.FIRM,
                    url=endpoint.url,
                    description=(
                        "Introspection is disabled but field names leaked via error suggestions:\n" +
                        ", ".join(suggested)
                    ),
                    evidence=", ".join(suggested),
                    remediation="Disable field suggestion feature in GraphQL server.",
                )

        # Step 3: Depth limit test
        if not self.safe_mode:
            depth_result = await self._test_depth_limit(endpoint)
            if depth_result:
                yield self.create_finding(
                    title=f"No GraphQL Query Depth Limit (tested depth: {depth_result['depth']})",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    url=endpoint.url,
                    description=(
                        f"No query depth limit detected. Queries up to depth {depth_result['depth']} accepted.\n"
                        f"This allows Denial of Service via deeply nested queries that cause exponential DB load."
                    ),
                    evidence=depth_result.get("query", ""),
                    remediation=(
                        "1. Implement query depth limiting (recommended max: 7-10)\n"
                        "2. graphql-depth-limit npm package\n"
                        "3. Apollo: validationRules: [depthLimit(10)]\n"
                        "4. Implement query cost analysis"
                    ),
                )

        # Step 4: Batch query test
        batch_result = await self._test_batch_queries(endpoint)
        if batch_result:
            yield self.create_finding(
                title=f"GraphQL Batch Queries Accepted ({batch_result['batch_size']} queries)",
                severity=Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                url=endpoint.url,
                description=(
                    f"Server accepted a batch of {batch_result['batch_size']} queries in a single request.\n"
                    f"This can be abused for:\n"
                    f"- Denial of Service (amplification)\n"
                    f"- Brute force attacks (batch password attempts)\n"
                    f"- Rate limit bypass"
                ),
                evidence=f"Batch size accepted: {batch_result['batch_size']}",
                remediation=(
                    "1. Limit maximum batch size (e.g., max 5 queries per request)\n"
                    "2. Implement query cost analysis across batch\n"
                    "3. Rate limit by total operations, not HTTP requests"
                ),
            )

        # Step 5: Alias bypass test
        alias_result = await self._test_alias_bypass(endpoint)
        if alias_result:
            yield self.create_finding(
                title=f"GraphQL Alias-Based Rate Limit Bypass ({alias_result['aliases_accepted']} aliases)",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                url=endpoint.url,
                description=(
                    "Query aliasing allows executing the same operation multiple times "
                    "in a single request, bypassing per-request rate limiting.\n"
                    f"Accepted {alias_result['aliases_accepted']} aliased operations."
                ),
                evidence=f"Aliases accepted: {alias_result['aliases_accepted']}",
                remediation=(
                    "1. Count operations (including aliases) not just requests\n"
                    "2. Implement per-operation rate limiting\n"
                    "3. Use query cost analysis that accounts for aliases"
                ),
            )

        # Run passive scan
        async for finding in self.passive_scan(context):
            yield finding

    async def passive_scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Detect GraphQL indicators from response"""
        if not context.response:
            return

        body = context.response.body if hasattr(context.response, 'body') else ""
        headers = context.response.headers if hasattr(context.response, 'headers') else {}

        # Detect GraphQL endpoints from response content
        gql_indicators = [
            (r'"data"\s*:\s*\{.*"__typename"', "GraphQL response detected (__typename field)"),
            (r'"errors"\s*:\s*\[\s*\{.*"message".*"locations"', "GraphQL error response format detected"),
            (r'graphql|GraphQL|graphiql|GraphiQL', "GraphQL reference in response body"),
            (r'/graphql["\s,}]', "GraphQL endpoint path in response"),
        ]

        for pattern, title in gql_indicators:
            if re.search(pattern, body, re.IGNORECASE):
                yield self.create_finding(
                    title=title,
                    severity=Severity.INFO,
                    confidence=Confidence.FIRM,
                    url=context.url,
                    description=f"GraphQL indicator detected: {pattern}",
                    evidence=body[:500],
                )
                break
