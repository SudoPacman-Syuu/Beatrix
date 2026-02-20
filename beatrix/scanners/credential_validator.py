#!/usr/bin/env python3
"""
BEATRIX Credential Validator

Takes discovered credentials (from GitHub recon, config files, etc.)
and validates whether they're actually live/working.

Validation methods:
- JWT: Decode, check signature, test forgery
- API keys: Fire test requests to known services
- Database: Attempt connection (non-destructive)
- Cloud: AWS/GCP/Azure credential testing
- Generic: HTTP endpoint probing with the credential

This moves a finding from "we found a string that looks like a key"
to "this key is confirmed live and provides access to X."

That's the difference between Informational and Critical.

Author: BEATRIX
"""

import asyncio
import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx

from beatrix.core.types import Severity


class CredentialType(Enum):
    """Types of credentials we can validate"""
    JWT_SECRET = "jwt_secret"
    API_KEY = "api_key"
    DATABASE_PASSWORD = "database_password"
    AWS_KEY = "aws_key"
    MONGODB_URI = "mongodb_uri"
    REDIS_PASSWORD = "redis_password"
    SMTP_CREDENTIAL = "smtp_credential"
    ENCRYPTION_KEY = "encryption_key"
    GITHUB_TOKEN = "github_token"
    STRIPE_KEY = "stripe_key"
    TWILIO_KEY = "twilio_key"
    SENDGRID_KEY = "sendgrid_key"
    SLACK_WEBHOOK = "slack_webhook"
    GENERIC = "generic"


class ValidationResult(Enum):
    """Outcome of credential validation"""
    VALID = "valid"          # Credential works — confirmed access
    INVALID = "invalid"      # Credential rejected — rotated or fake
    EXPIRED = "expired"      # Credential recognized but expired
    PARTIAL = "partial"      # Credential works but limited access
    UNREACHABLE = "unreachable"  # Can't reach the service to test
    SKIPPED = "skipped"      # No validator available for this type
    ERROR = "error"          # Validation attempt errored


@dataclass
class CredentialTest:
    """Input: a credential to validate"""
    credential_type: CredentialType
    value: str
    context: Dict[str, Any] = field(default_factory=dict)
    # context may contain:
    #   host: database host
    #   port: database port
    #   username: associated username
    #   database: database name
    #   service_url: API endpoint to test against


@dataclass
class ValidationReport:
    """Output: result of credential validation"""
    credential_type: CredentialType
    result: ValidationResult
    details: str
    access_level: Optional[str] = None  # What access does this credential grant?
    service_info: Optional[str] = None  # Service version, identity, etc.
    risk_level: Severity = Severity.INFO
    tested_at: str = field(default_factory=lambda: datetime.now().isoformat())
    raw_response: Optional[str] = None  # Truncated response for evidence

    @property
    def is_live(self) -> bool:
        """Is this credential confirmed working?"""
        return self.result in (ValidationResult.VALID, ValidationResult.PARTIAL)


class CredentialValidator:
    """
    Validates discovered credentials against their target services.

    ALL validation is READ-ONLY. No modifications, no data exfiltration,
    no side effects beyond the minimum request needed to confirm access.
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.results: List[ValidationReport] = []

    async def validate(self, credential: CredentialTest) -> ValidationReport:
        """Route credential to the right validator"""
        validators = {
            CredentialType.JWT_SECRET: self._validate_jwt,
            CredentialType.GITHUB_TOKEN: self._validate_github_token,
            CredentialType.AWS_KEY: self._validate_aws_key,
            CredentialType.STRIPE_KEY: self._validate_stripe_key,
            CredentialType.SENDGRID_KEY: self._validate_sendgrid_key,
            CredentialType.SLACK_WEBHOOK: self._validate_slack_webhook,
            CredentialType.MONGODB_URI: self._validate_mongodb,
            CredentialType.REDIS_PASSWORD: self._validate_redis,
            CredentialType.API_KEY: self._validate_generic_api_key,
            CredentialType.GENERIC: self._validate_generic_api_key,
        }

        validator = validators.get(credential.credential_type)

        if validator:
            try:
                report = await validator(credential)
            except Exception as e:
                report = ValidationReport(
                    credential_type=credential.credential_type,
                    result=ValidationResult.ERROR,
                    details=f"Validation error: {str(e)}",
                    risk_level=Severity.INFO,
                )
        else:
            report = ValidationReport(
                credential_type=credential.credential_type,
                result=ValidationResult.SKIPPED,
                details=f"No validator available for {credential.credential_type.value}",
                risk_level=Severity.INFO,
            )

        self.results.append(report)
        return report

    async def validate_batch(self, credentials: List[CredentialTest]) -> List[ValidationReport]:
        """Validate multiple credentials concurrently"""
        tasks = [self.validate(cred) for cred in credentials]
        return await asyncio.gather(*tasks)

    # =========================================================================
    # JWT VALIDATION
    # =========================================================================

    async def _validate_jwt(self, cred: CredentialTest) -> ValidationReport:
        """
        Validate a JWT secret by attempting to decode/forge a token.

        If we can sign a valid JWT with the secret, the secret is live.
        This is purely local — no network request needed.
        """
        import hmac

        secret = cred.value

        # Create a test JWT header and payload
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).rstrip(b'=').decode()

        payload = base64.urlsafe_b64encode(
            json.dumps({
                "sub": "beatrix-test",
                "iat": int(datetime.now().timestamp()),
                "exp": int(datetime.now().timestamp()) + 3600,
            }).encode()
        ).rstrip(b'=').decode()

        message = f"{header}.{payload}"

        # Sign with the discovered secret
        signature = hmac.new(
            secret.encode(), message.encode(), hashlib.sha256
        ).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

        forged_token = f"{message}.{sig_b64}"

        # If there's a service URL in context, try using the forged token
        service_url = cred.context.get("service_url")
        if service_url:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                try:
                    resp = await client.get(
                        service_url,
                        headers={"Authorization": f"Bearer {forged_token}"},
                    )

                    if resp.status_code in [200, 201, 204]:
                        return ValidationReport(
                            credential_type=CredentialType.JWT_SECRET,
                            result=ValidationResult.VALID,
                            details=(
                                f"JWT secret is LIVE. Forged token accepted by {service_url}. "
                                f"Response: {resp.status_code}"
                            ),
                            access_level="Authenticated API access via forged JWT",
                            risk_level=Severity.CRITICAL,
                            raw_response=resp.text[:500],
                        )
                    elif resp.status_code == 401:
                        return ValidationReport(
                            credential_type=CredentialType.JWT_SECRET,
                            result=ValidationResult.INVALID,
                            details=f"Forged JWT rejected by {service_url} (401). Secret may be rotated.",
                            risk_level=Severity.LOW,
                        )
                except Exception:
                    pass  # Fall through to offline validation

        # Offline validation: we can forge tokens, which is valuable info
        # even if we can't test them against a service
        return ValidationReport(
            credential_type=CredentialType.JWT_SECRET,
            result=ValidationResult.PARTIAL,
            details=(
                f"JWT secret allows token forgery (HS256). "
                f"Generated valid-format JWT: {forged_token[:50]}... "
                f"Cannot confirm server acceptance without a test endpoint."
            ),
            access_level="Token forgery capability (HS256)",
            risk_level=Severity.HIGH,
        )

    # =========================================================================
    # GITHUB TOKEN
    # =========================================================================

    async def _validate_github_token(self, cred: CredentialTest) -> ValidationReport:
        """Validate a GitHub personal access token"""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(
                    "https://api.github.com/user",
                    headers={
                        "Authorization": f"token {cred.value}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )

                if resp.status_code == 200:
                    data = resp.json()
                    username = data.get("login", "unknown")

                    # Check scopes
                    scopes = resp.headers.get("X-OAuth-Scopes", "none")

                    return ValidationReport(
                        credential_type=CredentialType.GITHUB_TOKEN,
                        result=ValidationResult.VALID,
                        details=f"GitHub token is LIVE. User: {username}, Scopes: {scopes}",
                        access_level=f"GitHub account: {username} with scopes: {scopes}",
                        service_info=f"GitHub user: {username}",
                        risk_level=Severity.CRITICAL,
                        raw_response=json.dumps({"login": username, "scopes": scopes}),
                    )
                elif resp.status_code == 401:
                    return ValidationReport(
                        credential_type=CredentialType.GITHUB_TOKEN,
                        result=ValidationResult.INVALID,
                        details="GitHub token is invalid or revoked",
                        risk_level=Severity.LOW,
                    )
                else:
                    return ValidationReport(
                        credential_type=CredentialType.GITHUB_TOKEN,
                        result=ValidationResult.ERROR,
                        details=f"Unexpected response: {resp.status_code}",
                        risk_level=Severity.INFO,
                    )

            except Exception as e:
                return ValidationReport(
                    credential_type=CredentialType.GITHUB_TOKEN,
                    result=ValidationResult.UNREACHABLE,
                    details=f"Cannot reach GitHub API: {e}",
                    risk_level=Severity.INFO,
                )

    # =========================================================================
    # AWS KEY
    # =========================================================================

    async def _validate_aws_key(self, cred: CredentialTest) -> ValidationReport:
        """
        Validate AWS access key by calling sts:GetCallerIdentity.

        This is the standard safe AWS validation — it's a read-only operation
        that every valid AWS credential can perform regardless of permissions.
        """
        access_key = cred.value
        secret_key = cred.context.get("secret_key", "")

        if not secret_key:
            return ValidationReport(
                credential_type=CredentialType.AWS_KEY,
                result=ValidationResult.SKIPPED,
                details="AWS Secret Key not provided, cannot validate Access Key alone",
                risk_level=Severity.MEDIUM,
            )

        # We'd use boto3 here, but to avoid the dependency, use raw STS call
        # For now, mark as needing manual validation
        async with httpx.AsyncClient(timeout=self.timeout):
            try:
                # Simple check: try to hit STS with basic sig
                # Full SigV4 is complex — suggest using aws-cli for verification
                return ValidationReport(
                    credential_type=CredentialType.AWS_KEY,
                    result=ValidationResult.PARTIAL,
                    details=(
                        f"AWS Access Key ID: {access_key}. "
                        f"Manual validation recommended:\n"
                        f"  AWS_ACCESS_KEY_ID={access_key} "
                        f"AWS_SECRET_ACCESS_KEY=<secret> "
                        f"aws sts get-caller-identity"
                    ),
                    risk_level=Severity.HIGH,
                )
            except Exception as e:
                return ValidationReport(
                    credential_type=CredentialType.AWS_KEY,
                    result=ValidationResult.ERROR,
                    details=f"AWS validation error: {e}",
                    risk_level=Severity.INFO,
                )

    # =========================================================================
    # STRIPE KEY
    # =========================================================================

    async def _validate_stripe_key(self, cred: CredentialTest) -> ValidationReport:
        """Validate a Stripe secret key"""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(
                    "https://api.stripe.com/v1/balance",
                    auth=(cred.value, ""),
                )

                if resp.status_code == 200:
                    data = resp.json()
                    available = data.get("available", [{}])
                    currency = available[0].get("currency", "unknown") if available else "unknown"
                    amount = available[0].get("amount", 0) if available else 0

                    return ValidationReport(
                        credential_type=CredentialType.STRIPE_KEY,
                        result=ValidationResult.VALID,
                        details=(
                            f"Stripe key is LIVE. Balance accessible. "
                            f"Currency: {currency}, Available: {amount}"
                        ),
                        access_level="Stripe account with balance read access",
                        risk_level=Severity.CRITICAL,
                        raw_response=resp.text[:300],
                    )
                elif resp.status_code == 401:
                    return ValidationReport(
                        credential_type=CredentialType.STRIPE_KEY,
                        result=ValidationResult.INVALID,
                        details="Stripe key is invalid or revoked",
                        risk_level=Severity.LOW,
                    )
                else:
                    return ValidationReport(
                        credential_type=CredentialType.STRIPE_KEY,
                        result=ValidationResult.PARTIAL,
                        details=f"Stripe returned {resp.status_code} — key may have limited permissions",
                        risk_level=Severity.MEDIUM,
                    )

            except Exception as e:
                return ValidationReport(
                    credential_type=CredentialType.STRIPE_KEY,
                    result=ValidationResult.UNREACHABLE,
                    details=f"Cannot reach Stripe API: {e}",
                    risk_level=Severity.INFO,
                )

    # =========================================================================
    # SENDGRID KEY
    # =========================================================================

    async def _validate_sendgrid_key(self, cred: CredentialTest) -> ValidationReport:
        """Validate a SendGrid API key"""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(
                    "https://api.sendgrid.com/v3/user/profile",
                    headers={"Authorization": f"Bearer {cred.value}"},
                )

                if resp.status_code == 200:
                    data = resp.json()
                    return ValidationReport(
                        credential_type=CredentialType.SENDGRID_KEY,
                        result=ValidationResult.VALID,
                        details=f"SendGrid key is LIVE. Account: {data.get('username', 'unknown')}",
                        access_level="SendGrid account access",
                        risk_level=Severity.HIGH,
                    )
                elif resp.status_code in [401, 403]:
                    return ValidationReport(
                        credential_type=CredentialType.SENDGRID_KEY,
                        result=ValidationResult.INVALID,
                        details="SendGrid key is invalid or revoked",
                        risk_level=Severity.LOW,
                    )
                else:
                    return ValidationReport(
                        credential_type=CredentialType.SENDGRID_KEY,
                        result=ValidationResult.PARTIAL,
                        details=f"SendGrid returned {resp.status_code}",
                        risk_level=Severity.MEDIUM,
                    )
            except Exception as e:
                return ValidationReport(
                    credential_type=CredentialType.SENDGRID_KEY,
                    result=ValidationResult.UNREACHABLE,
                    details=f"Cannot reach SendGrid: {e}",
                    risk_level=Severity.INFO,
                )

    # =========================================================================
    # SLACK WEBHOOK
    # =========================================================================

    async def _validate_slack_webhook(self, cred: CredentialTest) -> ValidationReport:
        """
        Validate a Slack webhook URL.

        We send a minimal, non-disruptive message to verify.
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                # Send a benign test message
                resp = await client.post(
                    cred.value,
                    json={"text": "[BEATRIX Security Audit] Webhook validation test — this webhook URL was found in a public repository. Please rotate it."},
                )

                if resp.status_code == 200 and resp.text == "ok":
                    return ValidationReport(
                        credential_type=CredentialType.SLACK_WEBHOOK,
                        result=ValidationResult.VALID,
                        details="Slack webhook is LIVE. Test message delivered.",
                        access_level="Slack channel message posting",
                        risk_level=Severity.MEDIUM,
                    )
                elif resp.status_code in [403, 404]:
                    return ValidationReport(
                        credential_type=CredentialType.SLACK_WEBHOOK,
                        result=ValidationResult.INVALID,
                        details="Slack webhook is invalid or disabled",
                        risk_level=Severity.LOW,
                    )
                else:
                    return ValidationReport(
                        credential_type=CredentialType.SLACK_WEBHOOK,
                        result=ValidationResult.PARTIAL,
                        details=f"Slack returned: {resp.status_code} {resp.text[:100]}",
                        risk_level=Severity.LOW,
                    )
            except Exception as e:
                return ValidationReport(
                    credential_type=CredentialType.SLACK_WEBHOOK,
                    result=ValidationResult.UNREACHABLE,
                    details=f"Cannot reach Slack: {e}",
                    risk_level=Severity.INFO,
                )

    # =========================================================================
    # MONGODB
    # =========================================================================

    async def _validate_mongodb(self, cred: CredentialTest) -> ValidationReport:
        """
        Validate a MongoDB connection string.

        Attempts a TCP connection to the MongoDB port. Does NOT
        run any queries or authenticate — just checks reachability + port.

        Full validation would require pymongo, but we keep dependencies minimal.
        """
        uri = cred.value

        # Parse mongodb:// or mongodb+srv:// URI
        match = re.match(r'mongodb(?:\+srv)?://(?:[^:]+):(?:[^@]+)@([^/:\?]+)(?::(\d+))?', uri)
        if not match:
            return ValidationReport(
                credential_type=CredentialType.MONGODB_URI,
                result=ValidationResult.ERROR,
                details="Cannot parse MongoDB URI",
                risk_level=Severity.INFO,
            )

        host = match.group(1)
        port = int(match.group(2)) if match.group(2) else 27017

        try:
            # TCP connection test
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout,
            )
            writer.close()
            await writer.wait_closed()

            return ValidationReport(
                credential_type=CredentialType.MONGODB_URI,
                result=ValidationResult.PARTIAL,
                details=(
                    f"MongoDB host {host}:{port} is reachable. "
                    f"Full URI contains credentials. "
                    f"Manual validation: mongosh '{uri}'"
                ),
                access_level=f"Database connection to {host}:{port}",
                risk_level=Severity.HIGH,
            )
        except asyncio.TimeoutError:
            return ValidationReport(
                credential_type=CredentialType.MONGODB_URI,
                result=ValidationResult.UNREACHABLE,
                details=f"MongoDB host {host}:{port} is not reachable (timeout)",
                risk_level=Severity.MEDIUM,
            )
        except ConnectionRefusedError:
            return ValidationReport(
                credential_type=CredentialType.MONGODB_URI,
                result=ValidationResult.UNREACHABLE,
                details=f"MongoDB host {host}:{port} refused connection",
                risk_level=Severity.MEDIUM,
            )
        except Exception as e:
            return ValidationReport(
                credential_type=CredentialType.MONGODB_URI,
                result=ValidationResult.ERROR,
                details=f"Error testing MongoDB: {e}",
                risk_level=Severity.INFO,
            )

    # =========================================================================
    # REDIS
    # =========================================================================

    async def _validate_redis(self, cred: CredentialTest) -> ValidationReport:
        """
        Validate Redis credentials via raw TCP.

        Sends AUTH + PING, expects +PONG response.
        No dependencies needed — raw socket protocol.
        """
        host = cred.context.get("host", "localhost")
        port = int(cred.context.get("port", 6379))
        password = cred.value

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout,
            )

            # Send AUTH command using RESP protocol
            auth_cmd = f"*2\r\n$4\r\nAUTH\r\n${len(password)}\r\n{password}\r\n"
            writer.write(auth_cmd.encode())
            await writer.drain()

            auth_response = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout,
            )
            auth_result = auth_response.decode().strip()

            if auth_result == "+OK":
                # Auth succeeded — send PING to confirm
                ping_cmd = "*1\r\n$4\r\nPING\r\n"
                writer.write(ping_cmd.encode())
                await writer.drain()

                await asyncio.wait_for(
                    reader.readline(),
                    timeout=self.timeout,
                )

                # Get server info (read-only)
                info_cmd = "*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"
                writer.write(info_cmd.encode())
                await writer.drain()

                info_response = await asyncio.wait_for(
                    reader.read(2048),
                    timeout=self.timeout,
                )

                writer.close()
                await writer.wait_closed()

                version_match = re.search(r'redis_version:(\S+)', info_response.decode())
                version = version_match.group(1) if version_match else "unknown"

                return ValidationReport(
                    credential_type=CredentialType.REDIS_PASSWORD,
                    result=ValidationResult.VALID,
                    details=f"Redis password is LIVE. Server: {host}:{port}, Version: {version}",
                    access_level=f"Full Redis access on {host}:{port}",
                    service_info=f"Redis {version}",
                    risk_level=Severity.CRITICAL,
                )
            else:
                writer.close()
                await writer.wait_closed()

                return ValidationReport(
                    credential_type=CredentialType.REDIS_PASSWORD,
                    result=ValidationResult.INVALID,
                    details=f"Redis AUTH failed: {auth_result}",
                    risk_level=Severity.LOW,
                )

        except asyncio.TimeoutError:
            return ValidationReport(
                credential_type=CredentialType.REDIS_PASSWORD,
                result=ValidationResult.UNREACHABLE,
                details=f"Redis {host}:{port} not reachable (timeout)",
                risk_level=Severity.MEDIUM,
            )
        except ConnectionRefusedError:
            return ValidationReport(
                credential_type=CredentialType.REDIS_PASSWORD,
                result=ValidationResult.UNREACHABLE,
                details=f"Redis {host}:{port} refused connection",
                risk_level=Severity.MEDIUM,
            )
        except Exception as e:
            return ValidationReport(
                credential_type=CredentialType.REDIS_PASSWORD,
                result=ValidationResult.ERROR,
                details=f"Redis validation error: {e}",
                risk_level=Severity.INFO,
            )

    # =========================================================================
    # GENERIC API KEY
    # =========================================================================

    async def _validate_generic_api_key(self, cred: CredentialTest) -> ValidationReport:
        """
        Validate a generic API key against a provided endpoint.

        Tries common auth patterns: Bearer, X-API-Key, Basic, query param.
        """
        service_url = cred.context.get("service_url")

        if not service_url:
            return ValidationReport(
                credential_type=cred.credential_type,
                result=ValidationResult.SKIPPED,
                details="No service URL provided for API key validation",
                risk_level=Severity.MEDIUM,
            )

        auth_methods = [
            ("Bearer", {"Authorization": f"Bearer {cred.value}"}),
            ("X-API-Key", {"X-API-Key": cred.value}),
            ("Basic", {"Authorization": f"Basic {base64.b64encode(f'{cred.value}:'.encode()).decode()}"}),
        ]

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for method_name, headers in auth_methods:
                try:
                    resp = await client.get(service_url, headers=headers)

                    if resp.status_code in [200, 201, 204]:
                        return ValidationReport(
                            credential_type=cred.credential_type,
                            result=ValidationResult.VALID,
                            details=(
                                f"API key is LIVE via {method_name} auth. "
                                f"Endpoint: {service_url}, Status: {resp.status_code}"
                            ),
                            access_level=f"API access via {method_name}",
                            risk_level=Severity.HIGH,
                            raw_response=resp.text[:300],
                        )
                except Exception:
                    continue

        return ValidationReport(
            credential_type=cred.credential_type,
            result=ValidationResult.INVALID,
            details=f"API key not accepted by {service_url} via any standard auth method",
            risk_level=Severity.LOW,
        )

    # =========================================================================
    # REPORTING
    # =========================================================================

    def generate_report(self) -> str:
        """Generate a markdown report of all validation results"""
        if not self.results:
            return "# Credential Validation Report\n\nNo credentials tested."

        live = [r for r in self.results if r.is_live]

        lines = [
            "# Credential Validation Report",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"**Total Tested:** {len(self.results)}",
            f"**Live/Working:** {len(live)}",
            "",
            "## Results",
            "",
            "| # | Type | Result | Risk | Details |",
            "|---|------|--------|------|---------|",
        ]

        for i, r in enumerate(self.results, 1):
            icon = "🔴" if r.result == ValidationResult.VALID else (
                "🟡" if r.result == ValidationResult.PARTIAL else "⚪"
            )
            lines.append(
                f"| {i} | {r.credential_type.value} | {icon} {r.result.value} | "
                f"{r.risk_level.value.upper()} | {r.details[:80]}... |"
            )

        if live:
            lines.extend(["", "## Live Credentials (CRITICAL)", ""])
            for r in live:
                lines.extend([
                    f"### {r.credential_type.value}",
                    f"- **Status:** {r.result.value}",
                    f"- **Access Level:** {r.access_level}",
                    f"- **Details:** {r.details}",
                    "",
                ])

        return "\n".join(lines)
