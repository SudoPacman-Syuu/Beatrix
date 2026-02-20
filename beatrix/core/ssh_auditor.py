"""
BEATRIX SSH Auditor — paramiko integration

SSH security assessment for bug bounty recon:
- SSH server fingerprinting (banner, KEX, ciphers, MACs)
- Auth method enumeration (password, publickey, keyboard-interactive)
- Weak credential checking (against known defaults)
- SSH key type/strength analysis
- Post-auth command execution (when creds are provided)
- SFTP enumeration

Usage:
    auditor = SSHAuditor()
    info = await auditor.fingerprint("target.com")
    auth = await auditor.enum_auth_methods("target.com", "admin")
    result = await auditor.check_default_creds("target.com")
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import paramiko
from paramiko.ssh_exception import (
    AuthenticationException,
    NoValidConnectionsError,
    SSHException,
)

# =============================================================================
# DATA TYPES
# =============================================================================

class AuthMethod(Enum):
    PASSWORD = "password"
    PUBLICKEY = "publickey"
    KEYBOARD_INTERACTIVE = "keyboard-interactive"
    GSSAPI_WITH_MIC = "gssapi-with-mic"
    HOSTBASED = "hostbased"
    NONE = "none"


class SSHRisk(Enum):
    CRITICAL = "critical"  # Default creds work, no auth, etc.
    HIGH = "high"          # Weak ciphers, key exchange issues
    MEDIUM = "medium"      # Outdated version, minor config issues
    LOW = "low"            # Informational, best-practice violations
    INFO = "info"


@dataclass
class SSHFingerprint:
    target: str
    port: int = 22
    banner: str = ""
    ssh_version: str = ""
    server_software: str = ""
    key_type: str = ""
    key_bits: int = 0
    key_fingerprint: str = ""
    kex_algorithms: List[str] = field(default_factory=list)
    ciphers: List[str] = field(default_factory=list)
    macs: List[str] = field(default_factory=list)
    compression: List[str] = field(default_factory=list)
    auth_methods: List[AuthMethod] = field(default_factory=list)
    host_keys: Dict[str, str] = field(default_factory=dict)
    risks: List[Dict[str, str]] = field(default_factory=list)
    error: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CredentialResult:
    target: str
    port: int
    username: str
    password: str
    success: bool
    auth_method: str = ""
    banner: str = ""
    error: str = ""


@dataclass
class CommandResult:
    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    error: str = ""


# Weak/deprecated algorithms
WEAK_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
}

WEAK_CIPHERS = {
    "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128",
    "arcfour256", "rijndael-cbc@lysator.liu.se",
}

WEAK_MACS = {
    "hmac-md5", "hmac-md5-96", "hmac-sha1-96",
    "umac-64@openssh.com", "hmac-ripemd160",
}

# Default/common credentials for various devices
DEFAULT_CREDS: List[Tuple[str, str]] = [
    ("root", "root"),
    ("root", "toor"),
    ("root", ""),
    ("root", "password"),
    ("root", "admin"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", ""),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("guest", "guest"),
    ("pi", "raspberry"),
    ("ubuntu", "ubuntu"),
    ("vagrant", "vagrant"),
    ("deploy", "deploy"),
    ("ftpuser", "ftpuser"),
    ("postgres", "postgres"),
    ("mysql", "mysql"),
    ("oracle", "oracle"),
    ("git", "git"),
]


# =============================================================================
# SSH AUDITOR
# =============================================================================

class SSHAuditor:
    """SSH security auditing with paramiko."""

    def __init__(
        self,
        timeout: float = 10.0,
        max_auth_attempts: int = 5,
    ):
        self.timeout = timeout
        self.max_auth_attempts = max_auth_attempts

    # ---- Fingerprinting ----

    async def fingerprint(
        self, target: str, port: int = 22,
    ) -> SSHFingerprint:
        """Full SSH server fingerprint."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._fingerprint_sync, target, port,
        )

    def _fingerprint_sync(self, target: str, port: int) -> SSHFingerprint:
        fp = SSHFingerprint(target=target, port=port)

        # 1) Banner grab
        try:
            sock = socket.create_connection((target, port), timeout=self.timeout)
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            fp.banner = banner
            # Parse SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
            if banner.startswith("SSH-"):
                parts = banner.split("-", 2)
                if len(parts) >= 3:
                    fp.ssh_version = parts[1]
                    fp.server_software = parts[2]
            sock.close()
        except Exception as e:
            fp.error = f"banner grab failed: {e}"
            return fp

        # 2) Transport-level negotiation
        try:
            transport = paramiko.Transport((target, port))
            transport.connect()

            # Key exchange info
            sec_opts = transport.get_security_options()
            fp.kex_algorithms = list(sec_opts.kex)
            fp.ciphers = list(sec_opts.ciphers)
            fp.macs = list(sec_opts.digests)
            fp.compression = list(sec_opts.compression)

            # Host key
            key = transport.get_remote_server_key()
            fp.key_type = key.get_name()
            fp.key_bits = key.get_bits()
            fp.key_fingerprint = key.get_fingerprint().hex()
            fp.host_keys[key.get_name()] = key.get_base64()

            transport.close()
        except Exception as e:
            fp.error = f"transport negotiation: {e}"

        # 3) Risk analysis
        fp.risks = self._analyze_risks(fp)

        return fp

    def _analyze_risks(self, fp: SSHFingerprint) -> List[Dict[str, str]]:
        risks = []

        # Weak KEX
        weak_kex = set(fp.kex_algorithms) & WEAK_KEX
        if weak_kex:
            risks.append({
                "severity": SSHRisk.HIGH.value,
                "issue": "Weak key exchange algorithms",
                "detail": ", ".join(sorted(weak_kex)),
                "remediation": "Disable SHA-1 based KEX algorithms",
            })

        # Weak ciphers
        weak_ciph = set(fp.ciphers) & WEAK_CIPHERS
        if weak_ciph:
            risks.append({
                "severity": SSHRisk.HIGH.value,
                "issue": "Weak/CBC ciphers enabled",
                "detail": ", ".join(sorted(weak_ciph)),
                "remediation": "Use only AES-GCM or ChaCha20-Poly1305 ciphers",
            })

        # Weak MACs
        weak_mac = set(fp.macs) & WEAK_MACS
        if weak_mac:
            risks.append({
                "severity": SSHRisk.MEDIUM.value,
                "issue": "Weak MAC algorithms",
                "detail": ", ".join(sorted(weak_mac)),
                "remediation": "Use HMAC-SHA2-256/512 or umac-128",
            })

        # Weak host key
        if fp.key_type == "ssh-dss":
            risks.append({
                "severity": SSHRisk.HIGH.value,
                "issue": "DSA host key (deprecated, 1024-bit max)",
                "detail": f"{fp.key_type} ({fp.key_bits} bits)",
                "remediation": "Use Ed25519 or RSA-4096 host keys",
            })
        elif fp.key_type == "ssh-rsa" and fp.key_bits < 2048:
            risks.append({
                "severity": SSHRisk.HIGH.value,
                "issue": f"Weak RSA host key ({fp.key_bits} bits)",
                "detail": f"{fp.key_type} ({fp.key_bits} bits)",
                "remediation": "Use at least 2048-bit RSA or Ed25519",
            })

        # SSH version 1
        if fp.ssh_version == "1.0" or "SSH-1" in fp.banner:
            risks.append({
                "severity": SSHRisk.CRITICAL.value,
                "issue": "SSH protocol version 1 supported",
                "detail": fp.banner,
                "remediation": "Disable SSH v1, enforce v2 only",
            })

        # Old OpenSSH versions (rough check)
        if "OpenSSH" in fp.server_software:
            import re
            m = re.search(r"OpenSSH[_]?(\d+)\.(\d+)", fp.server_software)
            if m:
                major, minor = int(m.group(1)), int(m.group(2))
                if major < 7 or (major == 7 and minor < 4):
                    risks.append({
                        "severity": SSHRisk.MEDIUM.value,
                        "issue": f"Outdated OpenSSH ({major}.{minor})",
                        "detail": fp.server_software,
                        "remediation": "Update to OpenSSH 8.x+ for security fixes",
                    })

        return risks

    # ---- Auth enumeration ----

    async def enum_auth_methods(
        self, target: str, username: str = "root", port: int = 22,
    ) -> List[AuthMethod]:
        """Enumerate supported authentication methods for a user."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._enum_auth_sync, target, username, port,
        )

    def _enum_auth_sync(
        self, target: str, username: str, port: int,
    ) -> List[AuthMethod]:
        methods: List[AuthMethod] = []
        try:
            transport = paramiko.Transport((target, port))
            transport.connect()
            try:
                transport.auth_none(username)
            except paramiko.BadAuthenticationType as e:
                for m in e.allowed_types:
                    try:
                        methods.append(AuthMethod(m))
                    except ValueError:
                        pass
            except AuthenticationException:
                # auth_none succeeded = no auth required!
                methods.append(AuthMethod.NONE)
            finally:
                transport.close()
        except Exception:
            pass
        return methods

    # ---- Credential checking ----

    async def check_credential(
        self, target: str, username: str, password: str,
        port: int = 22,
    ) -> CredentialResult:
        """Try a single username/password combo."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._check_cred_sync, target, username, password, port,
        )

    def _check_cred_sync(
        self, target: str, username: str, password: str, port: int,
    ) -> CredentialResult:
        result = CredentialResult(
            target=target, port=port,
            username=username, password=password, success=False,
        )
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=target, port=port,
                username=username, password=password,
                timeout=self.timeout,
                look_for_keys=False, allow_agent=False,
            )
            result.success = True
            result.auth_method = "password"

            # Grab banner
            transport = client.get_transport()
            if transport:
                result.banner = transport.remote_version

            client.close()
        except AuthenticationException:
            result.error = "auth_failed"
        except NoValidConnectionsError as e:
            result.error = f"connection_failed: {e}"
        except SSHException as e:
            result.error = f"ssh_error: {e}"
        except Exception as e:
            result.error = f"error: {e}"
        return result

    async def check_default_creds(
        self, target: str, port: int = 22,
        extra_creds: Optional[List[Tuple[str, str]]] = None,
    ) -> List[CredentialResult]:
        """Check common default credentials."""
        creds = list(DEFAULT_CREDS)
        if extra_creds:
            creds.extend(extra_creds)

        valid: List[CredentialResult] = []
        attempts = 0

        for username, password in creds:
            if attempts >= self.max_auth_attempts * 10:
                break

            result = await self.check_credential(target, username, password, port)
            attempts += 1

            if result.success:
                valid.append(result)
                # Don't stop — check for more valid creds

            # Small delay to avoid lockout
            await asyncio.sleep(0.5)

        return valid

    # ---- Post-auth operations ----

    async def exec_command(
        self, target: str, username: str, password: str,
        command: str, port: int = 22,
    ) -> CommandResult:
        """Execute a command over SSH."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._exec_sync, target, username, password, command, port,
        )

    def _exec_sync(
        self, target: str, username: str, password: str,
        command: str, port: int,
    ) -> CommandResult:
        result = CommandResult(command=command)
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=target, port=port,
                username=username, password=password,
                timeout=self.timeout,
                look_for_keys=False, allow_agent=False,
            )
            stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)
            result.stdout = stdout.read().decode("utf-8", errors="replace")
            result.stderr = stderr.read().decode("utf-8", errors="replace")
            result.exit_code = stdout.channel.recv_exit_status()
            client.close()
        except Exception as e:
            result.error = str(e)
        return result

    async def sftp_list(
        self, target: str, username: str, password: str,
        path: str = "/", port: int = 22,
    ) -> List[Dict[str, Any]]:
        """List files via SFTP."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._sftp_list_sync, target, username, password, path, port,
        )

    def _sftp_list_sync(
        self, target: str, username: str, password: str,
        path: str, port: int,
    ) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=target, port=port,
                username=username, password=password,
                timeout=self.timeout,
                look_for_keys=False, allow_agent=False,
            )
            sftp = client.open_sftp()
            for attr in sftp.listdir_attr(path):
                entries.append({
                    "filename": attr.filename,
                    "size": attr.st_size,
                    "uid": attr.st_uid,
                    "gid": attr.st_gid,
                    "mode": oct(attr.st_mode) if attr.st_mode else None,
                    "mtime": datetime.fromtimestamp(attr.st_mtime).isoformat() if attr.st_mtime else None,
                    "is_dir": attr.longname.startswith("d") if attr.longname else False,
                })
            sftp.close()
            client.close()
        except Exception:
            pass
        return entries

    # ---- Multi-host scanning ----

    async def scan_hosts(
        self, targets: List[str], port: int = 22,
    ) -> List[SSHFingerprint]:
        """Fingerprint multiple SSH servers."""
        tasks = [self.fingerprint(t, port) for t in targets]
        return await asyncio.gather(*tasks)
