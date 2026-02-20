"""
BEATRIX Subfinder Integration

Wraps the subfinder binary for subdomain enumeration.
Gracefully skips if subfinder is not installed.

Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
"""

import asyncio
import shutil
from pathlib import Path
from typing import List, Optional


class SubfinderRunner:
    """
    Subprocess wrapper for subfinder.

    Discovers subdomains for a given domain using passive sources.
    Gracefully returns empty list if subfinder binary is not found.
    """

    def __init__(self, timeout: int = 45):
        self.path = self._find_binary()
        self.timeout = timeout

    def _find_binary(self) -> Optional[str]:
        """Find subfinder on PATH or common locations."""
        path = shutil.which("subfinder")
        if path:
            return path
        for candidate in [
            "/usr/bin/subfinder",
            "/usr/local/bin/subfinder",
            str(Path.home() / "go/bin/subfinder"),
            str(Path.home() / ".local/bin/subfinder"),
        ]:
            if Path(candidate).exists():
                return candidate
        return None

    @property
    def available(self) -> bool:
        return self.path is not None

    async def enumerate(self, domain: str) -> List[str]:
        """
        Run subfinder against a domain and return discovered subdomains.

        Args:
            domain: Target domain (e.g., "example.com")

        Returns:
            List of discovered subdomains
        """
        if not self.available:
            return []

        # Strip protocol if present
        if "://" in domain:
            domain = domain.split("://", 1)[1]
        domain = domain.split("/")[0].split(":")[0]

        try:
            cmd = [
                self.path,
                "-d", domain,
                "-silent",          # Only output subdomains
                "-timeout", "15",   # Source timeout (seconds)
                "-nW",              # Remove wildcard subdomains
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )

            try:
                stdout, _ = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return []

            if process.returncode != 0:
                return []

            subdomains = []
            for line in stdout.decode('utf-8', errors='replace').strip().splitlines():
                sub = line.strip().lower()
                if sub and sub != domain:
                    subdomains.append(sub)

            return sorted(set(subdomains))

        except Exception:
            return []
