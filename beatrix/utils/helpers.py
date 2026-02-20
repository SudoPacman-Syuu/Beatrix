"""Utility functions for the framework"""

import asyncio
from typing import List, Optional

# Handle optional imports gracefully
try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


async def resolve_dns(domain: str, record_type: str = 'A') -> List[str]:
    """Resolve DNS records"""
    if not HAS_DNS:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        answers = resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


async def check_http(url: str, timeout: int = 5) -> Optional[dict]:
    """Check HTTP/HTTPS endpoint"""
    if not HAS_AIOHTTP:
        return None
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=timeout, ssl=False) as response:
                return {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "url": str(response.url)
                }
    except Exception:
        return None


def is_valid_domain(domain: str) -> bool:
    """Validate domain format"""
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    return all(part.replace('-', '').isalnum() for part in parts)


async def tcp_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    """Test TCP connection"""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


def extract_domain(target: str) -> str:
    """Extract base domain from URL or hostname"""
    target = target.lower()
    # Remove protocol
    for prefix in ['https://', 'http://', '//']:
        if target.startswith(prefix):
            target = target[len(prefix):]
    # Remove path
    target = target.split('/')[0]
    # Remove port
    target = target.split(':')[0]
    return target
