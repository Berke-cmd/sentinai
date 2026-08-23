import ssl
import aiohttp
from typing import Dict, Tuple, List
from models import HeaderAuditResult

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

class SecurityScanner:
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url if target_url.startswith("http") else f"https://{target_url}"
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def scan(self) -> Tuple[Dict[str, str], List[HeaderAuditResult], bool]:
        ssl_valid = False
        headers_found = {}
        audit_results = []

        ssl_ctx = ssl.create_default_context()
        connector = aiohttp.TCPConnector(ssl=ssl_ctx)

        try:
            async with aiohttp.ClientSession(connector=connector, timeout=self.timeout) as session:
                async with session.get(self.target_url, allow_redirects=True) as response:
                    ssl_valid = True
                    headers_found = dict(response.headers)
        except ssl.SSLError:
            ssl_valid = False
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False), timeout=self.timeout) as session:
                async with session.get(self.target_url) as response:
                    headers_found = dict(response.headers)
        except Exception:
            return {}, [], False

        for sec_header in SECURITY_HEADERS:
            val = headers_found.get(sec_header) or headers_found.get(sec_header.lower())
            if val:
                audit_results.append(HeaderAuditResult(
                    header=sec_header,
                    status="PRESENT",
                    description=f"{sec_header} başlığı mevcut."
                ))
            else:
                audit_results.append(HeaderAuditResult(
                    header=sec_header,
                    status="MISSING",
                    description=f"{sec_header} güvenlik başlığı eksik."
                ))

        return headers_found, audit_results, ssl_valid
