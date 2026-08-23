from typing import List, Optional
from pydantic import BaseModel

class HeaderAuditResult(BaseModel):
    header: str
    status: str
    description: str
    recommendation: Optional[str] = None

class CVESummary(BaseModel):
    cve_id: str
    severity: str
    summary: str

class TargetAuditReport(BaseModel):
    target_url: str
    server_banner: Optional[str] = "Unknown"
    ssl_valid: bool = False
    headers_analyzed: List[HeaderAuditResult] = []
    cves_found: List[CVESummary] = []
