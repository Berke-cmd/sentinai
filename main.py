import asyncio
import argparse
from sentinai.scanner import SecurityScanner
from sentinai.cve_engine import CVEHunter
from sentinai.models import TargetAuditReport
from sentinai.reporter import AuditReporter

async def run_audit(target: str, output: str = None):
    scanner = SecurityScanner(target)
    headers, audit_results, ssl_valid = await scanner.scan()

    server_banner = headers.get("Server", headers.get("server", "Unknown"))
    cves = await CVEHunter.query_cve_by_service(server_banner)

    report = TargetAuditReport(
        target_url=scanner.target_url,
        server_banner=server_banner,
        ssl_valid=ssl_valid,
        headers_analyzed=audit_results,
        cves_found=cves
    )

    AuditReporter.render_cli(report)

    if output:
        AuditReporter.export_json(report, output)

def main():
    parser = argparse.ArgumentParser(description="SentinAI - Asenkron Web Güvenliği & CVE Analiz Motoru")
    parser.add_argument("-t", "--target", required=True, help="Hedef URL")
    parser.add_argument("-o", "--output", help="Raporun kaydedileceği JSON dosya adı")
    args = parser.parse_args()

    asyncio.run(run_audit(args.target, args.output))

if _name_ == "_main_":
    main()
