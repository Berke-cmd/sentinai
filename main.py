import asyncio
import argparse
from scanner import SecurityScanner
from models import TargetAuditReport
from reporter import AuditReporter

async def run_audit(target: str, output: str = None):
    scanner = SecurityScanner(target)
    headers, audit_results, ssl_valid = await scanner.scan()

    server_banner = headers.get("Server", headers.get("server", "Unknown"))

    report = TargetAuditReport(
        target_url=scanner.target_url,
        server_banner=server_banner,
        ssl_valid=ssl_valid,
        headers_analyzed=audit_results,
        cves_found=[]
    )

    AuditReporter.render_cli(report)

    if output:
        AuditReporter.export_json(report, output)

def main():
    parser = argparse.ArgumentParser(description="SentinAI - Asenkron Web Güvenliği Analiz Motoru")
    parser.add_argument("-t", "--target", required=True, help="Hedef URL")
    parser.add_argument("-o", "--output", help="Raporun kaydedileceği JSON dosya adı")
    args = parser.parse_args()

    asyncio.run(run_audit(args.target, args.output))

if __name__ == "__main__":
    main()
