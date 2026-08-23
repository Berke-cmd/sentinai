import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from models import TargetAuditReport

console = Console()

class AuditReporter:
    @staticmethod
    def render_cli(report: TargetAuditReport):
        status_color = "green" if report.ssl_valid else "red"
        status_text = "VALID" if report.ssl_valid else "INVALID"
        
        console.print(Panel(
            f"[bold cyan]SentinAI Audit Report[/bold cyan]\n"
            f"Target: [yellow]{report.target_url}[/yellow] | "
            f"Server: [green]{report.server_banner}[/green] | "
            f"SSL: [{status_color}]{status_text}[/{status_color}]",
            expand=False
        ))

        h_table = Table(title="Security Headers", header_style="bold blue")
        h_table.add_column("Header", style="cyan")
        h_table.add_column("Status", justify="center")

        for h in report.headers_analyzed:
            status_style = "[green]PRESENT[/green]" if h.status == "PRESENT" else "[red]MISSING[/red]"
            h_table.add_row(h.header, status_style)

        console.print(h_table)

        if report.cves_found:
            c_table = Table(title="CVE Vulnerabilities", header_style="bold red")
            c_table.add_column("CVE ID", style="magenta")
            c_table.add_column("CVSS", justify="center", style="yellow")
            c_table.add_column("Summary", style="white")

            for c in report.cves_found:
                c_table.add_row(c.cve_id, c.severity, c.summary)

            console.print(c_table)

    @staticmethod
    def export_json(report: TargetAuditReport, output_path: str):
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report.model_dump(), f, indent=4)
        console.print(f"\n[green]JSON report saved: '{output_path}'[/green]")
