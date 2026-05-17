"""Typer CLI for IP Intelligence Tool."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ip_intel import __version__
from config import settings
from core.input_handler import parse_ips
from core.pipeline import run_pipeline
from models import IPIntelligenceReport
from reporting.renderer import render_csv, render_html, render_json
from storage.database import Database
from utils.logger import setup_logging

app = typer.Typer(
    name="ip-intel",
    help="🛡  IP Intelligence & Malicious Detection Tool",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold blue]ip-intel[/] v{__version__}")
        raise typer.Exit()


# ── Analyze command ───────────────────────────────────────────────────────────


@app.command()
def analyze(
    ips: list[str] = typer.Argument(
        default=None,
        help="IP addresses to analyze (space-separated, comma-separated, or CIDR)",
    ),
    file: Optional[Path] = typer.Option(
        None, "--file", "-f",
        help="File containing IPs (one per line)",
        exists=True,
        readable=True,
    ),
    output: str = typer.Option(
        "json", "--output", "-o",
        help="Output format: json, csv, html",
    ),
    save: Optional[Path] = typer.Option(
        None, "--save", "-s",
        help="Save output to file",
    ),
    no_store: bool = typer.Option(
        False, "--no-store",
        help="Skip storing results in database",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Enable debug logging",
    ),
    version: Optional[bool] = typer.Option(
        None, "--version", "-V",
        help="Show version",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """🔍 Analyze IP addresses for threat intelligence and risk scoring."""
    # Setup logging
    level = "DEBUG" if verbose else settings.log_level
    setup_logging(level)

    # Collect sources
    sources: list[str] = []
    if ips:
        sources.extend(ips)
    if file:
        sources.append(str(file))

    if not sources:
        console.print(
            "[red]Error:[/] No IPs provided. Use positional args or --file.",
        )
        raise typer.Exit(code=1)

    # Parse and validate
    parsed = parse_ips(sources)
    if not parsed:
        console.print("[red]Error:[/] No valid IPs found in input.")
        raise typer.Exit(code=1)

    # Show banner
    console.print()
    console.print(
        Panel(
            f"[bold]Analyzing {len(parsed)} IP(s)[/]\n"
            f"[dim]VT: {'✅' if settings.has_virustotal() else '❌ (no key)'}  "
            f"AbuseIPDB: {'✅' if settings.has_abuseipdb() else '❌ (no key)'}  "
            f"Shodan: {'✅ API' if settings.has_shodan() else '🌐 InternetDB (free)'}  "
            f"Output: {output.upper()}[/]",
            title="🛡  IP Intelligence",
            border_style="blue",
        )
    )
    console.print()

    # Run the pipeline
    reports = []
    try:
        reports = asyncio.run(
            run_pipeline(parsed, store=not no_store)
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Process cancelled by user.[/]")
        console.print("[dim]Note: Partial results may have been saved to the database if caching is enabled.[/]")
        raise typer.Exit(code=1)

    if not reports:
        console.print("[yellow]Warning:[/] No results produced.")
        raise typer.Exit(code=1)

    # Render output
    output_fmt = output.lower()
    if output_fmt == "csv":
        rendered = render_csv(reports)
    elif output_fmt == "html":
        rendered = render_html(reports)
    else:
        rendered = render_json(reports)

    # Save or print
    if save:
        save.write_text(rendered, encoding="utf-8")
        console.print(f"\n[green]✓[/] Report saved to [bold]{save}[/]")
    else:
        if output_fmt == "html":
            # HTML is too long for terminal — auto-save
            default_path = Path("report.html")
            default_path.write_text(rendered, encoding="utf-8")
            console.print(
                f"\n[green]✓[/] HTML report saved to [bold]{default_path}[/]"
            )
        else:
            console.print(rendered)

    # Print summary table
    _print_summary(reports)
    _print_details(reports)


def _print_details(reports: list[IPIntelligenceReport]) -> None:
    """Print detailed intelligence context panels."""
    for r in reports:
        content = ""
        
        # Header: Attribution + Infrastructure
        infra = getattr(r.risk, 'infrastructure_type', None)
        attrib = getattr(r.risk, 'attribution_confidence', None)
        completeness = getattr(r.risk, 'data_completeness', None)
        threat = getattr(r.risk, 'threat_activity_score', None)
        
        header_parts = []
        if infra:
            header_parts.append(f"[bold]Infrastructure:[/] {infra.value.replace('_', ' ').title()}")
        if attrib is not None:
            color = "green" if attrib >= 90 else "yellow" if attrib >= 70 else "red"
            header_parts.append(f"[bold]Attribution Confidence:[/] [{color}]{attrib}%[/{color}]")
        if threat is not None:
            header_parts.append(f"[bold]Threat Activity:[/] {threat}/100")
        if completeness is not None:
            color = "green" if completeness >= 80 else "yellow" if completeness >= 40 else "red"
            header_parts.append(f"[bold]Data Completeness:[/] [{color}]{completeness}%[/{color}]")
        
        if header_parts:
            content += "  ".join(header_parts) + "\n\n"
        
        if r.risk.conflicts:
            content += "[bold yellow]⚠ Contradictions Detected:[/]\n"
            for c in r.risk.conflicts:
                content += f"  [yellow]• {c.severity.upper()}: {c.explanation}[/]\n"
            content += "\n"
        if r.risk.reasoning_chain:
            content += "[bold cyan]🧠 Analyst Reasoning:[/]\n"
            for reason in r.risk.reasoning_chain:
                content += f"  [dim]• {reason}[/]\n"
        
        if content.strip():
            console.print(Panel(content.strip(), title=f"[bold]Intelligence Context: {r.ip}[/]", border_style="dim", padding=(1, 2)))
    console.print()


def _print_summary(reports: list[IPIntelligenceReport]) -> None:
    """Print a rich summary table to the console."""
    console.print()

    table = Table(
        title="📊  Results Summary",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        padding=(0, 1),
    )
    table.add_column("IP", style="bold white", min_width=15)
    table.add_column("Score", justify="center", min_width=6)
    table.add_column("Classification", min_width=16)
    table.add_column("Attrib", justify="center", min_width=6)
    table.add_column("Infra", min_width=10)
    table.add_column("ASN", min_width=8)
    table.add_column("Country", justify="center", min_width=4)
    table.add_column("Time", justify="right", min_width=6)

    for r in reports:
        score = r.risk.score
        cls_val = r.risk.classification.value
        attrib = getattr(r.risk, 'attribution_confidence', 100)
        infra = getattr(r.risk, 'infrastructure_type', None)
        infra_str = infra.value.replace('_', ' ').title() if infra else "—"

        if cls_val == "Insufficient Data":
            score_style = "dim"
        elif score <= 20:
            score_style = "green"
        elif score <= 50:
            score_style = "yellow"
        elif score <= 75:
            score_style = "dark_orange"
        else:
            score_style = "red"
        
        attrib_style = "green" if attrib >= 90 else "yellow" if attrib >= 70 else "red"

        table.add_row(
            r.ip,
            f"[{score_style}]{score}[/{score_style}]",
            f"[{score_style}]{cls_val}[/{score_style}]",
            f"[{attrib_style}]{attrib}%[/{attrib_style}]",
            infra_str,
            r.ownership.asn or "—",
            r.ownership.country or "—",
            f"{r.query_duration_s}s",
        )

    console.print(table)
    console.print()


# ── Query command ─────────────────────────────────────────────────────────────


@app.command()
def query(
    ip: Optional[str] = typer.Option(
        None, "--ip", "-i",
        help="Query a specific IP from the database",
    ),
    classification: Optional[str] = typer.Option(
        None, "--classification", "-c",
        help="Filter by classification (Benign, Suspicious, Likely Malicious, Malicious)",
    ),
    all_records: bool = typer.Option(
        False, "--all", "-a",
        help="List all stored records",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Enable debug logging",
    ),
) -> None:
    """📂 Query stored IP intelligence from the database."""
    level = "DEBUG" if verbose else settings.log_level
    setup_logging(level)

    async def _query():
        db = Database()
        try:
            await db.connect()

            if ip:
                record = await db.get_by_ip(ip)
                if record:
                    import json
                    console.print_json(json.dumps(dict(record), default=str))
                else:
                    console.print(f"[yellow]No record found for {ip}[/]")

            elif classification:
                records = await db.get_by_classification(classification)
                if records:
                    for rec in records:
                        console.print(
                            f"  {rec['ip']:>16}  score={rec['score']:>3}  "
                            f"{rec['classification']:<18}  {rec['org'] or '—'}"
                        )
                else:
                    console.print(
                        f"[yellow]No records with classification '{classification}'[/]"
                    )

            elif all_records:
                records = await db.get_all()
                if records:
                    table = Table(
                        title="Stored IP Intelligence",
                        show_header=True,
                        header_style="bold cyan",
                    )
                    table.add_column("IP", style="bold")
                    table.add_column("Score", justify="center")
                    table.add_column("Classification")
                    table.add_column("Country", justify="center")
                    table.add_column("Organization")
                    table.add_column("Updated")

                    for rec in records:
                        table.add_row(
                            rec["ip"],
                            str(rec["score"]),
                            rec["classification"],
                            rec["country"] or "—",
                            (rec["org"] or "—")[:30],
                            rec["updated_at"][:10] if rec["updated_at"] else "—",
                        )
                    console.print(table)
                else:
                    console.print("[yellow]Database is empty[/]")

            else:
                console.print(
                    "[yellow]Specify --ip, --classification, or --all[/]"
                )

        finally:
            await db.close()

    asyncio.run(_query())


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
