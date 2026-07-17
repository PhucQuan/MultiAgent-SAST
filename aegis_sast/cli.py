"""Main CLI interface for Aegis-SAST."""

import asyncio
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from aegis_sast.analysis.rule_engine import RuleEngine
from aegis_sast.analysis.vulnerability_detector import VulnerabilityDetector
from aegis_sast.core.config import get_config, set_config
from aegis_sast.core.models import ScanResult
from aegis_sast.core.registry import get_registry
from aegis_sast.integrations import SARIFFormatter
from aegis_sast.knowledge import KnowledgeLoader
from aegis_sast.orchestration import RepoIntake, ScanWorkflow
from aegis_sast.orchestration.state import RepoProfile
from aegis_sast.reporting.json_exporter import JSONExporter
from aegis_sast.reporting.markdown_exporter import MarkdownExporter

console = Console()


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """Aegis-SAST command-line interface."""


@cli.command()
@click.argument("target_path", type=click.Path(exists=True))
@click.option("--rules", type=click.Path(exists=True), help="Custom rules file (YAML/JSON)")
@click.option("--no-ai", is_flag=True, help="Disable AI verification")
@click.option("--max-depth", type=int, default=5, help="Maximum analysis depth")
@click.option(
    "-o",
    "--output",
    multiple=True,
    type=click.Choice(["json", "markdown", "sarif"]),
    default=["json", "markdown"],
    help="Output formats",
)
@click.option("--output-dir", type=click.Path(), default="reports", help="Output directory")
def scan(target_path, rules, no_ai, max_depth, output, output_dir):
    """Scan a file or directory for security vulnerabilities."""
    console.print(
        Panel.fit(
            "[bold cyan]Aegis-SAST Security Scanner[/bold cyan]\n"
            "[dim]AI-powered static analysis tool[/dim]",
            border_style="cyan",
        )
    )

    target = Path(target_path)
    config = get_config()

    if no_ai:
        config.enable_ai_verification = False

    config.max_analysis_depth = max_depth
    config.output_formats = list(output)
    config.output_dir = Path(output_dir)

    if rules:
        config.custom_rules_path = Path(rules)

    set_config(config)

    console.print("\n[yellow]Initializing...[/yellow]")
    registry = get_registry()
    _display_analyzer_status(registry)
    repo_profile = RepoIntake(registry).analyze_target(target)
    _display_repo_profile(repo_profile)

    rule_engine = RuleEngine(config.custom_rules_path)
    detector = VulnerabilityDetector(rule_engine, max_depth)

    ai_client = None
    if config.enable_ai_verification:
        try:
            from aegis_sast.llm import GeminiClient

            ai_client = GeminiClient()
            console.print("[green]OK[/green] AI verification enabled")
        except Exception as exc:
            console.print(f"[red]AI verification unavailable:[/red] {exc}")
            console.print("[yellow]Continuing without AI verification[/yellow]")
            config.enable_ai_verification = False
    else:
        console.print("[dim]AI verification disabled[/dim]")

    console.print(f"\n[yellow]Scanning:[/yellow] {target}\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing files...", total=None)
        scan_result = _run_scan(detector, target)
        progress.update(task, description="Analysis complete")

    if ai_client and scan_result.vulnerabilities:
        console.print(
            f"\n[yellow]AI Verification:[/yellow] "
            f"{len(scan_result.vulnerabilities)} findings\n"
        )
        asyncio.run(_verify_all(ai_client, scan_result))

    triage_records = []
    workflow_metadata = None
    if scan_result.vulnerabilities:
        console.print(
            f"\n[yellow]Knowledge-Assisted Triage:[/yellow] "
            f"{len(scan_result.vulnerabilities)} findings\n"
        )
        workflow_state = ScanWorkflow(KnowledgeLoader()).run(
            scan_result,
            repo_profile=repo_profile,
        )
        triage_records = workflow_state.triage_records
        workflow_metadata = workflow_state.metadata
        _display_triage_summary(workflow_state.metadata.get("triage_summary", {}))
        _display_route_summary(workflow_state.metadata.get("route_summary", {}))

    console.print("\n" + "=" * 60 + "\n")
    _display_summary(scan_result)

    console.print("\n[yellow]Generating reports...[/yellow]\n")
    _export_reports(
        config.output_formats,
        config.output_dir,
        scan_result,
        triage_records,
        workflow_metadata=workflow_metadata,
    )

    console.print("\n" + "=" * 60 + "\n")
    if scan_result.critical_count > 0:
        console.print("[red bold]Critical vulnerabilities found[/red bold]")
        sys.exit(2)
    if scan_result.total_vulnerabilities > 0:
        console.print("[yellow]Vulnerabilities found[/yellow]")
        sys.exit(1)

    console.print("[green]No vulnerabilities detected[/green]")
    sys.exit(0)


def _run_scan(detector: VulnerabilityDetector, target: Path) -> ScanResult:
    """Run the detector against the provided target."""
    if target.is_dir():
        return detector.analyze_directory(target)

    vulnerabilities = detector.analyze_file(target)
    return ScanResult(
        target_path=str(target),
        start_time=datetime.now(),
        end_time=datetime.now(),
        vulnerabilities=vulnerabilities,
        files_scanned=1,
    )


async def _verify_all(ai_client: Any, scan_result: ScanResult) -> None:
    """Verify all findings concurrently with the configured AI client."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        verify_task = progress.add_task(
            "Verifying vulnerabilities...",
            total=len(scan_result.vulnerabilities),
        )

        tasks = []
        for vuln in scan_result.vulnerabilities:
            tasks.append(
                ai_client.async_verify_vulnerability(
                    vuln_type=vuln.vuln_type,
                    source_code=vuln.dataflow.source.location.code_snippet,
                    dataflow_path=vuln.dataflow.get_path_summary(),
                    sink_code=vuln.dataflow.sink.location.code_snippet,
                )
            )

        results = await asyncio.gather(*tasks)
        for index, result in enumerate(results):
            scan_result.vulnerabilities[index].ai_verification = result
            progress.advance(verify_task)


def _export_reports(
    output_formats,
    output_dir,
    scan_result,
    triage_records,
    workflow_metadata=None,
) -> None:
    """Export reports in the requested formats."""
    if "json" in output_formats:
        json_path = JSONExporter(output_dir).export(
            scan_result,
            triage_records=triage_records,
            workflow_metadata=workflow_metadata,
        )
        console.print(f"[green]OK[/green] JSON report: {json_path}")

    if "markdown" in output_formats:
        markdown_path = MarkdownExporter(output_dir).export(
            scan_result,
            triage_records=triage_records,
            workflow_metadata=workflow_metadata,
        )
        console.print(f"[green]OK[/green] Markdown report: {markdown_path}")

    if "sarif" in output_formats:
        sarif_path = SARIFFormatter(output_dir).export(
            scan_result,
            triage_records=triage_records,
            workflow_metadata=workflow_metadata,
        )
        console.print(f"[green]OK[/green] SARIF report: {sarif_path}")


def _display_summary(scan_result: ScanResult) -> None:
    """Display a scan summary table."""
    table = Table(title="Scan Summary", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Target", scan_result.target_path)
    table.add_row("Files Scanned", str(scan_result.files_scanned))
    table.add_row("Duration", f"{scan_result.duration:.2f}s")
    table.add_row("", "")
    table.add_row("Total Findings", str(scan_result.total_vulnerabilities))

    if scan_result.critical_count > 0:
        table.add_row("Critical", str(scan_result.critical_count))
    if scan_result.high_count > 0:
        table.add_row("High", str(scan_result.high_count))
    if scan_result.medium_count > 0:
        table.add_row("Medium", str(scan_result.medium_count))
    if scan_result.low_count > 0:
        table.add_row("Low", str(scan_result.low_count))

    console.print(table)


def _display_repo_profile(repo_profile: RepoProfile) -> None:
    """Display the detected repo profile before scanning."""
    table = Table(title="Repo Intake", show_header=True, header_style="bold green")
    table.add_column("Field", style="green")
    table.add_column("Value")

    languages = ", ".join(repo_profile.detected_languages) or "none"
    frameworks = ", ".join(repo_profile.framework_hints) or "none"
    analysis_plan = repo_profile.metadata.get("analysis_plan", {})
    if analysis_plan:
        analysis_value = ", ".join(
            f"{language}:{depth}" for language, depth in sorted(analysis_plan.items())
        )
    else:
        analysis_value = "none"

    table.add_row("Scan Profile", repo_profile.scan_profile)
    table.add_row("Languages", languages)
    table.add_row("Framework Hints", frameworks)
    table.add_row("Analysis Plan", analysis_value)
    table.add_row(
        "Supported Files",
        str(repo_profile.metadata.get("supported_file_count", repo_profile.files_scanned)),
    )

    console.print(table)


def _display_analyzer_status(registry) -> None:
    """Display which built-in analyzers are currently available."""
    table = Table(
        title="Analyzer Availability",
        show_header=True,
        header_style="bold yellow",
    )
    table.add_column("Language", style="yellow")
    table.add_column("Status")
    table.add_column("Detail")

    enabled = set(registry.get_supported_languages())
    failures = registry.get_import_failures()

    for language in ["python", "javascript", "java", "php"]:
        if language in enabled:
            table.add_row(language, "[green]enabled[/green]", "plugin loaded")
            continue

        detail = failures.get(language, "not registered")
        table.add_row(language, "[red]missing[/red]", detail)

    console.print(table)


def _display_triage_summary(summary: dict) -> None:
    """Display a triage summary table."""
    table = Table(title="Triage Summary", show_header=True, header_style="bold magenta")
    table.add_column("Status", style="magenta")
    table.add_column("Count", justify="right")

    for status in ["confirmed", "likely", "needs-review", "suppressed"]:
        table.add_row(status, str(summary.get(status, 0)))

    console.print(table)


def _display_route_summary(summary: dict) -> None:
    """Display how findings were routed through the workflow."""
    table = Table(title="Workflow Routes", show_header=True, header_style="bold blue")
    table.add_column("Route", style="blue")
    table.add_column("Count", justify="right")

    for route_id in ["direct-judge", "skeptic-review"]:
        if route_id in summary:
            table.add_row(route_id, str(summary.get(route_id, 0)))

    if not summary:
        table.add_row("none", "0")

    console.print(table)


def main():
    """Main entry point."""
    try:
        cli()
    except Exception as exc:
        console.print(f"\n[red bold]Error:[/red bold] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
