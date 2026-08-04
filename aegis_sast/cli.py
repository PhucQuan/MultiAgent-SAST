"""Main CLI interface for Aegis-SAST."""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from aegis_sast.core.models import ScanResult
from aegis_sast.orchestration import ScanPipelineRequest, ScanPipelineService
from aegis_sast.orchestration.state import RepoProfile

console = Console()


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """Aegis-SAST command-line interface."""


@cli.command()
@click.argument("target_path", type=click.Path(exists=True))
@click.option("--rules", type=click.Path(exists=True), help="Custom rules file (YAML/JSON)")
@click.option(
    "--append-rules",
    multiple=True,
    type=click.Path(exists=True),
    help="Additional rules file to merge on top of the built-in rule set",
)
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
def scan(target_path, rules, append_rules, no_ai, max_depth, output, output_dir):
    """Scan a file or directory for security vulnerabilities."""
    console.print(
        Panel.fit(
            "[bold cyan]Aegis-SAST Security Scanner[/bold cyan]\n"
            "[dim]AI-powered static analysis tool[/dim]",
            border_style="cyan",
        )
    )

    request = ScanPipelineRequest(
        target_path=Path(target_path),
        rules_path=Path(rules) if rules else None,
        append_rules_paths=[Path(path) for path in append_rules],
        enable_ai_verification=not no_ai,
        max_analysis_depth=max_depth,
        output_formats=list(output),
        output_dir=Path(output_dir),
    )

    if rules or append_rules:
        console.print(
            "[dim]Rule controls:[/dim] "
            f"replace={rules or 'none'} "
            f"append={', '.join(append_rules) or 'none'}"
        )

    console.print(f"\n[yellow]Scanning:[/yellow] {request.target_path}\n")

    service = ScanPipelineService()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running scan pipeline...", total=None)
        pipeline_result = service.run(request)
        progress.update(task, description="Pipeline complete")

    _display_analyzer_status(
        pipeline_result.supported_languages,
        pipeline_result.import_failures,
    )
    _display_repo_profile(pipeline_result.repo_profile)

    if no_ai:
        console.print("[dim]AI verification disabled[/dim]")
    elif pipeline_result.ai_enabled:
        console.print("[green]OK[/green] AI verification enabled")
    elif pipeline_result.ai_error:
        console.print(f"[red]AI verification unavailable:[/red] {pipeline_result.ai_error}")
        console.print("[yellow]Continuing without AI verification[/yellow]")
    else:
        console.print("[dim]AI verification unavailable for this run[/dim]")

    if pipeline_result.ai_enabled and pipeline_result.scan_result.vulnerabilities:
        console.print(
            f"\n[yellow]AI Verification:[/yellow] "
            f"{len(pipeline_result.scan_result.vulnerabilities)} findings\n"
        )

    if pipeline_result.scan_result.vulnerabilities:
        console.print(
            f"\n[yellow]Knowledge-Assisted Triage:[/yellow] "
            f"{len(pipeline_result.scan_result.vulnerabilities)} findings\n"
        )
        _display_triage_summary(
            pipeline_result.workflow_metadata.get("triage_summary", {})
        )
        _display_route_summary(
            pipeline_result.workflow_metadata.get("route_summary", {})
        )

    console.print("\n" + "=" * 60 + "\n")
    _display_summary(pipeline_result.scan_result)

    if pipeline_result.exported_reports:
        console.print("\n[yellow]Generated reports:[/yellow]\n")
        for format_name, output_path in pipeline_result.exported_reports.items():
            console.print(
                f"[green]OK[/green] {format_name.upper()} report: {output_path}"
            )

    console.print("\n" + "=" * 60 + "\n")
    if pipeline_result.exit_code == 2:
        console.print("[red bold]Critical vulnerabilities found[/red bold]")
        sys.exit(2)
    if pipeline_result.exit_code == 1:
        console.print("[yellow]Vulnerabilities found[/yellow]")
        sys.exit(1)

    console.print("[green]No vulnerabilities detected[/green]")
    sys.exit(0)


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


def _display_analyzer_status(
    supported_languages: list[str],
    import_failures: dict[str, str],
) -> None:
    """Display which built-in analyzers are currently available."""
    table = Table(
        title="Analyzer Availability",
        show_header=True,
        header_style="bold yellow",
    )
    table.add_column("Language", style="yellow")
    table.add_column("Status")
    table.add_column("Detail")

    enabled = set(supported_languages)

    for language in ["python", "javascript", "java", "php"]:
        if language in enabled:
            table.add_row(language, "[green]enabled[/green]", "plugin loaded")
            continue

        detail = import_failures.get(language, "not registered")
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
