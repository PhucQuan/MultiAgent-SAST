"""
Main CLI interface for Aegis-SAST.

Provides command-line interface for security scanning.
"""

import sys
from pathlib import Path
import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.table import Table

from aegis_sast.core.config import get_config, set_config, AegisConfig
from aegis_sast.core.registry import get_registry
from aegis_sast.plugins.python_plugin import PythonPlugin
from aegis_sast.analysis.rule_engine import RuleEngine
from aegis_sast.analysis.vulnerability_detector import VulnerabilityDetector
from aegis_sast.ai.gemini_client import GeminiClient
from aegis_sast.reporting.json_exporter import JSONExporter
from aegis_sast.reporting.markdown_exporter import MarkdownExporter

console = Console()


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """🔒 Aegis-SAST - AI-Powered Static Application Security Testing"""
    pass


@cli.command()
@click.argument('target_path', type=click.Path(exists=True))
@click.option('--rules', type=click.Path(exists=True), help='Custom rules file (YAML/JSON)')
@click.option('--no-ai', is_flag=True, help='Disable AI verification (faster, less accurate)')
@click.option('--max-depth', type=int, default=5, help='Maximum analysis depth (default: 5)')
@click.option('-o', '--output', multiple=True, type=click.Choice(['json', 'markdown']), 
              default=['json', 'markdown'], help='Output formats')
@click.option('--output-dir', type=click.Path(), default='reports', help='Output directory')
def scan(target_path, rules, no_ai, max_depth, output, output_dir):
    """
    Scan directory or file for security vulnerabilities.
    
    TARGET_PATH: Path to directory or file to scan
    """
    console.print(Panel.fit(
        "[bold cyan]🔒 Aegis-SAST Security Scanner[/bold cyan]\n"
        "[dim]AI-Powered Static Analysis Tool[/dim]",
        border_style="cyan"
    ))
    
    target = Path(target_path)
    
    # Configure settings
    config = get_config()
    
    if no_ai:
        config.enable_ai_verification = False
    
    config.max_analysis_depth = max_depth
    config.output_formats = list(output)
    config.output_dir = Path(output_dir)
    
    if rules:
        config.custom_rules_path = Path(rules)
    
    set_config(config)
    
    # Initialize components
    console.print("\n[yellow]⚙️ Initializing...[/yellow]")
    
    # Register plugins
    registry = get_registry()
    try:
        registry.register(PythonPlugin())
    except ValueError:
        pass  # Already registered
    
    # Load rules
    rule_engine = RuleEngine(config.custom_rules_path)
    
    # Create detector
    detector = VulnerabilityDetector(rule_engine, max_depth)
    
    # Initialize AI client if enabled
    ai_client = None
    if config.enable_ai_verification:
        try:
            ai_client = GeminiClient()
            console.print("[green]✓[/green] AI verification enabled")
        except Exception as e:
            console.print(f"[red]✗[/red] AI verification failed: {e}")
            console.print("[yellow]Continuing without AI verification[/yellow]")
            config.enable_ai_verification = False
    else:
        console.print("[dim]AI verification disabled[/dim]")
    
    # Scan
    console.print(f"\n[yellow]🔍 Scanning:[/yellow] {target}\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Analyzing files...", total=None)
        
        # Analyze
        if target.is_dir():
            scan_result = detector.analyze_directory(target)
        else:
            # Single file
            vulns = detector.analyze_file(target)
            from datetime import datetime
            from aegis_sast.core.models import ScanResult
            scan_result = ScanResult(
                target_path=str(target),
                start_time=datetime.now(),
                end_time=datetime.now(),
                vulnerabilities=vulns,
                files_scanned=1
            )
        
        progress.update(task, description="Analysis complete!")
    
    # AI Verification
    if ai_client and scan_result.vulnerabilities:
        console.print(f"\n[yellow]🤖 AI Verification:[/yellow] {len(scan_result.vulnerabilities)} findings\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            verify_task = progress.add_task("Verifying vulnerabilities...", total=len(scan_result.vulnerabilities))
            
            for vuln in scan_result.vulnerabilities:
                # Get AI verification
                ai_result = ai_client.verify_vulnerability(
                    vuln_type=vuln.vuln_type,
                    source_code=vuln.dataflow.source.location.code_snippet,
                    dataflow_path=vuln.dataflow.get_path_summary(),
                    sink_code=vuln.dataflow.sink.location.code_snippet
                )
                
                vuln.ai_verification = ai_result
                progress.advance(verify_task)
    
    # Display summary
    console.print("\n" + "="*60 + "\n")
    _display_summary(scan_result)
    
    # Export reports
    console.print(f"\n[yellow]📝 Generating reports...[/yellow]\n")
    
    export_paths = []
    
    if 'json' in config.output_formats:
        json_exporter = JSONExporter(config.output_dir)
        json_path = json_exporter.export(scan_result)
        export_paths.append(json_path)
        console.print(f"[green]✓[/green] JSON report: {json_path}")
    
    if 'markdown' in config.output_formats:
        md_exporter = MarkdownExporter(config.output_dir)
        md_path = md_exporter.export(scan_result)
        export_paths.append(md_path)
        console.print(f"[green]✓[/green] Markdown report: {md_path}")
    
    # Exit code
    console.print("\n" + "="*60 + "\n")
    
    if scan_result.critical_count > 0:
        console.print("[red bold]⚠️ CRITICAL vulnerabilities found![/red bold]")
        sys.exit(2)
    elif scan_result.total_vulnerabilities > 0:
        console.print("[yellow]⚠️ Vulnerabilities found[/yellow]")
        sys.exit(1)
    else:
        console.print("[green]✓ No vulnerabilities detected[/green]")
        sys.exit(0)


def _display_summary(scan_result):
    """Display scan summary in a table."""
    table = Table(title="Scan Summary", show_header=True, header_style="bold cyan")
    
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    
    table.add_row("Target", scan_result.target_path)
    table.add_row("Files Scanned", str(scan_result.files_scanned))
    table.add_row("Duration", f"{scan_result.duration:.2f}s")
    table.add_row("", "")
    table.add_row("Total Findings", str(scan_result.total_vulnerabilities))
    
    if scan_result.critical_count > 0:
        table.add_row("🔴 Critical", f"[red bold]{scan_result.critical_count}[/red bold]")
    
    if scan_result.high_count > 0:
        table.add_row("🟠 High", f"[red]{scan_result.high_count}[/red]")
    
    if scan_result.medium_count > 0:
        table.add_row("🟡 Medium", f"[yellow]{scan_result.medium_count}[/yellow]")
    
    if scan_result.low_count > 0:
        table.add_row("🔵 Low", f"[blue]{scan_result.low_count}[/blue]")
    
    console.print(table)


def main():
    """Main entry point."""
    try:
        cli()
    except Exception as e:
        console.print(f"\n[red bold]Error:[/red bold] {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
