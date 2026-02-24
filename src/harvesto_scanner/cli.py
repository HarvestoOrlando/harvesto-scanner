"""
CLI entry point for Harvesto Scanner.

Usage:
    harvesto scan ./contracts/
    harvesto scan ./contracts/ --format markdown --output report.md
    harvesto scan ./contracts/ --severity critical  # only criticals
    harvesto bench ./audit/ --output submission/audit.md
"""

import sys
import json
from pathlib import Path

try:
    import click
    from rich.console import Console
    from rich.table import Table
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    click = None

from harvesto_scanner.scanner import HarvestoScanner
from harvesto_scanner.models import Severity, ScanResult
from harvesto_scanner.reporters.formatter import to_json, to_markdown, to_evmbench, save_report
from harvesto_scanner.fuzzer.generator import FuzzGenerator


def _print_results_plain(result: ScanResult):
    """Fallback plain text output when rich isn't installed."""
    print(f"\n{'='*60}")
    print(f"Harvesto Scanner Results")
    print(f"{'='*60}")
    print(f"Files scanned: {result.files_scanned}")
    print(f"SLOC: {result.sloc_scanned}")
    print(f"Scan time: {result.scan_time_seconds:.1f}s")
    print(f"Raw findings: {result.total_raw_findings}")
    print(f"After filtering: {result.filtered_findings}")
    print(f"FP reduction: {result.fp_reduction_rate:.1%}")
    print()

    for v in result.vulnerabilities:
        print(f"[{v.id}] {v.severity.value.upper()}: {v.title}")
        print(f"  File: {v.file} (line {v.lines[0] if v.lines else '?'})")
        print(f"  Confidence: {v.confidence}/100")
        print(f"  Impact: {v.impact}")
        print(f"  Exploitable by: {v.exploitable_by}")
        print()


def _print_results_rich(result: ScanResult):
    """Rich-formatted terminal output."""
    console = Console()

    # Header
    console.print("\n[bold cyan]━━━ Harvesto Scanner Results ━━━[/bold cyan]\n")

    # Stats
    stats_table = Table(show_header=False, box=None, padding=(0, 2))
    stats_table.add_column(style="dim")
    stats_table.add_column()
    stats_table.add_row("Files scanned", str(result.files_scanned))
    stats_table.add_row("SLOC", str(result.sloc_scanned))
    stats_table.add_row("Scan time", f"{result.scan_time_seconds:.1f}s")
    stats_table.add_row("Raw findings", str(result.total_raw_findings))
    stats_table.add_row("After filtering", str(result.filtered_findings))
    stats_table.add_row("FP reduction", f"{result.fp_reduction_rate:.1%}")
    console.print(stats_table)
    console.print()

    if not result.vulnerabilities:
        console.print("[green]✓ No vulnerabilities found after filtering.[/green]")
        return

    # Findings table
    severity_colors = {
        "Critical": "bold red",
        "High": "red",
        "Medium": "yellow",
        "Low": "blue",
    }

    findings_table = Table(title="Findings", show_lines=True)
    findings_table.add_column("ID", style="dim", width=14)
    findings_table.add_column("Severity", width=10)
    findings_table.add_column("Title", width=45)
    findings_table.add_column("File", width=30)
    findings_table.add_column("Conf", width=5, justify="right")

    for v in result.vulnerabilities:
        sev_style = severity_colors.get(v.severity.value, "white")
        findings_table.add_row(
            v.id,
            f"[{sev_style}]{v.severity.value}[/{sev_style}]",
            v.title,
            f"{v.file}:{v.lines[0] if v.lines else '?'}",
            str(v.confidence),
        )

    console.print(findings_table)

    # Detail per finding
    console.print("\n[bold]Details:[/bold]\n")
    for v in result.vulnerabilities:
        sev_style = severity_colors.get(v.severity.value, "white")
        console.print(f"[{sev_style}]■[/{sev_style}] [{sev_style}]{v.id}[/{sev_style}] {v.title}")
        console.print(f"  [dim]Impact:[/dim] {v.impact}")
        console.print(f"  [dim]Exploitable by:[/dim] {v.exploitable_by}")
        console.print(f"  [dim]Description:[/dim] {v.description[:200]}...")
        console.print(f"  [dim]Recommendation:[/dim] {v.recommendation[:200]}")
        console.print()


def main():
    """Entry point — works with or without Click/Rich."""
    if click is None:
        _main_simple()
    else:
        _main_click()


def _main_simple():
    """Minimal CLI without Click."""
    import argparse
    parser = argparse.ArgumentParser(description="Harvesto Scanner")
    parser.add_argument("command", choices=["scan", "bench"])
    parser.add_argument("target", help="Path to .sol file or directory")
    parser.add_argument("--format", "-f", default="json", choices=["json", "markdown", "evmbench"])
    parser.add_argument("--output", "-o", default=None)
    parser.add_argument("--severity", "-s", default="low", choices=["critical", "high", "medium", "low"])
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--solc", default=None)
    args = parser.parse_args()

    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }

    scanner = HarvestoScanner(
        min_severity=severity_map[args.severity],
        solc_version=args.solc,
        verbose=args.verbose,
    )

    result = scanner.scan(Path(args.target))

    fmt = "evmbench" if args.command == "bench" else args.format

    if args.output:
        out_path = save_report(result, Path(args.output), fmt)
        print(f"Report saved to: {out_path}")
    else:
        if fmt == "json":
            print(to_json(result))
        elif fmt in ("markdown", "md"):
            print(to_markdown(result))
        elif fmt == "evmbench":
            print(to_evmbench(result))

    _print_results_plain(result)


def _main_click():
    """Full CLI with Click + Rich."""

    @click.group()
    def cli():
        """Harvesto Scanner — Precision-first smart contract vulnerability detector."""
        pass

    @cli.command()
    @click.argument("target", type=click.Path(exists=True))
    @click.option("--format", "-f", "fmt", default="json",
                  type=click.Choice(["json", "markdown", "md", "evmbench"]))
    @click.option("--output", "-o", type=click.Path(), default=None)
    @click.option("--severity", "-s", default="low",
                  type=click.Choice(["critical", "high", "medium", "low"]))
    @click.option("--confidence", "-c", type=int, default=50,
                  help="Minimum confidence threshold (0-100)")
    @click.option("--solc", default=None, help="Solidity compiler version")
    @click.option("--verbose", "-v", is_flag=True)
    def scan(target, fmt, output, severity, confidence, solc, verbose):
        """Scan contracts for vulnerabilities."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }

        scanner = HarvestoScanner(
            confidence_threshold=confidence,
            min_severity=severity_map[severity],
            solc_version=solc,
            verbose=verbose,
        )

        result = scanner.scan(Path(target))

        if output:
            out_path = save_report(result, Path(output), fmt)
            click.echo(f"Report saved to: {out_path}")
        else:
            if fmt == "json":
                click.echo(to_json(result))
            elif fmt in ("markdown", "md"):
                click.echo(to_markdown(result))
            elif fmt == "evmbench":
                click.echo(to_evmbench(result))

        if HAS_RICH:
            _print_results_rich(result)
        else:
            _print_results_plain(result)

    @cli.command()
    @click.argument("target", type=click.Path(exists=True))
    @click.option("--output", "-o", type=click.Path(), default="submission/audit.md")
    @click.option("--solc", default=None)
    @click.option("--verbose", "-v", is_flag=True)
    def bench(target, output, solc, verbose):
        """Scan and output in evmbench format for benchmarking."""
        scanner = HarvestoScanner(
            min_severity=Severity.LOW,
            solc_version=solc,
            verbose=verbose,
        )

        result = scanner.scan(Path(target))
        out_path = save_report(result, Path(output), "evmbench")
        click.echo(f"evmbench report saved to: {out_path}")

        if HAS_RICH:
            _print_results_rich(result)
        else:
            _print_results_plain(result)

    @cli.command()
    @click.argument("scan_result", type=click.Path(exists=True))
    @click.option("--output", "-o", type=click.Path(), default="test/fuzzing")
    @click.option("--mode", "-m", type=click.Choice(["foundry", "echidna", "poc"]), default="foundry")
    @click.option("--finding", "-f", type=str, default=None, help="Generate for specific finding ID only")
    @click.option("--rpc-url", type=str, default=None, help="RPC URL for mainnet fork (e.g. $ALCHEMY_RPC_URL)")
    @click.option("--target-address", type=str, default=None, help="Deployed contract address (0x...)")
    @click.option("--block", type=int, default=None, help="Block number to fork at")
    def fuzz(scan_result, output, mode, finding, rpc_url, target_address, block):
        """Generate fuzz tests or PoC from scan results.

        Takes a JSON scan result file and generates Foundry invariant tests,
        Echidna property tests, or full PoC exploit contracts.

        \b
        Examples:
            harvesto fuzz results.json                                    # scaffold (needs manual editing)
            harvesto fuzz results.json --rpc-url $RPC --target-address 0x... --block 24519191  # mainnet-ready
            harvesto fuzz results.json --mode poc -f HARVESTO-0001 --rpc-url $RPC --target-address 0x... --block 24519191
        """
        # Build fork config if provided
        fork_config = None
        if rpc_url and target_address and block:
            fork_config = {
                "rpc_url": rpc_url,
                "target_address": target_address,
                "block": block,
            }
        elif any([rpc_url, target_address, block]) and not all([rpc_url, target_address, block]):
            click.echo("Error: --rpc-url, --target-address, and --block must ALL be provided together.")
            click.echo("  Example: harvesto fuzz results.json --rpc-url $ALCHEMY_RPC_URL --target-address 0x62De... --block 24519191")
            return

        gen = FuzzGenerator(fork_config=fork_config)
        scan_path = Path(scan_result)
        out_dir = Path(output)

        # Load findings
        data = json.loads(scan_path.read_text())
        findings = data.get("vulnerabilities", [])

        if finding:
            findings = [f for f in findings if f.get("id") == finding]
            if not findings:
                click.echo(f"Finding {finding} not found in scan results.")
                return

        fork_label = "mainnet fork" if fork_config else "scaffold (fill in addresses manually)"
        click.echo(f"Generating {mode} tests for {len(findings)} findings ({fork_label})...")
        generated = gen.generate_from_findings(findings, out_dir, mode)

        click.echo(f"\nGenerated {len(generated)} test files in {out_dir}/:")
        for t in generated:
            click.echo(f"  {t.filename} — {t.description}")

        click.echo(f"\nRun with:")
        if mode in ("foundry", "poc"):
            if fork_config:
                click.echo(f"  forge test --match-path {out_dir}/*.t.sol -vvvv")
            else:
                click.echo(f"  forge test --match-path {out_dir}/*.t.sol -vvvv --fork-url $RPC_URL --fork-block-number BLOCK")
        elif mode == "echidna":
            click.echo(f"  echidna {out_dir}/<file>.sol --contract <ContractName>")

    @cli.command()
    @click.argument("target", type=click.Path(exists=True))
    @click.option("--output", "-o", type=click.Path(), default="test/fuzzing")
    @click.option("--mode", "-m", type=click.Choice(["foundry", "echidna", "poc"]), default="foundry")
    @click.option("--severity", "-s", default="low",
                  type=click.Choice(["critical", "high", "medium", "low"]))
    @click.option("--rpc-url", type=str, default=None, help="RPC URL for mainnet fork")
    @click.option("--target-address", type=str, default=None, help="Deployed contract address")
    @click.option("--block", type=int, default=None, help="Block number to fork at")
    @click.option("--verbose", "-v", is_flag=True)
    def scan_and_fuzz(target, output, mode, severity, rpc_url, target_address, block, verbose):
        """Scan contracts AND generate fuzz tests in one step.

        Combines scan + fuzz: detects vulnerabilities, then immediately
        generates test harnesses to confirm them.

        \b
        Example:
            harvesto scan-and-fuzz ./contracts/ --mode poc -s critical --rpc-url $RPC --target-address 0x... --block 12345
        """
        severity_map = {
            "critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW,
        }

        fork_config = None
        if rpc_url and target_address and block:
            fork_config = {"rpc_url": rpc_url, "target_address": target_address, "block": block}

        # Step 1: Scan
        scanner = HarvestoScanner(min_severity=severity_map[severity], verbose=verbose)
        result = scanner.scan(Path(target))

        if not result.vulnerabilities:
            click.echo("No vulnerabilities found. Nothing to fuzz.")
            return

        if HAS_RICH:
            _print_results_rich(result)
        else:
            _print_results_plain(result)

        # Step 2: Generate fuzz tests
        fork_label = "mainnet fork" if fork_config else "scaffold"
        click.echo(f"\nGenerating {mode} tests for {len(result.vulnerabilities)} findings ({fork_label})...")
        gen = FuzzGenerator(target_dir=Path(target), fork_config=fork_config)
        findings_dicts = [v.to_dict() for v in result.vulnerabilities]
        generated = gen.generate_from_findings(findings_dicts, Path(output), mode)

        click.echo(f"\nGenerated {len(generated)} test files in {output}/:")
        for t in generated:
            click.echo(f"  {t.filename}")

    cli()


if __name__ == "__main__":
    main()
