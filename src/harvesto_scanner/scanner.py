"""
Main scanner pipeline — orchestrates Pass 1 through Pass 5.

Pipeline:
  1. Slither static analysis (high recall)
  2. Custom pattern detectors (DeFi-specific)
  3. FP Filter Engine (aggressive precision filtering)
  4. Severity classification (Immunefi standard)
  5. Deduplication & consolidation
"""

import time
from pathlib import Path
from typing import Optional

from harvesto_scanner.models import Finding, Severity, ScanResult
from harvesto_scanner.detectors.slither_runner import run_slither, parse_slither_finding
from harvesto_scanner.detectors.custom_patterns import run_custom_detectors
from harvesto_scanner.detectors.advanced_patterns import run_advanced_detectors
from harvesto_scanner.analyzers.fp_filter import FPFilterEngine
from harvesto_scanner.analyzers.dedup import deduplicate


class HarvestoScanner:
    """Main scanner class. Feed it contracts, get verified findings."""

    def __init__(
        self,
        confidence_threshold: int = 50,
        min_severity: Severity = Severity.LOW,
        solc_version: Optional[str] = None,
        verbose: bool = False,
    ):
        self.confidence_threshold = confidence_threshold
        self.min_severity = min_severity
        self.solc_version = solc_version
        self.verbose = verbose

    def scan(self, target: Path) -> ScanResult:
        """
        Scan a target (file or directory) for vulnerabilities.

        Returns a ScanResult with verified, deduplicated findings.
        """
        start_time = time.time()
        target = Path(target).resolve()

        if not target.exists():
            return ScanResult(
                vulnerabilities=[],
                errors=[f"Target not found: {target}"],
            )

        # Collect all .sol files
        sol_files = self._collect_sol_files(target)
        if not sol_files:
            return ScanResult(
                vulnerabilities=[],
                errors=["No .sol files found in target"],
            )

        # Build source cache for FP filtering
        source_cache = self._build_source_cache(sol_files, target)
        sloc = sum(
            len([l for l in src.split("\n") if l.strip() and not l.strip().startswith("//")])
            for src in source_cache.values()
        )

        if self.verbose:
            print(f"[*] Found {len(sol_files)} .sol files ({sloc} SLOC)")

        # =============================================
        # Pass 1: Slither static analysis
        # =============================================
        if self.verbose:
            print("[*] Pass 1: Running Slither...")

        slither_raw = []
        try:
            slither_raw = run_slither(
                target if target.is_dir() else target.parent,
                self.solc_version,
            )
        except Exception as e:
            if self.verbose:
                print(f"[!] Slither error: {e}")

        slither_findings = []
        for i, raw in enumerate(slither_raw):
            finding = parse_slither_finding(raw, i + 1)
            if finding:
                slither_findings.append(finding)

        if self.verbose:
            print(f"    → {len(slither_raw)} raw detectors, {len(slither_findings)} mapped findings")

        # =============================================
        # Pass 2: Custom pattern detectors
        # =============================================
        if self.verbose:
            print("[*] Pass 2: Running custom detectors...")

        # Use relative paths in source cache
        custom_files = [Path(f) for f in source_cache.keys()]
        custom_findings = run_custom_detectors(
            [target / f if not Path(f).is_absolute() else Path(f) for f in source_cache.keys()],
            counter_start=len(slither_findings) + 1,
        )
        # Fix paths to relative
        for f in custom_findings:
            if target.is_dir():
                try:
                    f.file = str(Path(f.file).relative_to(target))
                except ValueError:
                    pass

        if self.verbose:
            print(f"    → {len(custom_findings)} custom findings")

        # =============================================
        # Pass 2b: Advanced pattern detectors (new categories)
        # =============================================
        if self.verbose:
            print("[*] Pass 2b: Running advanced detectors (MEV, tokens, governance, economic, cross-chain, L2)...")

        advanced_findings = run_advanced_detectors(
            [target / f if not Path(f).is_absolute() else Path(f) for f in source_cache.keys()],
            counter_start=len(slither_findings) + len(custom_findings) + 1,
        )
        for f in advanced_findings:
            if target.is_dir():
                try:
                    f.file = str(Path(f.file).relative_to(target))
                except ValueError:
                    pass

        if self.verbose:
            print(f"    → {len(advanced_findings)} advanced findings")

        # Combine all raw findings
        all_findings = slither_findings + custom_findings + advanced_findings
        total_raw = len(all_findings)

        if self.verbose:
            print(f"[*] Total raw findings: {total_raw}")

        # =============================================
        # Pass 3: FP Filter Engine
        # =============================================
        if self.verbose:
            print("[*] Pass 3: Running FP filter engine...")

        fp_engine = FPFilterEngine(source_cache)
        filtered = fp_engine.filter_all(all_findings)

        if self.verbose:
            print(f"    → {len(filtered)} survived filtering")
            for key, count in fp_engine.stats.items():
                if count > 0 and key not in ("total_input", "survived"):
                    print(f"      {key}: {count}")

        # =============================================
        # Pass 4: Severity threshold
        # =============================================
        severity_rank = {
            Severity.CRITICAL: 0, Severity.HIGH: 1,
            Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFORMATIONAL: 4,
        }
        min_rank = severity_rank.get(self.min_severity, 3)
        filtered = [f for f in filtered if severity_rank.get(f.severity, 4) <= min_rank]

        # =============================================
        # Pass 5: Deduplication
        # =============================================
        if self.verbose:
            print("[*] Pass 5: Deduplicating...")

        final = deduplicate(filtered)

        if self.verbose:
            print(f"    → {len(final)} final findings")

        elapsed = time.time() - start_time

        return ScanResult(
            vulnerabilities=final,
            total_raw_findings=total_raw,
            filtered_findings=len(final),
            scan_time_seconds=elapsed,
            files_scanned=len(sol_files),
            sloc_scanned=sloc,
        )

    def _collect_sol_files(self, target: Path) -> list[Path]:
        """Find all .sol files in target, excluding node_modules and lib."""
        if target.is_file():
            return [target] if target.suffix == ".sol" else []

        exclude_dirs = {"node_modules", "lib", ".git", "cache", "out", "artifacts", "build"}
        sol_files = []

        for f in target.rglob("*.sol"):
            # Skip excluded directories
            parts = set(f.relative_to(target).parts)
            if parts & exclude_dirs:
                continue
            sol_files.append(f)

        return sorted(sol_files)

    def _build_source_cache(self, sol_files: list[Path], target: Path) -> dict[str, str]:
        """Read all source files into memory for analysis."""
        cache = {}
        for f in sol_files:
            try:
                rel = str(f.relative_to(target)) if target.is_dir() else str(f.name)
                cache[rel] = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
        return cache
