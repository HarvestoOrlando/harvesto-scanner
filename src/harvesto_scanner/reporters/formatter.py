"""
Output formatters — produce reports in multiple formats.

Supports:
- JSON (default, machine-readable)
- Markdown (human-readable audit report)
- evmbench format (compatible with paradigmxyz/evmbench harness)
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from harvesto_scanner.models import ScanResult, Finding, Severity


def to_json(result: ScanResult, indent: int = 2) -> str:
    """Produce JSON output compatible with standard tooling."""
    return json.dumps(result.to_dict(), indent=indent)


def to_markdown(result: ScanResult) -> str:
    """Produce a human-readable Markdown audit report."""
    lines = []
    lines.append("# Harvesto Scanner — Audit Report")
    lines.append(f"\n**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Files scanned:** {result.files_scanned}")
    lines.append(f"**SLOC:** {result.sloc_scanned}")
    lines.append(f"**Scan time:** {result.scan_time_seconds:.1f}s")
    lines.append(f"**Raw findings:** {result.total_raw_findings}")
    lines.append(f"**After filtering:** {result.filtered_findings}")
    lines.append(f"**FP reduction:** {result.fp_reduction_rate:.1%}")

    # Summary table
    severity_counts = {}
    for v in result.vulnerabilities:
        severity_counts[v.severity.value] = severity_counts.get(v.severity.value, 0) + 1

    lines.append("\n## Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["Critical", "High", "Medium", "Low"]:
        count = severity_counts.get(sev, 0)
        lines.append(f"| {sev} | {count} |")

    # Findings
    lines.append("\n## Findings\n")

    for v in result.vulnerabilities:
        lines.append(f"### [{v.id}] {v.title}\n")
        lines.append(f"**Severity:** {v.severity.value} | "
                     f"**Confidence:** {v.confidence}/100 | "
                     f"**Exploitable by:** {v.exploitable_by}")
        lines.append(f"\n**Impact:** {v.impact}")
        lines.append(f"\n**File:** `{v.file}` (lines {_format_lines(v.lines)})")
        lines.append(f"\n**Function:** `{v.function}()`")
        lines.append(f"\n**Description:**\n{v.description}")
        lines.append(f"\n**Recommendation:**\n{v.recommendation}")
        lines.append(f"\n**Detector:** `{v.detector}`")
        lines.append("\n---\n")

    if result.errors:
        lines.append("\n## Errors\n")
        for err in result.errors:
            lines.append(f"- {err}")

    return "\n".join(lines)


def to_evmbench(result: ScanResult) -> str:
    """
    Produce output compatible with the paradigmxyz/evmbench harness.

    evmbench expects a Markdown file containing a JSON block with:
    {"vulnerabilities": [...]}

    Each vulnerability object contains:
    - title: string
    - severity: "Critical" | "High" | "Medium" | "Low"
    - description: string
    - file: string (path to affected file)
    - lines: [int] (affected line numbers)
    - impact: string
    - recommendation: string
    """
    vulns = []
    for v in result.vulnerabilities:
        vulns.append({
            "title": v.title,
            "severity": v.severity.value,
            "description": v.description,
            "file": v.file,
            "lines": v.lines,
            "impact": v.impact,
            "recommendation": v.recommendation,
            "confidence": v.confidence,
        })

    json_block = json.dumps({"vulnerabilities": vulns}, indent=2)

    # evmbench format: Markdown with embedded JSON
    md_lines = [
        "# Vulnerability Report",
        "",
        f"**Scanner:** Harvesto Scanner v0.1.0",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Findings:** {len(vulns)}",
        "",
        "## Detailed Findings",
        "",
    ]

    for v in result.vulnerabilities:
        md_lines.append(f"### {v.title}")
        md_lines.append(f"- **Severity:** {v.severity.value}")
        md_lines.append(f"- **File:** `{v.file}`")
        md_lines.append(f"- **Impact:** {v.impact}")
        md_lines.append(f"- **Description:** {v.description}")
        md_lines.append(f"- **Recommendation:** {v.recommendation}")
        md_lines.append("")

    md_lines.append("## Machine-Readable Output")
    md_lines.append("")
    md_lines.append("```json")
    md_lines.append(json_block)
    md_lines.append("```")

    return "\n".join(md_lines)


def save_report(result: ScanResult, output_path: Path, fmt: str = "json") -> Path:
    """Save report to file in the specified format."""
    formatters = {
        "json": (to_json, ".json"),
        "markdown": (to_markdown, ".md"),
        "md": (to_markdown, ".md"),
        "evmbench": (to_evmbench, ".md"),
    }

    formatter, ext = formatters.get(fmt, (to_json, ".json"))
    content = formatter(result)

    if output_path.suffix != ext and not output_path.suffix:
        output_path = output_path.with_suffix(ext)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return output_path


def _format_lines(lines: list[int]) -> str:
    """Format line numbers nicely: [1,2,3,5,6] -> '1-3, 5-6'."""
    if not lines:
        return "N/A"

    ranges = []
    start = lines[0]
    end = lines[0]

    for line in lines[1:]:
        if line == end + 1:
            end = line
        else:
            ranges.append(f"{start}-{end}" if start != end else str(start))
            start = end = line

    ranges.append(f"{start}-{end}" if start != end else str(start))
    return ", ".join(ranges)
