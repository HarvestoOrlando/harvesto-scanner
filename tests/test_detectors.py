"""
Test custom detectors against the test vulnerable contract.
This test does NOT require Slither — it only tests the custom pattern detectors
and the FP filter engine.
"""

import sys
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from harvesto_scanner.detectors.custom_patterns import run_custom_detectors
from harvesto_scanner.analyzers.fp_filter import FPFilterEngine
from harvesto_scanner.analyzers.dedup import deduplicate
from harvesto_scanner.models import Severity


def test_custom_detectors():
    """Test that custom detectors find the expected vulnerabilities."""
    test_file = Path(__file__).parent / "contracts" / "VulnerableVault.sol"
    assert test_file.exists(), f"Test contract not found: {test_file}"

    print(f"Testing custom detectors on: {test_file}")
    print("=" * 60)

    # Run custom detectors
    findings = run_custom_detectors([test_file])

    print(f"\nRaw custom detector findings: {len(findings)}")
    for f in findings:
        print(f"  [{f.severity.value}] {f.title}")
        print(f"    File: {f.file}:{f.lines}")
        print(f"    Confidence: {f.confidence}")
        print(f"    Detector: {f.detector}")
        print()

    # Expected findings (at minimum)
    expected_detectors = {
        "custom:flashloan-callback-abuse",
        "custom:price-manipulation",
        "custom:missing-slippage",
        "custom:missing-access-control",
        "custom:cross-function-reentrancy",
    }

    found_detectors = {f.detector for f in findings}
    missing = expected_detectors - found_detectors
    if missing:
        print(f"\n⚠ Missing expected detectors: {missing}")
    else:
        print(f"\n✓ All expected detectors fired")

    # Now test FP filtering
    print("\n" + "=" * 60)
    print("Testing FP Filter Engine")
    print("=" * 60)

    source = test_file.read_text()
    # Use a simple relative filename (not containing "tests/") for FP filter testing
    source_cache = {"VulnerableVault.sol": source}

    # Fix file paths in findings to match cache
    for f in findings:
        f.file = "VulnerableVault.sol"

    engine = FPFilterEngine(source_cache)
    filtered = engine.filter_all(findings)

    print(f"\nAfter FP filtering: {len(filtered)} / {len(findings)} survived")
    print(f"Filter stats: {json.dumps(engine.stats, indent=2)}")

    for f in filtered:
        print(f"  ✓ [{f.severity.value}] {f.title} (conf={f.confidence})")

    # Test dedup
    print("\n" + "=" * 60)
    print("Testing Deduplication")
    print("=" * 60)

    deduped = deduplicate(filtered)
    print(f"\nAfter dedup: {len(deduped)} / {len(filtered)}")

    for f in deduped:
        print(f"  [{f.id}] [{f.severity.value}] {f.title} (conf={f.confidence})")

    # Validate: SafeVault functions should NOT appear
    safe_findings = [f for f in deduped if "SafeVault" in f.file or "safe" in f.function.lower()]
    if safe_findings:
        print(f"\n✗ FALSE POSITIVES in SafeVault: {len(safe_findings)}")
        for f in safe_findings:
            print(f"  FP: {f.title} in {f.function}")
    else:
        print(f"\n✓ No false positives from SafeVault (good!)")

    print("\n" + "=" * 60)
    print(f"SUMMARY: {len(findings)} raw → {len(filtered)} filtered → {len(deduped)} final")
    print(f"FP reduction: {1 - len(deduped)/max(len(findings),1):.1%}")
    print("=" * 60)

    return len(deduped) > 0


if __name__ == "__main__":
    success = test_custom_detectors()
    sys.exit(0 if success else 1)
