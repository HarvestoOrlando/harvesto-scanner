"""
Deduplication engine — collapse overlapping findings into single root-cause entries.

Multiple detectors often flag the same underlying issue. For example:
- Slither's reentrancy-eth AND our custom cross-function-reentrancy on the same function
- Multiple unchecked-transfer findings for the same transfer pattern
- Access control issues flagged by both Slither and custom detectors

We merge these into a single finding with the highest confidence and most specific info.
"""

from harvesto_scanner.models import Finding, Severity


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Group findings by root cause and keep the best representative.

    Root cause grouping:
    1. Same file + same function + related detector = same issue
    2. Same file + overlapping lines + same severity class = likely same issue
    """
    if not findings:
        return []

    # Group by (file, function) — most reliable clustering
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        key = (f.file, f.function)
        groups.setdefault(key, []).append(f)

    deduped: list[Finding] = []

    for (file, func), group in groups.items():
        if len(group) == 1:
            deduped.append(group[0])
            continue

        # Within a group, sub-cluster by detector family
        families = _cluster_by_family(group)

        for family_findings in families.values():
            if len(family_findings) == 1:
                deduped.append(family_findings[0])
            else:
                # Merge: keep highest confidence, highest severity, richest description
                best = _merge_findings(family_findings)
                deduped.append(best)

    # Sort by severity (Critical first), then confidence
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFORMATIONAL: 4,
    }
    deduped.sort(key=lambda f: (severity_order.get(f.severity, 5), -f.confidence))

    # Re-number
    for i, f in enumerate(deduped):
        f.id = f"HARVESTO-{i+1:04d}"

    return deduped


def _cluster_by_family(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group findings by detector family (reentrancy, access-control, etc.)."""
    families = {
        "reentrancy": ["reentrancy-eth", "reentrancy-no-eth", "reentrancy-benign",
                       "reentrancy-events", "cross-function-reentrancy", "reentrancy-unlimited-gas",
                       "erc721-callback-reentrancy"],
        "access-control": ["missing-access-control", "unprotected-upgrade", "tx-origin"],
        "delegatecall": ["controlled-delegatecall", "unsafe-delegatecall", "delegatecall-loop"],
        "transfer": ["arbitrary-send-eth", "arbitrary-send-erc20", "unchecked-transfer",
                     "unchecked-send", "unchecked-call"],
        "price": ["price-manipulation", "incorrect-equality", "oracle-staleness"],
        "slippage": ["missing-slippage"],
        "flashloan": ["flashloan-callback-abuse"],
        "proxy": ["storage-collision-proxy", "unprotected-upgrade"],
        # New families
        "mev": ["mev-sandwich-surface", "frontrun-approve"],
        "token-standard": ["weird-erc20-fee-on-transfer", "erc4626-inflation"],
        "governance": ["governance-flashloan-vote", "governance-no-timelock"],
        "economic": ["donation-attack", "rounding-direction"],
        "cross-chain": ["cross-chain-replay", "bridge-sender-validation"],
        "l2": ["l2-sequencer-check", "l2-block-properties", "l2-withdrawal-proof", "l2-withdrawal-replay"],
        "gas": ["return-bomb", "calls-loop", "costly-loop"],
    }

    # Build reverse lookup
    detector_to_family: dict[str, str] = {}
    for family, detectors in families.items():
        for d in detectors:
            detector_to_family[d] = family

    clustered: dict[str, list[Finding]] = {}
    for f in findings:
        family = detector_to_family.get(f.raw_detector_id, f.raw_detector_id)
        clustered.setdefault(family, []).append(f)

    return clustered


def _merge_findings(findings: list[Finding]) -> Finding:
    """Merge a list of related findings into the single best representative."""
    # Pick the one with highest severity, then highest confidence
    severity_rank = {
        Severity.CRITICAL: 0, Severity.HIGH: 1,
        Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFORMATIONAL: 4,
    }

    findings.sort(key=lambda f: (severity_rank.get(f.severity, 5), -f.confidence))
    best = findings[0]

    # Boost confidence when multiple detectors agree
    if len(findings) >= 2:
        unique_detectors = set(f.detector for f in findings)
        if len(unique_detectors) >= 2:
            # Cross-detector agreement is a strong signal
            best.confidence = min(best.confidence + 15, 98)

    # Merge line references
    all_lines = set()
    for f in findings:
        all_lines.update(f.lines)
    best.lines = sorted(all_lines)[:20]

    # Note the duplicate
    for f in findings[1:]:
        f.duplicate_of = best.id

    return best
