"""
Slither integration — runs Slither static analysis and parses raw findings.

This is Pass 1 of the pipeline: high recall, many false positives.
The FP filter engine (Pass 3) will aggressively prune these.
"""

import json
import subprocess
import os
import tempfile
from pathlib import Path
from typing import Optional

from harvesto_scanner.models import Finding, Severity


# Map Slither detector names to our severity + impact categories
SLITHER_SEVERITY_MAP: dict[str, tuple[Severity, str]] = {
    # CRITICAL — direct fund theft / permanent freeze / insolvency
    "reentrancy-eth": (Severity.CRITICAL, "Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield"),
    "arbitrary-send-eth": (Severity.CRITICAL, "Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield"),
    "arbitrary-send-erc20": (Severity.CRITICAL, "Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield"),
    "suicidal": (Severity.CRITICAL, "Permanent freezing of funds"),
    "unprotected-upgrade": (Severity.CRITICAL, "Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield"),
    "delegatecall-loop": (Severity.CRITICAL, "Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield"),
    "controlled-delegatecall": (Severity.CRITICAL, "Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield"),
    "msg-value-loop": (Severity.CRITICAL, "Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield"),
    "storage-signed-integer-array": (Severity.CRITICAL, "Protocol insolvency"),
    "unchecked-transfer": (Severity.CRITICAL, "Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield"),
    "unchecked-send": (Severity.CRITICAL, "Permanent freezing of funds"),
    "uninitialized-state": (Severity.CRITICAL, "Protocol insolvency"),
    "uninitialized-storage": (Severity.CRITICAL, "Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield"),

    # HIGH — theft of unclaimed yield
    "reentrancy-no-eth": (Severity.HIGH, "Theft of unclaimed yield"),
    "shadowing-state": (Severity.HIGH, "Theft of unclaimed yield"),
    "tautological-compare": (Severity.HIGH, "Theft of unclaimed yield"),
    "write-after-write": (Severity.HIGH, "Theft of unclaimed yield"),
    "incorrect-equality": (Severity.HIGH, "Theft of unclaimed yield"),
    "tx-origin": (Severity.HIGH, "Theft of unclaimed yield"),
    "uninitialized-local": (Severity.HIGH, "Theft of unclaimed yield"),
    "weak-prng": (Severity.HIGH, "Theft of unclaimed yield"),
    "domain-separator-collision": (Severity.HIGH, "Theft of unclaimed yield"),
    "codex": (Severity.HIGH, "Theft of unclaimed yield"),
    "encode-packed-collision": (Severity.HIGH, "Theft of unclaimed yield"),

    # MEDIUM — gas issues, temporary freezing, yield freezing
    "reentrancy-benign": (Severity.MEDIUM, "Temporary freezing of funds"),
    "locked-ether": (Severity.MEDIUM, "Permanent freezing of unclaimed yield"),
    "divide-before-multiply": (Severity.MEDIUM, "Contract fails to deliver promised returns, but doesn't lose value"),
    "incorrect-shift": (Severity.MEDIUM, "Temporary freezing of funds"),
    "missing-zero-check": (Severity.MEDIUM, "Permanent freezing of unclaimed yield"),
    "calls-loop": (Severity.MEDIUM, "Unbounded gas consumption"),
    "reentrancy-events": (Severity.MEDIUM, "Temporary freezing of funds"),
    "return-bomb": (Severity.MEDIUM, "Unbounded gas consumption"),

    # LOW — no direct value loss
    "boolean-equal": (Severity.LOW, "Block stuffing"),
    "shadowing-local": (Severity.LOW, "Contract fails to deliver promised returns, but doesn't lose value"),
    "unused-return": (Severity.LOW, "Contract fails to deliver promised returns, but doesn't lose value"),
    "reentrancy-unlimited-gas": (Severity.LOW, "Block stuffing"),
    "costly-loop": (Severity.LOW, "Unbounded gas consumption"),
}

# Detectors we never want (too noisy, informational-only)
BLOCKLISTED_DETECTORS = {
    "naming-convention", "solc-version", "pragma", "dead-code",
    "low-level-calls", "redundant-statements", "constable-states",
    "external-function", "too-many-digits", "variable-scope",
    "conformance-to-solidity-naming-conventions",
    "assembly", "timestamp", "similar-names",
    "immutable-states", "state-variable-read-in-inline-assembly",
    "incorrect-versions-of-solidity",
}


def run_slither(target: Path, solc_version: Optional[str] = None) -> list[dict]:
    """
    Run Slither on a target directory or file and return raw JSON findings.
    """
    cmd = ["slither", str(target), "--json", "-"]

    if solc_version:
        cmd.extend(["--solc-solcs-select", solc_version])

    # Try to detect framework
    if (target / "foundry.toml").exists():
        cmd.extend(["--compile-force-framework", "foundry"])
    elif (target / "hardhat.config.js").exists() or (target / "hardhat.config.ts").exists():
        cmd.extend(["--compile-force-framework", "hardhat"])
    elif (target / "truffle-config.js").exists():
        cmd.extend(["--compile-force-framework", "truffle"])

    env = os.environ.copy()
    env["SLITHER_DISABLE_COLOR"] = "1"

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
            cwd=str(target) if target.is_dir() else str(target.parent),
        )
        # Slither outputs JSON to stdout even on non-zero exit
        if result.stdout.strip():
            data = json.loads(result.stdout)
            return data.get("results", {}).get("detectors", [])
    except subprocess.TimeoutExpired:
        return []
    except json.JSONDecodeError:
        return []
    except FileNotFoundError:
        return []

    return []


def parse_slither_finding(raw: dict, finding_counter: int) -> Optional[Finding]:
    """
    Convert a single Slither JSON detector result into our Finding model.
    Returns None if the detector is blocklisted or unmapped.
    """
    detector_id = raw.get("check", "")

    if detector_id in BLOCKLISTED_DETECTORS:
        return None

    severity_info = SLITHER_SEVERITY_MAP.get(detector_id)
    if severity_info is None:
        # Unmapped detector — we skip rather than guess (precision > recall)
        return None

    severity, impact = severity_info

    # Extract file/line info from elements
    elements = raw.get("elements", [])
    file_path = ""
    lines = []
    func_name = ""

    for elem in elements:
        source = elem.get("source_mapping", {})
        if not file_path and source.get("filename_relative"):
            file_path = source["filename_relative"]
        if source.get("lines"):
            lines.extend(source["lines"])
        if elem.get("type") == "function" and elem.get("name"):
            func_name = elem["name"]

    lines = sorted(set(lines))[:20]  # cap line references

    description = raw.get("description", "").strip()
    if not description:
        description = f"Slither detector '{detector_id}' triggered."

    return Finding(
        id=f"HARVESTO-{finding_counter:04d}",
        title=_make_title(detector_id, func_name, file_path),
        severity=severity,
        impact=impact,
        confidence=_initial_confidence(detector_id, raw),
        file=file_path,
        lines=lines,
        function=func_name or "(unknown)",
        description=description,
        recommendation=_recommendation(detector_id),
        detector=f"slither:{detector_id}",
        exploitable_by="any_user",  # will be refined by FP filter
        raw_detector_id=detector_id,
    )


def _make_title(detector_id: str, func: str, file: str) -> str:
    titles = {
        "reentrancy-eth": "Reentrancy with ETH transfer",
        "arbitrary-send-eth": "Arbitrary ETH send",
        "arbitrary-send-erc20": "Arbitrary ERC20 transfer",
        "suicidal": "Unprotected selfdestruct",
        "unprotected-upgrade": "Unprotected upgrade function",
        "controlled-delegatecall": "Controlled delegatecall destination",
        "delegatecall-loop": "Delegatecall inside loop",
        "msg-value-loop": "msg.value used inside loop",
        "unchecked-transfer": "Unchecked token transfer return value",
        "unchecked-send": "Unchecked send return value",
        "uninitialized-state": "Uninitialized state variable",
        "uninitialized-storage": "Uninitialized storage pointer",
        "reentrancy-no-eth": "Reentrancy (no ETH, state modification)",
        "locked-ether": "Contract locks Ether without withdrawal",
        "calls-loop": "External calls inside unbounded loop",
        "incorrect-equality": "Dangerous strict equality check",
        "tx-origin": "tx.origin used for authentication",
        "weak-prng": "Weak pseudo-random number generation",
        "shadowing-state": "State variable shadowing",
    }
    base = titles.get(detector_id, detector_id.replace("-", " ").title())
    if func:
        return f"{base} in {func}()"
    return base


def _initial_confidence(detector_id: str, raw: dict) -> int:
    """Assign initial confidence before FP filtering."""
    # Slither's own confidence field
    slither_conf = raw.get("confidence", "").lower()
    base = {"high": 70, "medium": 50, "low": 30, "informational": 10}.get(slither_conf, 50)

    # Boost for high-signal detectors
    high_signal = {"reentrancy-eth", "arbitrary-send-eth", "arbitrary-send-erc20",
                   "suicidal", "controlled-delegatecall", "unprotected-upgrade"}
    if detector_id in high_signal:
        base = min(base + 15, 95)

    return base


def _recommendation(detector_id: str) -> str:
    recs = {
        "reentrancy-eth": "Apply checks-effects-interactions pattern. Update state before external calls. Consider using ReentrancyGuard.",
        "arbitrary-send-eth": "Restrict ETH transfer destinations. Use access control on withdrawal functions.",
        "arbitrary-send-erc20": "Validate transfer recipients. Ensure only authorized addresses can receive tokens.",
        "suicidal": "Add access control to selfdestruct. Consider removing selfdestruct entirely.",
        "unprotected-upgrade": "Add access control (onlyOwner/onlyAdmin) to upgrade functions.",
        "controlled-delegatecall": "Never delegatecall to user-controlled addresses. Validate targets against whitelist.",
        "locked-ether": "Add a withdrawal function or remove the payable modifier.",
        "calls-loop": "Limit loop iterations. Use pull-over-push pattern for batch operations.",
        "unchecked-transfer": "Check return value of transfer/transferFrom. Use SafeERC20.",
        "tx-origin": "Replace tx.origin with msg.sender for authentication.",
        "incorrect-equality": "Avoid strict equality (==) for balance checks. Use >= instead.",
    }
    return recs.get(detector_id, f"Review the {detector_id} finding and apply appropriate mitigation.")
