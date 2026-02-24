"""
Custom pattern-based detectors — catches patterns Slither misses or misclassifies.

These use regex + lightweight AST analysis on Solidity source files directly.
Each detector returns raw Finding objects that still need FP filtering.
"""

import re
from pathlib import Path
from typing import Generator

from harvesto_scanner.models import Finding, Severity


def run_custom_detectors(sol_files: list[Path], counter_start: int = 1000) -> list[Finding]:
    """Run all custom detectors across all .sol files."""
    findings: list[Finding] = []
    counter = counter_start

    for sol_file in sol_files:
        try:
            source = sol_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        lines = source.split("\n")
        rel_path = str(sol_file)

        for detector_fn in ALL_DETECTORS:
            for finding in detector_fn(source, lines, rel_path):
                finding.id = f"HARVESTO-{counter:04d}"
                counter += 1
                findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------

def detect_flashloan_callback_abuse(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect flash loan callbacks that don't validate the initiator.
    Critical in DeFi: allows anyone to trigger callbacks with attacker-controlled data.
    """
    # Common flash loan callback signatures
    callback_patterns = [
        r"function\s+(?:executeOperation|onFlashLoan|receiveFlashLoan|uniswapV3FlashCallback|pancakeV3FlashCallback)\s*\(",
    ]

    for pattern in callback_patterns:
        for match in re.finditer(pattern, source):
            line_no = source[:match.start()].count("\n") + 1
            func_name = re.search(r"function\s+(\w+)", match.group()).group(1)

            # Check if there's an initiator/sender validation within the function body
            func_body = _extract_function_body(lines, line_no - 1)
            func_body_lower = func_body.lower()

            has_initiator_check = any(
                kw in func_body_lower
                for kw in ["require(msg.sender", "if (msg.sender", "if(msg.sender",
                           "onlypool", "onlylendingpool", "msg.sender ==",
                           "_checkinitiator", "require(initiator"]
            )

            if not has_initiator_check:
                yield Finding(
                    id="",
                    title=f"Flash loan callback without initiator validation in {func_name}()",
                    severity=Severity.CRITICAL,
                    impact="Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
                    confidence=75,
                    file=file,
                    lines=[line_no],
                    function=func_name,
                    description=(
                        f"The flash loan callback `{func_name}()` does not appear to validate "
                        f"who initiated the flash loan. An attacker could call this callback directly "
                        f"or trigger it via a malicious flash loan to manipulate contract state."
                    ),
                    recommendation="Validate msg.sender is the expected lending pool and the initiator is this contract or an authorized address.",
                    detector="custom:flashloan-callback-abuse",
                    exploitable_by="any_user",
                    raw_detector_id="flashloan-callback-abuse",
                )


def detect_price_manipulation(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect spot price usage from AMM pools without TWAP or oracle validation.
    Common attack vector: flash loan → manipulate pool → read price → profit.
    """
    # Patterns that read spot price from pools
    spot_price_patterns = [
        (r"\.getReserves\s*\(\)", "getReserves"),
        (r"\.slot0\s*\(\)", "slot0"),
        (r"pool\.slot0\(\)", "slot0"),
        (r"balanceOf\([^)]*\)\s*/\s*balanceOf\([^)]*\)", "balance-ratio"),
        (r"reserve[01]\s*/\s*reserve[01]", "reserve-ratio"),
    ]

    for pattern, name in spot_price_patterns:
        for match in re.finditer(pattern, source):
            line_no = source[:match.start()].count("\n") + 1

            # Check for TWAP/oracle protection in surrounding context
            context = _get_context(lines, line_no - 1, radius=40)
            context_lower = context.lower()
            has_twap = any(kw in context_lower for kw in [
                "twap", ".observe(", ".consult(", "chainlink",
                "getcumulativeprice", "timeweighted", "pyth",
                "aggregatorv3", "latestround", "latestrounddata",
            ])
            # "oracle" in a contract/variable name doesn't count as protection
            # Only count it if it's used as a function call or import
            if not has_twap and "oracle" in context_lower:
                has_twap = bool(re.search(r"oracle\s*\.\s*\w+\s*\(", context_lower))

            if not has_twap:
                yield Finding(
                    id="",
                    title=f"Spot price used without oracle/TWAP protection ({name})",
                    severity=Severity.CRITICAL,
                    impact="Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
                    confidence=65,
                    file=file,
                    lines=[line_no],
                    function=_find_enclosing_function(lines, line_no - 1),
                    description=(
                        f"The contract reads a spot price via `{name}` without apparent TWAP or oracle validation. "
                        f"An attacker can use a flash loan to temporarily manipulate the pool's reserves/price, "
                        f"then exploit the stale price reading for profit."
                    ),
                    recommendation="Use a TWAP oracle (e.g., Uniswap v3 observe()) or a trusted oracle (Chainlink, Pyth) instead of spot prices.",
                    detector="custom:price-manipulation",
                    exploitable_by="any_user",
                    raw_detector_id="price-manipulation",
                )


def detect_missing_slippage(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect swap calls with amountOutMin=0 or no slippage check.
    Allows sandwich attacks that drain user value.
    """
    # Uniswap-style router swaps
    swap_patterns = [
        r"\.exactInputSingle\(",
        r"\.exactInput\(",
        r"\.swapExactTokensForTokens\(",
        r"\.swapExactETHForTokens\(",
        r"\.swap\([^)]*0\s*[,)]",  # swap with 0 as min amount
    ]

    for pattern in swap_patterns:
        for match in re.finditer(pattern, source):
            line_no = source[:match.start()].count("\n") + 1
            context = _get_context(lines, line_no - 1, radius=10)

            # Check for hardcoded 0 slippage
            has_zero_slippage = re.search(
                r"(?:amountOutMin|amountOutMinimum|minAmountOut)\s*[:=]\s*0\b", context
            )
            has_any_slippage = re.search(
                r"(?:amountOutMin|amountOutMinimum|minAmountOut|slippage)", context
            )

            if has_zero_slippage or not has_any_slippage:
                yield Finding(
                    id="",
                    title=f"Missing or zero slippage protection on swap",
                    severity=Severity.HIGH,
                    impact="Theft of unclaimed yield",
                    confidence=70,
                    file=file,
                    lines=[line_no],
                    function=_find_enclosing_function(lines, line_no - 1),
                    description=(
                        "A token swap is executed without slippage protection (amountOutMin = 0 or missing). "
                        "MEV bots can sandwich this transaction, extracting value from users."
                    ),
                    recommendation="Accept a minimum output amount as a parameter. Never hardcode amountOutMin to 0.",
                    detector="custom:missing-slippage",
                    exploitable_by="any_user",
                    raw_detector_id="missing-slippage",
                )


def detect_cross_function_reentrancy(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect cross-function reentrancy: external call in one function, state read in another,
    both operating on the same state variable. More subtle than basic reentrancy.
    """
    # Find functions with external calls (.call{, .transfer(, .send(, IERC*.safeTransfer)
    external_call_pattern = re.compile(
        r"\.call\{|\.transfer\(|\.send\(|\.safeTransfer\(|\.safeTransferFrom\("
    )

    # Find state variable writes (storage writes)
    state_write_pattern = re.compile(
        r"(\w+)\[.*\]\s*[+\-*/]?=|(\w+)\s*[+\-*/]?=\s*(?!.*memory|.*calldata)"
    )

    # Collect functions with external calls that have state writes AFTER the call
    funcs_with_calls = []
    in_function = False
    current_func = ""
    current_func_start = 0
    brace_depth = 0

    for i, line in enumerate(lines):
        func_match = re.match(r"\s*function\s+(\w+)", line)
        if func_match:
            current_func = func_match.group(1)
            current_func_start = i

        if external_call_pattern.search(line):
            # Check if state is written AFTER this line in the same function
            remaining = "\n".join(lines[i+1:min(i+50, len(lines))])
            if state_write_pattern.search(remaining):
                # Check no reentrancy guard
                func_context = _get_context(lines, current_func_start, radius=3)
                has_guard = any(kw in func_context.lower() for kw in [
                    "nonreentrant", "reentrancyguard", "locked", "_lock",
                ])
                if not has_guard:
                    yield Finding(
                        id="",
                        title=f"Potential cross-function reentrancy in {current_func}()",
                        severity=Severity.CRITICAL,
                        impact="Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
                        confidence=55,
                        file=file,
                        lines=[i + 1],
                        function=current_func,
                        description=(
                            f"Function `{current_func}()` makes an external call and writes to state after the call "
                            f"without a reentrancy guard. If another function reads the same state, an attacker can "
                            f"re-enter during the external call and exploit stale state."
                        ),
                        recommendation="Use ReentrancyGuard (nonReentrant modifier) or apply checks-effects-interactions pattern.",
                        detector="custom:cross-function-reentrancy",
                        exploitable_by="any_user",
                        raw_detector_id="cross-function-reentrancy",
                    )
                    break  # One finding per function


def detect_access_control_missing(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect sensitive functions (mint, burn, pause, upgrade, set*, withdraw)
    without access control modifiers.
    
    Skips:
    - Interface files (no function bodies = no modifiers possible)
    - Functions inside interface blocks
    - Files with /interfaces/ in path or I*.sol naming convention
    """
    # Skip interface files entirely
    basename = Path(file).name
    if "/interfaces/" in file or "/interface/" in file:
        return
    if re.match(r"^I[A-Z][a-zA-Z0-9]+\.sol$", basename):
        return
    
    # Skip files that only contain interfaces
    interface_count = len(re.findall(r"\binterface\s+\w+", source))
    contract_count = len(re.findall(r"\bcontract\s+\w+", source))
    if interface_count > 0 and contract_count == 0:
        return

    sensitive_funcs = re.compile(
        r"function\s+(mint|burn|pause|unpause|upgrade|set\w+|withdraw\w*|emergencyWithdraw|kill|destroy|transferOwnership)\s*\("
    )

    access_modifiers = {
        "onlyowner", "onlyadmin", "onlyrole", "onlyminter", "onlygovernance",
        "onlyauthorized", "onlyoperator", "onlycontroller", "restricted",
        "auth", "requiresauth", "access_control",
        # Additional patterns common in protocols
        "onlymanager", "onlykeeper", "onlyguardian", "onlygov",
        "onlylrtmanager", "onlylrtadmin", "onlykelpmanager",
        "onlysupportedasset", "onlylrtoperator",
        "whennotpaused",
    }

    # Check if the contract inherits from access control base classes
    ac_bases_lower = [
        "accesscontrol", "accesscontrolupgradeable",
        "ownable", "ownableupgradeable", "ownable2step",
        "lrtconfigrolechecker",
    ]
    source_lower = source.lower()
    has_inherited_ac = any(
        re.search(rf"\bis\s+[^{{]*\b{base}\b", source_lower)
        for base in ac_bases_lower
    )
    
    # Check for custom role modifier definitions in the file
    custom_modifiers = re.findall(r"modifier\s+(only\w+)\s*\(", source)
    for mod in custom_modifiers:
        access_modifiers.add(mod.lower())

    for match in sensitive_funcs.finditer(source):
        func_name = match.group(1)
        line_no = source[:match.start()].count("\n") + 1

        # Check if this function is inside an interface block
        in_interface = False
        for i in range(line_no - 1, max(line_no - 200, -1), -1):
            if i < 0 or i >= len(lines):
                continue
            line = lines[i].strip()
            if re.match(r"interface\s+\w+", line):
                in_interface = True
                break
            if re.match(r"(abstract\s+)?contract\s+\w+", line):
                break
        if in_interface:
            continue

        # Look at the function signature line(s) for modifiers
        sig_text = _get_context(lines, line_no - 1, radius=3).lower()

        has_access = any(mod in sig_text for mod in access_modifiers)
        is_internal = "internal" in sig_text or "private" in sig_text

        if not has_access and not is_internal:
            # Check if function body has require(msg.sender ...) or role checks early
            func_body = _extract_function_body(lines, line_no - 1)[:500]
            has_sender_check = re.search(
                r"require\s*\(\s*msg\.sender\s*==|_checkrole\(|_checkowner\(\)|hasrole\(",
                func_body.lower()
            )

            if not has_sender_check:
                # If contract inherits AC, reduce confidence significantly
                confidence = 60 if not has_inherited_ac else 30
                
                yield Finding(
                    id="",
                    title=f"Missing access control on sensitive function {func_name}()",
                    severity=Severity.CRITICAL,
                    impact="Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
                    confidence=confidence,
                    file=file,
                    lines=[line_no],
                    function=func_name,
                    description=(
                        f"The function `{func_name}()` performs a sensitive operation but has no "
                        f"access control modifier or msg.sender check. Any external caller can invoke it."
                        + (" (Note: contract inherits AccessControl/Ownable — modifier may be applied at implementation level)"
                           if has_inherited_ac else "")
                    ),
                    recommendation=f"Add an appropriate access control modifier (e.g., onlyOwner) to {func_name}().",
                    detector="custom:missing-access-control",
                    exploitable_by="any_user" if not has_inherited_ac else "likely_admin_only",
                    raw_detector_id="missing-access-control",
                )


def detect_unsafe_delegatecall(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect delegatecall where the target address comes from user input or storage
    that could be manipulated.
    """
    delegatecall_pattern = re.compile(r"\.delegatecall\(")

    for match in delegatecall_pattern.finditer(source):
        line_no = source[:match.start()].count("\n") + 1
        context = _get_context(lines, line_no - 1, radius=5)

        # Check if the target looks user-controlled
        target_line = lines[line_no - 1] if line_no <= len(lines) else ""

        # Safe patterns: delegatecall to immutable/constant, address(this)
        is_safe = any(kw in context.lower() for kw in [
            "immutable", "constant", "address(this)", "implementation()",
        ])

        if not is_safe:
            yield Finding(
                id="",
                title=f"Potentially unsafe delegatecall",
                severity=Severity.CRITICAL,
                impact="Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
                confidence=55,
                file=file,
                lines=[line_no],
                function=_find_enclosing_function(lines, line_no - 1),
                description=(
                    "A `delegatecall` is made to an address that may be user-controlled or stored in "
                    "mutable storage. An attacker could point this to a malicious contract that overwrites "
                    "critical storage slots, stealing funds or taking ownership."
                ),
                recommendation="Ensure delegatecall targets are immutable or only settable by trusted roles. Validate against a whitelist.",
                detector="custom:unsafe-delegatecall",
                exploitable_by="any_user",
                raw_detector_id="unsafe-delegatecall",
            )


def detect_unchecked_low_level_call(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect .call() where the return value (bool success) is not checked.
    """
    call_pattern = re.compile(r"\.call\{[^}]*\}\(")

    for match in call_pattern.finditer(source):
        line_no = source[:match.start()].count("\n") + 1
        line_text = lines[line_no - 1] if line_no <= len(lines) else ""

        # Check if success is captured
        is_checked = re.search(r"\(bool\s+\w+", line_text) or "require(" in _get_context(lines, line_no - 1, radius=3)
        is_discarded = line_text.strip().startswith("(") is False and "=" not in line_text

        if is_discarded or (not is_checked and "success" not in line_text.lower()):
            yield Finding(
                id="",
                title="Unchecked low-level call return value",
                severity=Severity.MEDIUM,
                impact="Temporary freezing of funds",
                confidence=60,
                file=file,
                lines=[line_no],
                function=_find_enclosing_function(lines, line_no - 1),
                description=(
                    "A low-level `.call{}()` is made without checking the boolean success return value. "
                    "If the call silently fails, the contract may continue execution with incorrect assumptions."
                ),
                recommendation="Always check the return value: `(bool success, ) = addr.call{...}(...); require(success);`",
                detector="custom:unchecked-call",
                exploitable_by="any_user",
                raw_detector_id="unchecked-call",
            )


def detect_storage_collision_proxy(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect proxy patterns with potential storage collision.
    If a contract inherits from a proxy AND declares its own state variables,
    there's a storage collision risk.
    """
    is_proxy = any(kw in source for kw in [
        "delegatecall", "Proxy", "ERC1967", "TransparentUpgradeable",
        "UUPSUpgradeable", "_implementation()",
    ])

    if not is_proxy:
        return

    # Check for state variable declarations in a proxy context
    state_var_pattern = re.compile(
        r"^\s+(?:uint|int|address|bool|string|bytes|mapping)\w*\s+(?:public|private|internal)?\s*\w+\s*[;=]",
        re.MULTILINE,
    )

    for match in state_var_pattern.finditer(source):
        line_no = source[:match.start()].count("\n") + 1

        # Safe if using EIP-1967 storage slots
        context = _get_context(lines, line_no - 1, radius=20)
        uses_eip1967 = any(kw in context for kw in [
            "StorageSlot", "bytes32 private constant", "keccak256",
            "_IMPLEMENTATION_SLOT", "ERC1967Utils",
        ])

        if not uses_eip1967:
            yield Finding(
                id="",
                title="Potential storage collision in proxy contract",
                severity=Severity.CRITICAL,
                impact="Protocol insolvency",
                confidence=45,
                file=file,
                lines=[line_no],
                function="(storage layout)",
                description=(
                    "This proxy contract declares state variables that may collide with the implementation's "
                    "storage layout. This can lead to corrupted state, fund loss, or contract takeover."
                ),
                recommendation="Use EIP-1967 storage slots or the unstructured storage pattern. Avoid declaring state in proxy contracts.",
                detector="custom:storage-collision-proxy",
                exploitable_by="any_user",
                raw_detector_id="storage-collision-proxy",
            )
            break  # One finding per contract


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_function_body(lines: list[str], start_line: int, max_lines: int = 80) -> str:
    """Extract the body of a function starting from the function declaration line."""
    body_lines = []
    brace_depth = 0
    started = False

    for i in range(start_line, min(start_line + max_lines, len(lines))):
        line = lines[i]
        body_lines.append(line)

        brace_depth += line.count("{") - line.count("}")
        if "{" in line:
            started = True
        if started and brace_depth <= 0:
            break

    return "\n".join(body_lines)


def _get_context(lines: list[str], center: int, radius: int = 10) -> str:
    """Get surrounding lines for context analysis."""
    start = max(0, center - radius)
    end = min(len(lines), center + radius + 1)
    return "\n".join(lines[start:end])


def _find_enclosing_function(lines: list[str], line_idx: int) -> str:
    """Walk backwards to find the enclosing function name."""
    for i in range(line_idx, max(line_idx - 60, -1), -1):
        match = re.match(r"\s*function\s+(\w+)", lines[i])
        if match:
            return match.group(1)
    return "(unknown)"


# Registry of all detector functions
ALL_DETECTORS = [
    detect_flashloan_callback_abuse,
    detect_price_manipulation,
    detect_missing_slippage,
    detect_cross_function_reentrancy,
    detect_access_control_missing,
    detect_unsafe_delegatecall,
    detect_unchecked_low_level_call,
    detect_storage_collision_proxy,
]
