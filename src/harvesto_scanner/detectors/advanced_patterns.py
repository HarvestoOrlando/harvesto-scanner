"""
Advanced pattern detectors — 6 new vulnerability categories.

Based on Trail of Bits' building-secure-contracts patterns, not-so-smart-contracts
vulnerability taxonomy, and property-based-testing methodology.

Categories:
  1. MEV & Trading vulnerabilities
  2. Token standard vulnerabilities (weird ERC, bridges, edge cases)
  3. Governance attacks (proposals, voting, delegation)
  4. Economic/financial vulnerabilities (incentive misalignment)
  5. Cross-chain protocol vulnerabilities
  6. L2-specific security (bridges, withdrawals, fraud proofs)
"""

import re
from pathlib import Path
from typing import Generator

from harvesto_scanner.models import Finding, Severity


def run_advanced_detectors(sol_files: list[Path], counter_start: int = 2000) -> list[Finding]:
    """Run all advanced detectors across all .sol files."""
    findings: list[Finding] = []
    counter = counter_start

    for sol_file in sol_files:
        try:
            source = sol_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        lines = source.split("\n")
        rel_path = str(sol_file)

        for detector_fn in ALL_ADVANCED_DETECTORS:
            for finding in detector_fn(source, lines, rel_path):
                finding.id = f"HARVESTO-{counter:04d}"
                counter += 1
                findings.append(finding)

    return findings


# ═══════════════════════════════════════════════════════════════════
# 1. MEV & TRADING VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════

def detect_sandwich_attack_surface(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect functions that perform swaps or large state changes observable in the mempool
    without commit-reveal, private mempool, or deadline protections.
    """
    # Patterns indicating publicly observable value-changing operations
    swap_sigs = [
        r"\.swap\s*\(", r"\.swapExact\w+\(", r"\.addLiquidity\(",
        r"\.removeLiquidity\(", r"\.deposit\s*\(.*amount",
    ]

    for pattern in swap_sigs:
        for match in re.finditer(pattern, source):
            line_no = source[:match.start()].count("\n") + 1
            context = _get_context(lines, line_no - 1, radius=15)
            ctx_lower = context.lower()

            has_protection = any(kw in ctx_lower for kw in [
                "deadline", "commit", "reveal", "flashbot",
                "private", "mev", "block.timestamp + ",
            ])

            if not has_protection:
                yield Finding(
                    id="", title=f"MEV-exposed operation without deadline/commit-reveal",
                    severity=Severity.HIGH, impact="Theft of unclaimed yield",
                    confidence=55, file=file, lines=[line_no],
                    function=_find_enclosing_function(lines, line_no - 1),
                    description=(
                        "This operation modifies on-chain state in a way visible to mempool observers. "
                        "Without deadline parameters or commit-reveal schemes, MEV bots can sandwich "
                        "this transaction to extract value from users."
                    ),
                    recommendation="Add deadline parameters, use commit-reveal for large operations, or integrate with private mempools (Flashbots Protect).",
                    detector="custom:mev-sandwich-surface",
                    exploitable_by="any_user", raw_detector_id="mev-sandwich-surface",
                )
                break  # one per pattern


def detect_frontrun_vulnerable_state(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Trail of Bits race_condition pattern: detect state that can be front-run.
    Approval patterns (ERC20 approve) and first-depositor advantages.
    """
    # ERC20 approve without increase/decrease pattern
    approve_pattern = re.compile(
        r"function\s+approve\s*\(\s*address\s+\w+\s*,\s*uint256\s+\w+\s*\)"
    )
    for match in approve_pattern.finditer(source):
        line_no = source[:match.start()].count("\n") + 1
        context = _get_context(lines, line_no - 1, radius=20)

        has_safe_approve = any(kw in context for kw in [
            "increaseAllowance", "decreaseAllowance", "safeIncreaseAllowance",
            "require(allowance == 0", "require(_allowance == 0",
        ])

        if not has_safe_approve:
            yield Finding(
                id="", title="ERC20 approve race condition (front-run allowance)",
                severity=Severity.MEDIUM, impact="Theft of unclaimed yield",
                confidence=50, file=file, lines=[line_no],
                function="approve",
                description=(
                    "The approve function is vulnerable to the well-known front-running attack. "
                    "When a user changes an allowance from N to M, a spender can front-run "
                    "and spend N, then also spend M after the approval tx confirms."
                ),
                recommendation="Use increaseAllowance/decreaseAllowance or require the current allowance to be 0 before setting a new non-zero value.",
                detector="custom:frontrun-approve",
                exploitable_by="any_user", raw_detector_id="frontrun-approve",
            )


def detect_return_value_bomb(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect external calls where the return data size is unbounded.
    Attacker can return massive data to consume all gas (returnbomb).
    """
    call_patterns = [
        (r"\.call\{[^}]*\}\([^)]*\)", "call"),
        (r"\.staticcall\([^)]*\)", "staticcall"),
    ]

    for pattern, name in call_patterns:
        for match in re.finditer(pattern, source):
            line_no = source[:match.start()].count("\n") + 1
            line_text = lines[line_no - 1] if line_no <= len(lines) else ""

            # Check if return data is captured with bounded size
            has_bound = any(kw in line_text for kw in [
                "assembly", "returndatasize", "ExcessivelySafeCall",
            ])
            context = _get_context(lines, line_no - 1, radius=5)
            has_bound = has_bound or "assembly" in context

            if not has_bound and "bytes memory" in line_text:
                yield Finding(
                    id="", title=f"Unbounded return data from {name} (return bomb)",
                    severity=Severity.MEDIUM, impact="Unbounded gas consumption",
                    confidence=50, file=file, lines=[line_no],
                    function=_find_enclosing_function(lines, line_no - 1),
                    description=(
                        f"An external `{name}` captures return data into a bytes variable without "
                        f"bounding the size. A malicious contract can return megabytes of data, "
                        f"consuming all available gas and causing the transaction to revert."
                    ),
                    recommendation="Use assembly to cap returndatasize, or use ExcessivelySafeCall library.",
                    detector="custom:return-bomb",
                    exploitable_by="any_user", raw_detector_id="return-bomb",
                )


# ═══════════════════════════════════════════════════════════════════
# 2. TOKEN STANDARD VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════

def detect_weird_erc20_handling(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Trail of Bits' token integration checklist: detect unsafe assumptions
    about ERC20 behavior. Fee-on-transfer, rebasing, missing return values,
    multiple entry points, etc.
    """
    # Pattern: balance check before/after transfer not matching
    # Indicates assuming transfer amount == received amount (breaks on fee tokens)
    transfer_patterns = [
        (r"\.transfer\(\s*\w+\s*,\s*(\w+)\s*\)", "transfer"),
        (r"\.transferFrom\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*\)", "transferFrom"),
    ]

    for pattern, name in transfer_patterns:
        for match in re.finditer(pattern, source):
            line_no = source[:match.start()].count("\n") + 1
            context = _get_context(lines, line_no - 1, radius=15)
            ctx_lower = context.lower()

            # Check for balance snapshot pattern (correct handling)
            has_balance_check = any(kw in ctx_lower for kw in [
                "balanceof", "balancebefore", "balanceafter",
                "received =", "actual =", "_amount =",
            ])
            # Check for SafeERC20
            uses_safe = "safetransfer" in ctx_lower

            if not has_balance_check and not uses_safe:
                yield Finding(
                    id="", title=f"Token {name} assumes exact amount received (breaks on fee-on-transfer)",
                    severity=Severity.HIGH, impact="Theft of unclaimed yield",
                    confidence=55, file=file, lines=[line_no],
                    function=_find_enclosing_function(lines, line_no - 1),
                    description=(
                        f"The `{name}` call does not verify the actual received amount using "
                        f"balanceOf snapshots before and after. Fee-on-transfer tokens, rebasing "
                        f"tokens, and tokens with transfer hooks will cause accounting mismatches."
                    ),
                    recommendation="Use the pattern: balanceBefore = token.balanceOf(this); token.transferFrom(...); received = token.balanceOf(this) - balanceBefore;",
                    detector="custom:weird-erc20-fee-on-transfer",
                    exploitable_by="any_user", raw_detector_id="weird-erc20-fee-on-transfer",
                )
                break


def detect_erc721_callback_reentrancy(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    ERC721/ERC1155 safe transfer callbacks can be used for reentrancy.
    _safeMint and safeTransferFrom invoke onERC721Received on the recipient.
    """
    callback_triggers = [
        (r"_safeMint\s*\(", "_safeMint"),
        (r"safeTransferFrom\s*\(", "safeTransferFrom"),
        (r"_safeTransfer\s*\(", "_safeTransfer"),
        (r"safeBatchTransferFrom\s*\(", "safeBatchTransferFrom"),  # ERC1155
    ]

    for pattern, name in callback_triggers:
        for match in re.finditer(pattern, source):
            line_no = source[:match.start()].count("\n") + 1
            func_name = _find_enclosing_function(lines, line_no - 1)

            # Check for reentrancy protection
            func_context = _get_context(lines, line_no - 1, radius=25)
            has_guard = any(kw in func_context.lower() for kw in [
                "nonreentrant", "reentrancyguard", "_lock",
            ])

            # Check if state is written before this call
            func_start = _find_function_start(lines, line_no - 1)
            pre_call_code = "\n".join(lines[func_start:line_no - 1]) if func_start else ""
            has_state_write = bool(re.search(r"\w+\[.*\]\s*[+\-*/]?=|\w+\s*\+=|\w+\s*-=", pre_call_code))

            if not has_guard and has_state_write:
                yield Finding(
                    id="", title=f"ERC721/1155 callback reentrancy via {name}()",
                    severity=Severity.CRITICAL, impact="Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
                    confidence=60, file=file, lines=[line_no],
                    function=func_name,
                    description=(
                        f"`{name}()` triggers an external callback (onERC721Received/onERC1155Received) "
                        f"to the recipient. Since state is written before this call and there's no "
                        f"reentrancy guard, a malicious recipient contract can re-enter and exploit stale state."
                    ),
                    recommendation="Add nonReentrant modifier, or move all state changes before the safe mint/transfer call.",
                    detector="custom:erc721-callback-reentrancy",
                    exploitable_by="any_user", raw_detector_id="erc721-callback-reentrancy",
                )


def detect_erc4626_inflation_attack(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    ERC4626 vault first-depositor inflation attack.
    If the vault has no virtual offset, the first depositor can manipulate share price.
    """
    if "ERC4626" not in source and "totalAssets" not in source:
        return

    has_deposit = bool(re.search(r"function\s+deposit\s*\(", source))
    has_virtual_offset = any(kw in source for kw in [
        "virtualAssets", "virtualShares", "_decimalsOffset",
        "1e", "10 **", "_initialConvertToShares",
    ])

    if has_deposit and not has_virtual_offset:
        # Find the deposit or convertToShares function
        deposit_match = re.search(r"function\s+(?:deposit|convertToShares)\s*\(", source)
        line_no = source[:deposit_match.start()].count("\n") + 1 if deposit_match else 1

        yield Finding(
            id="", title="ERC4626 vault vulnerable to first-depositor inflation attack",
            severity=Severity.CRITICAL, impact="Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
            confidence=60, file=file, lines=[line_no],
            function="deposit",
            description=(
                "This ERC4626 vault does not use virtual shares/assets offset. The first depositor "
                "can deposit 1 wei, then donate a large amount directly to the vault, inflating the "
                "share price. Subsequent depositors receive 0 shares, losing their entire deposit to "
                "the attacker via rounding."
            ),
            recommendation="Add virtual assets/shares offset (OpenZeppelin 4.9+ has this). Example: override _decimalsOffset() to return 3.",
            detector="custom:erc4626-inflation",
            exploitable_by="any_user", raw_detector_id="erc4626-inflation",
        )


# ═══════════════════════════════════════════════════════════════════
# 3. GOVERNANCE ATTACKS
# ═══════════════════════════════════════════════════════════════════

def detect_governance_flash_loan_vote(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect governance tokens that allow voting with current balance
    instead of snapshot/checkpoint-based balance.
    Flash loan governance attacks borrow tokens, vote, and return.
    """
    has_governance = any(kw in source for kw in [
        "propose(", "castVote(", "votingPower(", "getVotes(",
        "Governor", "governance", "quorum(",
    ])
    if not has_governance:
        return

    # Check for snapshot/checkpoint mechanism
    has_snapshot = any(kw in source for kw in [
        "getPastVotes", "getPastTotalSupply", "checkpoint",
        "Checkpoints", "snapshot", "_writeCheckpoint",
        "blockNumber", "proposalSnapshot",
    ])

    if not has_snapshot:
        vote_match = re.search(r"function\s+(?:castVote|vote|propose)\s*\(", source)
        line_no = source[:vote_match.start()].count("\n") + 1 if vote_match else 1

        yield Finding(
            id="", title="Governance voting without snapshot (flash loan vote attack)",
            severity=Severity.CRITICAL, impact="Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
            confidence=55, file=file, lines=[line_no],
            function=_find_enclosing_function(lines, line_no - 1) if vote_match else "(governance)",
            description=(
                "The governance system appears to use current token balance for voting power "
                "rather than snapshot-based (getPastVotes). An attacker can flash-loan a large "
                "amount of governance tokens, pass malicious proposals, and return the tokens."
            ),
            recommendation="Use ERC20Votes with getPastVotes() at the proposal's snapshot block. Never use balanceOf() for vote counting.",
            detector="custom:governance-flashloan-vote",
            exploitable_by="any_user", raw_detector_id="governance-flashloan-vote",
        )


def detect_governance_proposal_manipulation(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect proposals that can be executed without timelock,
    or where proposal threshold is dangerously low.
    """
    has_governance = "propose" in source and ("execute" in source or "queue" in source)
    if not has_governance:
        return

    # Check for timelock
    has_timelock = any(kw in source for kw in [
        "TimelockController", "Timelock", "eta", "timelock",
        "queuedTransactions", "MINIMUM_DELAY", "delay()",
    ])

    if not has_timelock:
        exec_match = re.search(r"function\s+execute\s*\(", source)
        line_no = source[:exec_match.start()].count("\n") + 1 if exec_match else 1

        yield Finding(
            id="", title="Governance execution without timelock delay",
            severity=Severity.HIGH, impact="Theft of unclaimed yield",
            confidence=50, file=file, lines=[line_no],
            function="execute",
            description=(
                "Governance proposals can be executed without a timelock delay. "
                "This prevents the community from reviewing and potentially vetoing "
                "malicious proposals before they take effect."
            ),
            recommendation="Add a TimelockController between governance voting and execution. Minimum 24-48h delay is standard.",
            detector="custom:governance-no-timelock",
            exploitable_by="privileged_role", raw_detector_id="governance-no-timelock",
        )


# ═══════════════════════════════════════════════════════════════════
# 4. ECONOMIC / FINANCIAL VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════

def detect_donation_attack(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect contracts where balance accounting relies on address(this).balance
    or token.balanceOf(address(this)) — vulnerable to donation attacks.
    """
    # ToB forced_ether_reception pattern
    balance_patterns = [
        (r"address\(this\)\.balance", "ETH balance"),
        (r"\.balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)", "token balance"),
    ]

    for pattern, name in balance_patterns:
        for match in re.finditer(pattern, source):
            line_no = source[:match.start()].count("\n") + 1
            context = _get_context(lines, line_no - 1, radius=20)

            # Check if used for accounting/share calculation, not just a view
            is_accounting = any(kw in context for kw in [
                "totalAssets", "convertToShares", "pricePerShare",
                "exchangeRate", "sharePrice", "/", "* ",
                "totalSupply", "ratio",
            ])

            # Check for internal accounting variable tracking
            has_internal_tracking = any(kw in context for kw in [
                "totalDeposited", "internalBalance", "_totalAssets",
                "trackedBalance",
            ])

            if is_accounting and not has_internal_tracking:
                yield Finding(
                    id="", title=f"Donation attack via direct {name} manipulation",
                    severity=Severity.CRITICAL, impact="Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
                    confidence=55, file=file, lines=[line_no],
                    function=_find_enclosing_function(lines, line_no - 1),
                    description=(
                        f"Share price or exchange rate is calculated using `{name}` of the contract. "
                        f"An attacker can donate tokens/ETH directly to the contract (bypassing deposit()), "
                        f"inflating the share price and exploiting rounding in favor of their position."
                    ),
                    recommendation="Track deposits internally with a state variable rather than relying on actual contract balance. Use virtual shares/assets offset for vaults.",
                    detector="custom:donation-attack",
                    exploitable_by="any_user", raw_detector_id="donation-attack",
                )
                break


def detect_oracle_staleness(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect Chainlink oracle usage without staleness checks.
    Stale prices can be exploited for profit in lending/liquidation.
    """
    chainlink_calls = [
        (r"\.latestRoundData\s*\(\)", "latestRoundData"),
        (r"\.latestAnswer\s*\(\)", "latestAnswer"),
    ]

    for pattern, name in chainlink_calls:
        for match in re.finditer(pattern, source):
            line_no = source[:match.start()].count("\n") + 1
            context = _get_context(lines, line_no - 1, radius=15)

            has_staleness = any(kw in context for kw in [
                "updatedAt", "answeredInRound", "roundId",
                "block.timestamp -", "STALENESS", "HEARTBEAT",
                "MAX_DELAY", "price > 0", "answer > 0",
            ])

            if not has_staleness:
                yield Finding(
                    id="", title=f"Chainlink {name}() without staleness check",
                    severity=Severity.HIGH, impact="Theft of unclaimed yield",
                    confidence=65, file=file, lines=[line_no],
                    function=_find_enclosing_function(lines, line_no - 1),
                    description=(
                        f"Chainlink `{name}()` is called without verifying the price is fresh. "
                        f"During network congestion or oracle failures, stale prices persist and "
                        f"can be exploited for arbitrage in lending, liquidation, or trading protocols."
                    ),
                    recommendation="Check updatedAt against a maximum staleness threshold, verify roundId, and ensure answer > 0.",
                    detector="custom:oracle-staleness",
                    exploitable_by="any_user", raw_detector_id="oracle-staleness",
                )


def detect_rounding_direction(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect division that may round in the wrong direction for the protocol.
    In DeFi, rounding should always favor the protocol, not the user.
    """
    # Division in share/asset conversion functions
    conversion_funcs = re.finditer(
        r"function\s+(convertToShares|convertToAssets|previewDeposit|previewMint|previewWithdraw|previewRedeem)\s*\(",
        source,
    )

    for match in conversion_funcs:
        func_name = match.group(1)
        line_no = source[:match.start()].count("\n") + 1
        func_body = _extract_function_body(lines, line_no - 1)

        has_division = "/" in func_body
        has_rounding = any(kw in func_body for kw in [
            "mulDiv", "Math.Rounding", "roundUp", "ceilDiv",
            "mulDivUp", "mulDivDown",
        ])

        if has_division and not has_rounding:
            yield Finding(
                id="", title=f"Potential rounding direction issue in {func_name}()",
                severity=Severity.MEDIUM, impact="Theft of unclaimed yield",
                confidence=45, file=file, lines=[line_no],
                function=func_name,
                description=(
                    f"The function `{func_name}()` performs division without explicit rounding "
                    f"direction control. Solidity truncates (rounds down). For deposit/mint previews, "
                    f"this can round in the user's favor, allowing small extractions over many txs."
                ),
                recommendation="Use mulDiv with explicit rounding: round UP for withdraw/redeem amounts, round DOWN for deposit/mint shares.",
                detector="custom:rounding-direction",
                exploitable_by="any_user", raw_detector_id="rounding-direction",
            )


# ═══════════════════════════════════════════════════════════════════
# 5. CROSS-CHAIN PROTOCOL VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════

def detect_cross_chain_replay(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect cross-chain message handling without chain ID verification.
    Messages can be replayed across chains if chainId isn't in the hash.
    """
    bridge_patterns = [
        r"function\s+(?:receiveMessage|processMessage|executeMessage|onMessage|_receive)\s*\(",
        r"function\s+(?:lzReceive|sgReceive|anySwapIn|bridgeIn)\s*\(",
    ]

    for pattern in bridge_patterns:
        for match in re.finditer(pattern, source):
            line_no = source[:match.start()].count("\n") + 1
            func_name = re.search(r"function\s+(\w+)", match.group()).group(1)
            func_body = _extract_function_body(lines, line_no - 1)

            has_chain_check = any(kw in func_body for kw in [
                "block.chainid", "chainId", "srcChainId",
                "sourceChain", "_srcChainId", "getChainId",
            ])

            if not has_chain_check:
                yield Finding(
                    id="", title=f"Cross-chain message handler without chain ID verification in {func_name}()",
                    severity=Severity.CRITICAL, impact="Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
                    confidence=60, file=file, lines=[line_no],
                    function=func_name,
                    description=(
                        f"The cross-chain message handler `{func_name}()` does not verify the source "
                        f"chain ID. Messages from one chain can be replayed on another chain, "
                        f"potentially draining funds from the bridge on multiple chains."
                    ),
                    recommendation="Always verify the source chain ID in cross-chain message handlers. Include chain ID in message hashes to prevent cross-chain replay.",
                    detector="custom:cross-chain-replay",
                    exploitable_by="any_user", raw_detector_id="cross-chain-replay",
                )


def detect_bridge_message_validation(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect bridge message handlers that don't validate the sender/origin.
    """
    bridge_receivers = re.finditer(
        r"function\s+(lzReceive|_nonblockingLzReceive|sgReceive|anySwapIn|onOFTReceived|receivePayload)\s*\(",
        source,
    )

    for match in bridge_receivers:
        func_name = match.group(1)
        line_no = source[:match.start()].count("\n") + 1
        func_body = _extract_function_body(lines, line_no - 1)

        has_sender_validation = any(kw in func_body for kw in [
            "trustedRemote", "trustedSource", "isTrustedRemote",
            "require(msg.sender", "onlyBridge", "onlyRelayer",
            "srcAddress", "_srcAddress",
        ])

        if not has_sender_validation:
            yield Finding(
                id="", title=f"Bridge receiver {func_name}() without sender validation",
                severity=Severity.CRITICAL, impact="Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
                confidence=60, file=file, lines=[line_no],
                function=func_name,
                description=(
                    f"The bridge message receiver `{func_name}()` does not validate the remote sender. "
                    f"An attacker can craft messages from an untrusted source to trigger unauthorized "
                    f"actions like minting tokens or releasing locked funds."
                ),
                recommendation="Validate the source address against a trusted remote mapping. For LayerZero, check trustedRemoteLookup[_srcChainId].",
                detector="custom:bridge-sender-validation",
                exploitable_by="any_user", raw_detector_id="bridge-sender-validation",
            )


# ═══════════════════════════════════════════════════════════════════
# 6. L2-SPECIFIC SECURITY
# ═══════════════════════════════════════════════════════════════════

def detect_l2_sequencer_dependency(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect L2 protocols using Chainlink without checking sequencer uptime.
    When the L2 sequencer goes down, prices become stale but look fresh.
    """
    has_chainlink = "latestRoundData" in source
    is_l2_aware = any(kw in source for kw in [
        "Optimism", "Arbitrum", "L2", "sequencer",
        "OP_STACK", "ARB", "BASE",
    ])

    if has_chainlink and is_l2_aware:
        has_sequencer_check = "sequencerUptimeFeed" in source or "SEQUENCER" in source

        if not has_sequencer_check:
            oracle_match = re.search(r"\.latestRoundData\s*\(\)", source)
            line_no = source[:oracle_match.start()].count("\n") + 1 if oracle_match else 1

            yield Finding(
                id="", title="L2 Chainlink oracle without sequencer uptime check",
                severity=Severity.HIGH, impact="Theft of unclaimed yield",
                confidence=60, file=file, lines=[line_no],
                function=_find_enclosing_function(lines, line_no - 1),
                description=(
                    "This L2 protocol uses Chainlink price feeds without checking the sequencer uptime feed. "
                    "When the L2 sequencer goes down and comes back up, prices may appear fresh but reflect "
                    "pre-downtime values. Attackers can exploit stale prices during the grace period."
                ),
                recommendation="Check the sequencer uptime feed (Chainlink provides L2 Sequencer Uptime Feeds). Add a grace period after sequencer recovery.",
                detector="custom:l2-sequencer-check",
                exploitable_by="any_user", raw_detector_id="l2-sequencer-check",
            )


def detect_l2_block_properties(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect reliance on L1 block properties (block.number, block.timestamp)
    that behave differently on L2s. On Optimism, block.number was the L1
    block number until Bedrock. On Arbitrum, block.number is the L2 block.
    """
    block_props = [
        (r"\bblock\.number\b", "block.number"),
        (r"\bblock\.timestamp\b", "block.timestamp"),
        (r"\bblock\.difficulty\b", "block.difficulty"),
        (r"\bblock\.basefee\b", "block.basefee"),
    ]

    l2_indicators = ["Optimism", "Arbitrum", "L2", "rollup", "OP_STACK", "BASE", "ZKSYNC"]
    is_l2 = any(kw in source for kw in l2_indicators)

    if not is_l2:
        return

    for pattern, name in block_props:
        for match in re.finditer(pattern, source):
            line_no = source[:match.start()].count("\n") + 1
            context = _get_context(lines, line_no - 1, radius=10)

            # Check if used for time-sensitive calculations
            is_time_sensitive = any(kw in context for kw in [
                "deadline", "expir", "lock", "vesting", "period",
                "duration", "interval", "timeout", "delay",
            ])

            if is_time_sensitive:
                yield Finding(
                    id="", title=f"L2 protocol relies on {name} for time-sensitive logic",
                    severity=Severity.MEDIUM, impact="Temporary freezing of funds",
                    confidence=45, file=file, lines=[line_no],
                    function=_find_enclosing_function(lines, line_no - 1),
                    description=(
                        f"This L2 protocol uses `{name}` in time-sensitive logic. Block properties "
                        f"behave differently on L2s: block times vary on Arbitrum, and Optimism "
                        f"had L1 block numbers pre-Bedrock. Hardcoded assumptions about block times "
                        f"can cause premature/delayed unlocks, liquidations, or expired transactions."
                    ),
                    recommendation=f"Use block.timestamp for time calculations (more consistent across L2s). Avoid assuming fixed block intervals.",
                    detector="custom:l2-block-properties",
                    exploitable_by="any_user", raw_detector_id="l2-block-properties",
                )
                break  # one per property per file


def detect_l2_withdrawal_validation(source: str, lines: list[str], file: str) -> Generator[Finding, None, None]:
    """
    Detect L2 bridge/withdrawal functions without proper finalization checks.
    """
    withdrawal_patterns = re.finditer(
        r"function\s+(finalizeWithdrawal|proveWithdrawal|claimWithdrawal|relayMessage)\s*\(",
        source,
    )

    for match in withdrawal_patterns:
        func_name = match.group(1)
        line_no = source[:match.start()].count("\n") + 1
        func_body = _extract_function_body(lines, line_no - 1)

        has_proof_check = any(kw in func_body for kw in [
            "provenWithdrawal", "finalizedWithdrawal", "l2OutputOracle",
            "withdrawalHash", "outputRoot", "merkleProof",
            "proven[", "finalized[", "processed[",
        ])

        has_replay_prevention = any(kw in func_body for kw in [
            "claimed[", "processed[", "used[", "executed[",
            "delete ", "= true",
        ])

        if not has_proof_check:
            yield Finding(
                id="", title=f"L2 withdrawal {func_name}() without proof verification",
                severity=Severity.CRITICAL, impact="Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
                confidence=55, file=file, lines=[line_no],
                function=func_name,
                description=(
                    f"The withdrawal function `{func_name}()` does not verify the withdrawal proof "
                    f"against the L2 output oracle or state root. An attacker could forge withdrawal "
                    f"proofs to drain bridge funds."
                ),
                recommendation="Verify withdrawal proofs against the L2OutputOracle. Check merkle proofs against the committed state root.",
                detector="custom:l2-withdrawal-proof",
                exploitable_by="any_user", raw_detector_id="l2-withdrawal-proof",
            )

        if has_proof_check and not has_replay_prevention:
            yield Finding(
                id="", title=f"L2 withdrawal {func_name}() without replay prevention",
                severity=Severity.CRITICAL, impact="Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
                confidence=55, file=file, lines=[line_no],
                function=func_name,
                description=(
                    f"The withdrawal function `{func_name}()` verifies proofs but does not mark "
                    f"withdrawals as claimed. The same valid proof can be replayed multiple times "
                    f"to drain bridge funds."
                ),
                recommendation="Mark each withdrawal hash as processed after successful execution. Use a mapping to prevent replay.",
                detector="custom:l2-withdrawal-replay",
                exploitable_by="any_user", raw_detector_id="l2-withdrawal-replay",
            )


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════

def _extract_function_body(lines: list[str], start_line: int, max_lines: int = 80) -> str:
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
    start = max(0, center - radius)
    end = min(len(lines), center + radius + 1)
    return "\n".join(lines[start:end])


def _find_enclosing_function(lines: list[str], line_idx: int) -> str:
    for i in range(line_idx, max(line_idx - 60, -1), -1):
        m = re.match(r"\s*function\s+(\w+)", lines[i])
        if m:
            return m.group(1)
    return "(unknown)"


def _find_function_start(lines: list[str], line_idx: int) -> int:
    for i in range(line_idx, max(line_idx - 60, -1), -1):
        if re.match(r"\s*function\s+\w+", lines[i]):
            return i
    return max(0, line_idx - 20)


# Registry
ALL_ADVANCED_DETECTORS = [
    # MEV & Trading
    detect_sandwich_attack_surface,
    detect_frontrun_vulnerable_state,
    detect_return_value_bomb,
    # Token Standards
    detect_weird_erc20_handling,
    detect_erc721_callback_reentrancy,
    detect_erc4626_inflation_attack,
    # Governance
    detect_governance_flash_loan_vote,
    detect_governance_proposal_manipulation,
    # Economic/Financial
    detect_donation_attack,
    detect_oracle_staleness,
    detect_rounding_direction,
    # Cross-chain
    detect_cross_chain_replay,
    detect_bridge_message_validation,
    # L2 Security
    detect_l2_sequencer_dependency,
    detect_l2_block_properties,
    detect_l2_withdrawal_validation,
]
