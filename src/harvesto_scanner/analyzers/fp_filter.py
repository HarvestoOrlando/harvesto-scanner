"""
False Positive Filter Engine — the heart of Harvesto's precision.

Applies layered context-aware filters to raw findings.
Each filter either adjusts confidence, downgrades severity, or removes the finding entirely.
The goal: if it survives all filters, it's almost certainly real.
"""

import re
from pathlib import Path
from typing import Optional

from harvesto_scanner.models import Finding, Severity


# Minimum confidence to survive filtering
CONFIDENCE_THRESHOLD = 50

# Access control modifier patterns
ACCESS_CONTROL_MODIFIERS = {
    "onlyowner", "onlyadmin", "onlyrole", "onlyminter", "onlygovernance",
    "onlyauthorized", "onlyoperator", "onlycontroller", "restricted",
    "auth", "requiresauth", "onlyproxy", "onlydelegateowner",
    "onlymanager", "onlygov", "onlykeeper", "onlyguardian",
    "onlyself", "onlypendingowner", "onlytimelockcontroller",
    "initializer",  # one-time setup
}

# Known safe library paths
SAFE_LIBRARIES = {
    "@openzeppelin/", "openzeppelin-contracts/", "openzeppelin-upgradeable/",
    "@chainlink/", "solmate/", "solady/",
    "forge-std/", "ds-test/", "prb-math/",
}

# Known test file patterns
TEST_FILE_PATTERNS = {
    "/test/", "/tests/", "Test.sol", ".t.sol", "/mock/", "/script/",
    "Migrations.sol",
}

# Patterns that only match at path component level
TEST_FILE_BASENAME_PATTERNS = {
    "Mock",
}


class FPFilterEngine:
    """
    Multi-layer false positive filter.
    Each filter is a method that takes a Finding + source context and either:
    - Returns the Finding (possibly with adjusted confidence/severity)
    - Returns None (finding is filtered out)
    """

    def __init__(self, source_cache: dict[str, str]):
        """
        Args:
            source_cache: mapping of file path -> source code content
        """
        self.source_cache = source_cache
        self.stats = {
            "total_input": 0,
            "filtered_test_file": 0,
            "filtered_library": 0,
            "filtered_access_control": 0,
            "filtered_constructor": 0,
            "filtered_view_pure": 0,
            "filtered_internal_private": 0,
            "filtered_low_confidence": 0,
            "filtered_interface": 0,
            "survived": 0,
        }

    def filter_all(self, findings: list[Finding]) -> list[Finding]:
        """Apply all filters to a list of findings. Returns survivors."""
        self.stats["total_input"] = len(findings)
        survivors = []

        for finding in findings:
            result = self._apply_filters(finding)
            if result is not None:
                survivors.append(result)

        self.stats["survived"] = len(survivors)
        return survivors

    def _apply_filters(self, f: Finding) -> Optional[Finding]:
        """Apply each filter in sequence. First None = finding is dead."""
        filters = [
            self._filter_test_files,
            self._filter_safe_libraries,
            self._filter_interfaces_abstracts,
            self._filter_constructor_initializer,
            self._filter_view_pure_functions,
            self._filter_internal_private_functions,
            self._filter_access_controlled,
            self._filter_msg_sender_validated,
            self._filter_immutable_constant_targets,
            self._filter_known_safe_patterns,
            # ── New filters from rejected report analysis ──
            self._filter_dust_impact_overstated,
            self._filter_self_inflicted_prerequisite,
            self._filter_admin_migration_roles,
            self._filter_external_integration_rounding,
            self._filter_confidence_threshold,
        ]

        for filter_fn in filters:
            f = filter_fn(f)
            if f is None:
                return None

        # Post-filter warnings (don't remove, just annotate)
        f = self._warn_poc_requirements(f)
        f = self._warn_unverified_assumptions(f)
        f = self._warn_mock_heavy_poc(f)

        return f

    # ------------------------------------------------------------------
    # Filter implementations
    # ------------------------------------------------------------------

    def _filter_test_files(self, f: Finding) -> Optional[Finding]:
        """Remove findings in test/mock/script files."""
        file_path = f"/{f.file}"  # ensure leading slash for pattern matching
        for pattern in TEST_FILE_PATTERNS:
            if pattern in file_path:
                self.stats["filtered_test_file"] += 1
                return None
        # Basename patterns
        basename = Path(f.file).name
        for pattern in TEST_FILE_BASENAME_PATTERNS:
            if pattern in basename:
                self.stats["filtered_test_file"] += 1
                return None
        return f

    def _filter_safe_libraries(self, f: Finding) -> Optional[Finding]:
        """Remove findings in well-audited libraries (OpenZeppelin, Solmate, etc.)."""
        for lib in SAFE_LIBRARIES:
            if lib in f.file:
                self.stats["filtered_library"] += 1
                return None
        return f

    def _filter_interfaces_abstracts(self, f: Finding) -> Optional[Finding]:
        """Remove findings in interface or abstract contract definitions."""
        source = self.source_cache.get(f.file, "")
        if not source:
            return f

        # Check if the file is predominantly an interface
        interface_count = len(re.findall(r"\binterface\s+\w+", source))
        contract_count = len(re.findall(r"\bcontract\s+\w+", source))

        if interface_count > 0 and contract_count == 0:
            self.stats["filtered_interface"] += 1
            return None

        return f

    def _filter_constructor_initializer(self, f: Finding) -> Optional[Finding]:
        """
        Filter findings in constructors and initializers.
        These run once during deployment by the deployer — not exploitable.
        """
        if f.function in ("constructor", "initialize", "init", "__init__", "_init"):
            self.stats["filtered_constructor"] += 1
            return None

        # Also check if the finding's actual line is within a constructor body
        source = self.source_cache.get(f.file, "")
        if source and f.lines:
            target_line = f.lines[0] - 1
            lines = source.split("\n")

            # Find the enclosing function by walking backwards from the finding line
            # Only filter if we're inside a constructor or initializer body
            brace_depth = 0
            for i in range(target_line, max(target_line - 80, -1), -1):
                if i < 0 or i >= len(lines):
                    continue
                line = lines[i]
                # Count braces backwards (reversed)
                brace_depth += line.count("}") - line.count("{")

                if brace_depth < 0:
                    # We've exited the enclosing block
                    break

                if re.match(r"\s*constructor\s*\(", line):
                    self.stats["filtered_constructor"] += 1
                    return None
                if re.match(r"\s*function\s+initialize\s*\(", line):
                    context = "\n".join(lines[max(0,i-1):min(len(lines),i+3)])
                    if "initializer" in context.lower():
                        self.stats["filtered_constructor"] += 1
                        return None
                    break
                if re.match(r"\s*function\s+\w+", line):
                    # Found a different function — not in constructor
                    break

        return f

    def _filter_view_pure_functions(self, f: Finding) -> Optional[Finding]:
        """
        View/pure functions can't modify state.
        Downgrade severity for findings in view/pure functions.
        Most can be outright removed for fund-theft concerns.
        """
        source = self.source_cache.get(f.file, "")
        if not source:
            return f

        func_sig = self._get_function_signature(source, f.function)
        if func_sig and (" view " in func_sig or " pure " in func_sig):
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                # View functions can't steal funds — but can provide wrong data
                # that OTHER functions use. Downgrade rather than remove.
                f.severity = Severity.LOW
                f.confidence = max(f.confidence - 30, 10)
                f.exploitable_by = "indirect_only"
                self.stats["filtered_view_pure"] += 1
            return f

        return f

    def _filter_internal_private_functions(self, f: Finding) -> Optional[Finding]:
        """
        Internal/private functions can only be called from within the contract.
        They might still be reachable via public functions, so we downgrade
        rather than remove — unless no public caller exists.
        """
        source = self.source_cache.get(f.file, "")
        if not source:
            return f

        func_sig = self._get_function_signature(source, f.function)
        if func_sig and (" internal " in func_sig or " private " in func_sig):
            # Check if any external/public function calls this internal function
            callers = re.findall(rf"\b{re.escape(f.function)}\s*\(", source)
            if len(callers) <= 1:  # only the definition itself
                self.stats["filtered_internal_private"] += 1
                return None

            # Has callers — keep but reduce confidence
            f.confidence = max(f.confidence - 15, 20)
            f.exploitable_by = "indirect_via_public_caller"
        return f

    def _filter_access_controlled(self, f: Finding) -> Optional[Finding]:
        """
        The big one. If a function requires a privileged role, an unprivileged
        attacker can't exploit it. Owner-protected functions are NOT vulnerabilities
        from a bug bounty perspective (Immunefi explicitly excludes these).
        """
        source = self.source_cache.get(f.file, "")
        if not source:
            return f

        func_sig = self._get_function_signature(source, f.function)
        if not func_sig:
            return f

        func_sig_lower = func_sig.lower()

        # Check for access control modifiers
        for mod in ACCESS_CONTROL_MODIFIERS:
            if mod in func_sig_lower:
                # This function is admin-only — not a bounty-eligible vuln
                self.stats["filtered_access_control"] += 1
                f.exploitable_by = "admin_only"
                # Don't remove entirely — could be useful info —
                # but drop to informational and below threshold
                f.severity = Severity.INFORMATIONAL
                f.confidence = 10
                return f  # will be caught by confidence threshold

        return f

    def _filter_msg_sender_validated(self, f: Finding) -> Optional[Finding]:
        """
        If a function validates msg.sender against a stored authorized address
        at the top of the body, it has inline access control.
        """
        source = self.source_cache.get(f.file, "")
        if not source:
            return f

        lines = source.split("\n")
        func_body = self._get_function_body_text(lines, f.function)
        if not func_body:
            return f

        # Check first 10 lines of function body for msg.sender check
        body_lines = func_body.split("\n")[:10]
        early_body = "\n".join(body_lines)

        sender_checks = [
            r"require\s*\(\s*msg\.sender\s*==",
            r"if\s*\(\s*msg\.sender\s*!=.*revert",
            r"_checkOwner\(\)",
            r"_checkRole\(",
            r"onlyOwner",
        ]

        for check in sender_checks:
            if re.search(check, early_body):
                f.confidence = max(f.confidence - 25, 15)
                f.exploitable_by = "privileged_role"
                break

        return f

    def _filter_immutable_constant_targets(self, f: Finding) -> Optional[Finding]:
        """
        If a finding involves a variable that's immutable or constant,
        it can't be manipulated by an attacker.
        """
        source = self.source_cache.get(f.file, "")
        if not source:
            return f

        # Only relevant for certain detector types
        if f.raw_detector_id not in (
            "controlled-delegatecall", "unsafe-delegatecall",
            "arbitrary-send-eth", "arbitrary-send-erc20",
        ):
            return f

        # Check if the target address is immutable/constant
        if re.search(r"\bimmutable\b.*\baddress\b|\baddress\b.*\bimmutable\b", source):
            f.confidence = max(f.confidence - 30, 10)

        return f

    def _filter_known_safe_patterns(self, f: Finding) -> Optional[Finding]:
        """
        Remove findings that match known safe code patterns.
        """
        source = self.source_cache.get(f.file, "")
        if not source:
            return f

        safe_patterns = {
            # Reentrancy in nonReentrant functions
            "reentrancy": [r"nonReentrant", r"ReentrancyGuard"],
            # Delegatecall in well-known proxy patterns
            "delegatecall": [r"ERC1967Upgrade", r"_implementation\(\)", r"StorageSlot"],
            # SafeERC20 usage covers unchecked transfers
            "unchecked-transfer": [r"SafeERC20", r"safeTransfer\(", r"safeTransferFrom\("],
        }

        for detector_key, patterns in safe_patterns.items():
            if detector_key in f.raw_detector_id:
                for pattern in patterns:
                    if re.search(pattern, source):
                        f.confidence = max(f.confidence - 35, 5)
                        break

        return f

    def _filter_confidence_threshold(self, f: Finding) -> Optional[Finding]:
        """Final gate: if confidence is below threshold, filter it out."""
        if f.confidence < CONFIDENCE_THRESHOLD:
            self.stats["filtered_low_confidence"] += 1
            return None
        return f

    # ------------------------------------------------------------------
    # NEW: Filters derived from rejected Immunefi reports (6 categories)
    # ------------------------------------------------------------------

    def _filter_dust_impact_overstated(self, f: Finding) -> Optional[Finding]:
        """
        FP Category 1: DUST_IMPACT_OVERSTATED (from Kelp DAO Reports 1 & 6)

        Finding involves wei-level rounding/truncation in protocols that
        operate at ether scale. The drift (N wei after N operations) is
        astronomically outpaced by interest/yield accrual.

        Kelp DAO rejection: "Yield collection is only blocked while
        aaveBalance <= totalETHDepositedToAave; once accrued yield exceeds
        any dust mismatch, collection resumes normally."

        Math: At 1.97% APY on $1M, daily yield = ~1.5e16 wei.
        Drift after 1000 deposits = 1000 wei. Ratio: 15 trillion to 1.

        Rule: If detector is about rounding AND affected path is yield/interest
        AND quantified drift is wei-scale → downgrade to Informational.
        """
        rounding_detectors = {
            "rounding-direction", "donation-attack",
        }

        is_rounding = f.raw_detector_id in rounding_detectors
        description_lower = (f.description or "").lower()
        title_lower = (f.title or "").lower()

        rounding_keywords = [
            "truncat", "round", "1 wei", "dust", "drift", "wei-level",
            "rounding error", "off by one", "index math", "scaled balance",
        ]
        has_rounding_language = any(kw in description_lower or kw in title_lower for kw in rounding_keywords)

        if not is_rounding and not has_rounding_language:
            return f

        source = self.source_cache.get(f.file, "")
        if not source:
            return f

        func_body = self._get_function_body_text(source.split("\n"), f.function) or ""
        func_lower = func_body.lower()

        yield_indicators = [
            "interest", "yield", "reward", "accrue", "treasury",
            "collectinterest", "harvestyield", "claimreward",
            "atoken", "aave", "compound", "deposit", "principal",
        ]
        is_yield_path = any(kw in func_lower or kw in description_lower for kw in yield_indicators)

        # Also check: does the description claim "permanent" impact from wei-level drift?
        permanent_claims = ["permanent", "forever", "irreversible", "no recovery"]
        overstated = any(kw in description_lower for kw in permanent_claims) and has_rounding_language

        if is_yield_path or overstated:
            f.severity = Severity.INFORMATIONAL
            f.confidence = max(f.confidence - 40, 5)
            f.recommendation = (
                f"[DUST_IMPACT_WARNING] {f.recommendation} "
                f"NOTE: Wei-level rounding drift is typically outpaced by yield accrual "
                f"by many orders of magnitude. At 2% APY on $1M, daily yield ~1.5e16 wei "
                f"vs N wei drift after N deposits. Verify that drift can REALISTICALLY "
                f"exceed accrued interest before reporting. Check live contract state — "
                f"if protocol is currently collecting yield, the 'permanent freeze' claim is wrong."
            )
            self.stats.setdefault("filtered_dust_impact", 0)
            self.stats["filtered_dust_impact"] += 1

        return f

    def _filter_self_inflicted_prerequisite(self, f: Finding) -> Optional[Finding]:
        """
        FP Category 3: SELF_INFLICTED_PREREQUISITE (from Forta Report 3)

        Attack path requires the victim to voluntarily damage their own position
        first (burn NFT, transfer to dead address, etc.). This is self-harm,
        not adversarial exploitation.

        Forta rejection: "This condition only occurs if the pool owner
        deliberately transfers the pool NFT to an address they don't control.
        Any unclaimable rewards are an expected consequence of that action."

        Rule: If exploitation requires user to transfer/burn/destroy their
        own assets → Invalid. Also catches "transfer to 0xdead/random address"
        patterns where "special-casing 0xdead would not solve this, since the
        same outcome can be achieved by sending the NFT to any arbitrary address."
        """
        description_lower = (f.description or "").lower()

        self_harm_patterns = [
            "burn", "0xdead", "dead address", "transferred to",
            "owner sends", "owner transfers", "voluntarily",
            "deliberately", "self-destruct", "forfeiting ownership",
            "irrevocably transfer", "sends to address they don't control",
        ]

        has_self_harm = sum(1 for p in self_harm_patterns if p in description_lower)

        if has_self_harm >= 2:
            f.confidence = max(f.confidence - 35, 5)
            f.recommendation = (
                f"[SELF_INFLICTED_WARNING] {f.recommendation} "
                f"NOTE: This scenario requires the victim to voluntarily damage their own "
                f"position (burn NFT, transfer to dead address, etc.). Bounty programs "
                f"exclude self-inflicted prerequisites. The 'attacker' IS the victim. "
                f"Special-casing specific addresses (0xdead) doesn't help because the "
                f"same outcome is achievable via any arbitrary address the owner doesn't control."
            )
            self.stats.setdefault("filtered_self_inflicted", 0)
            self.stats["filtered_self_inflicted"] += 1

        return f

    def _filter_admin_migration_roles(self, f: Finding) -> Optional[Finding]:
        """
        FP Category 4: ADMIN_ONLY_PATH — extended (from Forta Report 4)

        Strengthens the existing access control filter to catch non-obvious
        admin roles like MIGRATOR_ROLE, REWARDER_ROLE, OPERATOR_ROLE, etc.
        These are often missed because they don't match the standard
        "onlyOwner" pattern but are equally admin-gated.

        Forta rejection: "migrate() was introduced for a one-time historical
        migration to scanner pools and is gated behind
        SCANNER_2_SCANNER_POOL_MIGRATOR_ROLE. Outside of that specific process,
        there is no operational need to call it again."

        Rule: Functions with *_ROLE modifiers + one-time migration/setup
        functions are NOT user-facing attack surface.
        """
        source = self.source_cache.get(f.file, "")
        if not source:
            return f

        func_sig = self._get_function_signature(source, f.function)
        if not func_sig:
            return f

        func_sig_lower = func_sig.lower()

        # Extended admin role patterns (beyond the basic ACCESS_CONTROL_MODIFIERS)
        extended_admin_roles = [
            "migrator", "rewarder", "relayer", "bridge",
            "executor", "proposer", "canceller", "upgrader",
            "pauser", "unpauser", "sweeper", "rescuer",
            "liquidator", "setter", "configurator",
        ]

        for role in extended_admin_roles:
            if role in func_sig_lower:
                f.confidence = max(f.confidence - 30, 10)
                f.exploitable_by = "admin_only"
                f.recommendation = (
                    f"[ADMIN_ROLE_WARNING] {f.recommendation} "
                    f"NOTE: This function appears gated by a '{role}' role. "
                    f"Verify the role is not user-callable before reporting."
                )
                self.stats.setdefault("filtered_admin_migration", 0)
                self.stats["filtered_admin_migration"] += 1
                break

        # Also check for one-time migration functions
        one_time_keywords = ["migrate", "migration", "upgrade", "initialize"]
        is_one_time = any(kw in (f.function or "").lower() for kw in one_time_keywords)

        if is_one_time and f.exploitable_by != "any_user":
            f.confidence = max(f.confidence - 20, 10)
            if not f.recommendation.startswith("[ADMIN_ROLE_WARNING]"):
                f.recommendation = (
                    f"[ONE_TIME_FUNCTION_WARNING] {f.recommendation} "
                    f"NOTE: '{f.function}' appears to be a one-time migration/setup function. "
                    f"These are typically admin-only and not user-facing attack surface."
                )

        return f

    def _filter_external_integration_rounding(self, f: Finding) -> Optional[Finding]:
        """
        FP Category related to #1: EXTERNAL_INTEGRATION_ROUNDING

        Findings about rounding/truncation in external protocol integrations
        (Aave, Compound, Lido, etc.) where the rounding is an inherent,
        well-known property of the external protocol.

        Kelp DAO rejection: "We agree that small wei-level rounding differences
        can occur when interacting with Aave (share/index math)...we classify
        this as a non-security rounding edge case."

        Aave V3 specifically: scaledAmount = floor(amount / liquidityIndex),
        mintedTokens = floor(scaledAmount * liquidityIndex). This is BY DESIGN.
        Every protocol that integrates Aave accepts this behavior.

        Rule: Rounding findings in well-known external protocol integrations
        → strong confidence penalty + warning about accepted design behavior.
        """
        source = self.source_cache.get(f.file, "")
        if not source:
            return f

        description_lower = (f.description or "").lower()

        external_protocols = [
            "aave", "compound", "lido", "morpho", "maker",
            "uniswap", "balancer", "curve", "yearn",
        ]

        is_external_integration = any(p in source.lower() or p in description_lower for p in external_protocols)

        rounding_terms = ["truncat", "round", "1 wei", "scaled", "index math", "ray", "wad"]
        is_rounding_issue = any(t in description_lower for t in rounding_terms)

        if is_external_integration and is_rounding_issue:
            f.confidence = max(f.confidence - 25, 10)
            f.recommendation = (
                f"[EXTERNAL_ROUNDING_WARNING] {f.recommendation} "
                f"NOTE: Rounding in external protocol integrations (Aave/Compound/etc.) "
                f"is well-known behavior. Verify the rounding can cause measurable "
                f"(not wei-level) impact before reporting."
            )
            self.stats.setdefault("filtered_external_rounding", 0)
            self.stats["filtered_external_rounding"] += 1

        return f

    # ------------------------------------------------------------------
    # Post-filter warnings (annotate but don't remove)
    # ------------------------------------------------------------------

    def _warn_poc_requirements(self, f: Finding) -> Finding:
        """
        FP Category 2: POC_NOT_MEASURABLE (from Pinto Report 2)

        Pinto rejection: "The provided PoC does not demonstrate measurable impact.
        A valid PoC must show concrete evidence through before/after comparisons,
        such as balance changes, ownership transfers, broken invariants, or denial
        of service. PoCs that only describe a theoretical issue or lack assertions
        and logged outputs do not meet the required standard."

        Annotate HIGH/CRITICAL findings with mandatory PoC requirements.
        The scanner can't write the PoC, but it CAN prevent you from
        submitting a finding without one.
        """
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            if not hasattr(f, '_warnings'):
                f._warnings = []
            f._warnings.append(
                "POC_REQUIREMENT: This finding REQUIRES a PoC with:\n"
                "  1. before/after state comparisons (balanceOf, totalSupply, owner)\n"
                "  2. assert statements proving the impact (assertGt, assertLt, assertEq)\n"
                "  3. Quantified impact (exact funds stolen/lost in wei/tokens)\n"
                "  4. NO console.log-only tests — triagers reject these immediately\n"
                "  5. State-changing test functions (NOT view/pure)\n"
                "  Immunefi standard: 'PoCs that only describe a theoretical issue "
                "or lack assertions do not meet the required standard.'"
            )
        return f

    def _warn_unverified_assumptions(self, f: Finding) -> Finding:
        """
        FP Category 5: UNVERIFIED_ASSUMPTION (from Forta Report 4)

        Forta rejection: "The claim that no one holds SLASHER_ROLE is incorrect.
        Per our documentation, the Council multisig on Polygon holds SLASHER_ROLE
        on the AccessManager contract. This can also be verified on-chain via the
        Access contract read method (hasRole)."

        The report searched deployment scripts and event logs but missed the
        actual role assignment. The entire "permanent" claim hinged on this.

        Rule: If finding's impact depends on claims about deployment state
        (role not granted, function never called), flag for on-chain verification.
        Deployment scripts and event logs are NOT sufficient — roles can be
        granted via multisig/governance/timelock without appearing in deploy scripts.
        """
        description_lower = (f.description or "").lower()

        assumption_phrases = [
            "never been granted", "never assigned", "no one has",
            "never called", "never deployed", "not configured",
            "never set", "role does not exist", "no holder",
            "never granted", "has not been granted", "no address holds",
        ]

        for phrase in assumption_phrases:
            if phrase in description_lower:
                if not hasattr(f, '_warnings'):
                    f._warnings = []
                f._warnings.append(
                    f"UNVERIFIED_ASSUMPTION: This finding claims '{phrase}'. "
                    f"CRITICAL: Verify on-chain using hasRole(roleHash, address) read calls "
                    f"on the AccessManager/AccessControl contract. DO NOT rely solely on:\n"
                    f"  - Deployment script analysis (roles granted via multisig/governance won't appear)\n"
                    f"  - Event log search (events may be on different contracts or pre-date indexing)\n"
                    f"  - Git history (role grants happen on-chain, not in code)\n"
                    f"Check the project's documentation for role holders before claiming "
                    f"'no one has this role'. One wrong factual claim invalidates the entire report."
                )
                break
        return f

    def _warn_mock_heavy_poc(self, f: Finding) -> Finding:
        """
        FP Category 6: MOCK_HEAVY_POC (from Twyne Report 5)

        Twyne rejection (entire response): "poc is mocked heavily"

        The PoC used MockVToken, MockERC20, MockAavePool — completely custom
        mocks that simulate what the researcher THOUGHT Aave does internally.
        When you mock the exact behavior you're trying to prove, the PoC is
        circular reasoning: "My mock proves my mock works."

        Rule: If finding involves external protocol integration, warn that
        PoCs MUST fork mainnet. Mock only the ATTACKER contract, never the
        VICTIM protocol's contracts. Use vm.createSelectFork() with real
        deployed addresses and a specific block number.
        """
        description_lower = (f.description or "").lower()

        external_integrations = [
            "aave", "compound", "lido", "morpho", "uniswap",
            "chainlink", "balancer", "curve", "maker", "yearn",
            "sushiswap", "pancakeswap", "gmx", "layerzero",
        ]

        for protocol in external_integrations:
            if protocol in description_lower:
                if not hasattr(f, '_warnings'):
                    f._warnings = []
                f._warnings.append(
                    f"FORK_TEST_REQUIRED: This finding involves {protocol} integration.\n"
                    f"PoC RULES (from Twyne rejection 'poc is mocked heavily'):\n"
                    f"  1. MUST use vm.createSelectFork(rpcUrl, blockNumber) against REAL mainnet\n"
                    f"  2. NEVER mock the victim protocol's contracts (Mock{protocol.title()}Pool = instant reject)\n"
                    f"  3. Use REAL deployed contract addresses (verified on Etherscan/Basescan)\n"
                    f"  4. Only the ATTACKER contract should be custom Solidity code\n"
                    f"  5. If you mock the behavior you're trying to prove, it's circular reasoning\n"
                    f"  Triagers will reject mocked PoCs with a one-line dismissal."
                )
                break
        return f

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_function_signature(self, source: str, func_name: str) -> Optional[str]:
        """Extract the full function signature (including modifiers) for a function."""
        if func_name == "(unknown)" or func_name == "(storage layout)":
            return None

        pattern = re.compile(
            rf"function\s+{re.escape(func_name)}\s*\([^)]*\)[^{{]*",
            re.DOTALL,
        )
        match = pattern.search(source)
        if match:
            return match.group(0)
        return None

    def _get_function_body_text(self, lines: list[str], func_name: str) -> Optional[str]:
        """Get the text body of a function."""
        if func_name in ("(unknown)", "(storage layout)"):
            return None

        for i, line in enumerate(lines):
            if re.match(rf"\s*function\s+{re.escape(func_name)}\s*\(", line):
                body_lines = []
                brace_depth = 0
                started = False
                for j in range(i, min(i + 100, len(lines))):
                    body_lines.append(lines[j])
                    brace_depth += lines[j].count("{") - lines[j].count("}")
                    if "{" in lines[j]:
                        started = True
                    if started and brace_depth <= 0:
                        break
                return "\n".join(body_lines)
        return None
