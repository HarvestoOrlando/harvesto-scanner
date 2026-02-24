# Harvesto Scanner — Smart Contract Vulnerability Detector

**Precision-first smart contract bug finder. Catches fewer bugs, but the ones it catches are real.**

Harvesto Scanner uses layered static analysis with aggressive false-positive filtering to detect Critical, High, Medium, and Low severity vulnerabilities in Solidity smart contracts. Instead of flagging everything, it applies multi-pass verification to reduce false positives by ~90% compared to raw Slither/Mythril output.

## Severity Classification (Immunefi Standard)

| Severity | Impact |
|----------|--------|
| **Critical** | Direct theft of user funds (at-rest or in-motion), permanent freezing of funds, protocol insolvency |
| **High** | Theft of unclaimed yield |
| **Medium** | Unbounded gas consumption, permanent freezing of unclaimed yield, temporary freezing of funds |
| **Low** | Contract fails to deliver promised returns (no value loss), block stuffing |

## Quick Start (GitHub Codespaces)

```bash
# 1. Clone and enter the project
git clone <this-repo>
cd harvesto-scanner

# 2. Run the setup script (installs everything)
chmod +x scripts/setup-codespaces.sh
./scripts/setup-codespaces.sh

# 3. Scan a contract or directory
harvesto scan ./path/to/contracts/

# 4. Scan with evmbench benchmark
harvesto bench ./benchmarks/evmbench/
```

## Architecture

```
                    ┌─────────────────────┐
                    │   Contract Input     │
                    │  (.sol files / dir)  │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Pass 1: Slither    │  Raw detector output
                    │   Static Analysis    │  (high recall, many FPs)
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Pass 2: Pattern    │  Regex + AST checks
                    │   Detectors          │  for known vuln patterns
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Pass 3: FP Filter  │  Context-aware filtering
                    │   Engine             │  (access control, constructors,
                    └──────────┬──────────┘   msg.sender, owner-only, etc.)
                               │
                    ┌──────────▼──────────┐
                    │   Pass 4: Severity   │  Map to Immunefi severity
                    │   Classifier         │  + exploitability scoring
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Pass 5: Dedup &    │  Remove overlapping findings
                    │   Consolidation      │  across detectors
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
        ┌──────────┐   ┌──────────────┐  ┌───────────┐
        │  JSON     │   │  Markdown    │  │  evmbench  │
        │  Report   │   │  Report      │  │  Format    │
        └──────────┘   └──────────────┘  └───────────┘
```

## FP Reduction Strategy (the 90% goal)

The core philosophy: **it's better to miss a bug than to cry wolf.**

### Filter Layers:
1. **Owner/Admin Filter** — Functions gated by `onlyOwner`, `onlyAdmin`, `onlyRole`, `Ownable` modifiers are deprioritized (attacker can't call them)
2. **Constructor Filter** — Findings in constructors/initializers are filtered (one-time setup code)
3. **Immutable/Constant Filter** — State variables marked `immutable` or `constant` can't be manipulated
4. **Known-Safe Pattern Filter** — OpenZeppelin, well-audited library calls are whitelisted
5. **msg.sender Validation Filter** — Functions that validate msg.sender early are lower risk
6. **View/Pure Filter** — Read-only functions can't cause state damage
7. **Duplicate Collapse** — Same root cause across multiple functions = 1 finding
8. **Confidence Scoring** — Each finding gets a 0-100 confidence score; below threshold = filtered

## evmbench Integration

Harvesto outputs are compatible with the evmbench `{"vulnerabilities": [...]}` format used by Paradigm/OpenAI's benchmark. Run:

```bash
harvesto bench ./path/to/audit/ --output submission/audit.md
```

This produces output parseable by the evmbench harness for benchmarking against the 120-vulnerability dataset.

## Output Formats

### JSON (default)
```json
{
  "vulnerabilities": [
    {
      "id": "HARVESTO-001",
      "title": "Reentrancy in withdraw()",
      "severity": "Critical",
      "impact": "Direct theft of user funds",
      "confidence": 92,
      "file": "src/Vault.sol",
      "lines": [45, 52],
      "function": "withdraw",
      "description": "External call before state update allows recursive withdrawal...",
      "recommendation": "Apply checks-effects-interactions pattern...",
      "detector": "reentrancy-eth",
      "exploitable_by": "any_user"
    }
  ],
  "metadata": {
    "scanner_version": "0.1.0",
    "scan_time_seconds": 12.4,
    "total_raw_findings": 847,
    "filtered_findings": 6,
    "fp_reduction_rate": 0.993
  }
}
```

## License

MIT
