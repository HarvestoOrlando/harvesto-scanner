"""
Harvesto Fuzzer — companion tool to Harvesto Scanner.

Takes vulnerability findings from the scanner and generates:
1. Foundry invariant fuzz tests to confirm the bug
2. Echidna property tests as alternative
3. Full PoC exploit contracts for bug bounty submissions

Usage:
    harvesto fuzz ./scan-results.json            # Generate fuzz tests for all findings
    harvesto fuzz ./scan-results.json --poc       # Generate PoC exploit contracts
    harvesto fuzz ./scan-results.json --echidna   # Use Echidna format instead of Foundry
"""
