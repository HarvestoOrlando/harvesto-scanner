#!/bin/bash
set -euo pipefail

echo "============================================"
echo "  Harvesto Scanner — evmbench Benchmark Setup"
echo "============================================"
echo ""
echo "This script clones the paradigmxyz/evmbench repo"
echo "and prepares it for benchmarking Harvesto Scanner."
echo ""

# Clone evmbench
if [ ! -d "benchmarks/evmbench" ]; then
    echo "[1/3] Cloning evmbench..."
    git clone --depth 1 https://github.com/paradigmxyz/evmbench.git benchmarks/evmbench
else
    echo "[1/3] evmbench already cloned."
fi

# Check if the frontier-evals submodule has tasks
echo "[2/3] Checking for task files..."
if [ -d "benchmarks/evmbench/frontier-evals" ]; then
    echo "  Found frontier-evals submodule."
elif [ -d "benchmarks/evmbench/backend/worker_runner" ]; then
    echo "  Found worker_runner with detect prompt."
fi

# Create benchmark runner
echo "[3/3] Creating benchmark runner..."
cat > benchmarks/run_benchmark.sh << 'BENCH_EOF'
#!/bin/bash
set -euo pipefail

# Usage: ./benchmarks/run_benchmark.sh <path-to-audit-dir>
# Example: ./benchmarks/run_benchmark.sh ./benchmarks/evmbench/tasks/2024-04-noya/

AUDIT_DIR="${1:-.}"
OUTPUT_DIR="${2:-submission}"

mkdir -p "$OUTPUT_DIR"

echo "Running Harvesto Scanner on: $AUDIT_DIR"
echo "Output: $OUTPUT_DIR/audit.md"
echo ""

# Run scanner in evmbench mode
python -m harvesto_scanner bench "$AUDIT_DIR" \
    --output "$OUTPUT_DIR/audit.md" \
    --verbose

echo ""
echo "Done! Report at: $OUTPUT_DIR/audit.md"
echo ""
echo "To validate format:"
echo "  python -c \"import json; d=open('$OUTPUT_DIR/audit.md').read(); start=d.index('{'); end=d.rindex('}')+1; print(json.loads(d[start:end]))\""
BENCH_EOF
chmod +x benchmarks/run_benchmark.sh

echo ""
echo "============================================"
echo "  Setup complete!"
echo ""
echo "  To benchmark against evmbench tasks:"
echo "    ./benchmarks/run_benchmark.sh ./benchmarks/evmbench/<task_dir>/"
echo ""
echo "  To run against your own contracts:"
echo "    harvesto bench ./path/to/audit/ --output submission/audit.md"
echo "============================================"
