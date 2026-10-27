#!/usr/bin/env bash
set -euo pipefail

echo "========================================================"
echo "  Zero-Trust Cloud Edge & Intelligent WAF Defense Mesh"
echo "========================================================"

ACTION="${1:-simulate}"

case "$ACTION" in
    test)
        echo "[*] Running Pytest Suite with Moto..."
        pytest -v
        ;;
    lint)
        echo "[*] Running Ruff Code Quality Checks..."
        ruff check src/ tests/
        ;;
    evaluate)
        shift || true
        echo "[*] Evaluating Custom Request..."
        python -m src.cli evaluate "$@"
        ;;
    simulate|*)
        echo "[*] Executing Edge Threat Simulation..."
        python -m src.cli simulate
        ;;
esac
