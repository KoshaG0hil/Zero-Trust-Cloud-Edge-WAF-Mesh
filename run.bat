@echo off
setlocal
echo ========================================================
echo   Zero-Trust Cloud Edge ^& Intelligent WAF Defense Mesh
echo ========================================================

if "%1"=="test" (
    echo [*] Running Pytest Suite...
    pytest -v
    goto end
)

if "%1"=="lint" (
    echo [*] Running Ruff Code Quality Checks...
    ruff check src/ tests/
    goto end
)

if "%1"=="evaluate" (
    echo [*] Running Custom Evaluation...
    python -m src.cli evaluate %2 %3 %4 %5
    goto end
)

echo [*] Running Multi-Scenario Edge Simulation...
python -m src.cli simulate

:end
endlocal
