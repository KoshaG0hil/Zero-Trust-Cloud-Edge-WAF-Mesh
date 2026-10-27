# Zero-Trust Cloud Edge & Intelligent WAF Mesh - Execution Script for Windows PowerShell
[CmdletBinding()]
param(
    [ValidateSet("simulate", "evaluate", "test", "lint", "report")]
    [string]$Action = "simulate",
    [string]$Uri = "/api/v1/search",
    [string]$Payload = "' UNION SELECT null, username, password FROM users--"
)

$ErrorActionPreference = "Stop"

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "  Zero-Trust Cloud Edge & Intelligent WAF Defense Mesh" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

switch ($Action) {
    "simulate" {
        Write-Host "[*] Executing Multi-Vector Edge Attack Simulation..." -ForegroundColor Yellow
        python -m src.cli simulate
    }
    "evaluate" {
        Write-Host "[*] Evaluating Custom Edge Request URI: $Uri..." -ForegroundColor Yellow
        python -m src.cli evaluate --uri $Uri --body $Payload
    }
    "test" {
        Write-Host "[*] Running Test Suite with Pytest & Moto..." -ForegroundColor Yellow
        pytest -v
    }
    "lint" {
        Write-Host "[*] Running Ruff Linter and Code Quality Checks..." -ForegroundColor Yellow
        ruff check src/ tests/
    }
    "report" {
        Write-Host "[*] Generating Tamper-Evident Threat Posture Bulletin..." -ForegroundColor Yellow
        python -m src.cli simulate
    }
}
