# Argus installer - Windows PowerShell.
# Sets up a venv, installs deps, generates a bridge token, ensures Ollama
# has the default model, and prints the next-step instructions.
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Write-Host "=== Argus installer (repo: $RepoRoot) ==="

# 1. Python
$py = (Get-Command python -ErrorAction SilentlyContinue) `
      ?? (Get-Command python3 -ErrorAction SilentlyContinue)
if (-not $py) {
    Write-Error "Python is required. Install Python 3.11+ from https://python.org/downloads"
    exit 1
}
$pyVer = & $py.Source -c "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')"
Write-Host "Found Python $pyVer"

# 2. Venv + deps
$venv = Join-Path $RepoRoot ".venv"
if (-not (Test-Path $venv)) {
    Write-Host "[1/4] Creating venv at $venv"
    & $py.Source -m venv $venv
} else {
    Write-Host "[1/4] Reusing existing venv at $venv"
}
$venvPy  = Join-Path $venv "Scripts\python.exe"
$venvPip = Join-Path $venv "Scripts\pip.exe"
& $venvPy -m pip install --upgrade pip | Out-Null
Write-Host "[2/4] Installing Python deps (can take a minute)"
& $venvPip install -r (Join-Path $RepoRoot "requirements.txt")

# 3. Ollama
$ollama = Get-Command ollama -ErrorAction SilentlyContinue
if (-not $ollama) {
    Write-Host "[3/4] Ollama is NOT installed."
    Write-Host "      Install from https://ollama.com/download then run: ollama pull mistral"
} else {
    Write-Host "[3/4] Found ollama; ensuring 'mistral' is pulled"
    $installed = & ollama list 2>$null | Select-Object -Skip 1 | ForEach-Object { ($_ -split '\s+')[0] }
    if ($installed -notcontains "mistral" -and $installed -notcontains "mistral:latest") {
        & ollama pull mistral
    } else {
        Write-Host "      'mistral' already present."
    }
}

# 4. Token
$cfg = Join-Path $RepoRoot "config.yaml"
$cfgText = Get-Content -Raw $cfg
if ($cfgText -match "change-me-before-first-run") {
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    $token = & $venvPy -c "import secrets; print(secrets.token_urlsafe(24))"
    ($cfgText -replace "change-me-before-first-run", $token) | Set-Content -Encoding UTF8 $cfg
    Write-Host "[4/4] Generated bridge auth token: $token"
    $json = "{`"bridge_url`":`"http://127.0.0.1:8765/analyse`",`"auth_token`":`"$token`",`"bridge_timeout_seconds`":60}"
    Set-Content -Path (Join-Path $RepoRoot "burp_extension\argus_config.json") -Value $json -Encoding UTF8
    Write-Host "       Burp_extension\argus_config.json written."
} else {
    Write-Host "[4/4] Auth token already set in config.yaml"
}

Write-Host ""
Write-Host "=== Install complete ==="
Write-Host "Next steps:"
Write-Host "  1. Start Ollama:           ollama serve   (in its own terminal)"
Write-Host "  2. Activate venv:          . $venv\Scripts\Activate.ps1"
Write-Host "  3. Start the bridge:       python -m llm_bridge.bridge"
Write-Host "  4. Start the dashboard:    streamlit run dashboard\app.py"
Write-Host "  5. Load the Burp extension: $RepoRoot\burp_extension\llm_analyser.py"
Write-Host "     (point Burp at a Jython 2.7 standalone JAR first)"
Write-Host ""
Write-Host "For full details see USAGE.md."
