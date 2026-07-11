#!/usr/bin/env bash
# Argus installer - Linux / macOS.
# Sets up a venv, installs deps, pulls the default Ollama model, and prints
# the next-step instructions for loading the Burp extension.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "=== Argus installer (repo: $REPO_ROOT) ==="

# 1. Python 3.11+
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required." >&2
    exit 1
fi
PY_MAJ=$(python3 -c 'import sys; print(sys.version_info[0])')
PY_MIN=$(python3 -c 'import sys; print(sys.version_info[1])')
if [ "$PY_MAJ" -lt 3 ] || { [ "$PY_MAJ" -eq 3 ] && [ "$PY_MIN" -lt 11 ]; }; then
    echo "WARN: Python 3.11+ recommended (found ${PY_MAJ}.${PY_MIN}). Continuing anyway."
fi

# 2. Venv + deps
VENV="$REPO_ROOT/.venv"
if [ ! -d "$VENV" ]; then
    echo "[1/4] Creating venv at $VENV"
    python3 -m venv "$VENV"
else
    echo "[1/4] Reusing existing venv at $VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
python -m pip install --upgrade pip >/dev/null
echo "[2/4] Installing Python deps (this can take a minute)"
pip install -r "$REPO_ROOT/requirements.txt"

# 3. Ollama check + model pull
if ! command -v ollama >/dev/null 2>&1; then
    cat <<EOM
[3/4] Ollama is NOT installed.
      Install it from https://ollama.com/download then re-run this script
      (or run: ollama pull mistral) to fetch the default model.
EOM
else
    echo "[3/4] Found ollama; ensuring 'mistral' is pulled"
    if ! ollama list 2>/dev/null | awk 'NR>1 {print $1}' | grep -q '^mistral'; then
        ollama pull mistral
    else
        echo "      'mistral' already present."
    fi
fi

# 4. Generate auth token if config.yaml has the placeholder
CFG="$REPO_ROOT/config.yaml"
if grep -q 'change-me-before-first-run' "$CFG"; then
    TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
    sed -i.bak "s/change-me-before-first-run/$TOKEN/" "$CFG"
    rm -f "$CFG.bak"
    echo "[4/4] Generated bridge auth token in config.yaml"
    echo "      Token: $TOKEN"
    echo "      Burp_extension/argus_config.json updated as well."
    cat > "$REPO_ROOT/burp_extension/argus_config.json" <<JSON
{"bridge_url":"http://127.0.0.1:8765/analyse","auth_token":"$TOKEN","bridge_timeout_seconds":60}
JSON
else
    echo "[4/4] Auth token already set in config.yaml"
fi

cat <<DONE

=== Install complete ===
Next steps:
  1. Start Ollama:               ollama serve   (in its own terminal)
  2. Start the Argus bridge:     source $VENV/bin/activate && python -m llm_bridge.bridge
  3. Start the dashboard:        source $VENV/bin/activate && streamlit run dashboard/app.py
  4. Load the Burp extension:    Burp -> Extensions -> Add -> Python
                                  File: $REPO_ROOT/burp_extension/llm_analyser.py
                                  (point Burp at a Jython 2.7 standalone JAR first)

For full details see USAGE.md.
DONE
