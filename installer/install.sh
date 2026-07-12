#!/usr/bin/env bash
# Argus installer - Linux / macOS.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "=== Argus installer (repo: $REPO_ROOT) ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required." >&2
    exit 1
fi
PY_MAJ=$(python3 -c 'import sys; print(sys.version_info[0])')
PY_MIN=$(python3 -c 'import sys; print(sys.version_info[1])')
if [ "$PY_MAJ" -lt 3 ] || { [ "$PY_MAJ" -eq 3 ] && [ "$PY_MIN" -lt 11 ]; }; then
    echo "WARN: Python 3.11+ recommended (found ${PY_MAJ}.${PY_MIN}). Continuing anyway."
fi

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

# fastembed (ONNX) replaces sentence-transformers - no torch, no CUDA wheels
echo "[2/4] Installing Python deps (fastembed / ONNX, no torch, no CUDA)"
pip install -r "$REPO_ROOT/requirements.txt"

# Default LLM: phi3:mini (~2.3 GB) instead of mistral (~4 GB)
DEFAULT_MODEL="${ARGUS_MODEL:-phi3}"

if ! command -v ollama >/dev/null 2>&1; then
    cat <<EOM
[3/4] Ollama is NOT installed.
      Install it from https://ollama.com/download then re-run this script
      (or run: ollama pull $DEFAULT_MODEL) to fetch the default model.
EOM
else
    echo "[3/4] Found ollama; ensuring '$DEFAULT_MODEL' is pulled"
    if ! ollama list 2>/dev/null | awk 'NR>1 {print $1}' | grep -q "^$DEFAULT_MODEL"; then
        ollama pull "$DEFAULT_MODEL"
    else
        echo "      '$DEFAULT_MODEL' already present."
    fi
fi

CFG="$REPO_ROOT/config.yaml"
if grep -q 'change-me-before-first-run' "$CFG"; then
    TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
    sed -i.bak "s/change-me-before-first-run/$TOKEN/" "$CFG"
    rm -f "$CFG.bak"
    echo "[4/4] Generated bridge auth token in config.yaml"
    echo "      Token: $TOKEN"
    cat > "$REPO_ROOT/burp_extension/argus_config.json" <<JSON
{"bridge_url":"http://127.0.0.1:8765/analyse","auth_token":"$TOKEN","bridge_timeout_seconds":60}
JSON
else
    echo "[4/4] Auth token already set in config.yaml"
fi

cat <<DONE

=== Install complete ===
Default LLM: $DEFAULT_MODEL   (override with ARGUS_MODEL env var before install)
Next steps:
echo "=== Install complete ==="
echo "Default LLM: $DEFAULT_MODEL   (override with ARGUS_MODEL env var before install)"
echo ""
echo "Start everything with one command:"
echo "  $REPO/bin/argus start"
echo ""
echo "Then:"
echo "  $REPO/bin/argus status     # check running state"
echo "  $REPO/bin/argus smoke      # send a synthetic SQLi to /analyse"
echo "  $REPO/bin/argus logs       # tail the bridge log"
echo "  $REPO/bin/argus stop       # tear it all down"
echo ""
echo "Dashboard: http://127.0.0.1:8501    Bridge: http://127.0.0.1:8765"
echo "Burp extension (optional): $REPO/burp_extension/llm_analyser.py"

For full details see USAGE.md.
DONE
