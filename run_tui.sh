#!/usr/bin/env bash
# Inicializador rápido da Interface TUI do CyberLLM 32B
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -x ".venv/bin/python" ]; then
    echo "[*] Criando ambiente virtual .venv para o CyberLLM TUI..."
    if command -v uv >/dev/null 2>&1; then
        uv venv .venv
        uv pip install --python .venv/bin/python -r requirements-tui.txt
    else
        python3 -m venv .venv
        .venv/bin/pip install --upgrade pip
        .venv/bin/pip install -r requirements-tui.txt
    fi
fi

exec .venv/bin/python cyberllm_tui.py "$@"
