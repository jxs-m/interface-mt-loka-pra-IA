#!/usr/bin/env bash
# Inicializador do Servidor de Simulação vLLM / OpenAI API para Testes da Interface
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON_BIN="python3"
if [ -x ".venv/bin/python" ]; then
    PYTHON_BIN=".venv/bin/python"
fi

echo "=============================================================="
echo "🛡️ CyberLLM 32B — Servidor Local de Teste de Interface (vLLM)"
echo "=============================================================="
echo "[*] Iniciando servidor em http://127.0.0.1:8000/v1..."
echo "[*] Modelo servido: qwen32b-cyber"
echo "[*] Pressione Ctrl+C para encerrar quando desejar."
echo "=============================================================="

exec "$PYTHON_BIN" mock_vllm_server.py --host 127.0.0.1 --port 8000 --model qwen32b-cyber "$@"

