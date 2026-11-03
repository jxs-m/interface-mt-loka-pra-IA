#!/usr/bin/env bash
# ==============================================================================
# Launcher do Open-WebUI com Integração Nativa ao vLLM e DuckDuckGo Search
# ==============================================================================

set -e

VLLM_HOST="${VLLM_HOST:-http://host.docker.internal:8000/v1}"
WEBUI_PORT="${WEBUI_PORT:-3000}"
CONTAINER_NAME="cyberllm-openwebui"

echo "=================================================================="
echo "🌐 Iniciando Open-WebUI com Suporte a DuckDuckGo e CyberLLM 32B"
echo "=================================================================="
echo "• URL da Interface:   http://localhost:${WEBUI_PORT}"
echo "• Endpoint vLLM:      ${VLLM_HOST}"
echo "• Mecanismo de Busca: DuckDuckGo (100% Gratuito)"
echo "------------------------------------------------------------------"

# Verifica se o container já está em execução
if [ "$(docker ps -q -f name=${CONTAINER_NAME})" ]; then
    echo "[!] O container '${CONTAINER_NAME}' já está rodando."
    echo "[*] Acesse em seu navegador: http://localhost:${WEBUI_PORT}"
    exit 0
fi

# Se o container existir mas estiver parado, inicia-o
if [ "$(docker ps -aq -f status=exited -f name=${CONTAINER_NAME})" ]; then
    echo "[*] Reiniciando container existente '${CONTAINER_NAME}'..."
    docker start ${CONTAINER_NAME}
    echo "✓ Open-WebUI ativo em: http://localhost:${WEBUI_PORT}"
    exit 0
fi

# Cria novo container pré-configurado
echo "[*] Baixando e iniciando o Open-WebUI..."
docker run -d \
    -p ${WEBUI_PORT}:8080 \
    --add-host=host.docker.internal:host-gateway \
    -e OPENAI_API_BASE_URL="${VLLM_HOST}" \
    -e OPENAI_API_KEY="EMPTY" \
    -e ENABLE_RAG_WEB_SEARCH=True \
    -e RAG_WEB_SEARCH_ENGINE="duckduckgo" \
    -e RAG_WEB_SEARCH_RESULT_COUNT=4 \
    -e DEFAULT_MODELS="qwen32b-cyber" \
    -v open-webui-data:/app/backend/data \
    --name ${CONTAINER_NAME} \
    --restart unless-stopped \
    ghcr.io/open-webui/open-webui:main

echo "=================================================================="
echo "✓ Open-WebUI iniciado com sucesso!"
echo "👉 Acesse no seu navegador: http://localhost:${WEBUI_PORT}"
echo "=================================================================="

