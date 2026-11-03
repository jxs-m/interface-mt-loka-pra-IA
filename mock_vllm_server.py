#!/usr/bin/env python3
"""
Servidor de Simulação vLLM / OpenAI API para Testes da Interface do CyberLLM 32B.

Fornece uma API compatível com vLLM e OpenAI na porta 8000 (ou configurável),
permitindo testar a Interface TUI (ou clientes VS Code/Continue.dev/Cline) localmente
com streaming Server-Sent Events (SSE), telemetria em tempo real e raciocínio deliberado (<think>).

Endpoints implementados:
    - GET  /health
    - GET  /v1/models
    - POST /v1/chat/completions (Suporte total a SSE streaming e não-streaming)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
import time
import uuid
from typing import AsyncIterator, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("CyberLLM-MockServer")


def generate_security_response(prompt_text: str) -> str:
    """Gera uma resposta realista de auditoria SAST com raciocínio deliberado <think>."""
    prompt_lower = prompt_text.lower()

    if any(k in prompt_lower for k in ["strcpy", "gets", "sprintf", "buffer", "overflow", "local_buffer"]):
        cwe = "CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')"
        mitre = "MITRE Top 25 (Rank 1)"
        code_patch = (
            "```c\n"
            "#include <stdio.h>\n"
            "#include <string.h>\n\n"
            "/* Patch de Segurança: Substituição de strcpy por snprintf com bound checking estrito */\n"
            "int process_input_secure(const char *src) {\n"
            "    char local_buffer[64];\n"
            "    if (src == NULL) {\n"
            "        return -1;\n"
            "    }\n"
            "    int written = snprintf(local_buffer, sizeof(local_buffer), \"%s\", src);\n"
            "    if (written < 0 || (size_t)written >= sizeof(local_buffer)) {\n"
            "        /* Trunca ou descarta pacote com payload anômalo */\n"
            "        fprintf(stderr, \"[ALERTA] Payload truncado por exceder o tamanho do buffer.\\n\");\n"
            "        return -1;\n"
            "    }\n"
            "    printf(\"Buffer processado com segurança: %s\\n\", local_buffer);\n"
            "    return 0;\n"
            "}\n"
            "```"
        )
        think_reasoning = (
            "<think>\n"
            "1. Análise de Superfície de Ataque e Stack Frame:\n"
            "   - A função alvo aloca um array estático na pilha (Stack Buffer) sem validação de limites.\n"
            "   - O uso de primitivas desprotegidas (`strcpy`, `sprintf` ou `gets`) permite que uma entrada do usuário com tamanho superior à capacidade do buffer sobrescreva bytes contíguos na memória.\n"
            "   - Em arquitetura x86_64, a corrupção afeta primeiramente o Saved RBP (Frame Pointer) e subsequentemente o Saved RIP (Instruction Pointer / Return Address).\n"
            "2. Vetor de Exploração e Gravidade:\n"
            "   - Classificação: CWE-120 / CWE-787. Gravidade Crítica (CVSS 9.8).\n"
            "   - Impacto: Possibilidade de desvio do fluxo de execução para gadgets ROP (Return-Oriented Programming) ou execução de shellcode caso proteções como NX/DEP e Stack Canaries estejam desabilitadas.\n"
            "3. Formulação do Patch Defensivo:\n"
            "   - Substituição obrigatória de funções não delimitadas por APIs com controle de comprimento explícito (`snprintf(..., sizeof(buffer), ...)` ou `strlcpy`).\n"
            "   - Adição de checagem contra ponteiro nulo (NULL pointer dereference).\n"
            "   - Tratamento explícito do código de retorno para identificar se houve truncamento.\n"
            "   - O código corrigido é 100% compatível com as flags estritas `gcc -Wall -Wextra -Werror`.\n"
            "</think>\n\n"
        )
        report = (
            f"### 🛡️ Relatório de Auditoria SAST — CyberLLM 32B\n\n"
            f"**Diagnóstico de Vulnerabilidade:** `{cwe}`\n"
            f"**Catálogo:** {mitre} | **Severidade:** `CRÍTICA (CVSS: 9.8)`\n\n"
            f"#### 🔍 Detalhes Técnicos da Falha\n"
            f"Foi identificada uma cópia irrestrita de bytes diretamente na pilha. A ausência de cálculo do tamanho da entrada antes da operação de transferência possibilita o transbordamento do buffer local e a eventual corrupção do ponteiro de instrução (`$rip`).\n\n"
            f"#### 🔒 Código Corrigido (Patch Defensivo Validado)\n\n"
            f"{code_patch}\n\n"
            f"**Validação de Compilação:** Aprovado via GCC com `-Wall -Wextra -Werror` sem emissão de *warnings*."
        )
        return think_reasoning + report

    elif any(k in prompt_lower for k in ["sql", "select", "injection", "query", "database"]):
        code_patch = (
            "```python\n"
            "# Patch de Segurança: Uso de Queries Parametrizadas / Prepared Statements\n"
            "import sqlite3\n"
            "from typing import Optional, Dict\n\n"
            "def authenticate_user_secure(db_conn: sqlite3.Connection, username: str, password_hash: str) -> Optional[Dict]:\n"
            "    cursor = db_conn.cursor()\n"
            "    # Parâmetros vinculados evitam concatenação de strings maliciosas\n"
            "    query = 'SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?'\n"
            "    cursor.execute(query, (username, password_hash))\n"
            "    row = cursor.fetchone()\n"
            "    if row:\n"
            "        return {'id': row[0], 'username': row[1], 'role': row[2]}\n"
            "    return None\n"
            "```"
        )
        think_reasoning = (
            "<think>\n"
            "1. Superfície de Injeção:\n"
            "   - Concatenação direta de strings na query SQL permite a quebra do contexto sintático original.\n"
            "   - Classificação: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command).\n"
            "2. Vetor de Ataque:\n"
            "   - Injeção de tautologias (`' OR '1'='1`) ou comandos empilhados (`UNION SELECT`).\n"
            "3. Mitigação:\n"
            "   - Implementação de query parametrizada isolando dados de instruções do motor SQL.\n"
            "</think>\n\n"
        )
        report = (
            "### 🛡️ Relatório de Auditoria SAST — CyberLLM 32B\n\n"
            "**Diagnóstico:** `CWE-89: SQL Injection`\n"
            "**Severidade:** `ALTA (CVSS: 8.8)`\n\n"
            "#### 🔒 Correção Implementada\n"
            f"{code_patch}"
        )
        return think_reasoning + report

    # Resposta genérica técnica investigativa
    think_reasoning = (
        "<think>\n"
        "1. Contextualizando a solicitação do usuário sob a ótica de engenharia reversa e desenvolvimento defensivo.\n"
        "2. Avaliando melhores práticas de segurança de memória, tipagem forte e neutralização de vetores de exploração.\n"
        "3. Sintetizando orientações técnicas sem recusas indevidas ou bloqueios artificiais.\n"
        "</think>\n\n"
    )
    report = (
        "### 🛡️ CyberLLM 32B — Especialista Defensivo\n\n"
        "Ambiente operacional ativo e pronto para análise técnica.\n\n"
        "Posso executar:\n"
        "- **Auditoria Estática de Código (SAST):** Análise de memória em C/C++, Rust e Assembly x86_64.\n"
        "- **Mapeamento CWE e CVE:** Identificação de falhas clássicas e modernas de corrupção de estado.\n"
        "- **Geração de Patches Seguros:** Geração de código defensivo imune a *warnings* de compiladores estritos.\n"
        "- **Criação de Regras Semgrep e YARA:** Detecção de padrões maliciosos e assinaturas binárias.\n\n"
        "Envie um trecho de código ou especificação para iniciarmos a auditoria."
    )
    return think_reasoning + report


class MockVLLMServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8000, model_name: str = "qwen32b-cyber"):
        self.host = host
        self.port = port
        self.model_name = model_name
        self.server: Optional[asyncio.AbstractServer] = None

    async def handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client_addr = writer.get_extra_info("peername")
        try:
            req_line = await reader.readline()
            if not req_line:
                writer.close()
                return

            req_decoded = req_line.decode("utf-8", errors="replace").strip()
            parts = req_decoded.split()
            if len(parts) < 2:
                writer.close()
                return

            method, path = parts[0], parts[1]
            logger.info(f"Requisição recebida: {method} {path} de {client_addr}")

            # Leitura de cabeçalhos
            headers: Dict[str, str] = {}
            content_length = 0
            while True:
                line = await reader.readline()
                if not line or line in (b"\r\n", b"\n"):
                    break
                header_text = line.decode("utf-8", errors="replace").strip()
                if ":" in header_text:
                    k, v = header_text.split(":", 1)
                    k_lower = k.strip().lower()
                    headers[k_lower] = v.strip()
                    if k_lower == "content-length":
                        content_length = int(v.strip())

            # Leitura do corpo (se presente)
            body_bytes = b""
            if content_length > 0:
                body_bytes = await reader.readexactly(content_length)

            # Roteamento
            if method == "OPTIONS":
                self._send_cors(writer)
                return

            if method == "GET" and path in ("/health", "/"):
                resp_data = {"status": "ok", "service": "cyberllm-vllm-simulator", "model": self.model_name}
                self._send_json(writer, 200, resp_data)
                return

            if method == "GET" and path.startswith("/v1/models"):
                resp_data = {
                    "object": "list",
                    "data": [
                        {
                            "id": self.model_name,
                            "object": "model",
                            "created": int(time.time()),
                            "owned_by": "vllm",
                            "root": self.model_name,
                            "parent": None,
                            "permission": [],
                        }
                    ],
                }
                self._send_json(writer, 200, resp_data)
                return

            if method == "POST" and path.startswith("/v1/chat/completions"):
                await self._handle_chat_completions(writer, body_bytes)
                return

            # Endpoint não encontrado
            self._send_json(writer, 404, {"error": f"Endpoint {path} não encontrado"})

        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.exception(f"Erro processando requisição: {e}")
        finally:
            try:
                await writer.drain()
                writer.close()
            except Exception:
                pass

    async def _handle_chat_completions(self, writer: asyncio.StreamWriter, body_bytes: bytes) -> None:
        try:
            req_json = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:
            req_json = {}

        stream_mode = req_json.get("stream", False)
        messages = req_json.get("messages", [])

        # Extrai o último prompt do usuário
        user_prompt = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                user_prompt = m.get("content", "")
                break

        full_response = generate_security_response(user_prompt)
        chat_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        created_ts = int(time.time())

        if not stream_mode:
            resp_data = {
                "id": chat_id,
                "object": "chat.completion",
                "created": created_ts,
                "model": self.model_name,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": full_response,
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": len(user_prompt.split()),
                    "completion_tokens": len(full_response.split()),
                    "total_tokens": len(user_prompt.split()) + len(full_response.split()),
                },
            }
            self._send_json(writer, 200, resp_data)
            return

        # Modo Streaming SSE
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/event-stream\r\n"
            b"Cache-Control: no-cache\r\n"
            b"Connection: keep-alive\r\n"
            b"Access-Control-Allow-Origin: *\r\n\r\n"
        )
        await writer.drain()

        # Quebra a resposta em pedaços com pausas para simular digitação em tempo real (60-80 tokens/s)
        chunks = self._tokenize_for_streaming(full_response)
        for chunk_text in chunks:
            chunk_obj = {
                "id": chat_id,
                "object": "chat.completion.chunk",
                "created": created_ts,
                "model": self.model_name,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": chunk_text},
                        "finish_reason": None,
                    }
                ],
            }
            line = f"data: {json.dumps(chunk_obj, ensure_ascii=False)}\n\n"
            writer.write(line.encode("utf-8"))
            await writer.drain()
            await asyncio.sleep(0.015)  # Cadência suave de digitação

        # Chunk final com finish_reason
        stop_chunk = {
            "id": chat_id,
            "object": "chat.completion.chunk",
            "created": created_ts,
            "model": self.model_name,
            "choices": [
                {
                    "index": 0,
                    "delta": {},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": len(user_prompt.split()),
                "completion_tokens": len(full_response.split()),
                "total_tokens": len(user_prompt.split()) + len(full_response.split()),
            },
        }
        writer.write(f"data: {json.dumps(stop_chunk)}\n\ndata: [DONE]\n\n".encode("utf-8"))
        await writer.drain()

    def _tokenize_for_streaming(self, text: str) -> List[str]:
        """Divide o texto em pedaços de 1 a 4 palavras para simulação realista de tokens."""
        words = re.findall(r"\S+|\n|\s+", text)
        chunks: List[str] = []
        buf: List[str] = []
        for token in words:
            buf.append(token)
            if token == "\n" or len(buf) >= 3:
                chunks.append("".join(buf))
                buf = []
        if buf:
            chunks.append("".join(buf))
        return chunks

    def _send_cors(self, writer: asyncio.StreamWriter) -> None:
        writer.write(
            b"HTTP/1.1 204 No Content\r\n"
            b"Access-Control-Allow-Origin: *\r\n"
            b"Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
            b"Access-Control-Allow-Headers: Content-Type, Authorization\r\n\r\n"
        )

    def _send_json(self, writer: asyncio.StreamWriter, status_code: int, data: dict) -> None:
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        status_msg = "OK" if status_code == 200 else ("Not Found" if status_code == 401 else "Error")
        header = (
            f"HTTP/1.1 {status_code} {status_msg}\r\n"
            f"Content-Type: application/json; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Access-Control-Allow-Origin: *\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("utf-8")
        writer.write(header + body)

    async def start(self) -> None:
        self.server = await asyncio.start_server(self.handle_request, self.host, self.port)
        logger.info(f"🚀 Servidor vLLM Simulator ativo em: http://{self.host}:{self.port}/v1")
        logger.info(f"📦 Modelo servido: {self.model_name}")
        logger.info("⚡ Suporte a SSE streaming e raciocínio deliberado <think> habilitado.")
        async with self.server:
            await self.server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="Servidor de Teste vLLM / OpenAI API para CyberLLM 32B")
    parser.add_argument("--host", default="127.0.0.1", help="Endereço de escuta (padrão: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Porta HTTP (padrão: 8000)")
    parser.add_argument("--model", default="qwen32b-cyber", help="Identificador do modelo (padrão: qwen32b-cyber)")
    args = parser.parse_args()

    server = MockVLLMServer(host=args.host, port=args.port, model_name=args.model)
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        logger.info("Servidor encerrado pelo usuário.")


if __name__ == "__main__":
    main()

