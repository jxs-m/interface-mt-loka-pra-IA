"""
Cliente assíncrono dedicado ao servidor de inferência vLLM (API compatível com OpenAI).
Suporta streaming SSE em tempo real, telemetria TTFT / Tokens por segundo (TPS),
cancelamento imediato via asyncio.Event e verificação de saúde em /v1/models.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import AsyncIterator, Dict, List, Optional

import httpx

from tui.config import CyberLLMConfig, normalize_api_base
from tui.cot_parser import StreamingCoTParser


@dataclass
class HealthStatus:
    """Estado de conectividade com o servidor vLLM."""

    online: bool
    api_base: str
    latency_ms: float = 0.0
    models: List[str] = field(default_factory=list)
    configured_model_present: bool = False
    is_mock_simulator: bool = False
    error: str = ""


@dataclass
class StreamChunk:
    """Evento incremental emitido durante o streaming SSE do vLLM."""

    thinking_delta: str = ""
    content_delta: str = ""
    in_thinking: bool = False
    ttft_ms: float = 0.0
    tps: float = 0.0
    tokens_est: int = 0
    done: bool = False
    cancelled: bool = False
    error: str = ""


def _build_headers(api_key: str) -> Dict[str, str]:
    token = (api_key or "EMPTY").strip()
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }


def format_vllm_offline_help(config: CyberLLMConfig, raw_error: str) -> str:
    """Gera diagnóstico operacional claro quando o servidor vLLM não está acessível."""
    return (
        f"Falha ao conectar ao servidor vLLM em `{config.api_base}` (`{raw_error}`).\n\n"
        "**Verifique se o motor vLLM está ativo na VM ou máquina local:**\n"
        "```bash\n"
        "python3 -m vllm.entrypoints.openai.api_server \\\n"
        "    --model ~/models/qwen32b_cyber \\\n"
        f"    --served-model-name {config.model} \\\n"
        "    --host 0.0.0.0 --port 8000 \\\n"
        "    --max-model-len 16384 --dtype bfloat16\n"
        "```\n"
        "**Se o vLLM estiver em uma VM remota com porta fechada, abra um túnel SSH:**\n"
        "```bash\n"
        "ssh -N -L 8000:localhost:8000 usuario@IP_DA_SUA_VM\n"
        "```\n"
        "Ou ajuste a URL/Modelo na aba **`[F5] Servidor vLLM`**."
    )


class VLLMClient:
    """Cliente OpenAI-compatível otimizado para servidores vLLM."""

    async def check_health(
        self, config: CyberLLMConfig, timeout: float = 4.0
    ) -> HealthStatus:
        base = normalize_api_base(config.api_base)
        url = f"{base}/models"
        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(
                    url,
                    headers={"Authorization": f"Bearer {(config.api_key or 'EMPTY').strip()}"},
                )
                latency_ms = (time.perf_counter() - t0) * 1000.0
                if resp.status_code >= 400:
                    return HealthStatus(
                        online=False,
                        api_base=base,
                        latency_ms=latency_ms,
                        error=f"HTTP {resp.status_code}: {resp.text[:160]}",
                    )
                payload = resp.json()
                data = payload.get("data", []) if isinstance(payload, dict) else []
                models = [
                    str(item.get("id"))
                    for item in data
                    if isinstance(item, dict) and item.get("id")
                ]

                # Detecta se o endpoint é o mock_vllm_server.py local (sem IA real)
                is_mock = False
                root_url = base[:-3] if base.endswith("/v1") else base
                try:
                    h_resp = await client.get(f"{root_url}/health", timeout=1.5)
                    if h_resp.status_code == 200 and "cyberllm-vllm-simulator" in h_resp.text:
                        is_mock = True
                except Exception:
                    pass

                return HealthStatus(
                    online=True,
                    api_base=base,
                    latency_ms=latency_ms,
                    models=models,
                    configured_model_present=(config.model in models) if models else True,
                    is_mock_simulator=is_mock,
                )
        except Exception as exc:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            return HealthStatus(
                online=False,
                api_base=base,
                latency_ms=latency_ms,
                error=str(exc) or exc.__class__.__name__,
            )

    async def stream_chat(
        self,
        messages: List[Dict[str, str]],
        config: CyberLLMConfig,
        cancel_event: Optional[asyncio.Event] = None,
    ) -> AsyncIterator[StreamChunk]:
        """
        Executa POST `/v1/chat/completions` com `stream=True` e emite `StreamChunk`
        já particionados entre `<think>` e resposta final Markdown.
        """
        base = normalize_api_base(config.api_base)
        url = f"{base}/chat/completions"

        payload = {
            "model": config.model,
            "messages": messages,
            "temperature": config.temperature,
            "top_p": config.top_p,
            "max_tokens": config.max_tokens,
            "stream": True,
        }

        parser = StreamingCoTParser()
        t_start = time.perf_counter()
        t_first_token: Optional[float] = None
        ttft_ms = 0.0
        chunk_tokens = 0
        reported_completion_tokens: Optional[int] = None

        timeout = httpx.Timeout(
            connect=8.0,
            read=config.timeout_seconds,
            write=15.0,
            pool=8.0,
        )

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                async with client.stream(
                    "POST",
                    url,
                    headers=_build_headers(config.api_key),
                    json=payload,
                ) as response:
                    if response.status_code >= 400:
                        body_bytes = await response.aread()
                        body_text = body_bytes.decode("utf-8", errors="replace")
                        try:
                            err_json = json.loads(body_text)
                            msg = (
                                err_json.get("error", {}).get("message")
                                or err_json.get("detail")
                                or body_text
                            )
                        except Exception:
                            msg = body_text
                        yield StreamChunk(
                            error=f"Erro HTTP {response.status_code} do vLLM: {str(msg)[:400]}",
                            done=True,
                        )
                        return

                    # Caso o endpoint responda JSON único sem SSE
                    content_type = response.headers.get("content-type", "")
                    if "application/json" in content_type and "text/event-stream" not in content_type:
                        raw_bytes = await response.aread()
                        data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
                        ttft_ms = (time.perf_counter() - t_start) * 1000.0
                        choice = (data.get("choices") or [{}])[0]
                        message = choice.get("message") or {}
                        reasoning = (
                            message.get("reasoning_content")
                            or message.get("reasoning")
                            or ""
                        )
                        content = message.get("content") or ""
                        t_delta, c_delta = parser.feed(content, reasoning)
                        t_tail, c_tail = parser.flush()
                        usage = data.get("usage") or {}
                        tok = int(
                            usage.get("completion_tokens")
                            or max(1, (len(content) + len(reasoning)) // 4)
                        )
                        elapsed = max(0.001, time.perf_counter() - t_start)
                        yield StreamChunk(
                            thinking_delta=t_delta + t_tail,
                            content_delta=c_delta + c_tail,
                            in_thinking=False,
                            ttft_ms=ttft_ms,
                            tps=tok / elapsed,
                            tokens_est=tok,
                            done=True,
                        )
                        return

                    async for raw_line in response.aiter_lines():
                        if cancel_event and cancel_event.is_set():
                            t_tail, c_tail = parser.flush()
                            elapsed = max(0.001, time.perf_counter() - t_start)
                            yield StreamChunk(
                                thinking_delta=t_tail,
                                content_delta=c_tail,
                                in_thinking=False,
                                ttft_ms=ttft_ms,
                                tps=chunk_tokens / elapsed if chunk_tokens else 0.0,
                                tokens_est=reported_completion_tokens or chunk_tokens,
                                done=True,
                                cancelled=True,
                            )
                            return

                        line = raw_line.strip()
                        if not line or line.startswith(":"):
                            continue
                        if not line.startswith("data:"):
                            continue

                        data_str = line[5:].strip()
                        if data_str == "[DONE]":
                            break

                        try:
                            event = json.loads(data_str)
                        except json.JSONDecodeError:
                            continue

                        usage = event.get("usage")
                        if isinstance(usage, dict) and usage.get("completion_tokens"):
                            reported_completion_tokens = int(usage["completion_tokens"])

                        choices = event.get("choices") or []
                        if not choices:
                            continue

                        delta = choices[0].get("delta") or {}
                        reasoning_piece = (
                            delta.get("reasoning_content")
                            or delta.get("reasoning")
                            or ""
                        )
                        content_piece = delta.get("content") or ""

                        # Compatibilidade caso endpoint retorne text em completions legadas
                        if not content_piece and not reasoning_piece:
                            content_piece = choices[0].get("text") or ""

                        if not content_piece and not reasoning_piece:
                            continue

                        now = time.perf_counter()
                        if t_first_token is None:
                            t_first_token = now
                            ttft_ms = (now - t_start) * 1000.0

                        chunk_tokens += 1
                        gen_elapsed = max(0.001, now - t_first_token)
                        tps = chunk_tokens / gen_elapsed

                        t_delta, c_delta = parser.feed(content_piece, reasoning_piece)
                        if t_delta or c_delta:
                            yield StreamChunk(
                                thinking_delta=t_delta,
                                content_delta=c_delta,
                                in_thinking=parser.in_thinking,
                                ttft_ms=ttft_ms,
                                tps=tps,
                                tokens_est=reported_completion_tokens or chunk_tokens,
                                done=False,
                            )

                    t_tail, c_tail = parser.flush()
                    end_now = time.perf_counter()
                    gen_elapsed = (
                        max(0.001, end_now - t_first_token)
                        if t_first_token is not None
                        else max(0.001, end_now - t_start)
                    )
                    final_tokens = reported_completion_tokens or chunk_tokens
                    yield StreamChunk(
                        thinking_delta=t_tail,
                        content_delta=c_tail,
                        in_thinking=False,
                        ttft_ms=ttft_ms,
                        tps=(final_tokens / gen_elapsed) if final_tokens else 0.0,
                        tokens_est=final_tokens,
                        done=True,
                    )

        except httpx.ConnectError as exc:
            yield StreamChunk(
                error=format_vllm_offline_help(config, f"Conexão recusada ({exc})"),
                done=True,
            )
        except httpx.TimeoutException as exc:
            yield StreamChunk(
                error=format_vllm_offline_help(config, f"Timeout de rede ({exc})"),
                done=True,
            )
        except Exception as exc:
            yield StreamChunk(
                error=format_vllm_offline_help(config, str(exc) or exc.__class__.__name__),
                done=True,
            )
