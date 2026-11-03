#!/usr/bin/env python3
"""
Ponto de entrada CLI para a Interface de Terminal TUI do CyberLLM 32B.

Exemplos de uso:
    ./run_tui.sh
    .venv/bin/python cyberllm_tui.py --api-base http://10.0.0.12:8000/v1 --model qwen32b-cyber
    .venv/bin/python cyberllm_tui.py --check
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from rich.console import Console
from rich.panel import Panel

from tui.app import CyberLLMApp
from tui.config import load_config, save_config
from tui.vllm_client import VLLMClient


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CyberLLM 32B — Interface de Terminal TUI estilo Hacker (vLLM / OpenAI API)"
    )
    parser.add_argument(
        "--api-base",
        type=str,
        default=None,
        help="URL base do servidor vLLM (ex: http://localhost:8000/v1 ou http://IP_VM:8000/v1)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Nome do modelo servido no vLLM (ex: qwen32b-cyber)",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="Chave da API (padrão vLLM: EMPTY)",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=None,
        help="Temperatura de amostragem (padrão: 0.1)",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=None,
        help="Limite máximo de tokens gerados por resposta (padrão: 4096)",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Persiste os argumentos passados em ~/.cyberllm/config.json",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Apenas testa a conectividade com o servidor vLLM no terminal e encerra",
    )
    return parser.parse_args()


async def _run_health_check(cfg) -> int:
    console = Console()
    client = VLLMClient()
    status = await client.check_health(cfg, timeout=5.0)
    if status.online and status.is_mock_simulator:
        models_txt = ", ".join(status.models) if status.models else "(nenhum listado)"
        console.print(
            Panel(
                f"[bold yellow]⚠ SERVIDOR DE SIMULAÇÃO MOCK DETECTADO (SEM IA REAL)[/]\n"
                f"Endpoint: [cyan]{status.api_base}[/]\n"
                f"Modelo:   [bold]{models_txt}[/]\n\n"
                f"[yellow]O processo `mock_vllm_server.py` está respondendo na porta 8000 com textos fixos de teste.\n"
                f"Para respostas reais da sua IA 32B, conecte ao vLLM real (Colab/VM) na aba F5![/]",
                title="🛡️ CyberLLM Health Probe",
                border_style="yellow",
            )
        )
        return 0
    if status.online:
        models_txt = ", ".join(status.models) if status.models else "(nenhum listado)"
        console.print(
            Panel(
                f"[bold bright_green]● SERVIDOR vLLM ONLINE[/]\n"
                f"Endpoint: [cyan]{status.api_base}[/]\n"
                f"Latência: [bright_green]{status.latency_ms:.1f} ms[/]\n"
                f"Modelos:  [bold]{models_txt}[/]",
                title="🛡️ CyberLLM Health Probe",
                border_style="bright_green",
            )
        )
        return 0

    console.print(
        Panel(
            f"[bold bright_red]○ SERVIDOR vLLM OFFLINE[/]\n"
            f"Endpoint: [cyan]{status.api_base}[/]\n"
            f"Erro:     [yellow]{status.error}[/]\n\n"
            f"[dim]Você ainda pode abrir a TUI normalmente para usar a Triagem SAST Local, "
            f"o Validador de Compiladores (gcc/g++/python), Templates e Histórico.[/]",
            title="🛡️ CyberLLM Health Probe",
            border_style="bright_red",
        )
    )
    return 1


def main() -> int:
    args = parse_args()
    cfg = load_config()

    if args.api_base is not None:
        cfg.api_base = args.api_base
    if args.model is not None:
        cfg.model = args.model
    if args.api_key is not None:
        cfg.api_key = args.api_key
    if args.temperature is not None:
        cfg.temperature = args.temperature
    if args.max_tokens is not None:
        cfg.max_tokens = args.max_tokens
    cfg.normalized()

    if args.save:
        save_config(cfg)

    if args.check:
        return asyncio.run(_run_health_check(cfg))

    app = CyberLLMApp(config=cfg)
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
