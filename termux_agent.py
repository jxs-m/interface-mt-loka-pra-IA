#!/usr/bin/env python3
"""
CyberLLM Termux Agent — Cliente de Terminal Leve para Android (Termux)
Conecta diretamente à API vLLM / OpenAI hospedada no Google Colab (via Cloudflare Tunnel)
e opera como um agente interativo capaz de responder dúvidas e executar comandos no Termux.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error

CONFIG_PATH = os.path.expanduser("~/.cyberllm_termux.json")

SYSTEM_PROMPT = """Você é o CyberLLM Agent, um assistente técnico avançado de cibersegurança e terminal rodando no Termux (Android).
Seu cérebro está sendo executado em uma GPU remota no Google Colab.

Quando o usuário fizer uma pergunta ou pedir uma tarefa:
1. Responda de forma clara, técnica e concisa (ideal para telas de celular).
2. Se a tarefa exigir executar um comando no Termux (como checar IP, testar portas com nmap, listar arquivos, ler logs ou criar scripts), forneça o comando exato em um bloco de código:
```bash
comando aqui
```
3. Mostre seu raciocínio de análise de forma objetiva."""


def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "api_base": "http://localhost:8000/v1",
        "model": "qwen32b-cyber",
        "api_key": "EMPTY",
        "allow_exec": True
    }


def save_config(cfg: dict) -> None:
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"[!] Erro ao salvar configuração: {e}")


def check_api_health(api_base: str, api_key: str = "EMPTY") -> tuple[bool, str]:
    """Testa se o endpoint /v1/models do Colab está acessível."""
    url = f"{api_base.rstrip('/')}/models"
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {api_key}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("id", "") for m in data.get("data", [])]
            return True, ", ".join(models) if models else "online"
    except Exception as e:
        return False, str(e)


def stream_chat_completion(
    messages: list[dict],
    api_base: str,
    model: str,
    api_key: str = "EMPTY"
) -> str:
    """Envia a conversa para a API vLLM com streaming de resposta caractere a caractere."""
    url = f"{api_base.rstrip('/')}/chat/completions"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": 2048,
        "stream": True
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
    )

    full_response = []
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            for line in resp:
                line_str = line.decode("utf-8").strip()
                if not line_str or line_str == "data: [DONE]":
                    continue
                if line_str.startswith("data: "):
                    line_data = line_str[6:]
                    try:
                        chunk = json.loads(line_data)
                        delta = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "")
                        if delta:
                            sys.stdout.write(delta)
                            sys.stdout.flush()
                            full_response.append(delta)
                    except json.JSONDecodeError:
                        continue
    except urllib.error.URLError as e:
        print(f"\n[!] Falha de conexão com a API no Colab: {e}")
        return ""
    except Exception as e:
        print(f"\n[!] Erro durante o streaming: {e}")
        return ""

    print()
    return "".join(full_response)


def extract_bash_commands(text: str) -> list[str]:
    """Extrai blocos de comandos bash sugeridos pela IA."""
    import re
    commands = []
    matches = re.findall(r"```(?:bash|sh)\n(.*?)```", text, re.DOTALL)
    for match in matches:
        cmd = match.strip()
        if cmd and not cmd.startswith("#"):
            commands.append(cmd)
    return commands


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberLLM Termux Agent")
    parser.add_argument("--api-base", type=str, help="URL pública Cloudflare do Colab (ex: https://...trycloudflare.com/v1)")
    parser.add_argument("--model", type=str, help="Nome do modelo (ex: qwen32b-cyber)")
    parser.add_argument("--check", action="store_true", help="Testa conectividade com o Colab")
    args = parser.parse_args()

    cfg = load_config()

    if args.api_base:
        cfg["api_base"] = args.api_base
        save_config(cfg)
    if args.model:
        cfg["model"] = args.model
        save_config(cfg)

    print("\033[1;36m" + "="*50)
    print(" 🤖 CYBERLLM — TERMUX AGENT (ANDROID)")
    print(" Cérebro: Google Colab GPU (vLLM API)")
    print("="*50 + "\033[0m")

    # Se a URL padrão for localhost, solicita a URL do Colab se não tiver sido configurada
    if "localhost" in cfg["api_base"] and not args.api_base:
        print("\n\033[1;33m[!] Nenhuma URL remota configurada.\033[0m")
        url_input = input("Cole a URL do Colab (ex: https://xyz.trycloudflare.com/v1): ").strip()
        if url_input:
            if not url_input.endswith("/v1"):
                url_input = url_input.rstrip("/") + "/v1"
            cfg["api_base"] = url_input
            save_config(cfg)

    print(f"\n[+] Endpoint: \033[1;32m{cfg['api_base']}\033[0m")
    print(f"[+] Modelo:   \033[1;32m{cfg['model']}\033[0m")

    print("[*] Testando conexão com o Colab...", end=" ", flush=True)
    online, info = check_api_health(cfg["api_base"], cfg["api_key"])
    if online:
        print(f"\033[1;32m[ONLINE]\033[0m ({info})")
    else:
        print(f"\033[1;31m[OFFLINE / ERRO]\033[0m")
        print(f"    Detalhe: {info}")
        print("\nCertifique-se de que o Notebook 05 está em execução no Google Colab.")
        if args.check:
            sys.exit(1)

    if args.check:
        sys.exit(0)

    print("\n\033[1;30mDigite sua mensagem abaixo. Comandos especiais: '/sair', '/limpar', '/api <nova_url>'\033[0m\n")

    history = [{"role": "system", "content": SYSTEM_PROMPT}]

    while True:
        try:
            user_input = input("\033[1;32mtermux@android\033[0m:\033[1;34m~$\033[0m ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nEncerrando...")
            break

        if not user_input:
            continue

        if user_input.lower() in ("/sair", "exit", "quit"):
            break

        if user_input.lower() == "/limpar":
            history = [{"role": "system", "content": SYSTEM_PROMPT}]
            os.system("clear")
            print("[+] Histórico reiniciado.")
            continue

        if user_input.startswith("/api "):
            new_url = user_input.split(" ", 1)[1].strip()
            if not new_url.endswith("/v1"):
                new_url = new_url.rstrip("/") + "/v1"
            cfg["api_base"] = new_url
            save_config(cfg)
            print(f"[✓] Nova URL salva: {new_url}")
            continue

        history.append({"role": "user", "content": user_input})

        print("\n\033[1;35m[CyberLLM]:\033[0m ", end="", flush=True)
        response_text = stream_chat_completion(
            messages=history,
            api_base=cfg["api_base"],
            model=cfg["model"],
            api_key=cfg["api_key"]
        )

        if not response_text:
            continue

        history.append({"role": "assistant", "content": response_text})

        # Verifica se a IA sugeriu comandos de terminal e oferece execução no Termux
        cmds = extract_bash_commands(response_text)
        if cmds and cfg.get("allow_exec", True):
            for cmd in cmds:
                print(f"\n\033[1;33m[Agente sugeriu executar no Termux]:\033[0m\n  \033[1;37m{cmd}\033[0m")
                confirm = input("Deseja executar este comando no seu Termux? [s/N]: ").strip().lower()
                if confirm in ("s", "sim", "y", "yes"):
                    print("\033[1;30m--- Saída do Comando ---\033[0m")
                    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    output = res.stdout + res.stderr
                    print(output if output else "(sem saída)")
                    print("\033[1;30m------------------------\033[0m")

                    # Devolve a saída para o contexto do agente
                    history.append({
                        "role": "user",
                        "content": f"[SAÍDA DA EXECUÇÃO NO TERMUX DO COMANDO `{cmd}`]:\n{output}"
                    })
                    print("\n\033[1;35m[CyberLLM analisando resultado...]:\033[0m ", end="", flush=True)
                    feedback = stream_chat_completion(
                        messages=history,
                        api_base=cfg["api_base"],
                        model=cfg["model"],
                        api_key=cfg["api_key"]
                    )
                    if feedback:
                        history.append({"role": "assistant", "content": feedback})
                else:
                    print("[*] Execução cancelada pelo usuário.")


if __name__ == "__main__":
    main()

