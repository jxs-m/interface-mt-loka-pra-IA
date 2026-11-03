#!/usr/bin/env python3
"""
CLI Interativo: Chat com o CyberLLM 32B com Acesso em Tempo Real à Internet (DuckDuckGo).
Permite fazer perguntas técnicas sobre CVEs recentes, novas RFCs e exploits do dia
com busca ao vivo e injeção contextual de fontes.
"""

import sys
import json
import urllib.request
import urllib.parse
from src.web_search import search_duckduckgo, format_search_context

DEFAULT_API_BASE = "http://localhost:8000/v1"
DEFAULT_MODEL = "qwen32b-cyber"

SYSTEM_PROMPT = (
    "Você é o CyberLLM 32B, especialista sênior em cibersegurança defensiva/ofensiva, "
    "engenharia reversa e programação de baixo nível. "
    "Quando fornecido contexto em tempo real obtido via busca na internet (DuckDuckGo), "
    "analise minuciosamente os fatos mais recentes, cite as fontes e apresente a análise técnica "
    "com raciocínio deliberado dentro de tags <think> ... </think>."
)


def call_vllm_api(prompt: str, api_base: str = DEFAULT_API_BASE, model: str = DEFAULT_MODEL) -> str:
    """Envia a requisição para o servidor vLLM via API compatível com OpenAI."""
    url = f"{api_base.rstrip('/')}/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 1024
    }
    
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Authorization": "Bearer EMPTY"}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result["choices"][0]["message"]["content"]
    except urllib.error.URLError as e:
        return (
            f"[!] Erro ao conectar ao servidor vLLM em {api_base}: {e}\n"
            "Certifique-se de que o servidor vLLM está rodando com:\n"
            "python3 -m vllm.entrypoints.openai.api_server --model ... --port 8000"
        )


def main():
    print("==================================================================")
    print("🌐 CyberLLM 32B com Acesso em Tempo Real à Internet (DuckDuckGo)")
    print(f"Endpoint vLLM: {DEFAULT_API_BASE} | Modelo: {DEFAULT_MODEL}")
    print("Digite sua pergunta ou 'sair' para encerrar.")
    print("==================================================================\n")

    while True:
        try:
            user_input = input("\n[Usuário] > ").strip()
            if not user_input:
                continue
            if user_input.lower() in ["sair", "exit", "quit"]:
                print("Encerrando...")
                break

            # 1. Busca no DuckDuckGo
            print("[*] Pesquisando na internet via DuckDuckGo...")
            results = search_duckduckgo(user_input, max_results=4)
            if results:
                print(f"✓ {len(results)} fontes recentes encontradas na web:")
                for r in results:
                    print(f"   • {r['title'][:60]} -> {r['href']}")
            else:
                print("[!] Nenhuma fonte externa necessária ou retornada.")

            # 2. Formata prompt enriquecido
            web_context = format_search_context(user_input, results)
            enhanced_prompt = f"{web_context}\nPergunta do Usuário:\n{user_input}" if web_context else user_input

            # 3. Consulta ao modelo
            print("[*] Gerando análise com CyberLLM 32B...")
            response = call_vllm_api(enhanced_prompt)
            print("\n[CyberLLM 32B]:")
            print(response)

        except KeyboardInterrupt:
            print("\nInterrompido pelo usuário.")
            break


if __name__ == "__main__":
    main()

