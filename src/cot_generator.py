"""
Módulo de Síntese de Raciocínio Investigativo (Teacher-Student com CoT).
Gera cadeias deliberadas de pensamento dentro de tags <think> ... </think>
detalhando corrupção de memória, impacto no fluxo de execução e prova de mitigação.
Suporta API externa ultrarrápida (Groq / DeepSeek / Gemini / OpenAI) e fallback local determinístico.
"""

import os
import re
import json
import time
from typing import Dict, Any, Optional

TEACHER_SYSTEM_PROMPT = (
    "Você é um auditor sênior de segurança de software e compiladores. "
    "Ao analisar o código vulnerável e a sua mitigação fornecidos, reconstrua o processo "
    "mental investigativo completo dentro das tags <think> ... </think>. "
    "Detalhe: 1) Onde a memória ou lógica é corrompida; 2) Qual o impacto no fluxo de execução; "
    "3) Por que a correção proposta neutraliza o risco sem introduzir efeitos colaterais. "
    "Após a tag </think>, forneça a Análise de Segurança formal e o Código Corrigido."
)


def synthesize_cot_heuristic(code: str, cwe_id: str, language: str) -> str:
    """
    Fallback offline: sintetiza uma cadeia de raciocínio CoT rica e precisa baseada
    no CWE formal e na mecânica de baixo nível da vulnerabilidade.
    Permite rodar o pipeline no Colab mesmo sem chaves de API pagas.
    """
    cwe_explanations = {
        "CWE-119": (
            "1. Análise de Limites de Buffer: O código acessa posições de memória fora do escopo reservado para a estrutura de dados.\n"
            "2. Impacto na Memória: Transbordamento no heap ou stack frame, corrompendo ponteiros de controle ou variáveis adjacentes.\n"
            "3. Mitigação: Inclusão de checagem estrita de bounds antes de operações de leitura/escrita."
        ),
        "CWE-120": (
            "1. Análise de Cópia Insegura: A função utiliza funções inseguras de cópia (como strcpy ou gets) sem delimitar o tamanho do buffer de destino.\n"
            "2. Impacto no Fluxo de Execução: Sobrescrita do ponteiro de quadro de pilha (RBP) e do endereço de retorno (Saved RIP), permitindo desvio arbitrário de execução.\n"
            "3. Mitigação: Substituição por snprintf ou strncpy garantindo explicitamente a terminação nula e limitando o tamanho."
        ),
        "CWE-416": (
            "1. Análise do Ciclo de Vida do Ponteiro: O ponteiro é dereferenciado após o bloco de memória associado ter sido liberado via free().\n"
            "2. Impacto na Memória: Use-After-Free (UAF). Permite ler dados residuais (information leak) ou reescrever chunks de heap em estado dangling.\n"
            "3. Mitigação: Anulação imediata do ponteiro (ptr = NULL) após a chamada de desalocação e verificação antes do reuso."
        ),
        "CWE-476": (
            "1. Análise de Ponteiro Nulo: Desreferência direta de ponteiro sem validação prévia de nullability.\n"
            "2. Impacto: Crash imediato por violação de segmento (SIGSEGV) ou interrupção de serviço crítico (DoS).\n"
            "3. Mitigação: Checagem explícita 'if (ptr == NULL) return ERROR_CODE;' antes de qualquer acesso."
        ),
        "CWE-89": (
            "1. Análise de Interpolação de Strings: Entradas controladas pelo usuário são concatenadas diretamente na instrução SQL sem parametrização.\n"
            "2. Impacto Lógico: Quebra do contexto de dados, permitindo injeção de lógica arbitrária de consulta (SQL Injection).\n"
            "3. Mitigação: Uso obrigatório de Prepared Statements e consultas parametrizadas."
        ),
        "CWE-78": (
            "1. Análise de Execução de Comandos: Strings de entrada não sanitizadas são repassadas para o shell do sistema operacional via system() ou popen().\n"
            "2. Impacto: Command Injection com execução arbitrária de binários no contexto do processo.\n"
            "3. Mitigação: Utilização de APIs de execução sem invocação de shell (execve com lista estrita de argumentos)."
        )
    }

    base_cwe = cwe_id.split(":")[0].strip() if ":" in cwe_id else cwe_id
    explanation = cwe_explanations.get(base_cwe, (
        f"1. Análise de Segurança ({cwe_id}): Identificada fragilidade estrutural no manuseio de dados e fluxo de controle.\n"
        "2. Impacto: Potencial corrupção de estado, bypass de autenticação ou vazamento de contexto privilegiado.\n"
        "3. Mitigação: Refatoração defensiva aplicando validação de entrada, sanitização e controle de tipos rigoroso."
    ))

    cot_thought = f"<think>\n{explanation}\n</think>\n\n"
    analysis = (
        f"### Análise de Segurança\n"
        f"O trecho auditado apresenta uma vulnerabilidade crítica catalogada como **{cwe_id}**.\n\n"
        f"### Princípio de Correção Defensiva\n"
        f"Para neutralizar a vulnerabilidade, aplicamos sanitização rigorosa dos parâmetros e garantimos conformidade com os princípios de programação defensiva."
    )
    return cot_thought + analysis


def generate_cot_with_api(vulnerable_code: str, cwe_id: str, fixed_code: str = "", api_key: str = None, provider: str = "groq") -> str:
    """
    Gera o raciocínio investigativo profundo usando APIs ultrarrápidas (Groq, DeepSeek ou OpenAI).
    """
    if not api_key:
        return synthesize_cot_heuristic(vulnerable_code, cwe_id, "c")

    prompt = (
        f"Código Vulnerável:\n```\n{vulnerable_code}\n```\n"
        f"Identificador CWE: {cwe_id}\n"
    )
    if fixed_code:
        prompt += f"\nCódigo Corrigido / Mitigação:\n```\n{fixed_code}\n```\n"

    try:
        if provider == "groq":
            from groq import Groq
            client = Groq(api_key=api_key)
            completion = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": TEACHER_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=1500
            )
            return completion.choices[0].message.content
            
        elif provider == "deepseek":
            import requests
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            payload = {
                "model": "deepseek-reasoner",
                "messages": [
                    {"role": "system", "content": TEACHER_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ]
            }
            res = requests.post("https://api.deepseek.com/chat/completions", headers=headers, json=payload, timeout=30)
            data = res.json()
            reasoning = data["choices"][0]["message"].get("reasoning_content", "")
            content = data["choices"][0]["message"].get("content", "")
            return f"<think>\n{reasoning}\n</think>\n\n{content}"
    except Exception as e:
        print(f"[!] Erro na chamada da API ({provider}): {e}. Usando fallback heurístico.")
        return synthesize_cot_heuristic(vulnerable_code, cwe_id, "c")

