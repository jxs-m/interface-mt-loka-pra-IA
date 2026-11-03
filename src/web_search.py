"""
Módulo de Integração com a Internet via DuckDuckGo (100% Gratuito e sem Chaves de API).
Suporta busca em tempo real usando a biblioteca padrão do Python e opcionalmente duckduckgo_search.
Injeta os resultados mais recentes no contexto do CyberLLM 32B.
"""

import re
import urllib.parse
import urllib.request
from typing import List, Dict, Any, Optional


def search_duckduckgo(query: str, max_results: int = 4, timeout: float = 8.0) -> List[Dict[str, str]]:
    """
    Executa busca em tempo real no DuckDuckGo sem necessidade de chave de API.
    Retorna uma lista com título, link e resumo (snippet) de cada resultado.
    """
    # 1. Tenta usar biblioteca duckduckgo_search se estiver instalada
    try:
        from duckduckgo_search import DDGS
        results = []
        with DDGS() as ddgs:
            for r in ddgs.text(query, max_results=max_results):
                results.append({
                    "title": r.get("title", ""),
                    "href": r.get("href", ""),
                    "snippet": r.get("body", "")
                })
        if results:
            return results
    except Exception:
        pass

    # 2. Fallback resiliente usando pure Python urllib (sem dependências externas)
    results = []
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        data = urllib.parse.urlencode({"q": query}).encode("utf-8")
        req = urllib.request.Request("https://html.duckduckgo.com/html/", data=data, headers=headers)
        
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="ignore")

        # Extrai links e snippets do HTML retornado
        raw_snippets = re.findall(r'<a class="result__snippet[^"]*"[^>]*>(.*?)</a>', html, re.DOTALL)
        raw_titles = re.findall(r'<h2 class="result__title">.*?<a class="result__url" href="([^"]+)">(.*?)</a>', html, re.DOTALL)
        
        # Fallback para regex alternativo caso a classe varie
        if not raw_titles:
            raw_titles_alt = re.findall(r'<a class="result__url" href="([^"]+)">', html)
            raw_titles = [(u, u) for u in raw_titles_alt]

        for i in range(min(len(raw_snippets), max_results)):
            snippet_clean = re.sub(r"<[^<]+?>", "", raw_snippets[i]).strip()
            href = raw_titles[i][0] if i < len(raw_titles) else ""
            title = re.sub(r"<[^<]+?>", "", raw_titles[i][1]).strip() if i < len(raw_titles) else f"Resultado {i+1}"
            
            # Limpa redirecionamento do DuckDuckGo se presente
            if "/l/?uddg=" in href:
                parsed = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
                href = parsed.get("uddg", [href])[0]
                
            results.append({
                "title": title,
                "href": href,
                "snippet": snippet_clean
            })
    except Exception as e:
        print(f"[!] Aviso na busca DuckDuckGo: {e}")
        
    return results


def format_search_context(query: str, results: List[Dict[str, str]]) -> str:
    """Formata os resultados da web em um bloco Markdown claro para ser injetado no prompt da IA."""
    if not results:
        return ""
        
    lines = [f"### [Resultados da Busca na Internet via DuckDuckGo para: '{query}']\n"]
    for idx, r in enumerate(results, 1):
        lines.append(f"**Fonte {idx}:** [{r['title']}]({r['href']})")
        lines.append(f"> {r['snippet']}\n")
        
    lines.append("*(Utilize as informações acima para enriquecer sua análise técnica e citar as fontes correspondentes)*\n")
    return "\n".join(lines)


def build_web_enhanced_prompt(user_question: str, max_results: int = 4) -> str:
    """Executa a busca e combina a pergunta do usuário com o contexto atualizado da internet."""
    search_results = search_duckduckgo(user_question, max_results=max_results)
    web_context = format_search_context(user_question, search_results)
    
    if not web_context:
        return user_question
        
    return f"{web_context}\nPergunta do Usuário:\n{user_question}"

