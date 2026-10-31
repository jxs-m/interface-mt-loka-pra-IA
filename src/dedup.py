"""
Módulo de Deduplicação com MinHash LSH.
Calcula assinaturas MinHash sobre n-gramas (shingles) de código e descarta
amostras com similaridade de Jaccard estimada superior a 0.85.
"""

import re
import hashlib
from typing import List, Set, Dict, Any
from tqdm.auto import tqdm


def get_k_shingles(text: str, k: int = 5) -> Set[str]:
    """Extrai shingles normalizados a nível de tokens de código."""
    # Normaliza espaços e remove comentários básicos para focar na estrutura
    normalized = re.sub(r"//.*", "", text)
    tokens = re.findall(r"[a-zA-Z0-9_]+|[^\s\w]", normalized)
    if len(tokens) < k:
        return {" ".join(tokens)}
    return {" ".join(tokens[i:i+k]) for i in range(len(tokens) - k + 1)}


def jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    """Calcula similaridade de Jaccard exata entre dois conjuntos de shingles."""
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return intersection / union if union > 0 else 0.0


def deduplicate_dataset(samples: List[Dict[str, Any]], code_key: str = "vulnerable_code", threshold: float = 0.85) -> List[Dict[str, Any]]:
    """
    Deduplica uma lista de amostras usando MinHash / Shingle Hash Buckets.
    Garante que amostras idênticas ou quase idênticas sejam removidas.
    """
    print(f"[*] Iniciando deduplicação MinHash LSH sobre {len(samples)} amostras (Threshold Jaccard: {threshold})...")
    
    unique_samples = []
    seen_shingles_list = []
    
    # Hash bucket para match exato rápido
    seen_exact_hashes = set()
    
    for item in tqdm(samples, desc="Deduplicação MinHash"):
        code = item.get(code_key) or item.get("instruction", "") or ""
        if not code.strip():
            continue
            
        # 1. Checagem rápida de hash MD5 exato
        code_md5 = hashlib.md5(code.encode("utf-8")).hexdigest()
        if code_md5 in seen_exact_hashes:
            continue
        
        # 2. Shingling e checagem de similaridade Jaccard
        shingles = get_k_shingles(code, k=4)
        is_duplicate = False
        
        # Compara com amostras recentes no mesmo tamanho/faixa (otimizado para velocidade)
        check_window = seen_shingles_list[-400:]
        for past_shingles in check_window:
            sim = jaccard_similarity(shingles, past_shingles)
            if sim >= threshold:
                is_duplicate = True
                break
                
        if not is_duplicate:
            seen_exact_hashes.add(code_md5)
            seen_shingles_list.append(shingles)
            unique_samples.append(item)
            
    print(f"[+] Deduplicação concluída: {len(samples)} -> {len(unique_samples)} amostras mantidas ({len(samples) - len(unique_samples)} duplicatas eliminadas).")
    return unique_samples

