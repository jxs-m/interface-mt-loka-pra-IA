"""
Módulo de Formatação e Particionamento de Datasets no Schema ChatML Oficial.
Gera a estrutura de mensagens compativel com o template Qwen 2.5 (<|im_start|> ... <|im_end|>)
e salva partições Parquet com compressão Snappy no Google Drive.
"""

import os
import uuid
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Tuple

DEFAULT_SYSTEM_PROMPT = (
    "Você é um especialista de classe mundial em cibersegurança ofensiva/defensiva, "
    "engenharia reversa e programação de baixo nível (C, C++, Rust, Assembly x86/ARM, Go, Python). "
    "Você conduz auditorias de segurança estritas, identifica falhas de corrupção de memória e lógica, "
    "escreve exploits e provas de conceito (PoC) para ambientes de teste e produz patches defensivos robustos."
)


def format_to_chatml(category: str, user_content: str, assistant_content: str, cwe_id: str = None, language: str = "c", syntax_verified: bool = True) -> Dict[str, Any]:
    """Cria um registro padronizado no schema exato especificado no Plano Diretor."""
    return {
        "id": f"sec-{str(uuid.uuid4())[:8]}",
        "category": category,
        "cwe_id": cwe_id if cwe_id else "None",
        "language": language,
        "syntax_verified": syntax_verified,
        "messages": [
            {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
            {"role": "user", "content": user_content.strip()},
            {"role": "assistant", "content": assistant_content.strip()}
        ]
    }


def save_and_split_parquet(records: List[Dict[str, Any]], output_dir: str, train_ratio: float = 0.95) -> Tuple[str, str]:
    """
    Embaralha o dataset consolidado e divide nas partições de treino e validação,
    salvando em arquivos Parquet compactados com Snappy.
    """
    os.makedirs(output_dir, exist_ok=True)
    df = pd.DataFrame(records)
    
    # Embaralhamento pseudo-aleatório reprodutível
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    
    split_idx = int(len(df) * train_ratio)
    train_df = df.iloc[:split_idx]
    val_df = df.iloc[split_idx:]
    
    train_path = os.path.join(output_dir, "train.parquet")
    val_path = os.path.join(output_dir, "validation.parquet")
    
    train_df.to_parquet(train_path, engine="pyarrow", compression="snappy", index=False)
    val_df.to_parquet(val_path, engine="pyarrow", compression="snappy", index=False)
    
    print(f"[+] Dataset final exportado com sucesso!")
    print(f"    • Treino:      {len(train_df):,} amostras -> {train_path}")
    print(f"    • Validação:   {len(val_df):,} amostras -> {val_path}")
    
    return train_path, val_path

