"""
Módulo de Aquisição e Mineração de Datasets para Cibersegurança no Google Colab.
Implementa download via streaming do Hugging Face Hub, clonagem e extração de regras estáticas (Semgrep, YARA).
"""

import os
import re
import json
import glob
import subprocess
import pandas as pd
from typing import List, Dict, Any, Generator
from datasets import load_dataset
from tqdm.auto import tqdm

try:
    from src.config import CRITICAL_CWES, DIR_RAW_SOURCES, LOCAL_CACHE_DIR
except ImportError:
    from config import CRITICAL_CWES, DIR_RAW_SOURCES, LOCAL_CACHE_DIR


def mine_diversevul(max_samples: int = 10000, target_cwes: set = CRITICAL_CWES) -> pd.DataFrame:
    """
    Minera amostras vulneráveis do dataset michelec/DiverseVul via streaming.
    Filtra especificamente por CWEs críticas de corrupção de memória e injeção.
    """
    print(f"[*] Iniciando streaming de 'michelec/DiverseVul' (Alvo: {max_samples} amostras)...")
    dataset = load_dataset("michelec/DiverseVul", split="train", streaming=True)
    
    records = []
    pbar = tqdm(total=max_samples, desc="DiverseVul")
    
    for item in dataset:
        cwe_list = item.get("cwe", [])
        if not isinstance(cwe_list, list):
            cwe_list = [cwe_list] if cwe_list else []
            
        is_target_cwe = any(c in target_cwes for c in cwe_list)
        is_vuln = (item.get("target") == 1)
        
        # Coletamos amostras vulneráveis com CWE mapeada
        if is_target_cwe and is_vuln and item.get("func"):
            func_code = item["func"].strip()
            if len(func_code) > 40 and len(func_code) < 12000: # Filtra ruídos vazios ou arquivos colossais
                records.append({
                    "id": f"diversevul-{len(records):06d}",
                    "category": "sast_patch",
                    "cwe_id": cwe_list[0] if cwe_list else "CWE-Other",
                    "language": "c_cpp",
                    "project": item.get("project", "unknown"),
                    "vulnerable_code": func_code,
                    "fixed_code": "", # Será complementado ou usado em auditoria
                    "commit_id": item.get("commit_id", "")
                })
                pbar.update(1)
                if len(records) >= max_samples:
                    break
                    
    pbar.close()
    df = pd.DataFrame(records)
    print(f"[+] Coletadas {len(df)} amostras do DiverseVul.")
    return df


def mine_primevul(max_samples: int = 10000) -> pd.DataFrame:
    """
    Minera amostras de DLVul/PrimeVul (pares vulnerável e mitigado).
    """
    print(f"[*] Conectando ao 'DLVul/PrimeVul' (Alvo: {max_samples} amostras)...")
    try:
        dataset = load_dataset("DLVul/PrimeVul", split="train", streaming=True)
    except Exception as e:
        print(f"[!] Erro ao carregar DLVul/PrimeVul: {e}. Tentando fallback alternativo...")
        return pd.DataFrame()

    records = []
    pbar = tqdm(total=max_samples, desc="PrimeVul")
    for item in dataset:
        func = item.get("func") or item.get("code")
        if func and len(func.strip()) > 50:
            cwe = item.get("cwe") or "CWE-119"
            if isinstance(cwe, list):
                cwe = cwe[0] if len(cwe) > 0 else "CWE-119"
            records.append({
                "id": f"primevul-{len(records):06d}",
                "category": "sast_patch",
                "cwe_id": str(cwe),
                "language": "c_cpp",
                "project": item.get("project", "open_source"),
                "vulnerable_code": func.strip(),
                "fixed_code": item.get("target_code", "").strip() if "target_code" in item else "",
                "commit_id": item.get("commit_id", "")
            })
            pbar.update(1)
            if len(records) >= max_samples:
                break
    pbar.close()
    return pd.DataFrame(records)


def mine_magicoder_for_coding(max_samples: int = 15000) -> pd.DataFrame:
    """
    Coleta amostras do Pilar 1 (Engenharia Geral e Algoritmos) a partir de
    ise-uiuc/Magicoder-Evol-Instruct-110K, filtrando C, C++, Rust, Go e Python.
    """
    print(f"[*] Mineração do Pilar 1: Magicoder-Evol-Instruct-110K (Alvo: {max_samples} amostras)...")
    try:
        dataset = load_dataset("ise-uiuc/Magicoder-Evol-Instruct-110K", split="train", streaming=True)
    except Exception as e:
        print(f"[!] Erro ao carregar Magicoder: {e}")
        return pd.DataFrame()

    target_keywords = ["c++", "rust", "golang", "python", "memory allocation", "buffer", "pointer", "socket", "concurrency", "thread", "algorithm"]
    records = []
    pbar = tqdm(total=max_samples, desc="Magicoder")
    
    for item in dataset:
        instruction = item.get("instruction", "")
        response = item.get("response", "")
        combined = (instruction + " " + response).lower()
        
        # Filtra amostras técnicas de baixo nível e linguagens de sistemas
        if any(kw in combined for kw in target_keywords):
            # Detecta linguagem predominante
            lang = "python"
            if "rust" in combined or "fn main" in response:
                lang = "rust"
            elif "c++" in combined or "#include <iostream>" in response:
                lang = "cpp"
            elif "#include <stdio.h>" in response or "malloc(" in response:
                lang = "c"
            elif "golang" in combined or "package main" in response:
                lang = "go"
                
            records.append({
                "id": f"code-gen-{len(records):06d}",
                "category": "general_code",
                "cwe_id": None,
                "language": lang,
                "instruction": instruction,
                "response": response
            })
            pbar.update(1)
            if len(records) >= max_samples:
                break
                
    pbar.close()
    df = pd.DataFrame(records)
    print(f"[+] Coletadas {len(df)} amostras de engenharia de software geral.")
    return df


def mine_semgrep_and_yara_rules(max_rules: int = 11000) -> pd.DataFrame:
    """
    Clona os repositórios públicos oficiais do Semgrep e YARA e extrai
    as regras em formato de instrução e padrão AST/assinatura.
    """
    print("[*] Mineração do Pilar 3: Clonando repositórios de regras Semgrep e YARA...")
    cache_repos = os.path.join(LOCAL_CACHE_DIR, "rule_repos")
    os.makedirs(cache_repos, exist_ok=True)
    
    semgrep_repo_dir = os.path.join(cache_repos, "semgrep-rules")
    yara_repo_dir = os.path.join(cache_repos, "yara-rules")
    
    # Clona repositório Semgrep se ainda não existir
    if not os.path.exists(semgrep_repo_dir):
        print("  -> Clonando Semgrep Rules (shallow clone)...")
        subprocess.run(["git", "clone", "--depth", "1", "https://github.com/semgrep/semgrep-rules.git", semgrep_repo_dir], capture_output=True)
        
    # Clona repositório YARA se ainda não existir
    if not os.path.exists(yara_repo_dir):
        print("  -> Clonando YARA Rules (shallow clone)...")
        subprocess.run(["git", "clone", "--depth", "1", "https://github.com/Yara-Rules/rules.git", yara_repo_dir], capture_output=True)

    records = []
    
    # 1. Extração de Regras Semgrep (.yaml / .yml)
    yaml_files = glob.glob(f"{semgrep_repo_dir}/**/*.y*ml", recursive=True)
    print(f"  -> Processando {len(yaml_files)} arquivos de regras Semgrep...")
    for yf in yaml_files[:7000]:
        try:
            with open(yf, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if "rules:" in content and "pattern" in content:
                # Extrai mensagem e ID da regra
                rule_id_match = re.search(r"id:\s*([^\n]+)", content)
                rule_id = rule_id_match.group(1).strip() if rule_id_match else os.path.basename(yf)
                
                records.append({
                    "id": f"semgrep-{len(records):06d}",
                    "category": "detection_rule",
                    "cwe_id": "CWE-StaticRule",
                    "language": "semgrep",
                    "instruction": f"Crie uma regra de análise estática Semgrep para detectar a seguinte vulnerabilidade/padrão inseguro: {rule_id}",
                    "response": f"```yaml\n{content.strip()}\n```"
                })
        except Exception:
            continue
            
    # 2. Extração de Regras YARA (.yar / .yara)
    yara_files = glob.glob(f"{yara_repo_dir}/**/*.yar*", recursive=True)
    print(f"  -> Processando {len(yara_files)} arquivos de assinaturas YARA...")
    for yf in yara_files[:5000]:
        try:
            with open(yf, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if "rule " in content and "strings:" in content:
                rule_name_match = re.search(r"rule\s+([a-zA-Z0-9_]+)", content)
                rname = rule_name_match.group(1) if rule_name_match else os.path.basename(yf)
                
                records.append({
                    "id": f"yara-{len(records):06d}",
                    "category": "detection_rule",
                    "cwe_id": "Malware-Signature",
                    "language": "yara",
                    "instruction": f"Escreva uma regra YARA rigorosa para identificar padrões maliciosos associados a: {rname}",
                    "response": f"```yara\n{content.strip()}\n```"
                })
        except Exception:
            continue
            
    df = pd.DataFrame(records[:max_rules])
    print(f"[+] Coletadas {len(df)} regras defensivas estruturadas.")
    return df

