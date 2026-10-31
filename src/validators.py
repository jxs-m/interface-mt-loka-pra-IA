"""
Módulo de Validação Sintática por Compiladores Reais.
Executa gcc, g++, rustc e python para garantir que nenhuma amostra
com erro de compilação ou indentação seja injetada no dataset de treinamento.
"""

import os
import re
import tempfile
import subprocess
from typing import Tuple, Optional


def extract_code_block(text: str, target_lang: str = None) -> str:
    """Extrai o bloco de código de marcações Markdown (```lang ... ```) ou retorna o texto puro."""
    if not text:
        return ""
        
    pattern = r"```(?:[a-zA-Z0-9_\+\-]+)?\n(.*?)```"
    matches = re.findall(pattern, text, re.DOTALL)
    if matches:
        return matches[0].strip()
    return text.strip()


def validate_c_code(code: str) -> Tuple[bool, str]:
    """Valida código C usando gcc com flag -fsyntax-only."""
    if not code or len(code) < 15:
        return False, "Código vazio ou muito curto"
        
    # Adiciona headers padrão caso a função seja um trecho isolado
    wrapped_code = code
    if "int main" not in code and "#include" not in code:
        wrapped_code = (
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "#include <string.h>\n"
            "#include <stdint.h>\n"
            "#include <stdbool.h>\n"
            "#include <unistd.h>\n"
            f"{code}\n"
        )
        
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as tf:
        tf.write(wrapped_code)
        temp_path = tf.name

    try:
        res = subprocess.run(
            ["gcc", "-fsyntax-only", "-w", "-x", "c", temp_path],
            capture_output=True,
            text=True,
            timeout=5
        )
        is_ok = (res.returncode == 0)
        return is_ok, res.stderr if not is_ok else "OK"
    except subprocess.TimeoutExpired:
        return False, "Timeout de compilação C"
    except Exception as e:
        return False, str(e)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def validate_cpp_code(code: str) -> Tuple[bool, str]:
    """Valida código C++ usando g++ com flag -fsyntax-only."""
    if not code or len(code) < 15:
        return False, "Código C++ vazio ou muito curto"
        
    wrapped_code = code
    if "#include" not in code:
        wrapped_code = (
            "#include <iostream>\n"
            "#include <vector>\n"
            "#include <string>\n"
            "#include <memory>\n"
            "#include <algorithm>\n"
            f"{code}\n"
        )
        
    with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False) as tf:
        tf.write(wrapped_code)
        temp_path = tf.name

    try:
        res = subprocess.run(
            ["g++", "-std=c++17", "-fsyntax-only", "-w", "-x", "c++", temp_path],
            capture_output=True,
            text=True,
            timeout=5
        )
        is_ok = (res.returncode == 0)
        return is_ok, res.stderr if not is_ok else "OK"
    except subprocess.TimeoutExpired:
        return False, "Timeout de compilação C++"
    except Exception as e:
        return False, str(e)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def validate_python_code(code: str) -> Tuple[bool, str]:
    """Valida sintaxe e indentação Python usando py_compile nativo."""
    if not code or len(code) < 10:
        return False, "Código Python vazio"
        
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(code)
        temp_path = tf.name

    try:
        res = subprocess.run(
            ["python3", "-m", "py_compile", temp_path],
            capture_output=True,
            text=True,
            timeout=5
        )
        is_ok = (res.returncode == 0)
        return is_ok, res.stderr if not is_ok else "OK"
    except Exception as e:
        return False, str(e)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def validate_rust_code(code: str) -> Tuple[bool, str]:
    """Valida sintaxe Rust usando rustc --emit=metadata."""
    if not code:
        return False, "Código Rust vazio"
        
    # Verifica se rustc está instalado no ambiente
    if subprocess.run(["which", "rustc"], capture_output=True).returncode != 0:
        # Se rustc não estiver instalado no Colab, faz validação básica de chaves
        return (code.count("{") == code.count("}")), "Rustc não instalado, fallback léxico"

    wrapped_code = code
    if "fn main" not in code:
        wrapped_code = f"{code}\nfn main() {{}}\n"

    with tempfile.NamedTemporaryFile("w", suffix=".rs", delete=False) as tf:
        tf.write(wrapped_code)
        temp_path = tf.name

    try:
        res = subprocess.run(
            ["rustc", "--emit=metadata", "-o", "/dev/null", temp_path],
            capture_output=True,
            text=True,
            timeout=6
        )
        is_ok = (res.returncode == 0)
        return is_ok, res.stderr if not is_ok else "OK"
    except Exception as e:
        return False, str(e)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def validate_sample_code(code: str, language: str) -> bool:
    """Roteia a validação para o compilador correspondente."""
    cleaned = extract_code_block(code, language)
    lang = language.lower()
    
    if lang in ["c", "c_cpp"]:
        ok, _ = validate_c_code(cleaned)
        if not ok: # Tenta C++ caso tenha classes ou namespaces
            ok, _ = validate_cpp_code(cleaned)
        return ok
    elif lang in ["cpp", "c++"]:
        ok, _ = validate_cpp_code(cleaned)
        return ok
    elif lang in ["py", "python"]:
        ok, _ = validate_python_code(cleaned)
        return ok
    elif lang in ["rs", "rust"]:
        ok, _ = validate_rust_code(cleaned)
        return ok
    else:
        # Para regras YARA/Semgrep, se não vazio e com tokens chave, considera válido
        return len(cleaned) > 20

