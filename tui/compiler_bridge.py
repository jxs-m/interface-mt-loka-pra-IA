"""
Ponte de Validação Sintática e Hardening com Compiladores Reais.
Reutiliza diretamente `src/validators.py` (gcc, g++, rustc, python3) do pipeline CyberLLM
e adiciona modo de auditoria estrita (-Wall -Wextra -Wformat-security) + validação YARA e YAML (Semgrep/Sigma).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, List, Tuple

import yaml

from src import validators as core_validators


@dataclass
class ToolchainInfo:
    """Informação sobre um compilador ou validador instalado no sistema operacional."""

    name: str
    binary: str
    available: bool
    version: str = ""


@dataclass
class ValidationResult:
    """Resultado detalhado da validação sintática ou checagem estrita de segurança."""

    valid: bool
    language: str
    mode: str  # "standard" (src/validators.py) | "strict" (-Wall -Wextra -Wformat-security)
    compiler_used: str
    output: str
    warnings_count: int = 0
    elapsed_ms: float = 0.0


def detect_installed_toolchains() -> Dict[str, ToolchainInfo]:
    """Inspeciona quais compiladores e ferramentas de segurança estão instalados na máquina."""
    specs = [
        ("gcc", "gcc", ["gcc", "--version"]),
        ("g++", "g++", ["g++", "--version"]),
        ("python3", "python3", ["python3", "--version"]),
        ("rustc", "rustc", ["rustc", "--version"]),
        ("yara", "yara", ["yara", "--version"]),
    ]
    results: Dict[str, ToolchainInfo] = {}
    for key, binary, cmd in specs:
        path = shutil.which(binary)
        if not path:
            results[key] = ToolchainInfo(name=key, binary=binary, available=False)
            continue
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            first_line = (res.stdout or res.stderr or "").strip().splitlines()[0]
        except Exception:
            first_line = path
        results[key] = ToolchainInfo(
            name=key,
            binary=path,
            available=True,
            version=first_line,
        )
    return results


def _wrap_c_snippet(code: str) -> str:
    if "int main" not in code and "#include" not in code:
        return (
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "#include <string.h>\n"
            "#include <stdint.h>\n"
            "#include <stdbool.h>\n"
            "#include <unistd.h>\n"
            f"{code}\n"
        )
    return code


def _wrap_cpp_snippet(code: str) -> str:
    if "#include" not in code:
        return (
            "#include <iostream>\n"
            "#include <vector>\n"
            "#include <string>\n"
            "#include <memory>\n"
            "#include <algorithm>\n"
            f"{code}\n"
        )
    return code


def _run_strict_gcc_or_gpp(code: str, is_cpp: bool) -> Tuple[bool, str, int]:
    compiler = "g++" if is_cpp else "gcc"
    if not shutil.which(compiler):
        return False, f"Compilador `{compiler}` não encontrado no PATH.", 0

    wrapped = _wrap_cpp_snippet(code) if is_cpp else _wrap_c_snippet(code)
    suffix = ".cpp" if is_cpp else ".c"
    lang_flag = "c++" if is_cpp else "c"
    flags: List[str] = [
        compiler,
        "-fsyntax-only",
        "-Wall",
        "-Wextra",
        "-Wformat=2",
        "-Wformat-security",
    ]
    if is_cpp:
        flags.insert(1, "-std=c++17")
    flags.extend(["-x", lang_flag])

    with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8") as tf:
        tf.write(wrapped)
        temp_path = tf.name

    try:
        res = subprocess.run(
            [*flags, temp_path],
            capture_output=True,
            text=True,
            timeout=6,
        )
        diag = (res.stderr or res.stdout or "").replace(temp_path, f"<target{suffix}>").strip()
        warnings_count = len(re.findall(r"\bwarning:", diag))
        is_ok = res.returncode == 0
        if is_ok and not diag:
            diag = f"OK — Zero erros e zero avisos com `{' '.join(flags[:-2])}`."
        return is_ok, diag, warnings_count
    except subprocess.TimeoutExpired:
        return False, f"Timeout na execução estrita do {compiler}.", 0
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def validate_yara_rule(code: str) -> Tuple[bool, str]:
    """Valida regra YARA usando o binário `yara` (se instalado) ou análise estrutural léxica."""
    cleaned = code.strip()
    if not cleaned:
        return False, "Regra YARA vazia."

    yara_bin = shutil.which("yara")
    if yara_bin:
        with tempfile.NamedTemporaryFile("w", suffix=".yar", delete=False, encoding="utf-8") as rf:
            rf.write(cleaned)
            rule_path = rf.name
        with tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False) as df:
            df.write(b"\x7fELF\x00\x00cyberllm_dummy_probe")
            dummy_path = df.name
        try:
            res = subprocess.run(
                [yara_bin, rule_path, dummy_path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                return True, "OK — Compilada e validada pelo motor nativo `yara`."
            return False, (res.stderr or res.stdout).replace(rule_path, "<rule.yar>").strip()
        finally:
            for p in (rule_path, dummy_path):
                if os.path.exists(p):
                    os.remove(p)

    # Validação estrutural offline quando o binário yara não está instalado
    rule_match = re.search(r"\brule\s+[A-Za-z_][A-Za-z0-9_]*", cleaned)
    if not rule_match:
        return False, "Estrutura inválida: declaração `rule <identificador>` não encontrada."
    if cleaned.count("{") == 0 or cleaned.count("{") != cleaned.count("}"):
        return False, "Estrutura inválida: chaves `{ ... }` desbalanceadas na regra YARA."
    if "condition:" not in cleaned:
        return False, "Estrutura inválida: seção obrigatória `condition:` ausente na regra YARA."
    return True, "OK — Estrutura léxica YARA válida (`rule`, chaves balanceadas e seção `condition:`)."


def validate_detection_yaml(code: str) -> Tuple[bool, str]:
    """Valida sintaxe YAML e schema estrutural de regras Semgrep ou Sigma."""
    cleaned = code.strip()
    if not cleaned:
        return False, "Documento YAML vazio."
    try:
        parsed = yaml.safe_load(cleaned)
    except yaml.YAMLError as exc:
        return False, f"Erro de sintaxe YAML:\n{exc}"

    if not isinstance(parsed, dict):
        return False, "O documento YAML deve ter um mapeamento (dict) na raiz."

    # Verifica assinatura de regra Semgrep
    if "rules" in parsed and isinstance(parsed["rules"], list):
        for idx, rule in enumerate(parsed["rules"], start=1):
            if not isinstance(rule, dict):
                return False, f"Regra Semgrep #{idx} não é um objeto válido."
            missing = [k for k in ("id", "message", "severity") if k not in rule]
            if missing:
                return False, f"Regra Semgrep #{idx} sem campos obrigatórios: {', '.join(missing)}"
        return True, f"OK — YAML Semgrep válido ({len(parsed['rules'])} regra(s) verificada(s))."

    # Verifica assinatura de regra Sigma
    if "detection" in parsed and "logsource" in parsed:
        if "condition" not in (parsed.get("detection") or {}):
            return False, "Regra Sigma sem `detection.condition`."
        title = parsed.get("title", "Sem título")
        return True, f"OK — Regra SIEM Sigma válida (`{title}`)."

    return True, f"OK — Sintaxe YAML válida (chaves raiz: {', '.join(map(str, parsed.keys()))})."


def run_compiler_validation(
    raw_code: str,
    language: str = "c",
    strict_security: bool = False,
) -> ValidationResult:
    """
    Executa validação sintática de código via `src/validators.py` ou modo estrito de segurança.
    """
    t0 = time.perf_counter()
    cleaned = core_validators.extract_code_block(raw_code, language)
    lang = (language or "c").strip().lower()
    mode = "strict" if strict_security else "standard"

    if lang in ("c", "c_cpp"):
        if strict_security:
            ok, msg, warns = _run_strict_gcc_or_gpp(cleaned, is_cpp=False)
            compiler_label = "gcc -Wall -Wextra -Wformat-security"
            if not ok and ("class " in cleaned or "namespace " in cleaned or "std::" in cleaned):
                ok_cpp, msg_cpp, warns_cpp = _run_strict_gcc_or_gpp(cleaned, is_cpp=True)
                if ok_cpp:
                    ok, msg, warns = ok_cpp, msg_cpp, warns_cpp
                    compiler_label = "g++ -std=c++17 -Wall -Wextra -Wformat-security"
        else:
            ok, msg = core_validators.validate_c_code(cleaned)
            warns = 0
            compiler_label = "src.validators.validate_c_code (gcc -fsyntax-only)"
            if not ok:
                ok_cpp, msg_cpp = core_validators.validate_cpp_code(cleaned)
                if ok_cpp:
                    ok, msg = ok_cpp, msg_cpp
                    compiler_label = "src.validators.validate_cpp_code (g++ -std=c++17)"

    elif lang in ("cpp", "c++"):
        if strict_security:
            ok, msg, warns = _run_strict_gcc_or_gpp(cleaned, is_cpp=True)
            compiler_label = "g++ -std=c++17 -Wall -Wextra -Wformat-security"
        else:
            ok, msg = core_validators.validate_cpp_code(cleaned)
            warns = 0
            compiler_label = "src.validators.validate_cpp_code (g++ -std=c++17)"

    elif lang in ("py", "python"):
        ok, msg = core_validators.validate_python_code(cleaned)
        warns = 0
        compiler_label = "src.validators.validate_python_code (python3 -m py_compile)"
        if ok and msg == "OK":
            msg = "OK — AST e bytecode Python validados sem erros de sintaxe ou indentação."

    elif lang in ("rs", "rust"):
        ok, msg = core_validators.validate_rust_code(cleaned)
        warns = len(re.findall(r"\bwarning:", msg))
        compiler_label = "src.validators.validate_rust_code (rustc --emit=metadata)"

    elif lang in ("yara", "yar"):
        ok, msg = validate_yara_rule(cleaned)
        warns = 0
        compiler_label = "validador YARA"

    elif lang in ("yaml", "yml", "semgrep", "sigma"):
        ok, msg = validate_detection_yaml(cleaned)
        warns = 0
        compiler_label = "validador YAML (Semgrep / Sigma)"

    else:
        ok = core_validators.validate_sample_code(cleaned, lang)
        warns = 0
        compiler_label = f"src.validators.validate_sample_code ({lang})"
        msg = "OK — Bloco estruturalmente válido." if ok else "Código vazio ou muito curto."

    if ok and msg == "OK":
        msg = f"OK — Sintaxe aprovada por `{compiler_label}`."

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return ValidationResult(
        valid=ok,
        language=lang,
        mode=mode,
        compiler_used=compiler_label,
        output=msg,
        warnings_count=warns,
        elapsed_ms=elapsed_ms,
    )
