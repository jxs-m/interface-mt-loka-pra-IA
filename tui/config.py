"""
Gerenciamento de configuração persistente do CyberLLM TUI.
Focado em servidores vLLM / API compatível com OpenAI (local ou VM remota).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict


DEFAULT_CYBER_SYSTEM_PROMPT = (
    "Você é um especialista de classe mundial em cibersegurança ofensiva/defensiva, "
    "engenharia reversa e programação de baixo nível (C, C++, Rust, Assembly x86/ARM, Go, Python). "
    "Você conduz auditorias de segurança estritas, identifica falhas de corrupção de memória e lógica, "
    "escreve exploits e provas de conceito (PoC) para ambientes de teste e produz patches defensivos robustos. "
    "Antes da resposta técnica final, estruture seu raciocínio investigativo dentro das tags <think> ... </think>."
)

SYSTEM_PROMPT_PRESETS: Dict[str, tuple[str, str]] = {
    "cyber_full": (
        "Especialista Integral CyberLLM 32B (Padrão)",
        DEFAULT_CYBER_SYSTEM_PROMPT,
    ),
    "sast_compiler": (
        "Auditor Sênior SAST & Compiladores (CoT Estrito)",
        (
            "Você é um auditor sênior de segurança de software e compiladores. "
            "Ao analisar código-fonte, reconstrua o processo mental investigativo completo dentro das tags <think> ... </think>, "
            "detalhando: 1) Onde a memória ou lógica é corrompida; 2) Qual o impacto no fluxo de execução e registradores "
            "(Saved RIP/RBP, heap chunks); 3) Por que a correção proposta neutraliza o risco sem efeitos colaterais. "
            "Após </think>, mapeie as CWEs aplicáveis e forneça o código corrigido completo e compilável."
        ),
    ),
    "detection_eng": (
        "Engenheiro de Detecção (YARA / Semgrep / Sigma)",
        (
            "Você é um engenheiro sênior de detecção de ameaças e Threat Hunting. "
            "Raciocine dentro de <think> ... </think> para minimizar falsos positivos e maximizar resiliência contra evasão. "
            "Produza regras YARA otimizadas (evitando regex lentas), regras AST YAML do Semgrep e regras SIEM Sigma "
            "seguindo estritamente as especificações oficiais."
        ),
    ),
    "low_level_rev": (
        "Analista de Binários & Assembly (x86_64 / ARM64 / Rust)",
        (
            "Você é um pesquisador de vulnerabilidades de baixo nível, kernel Linux e engenharia reversa em x86_64, ARM64, C e Rust. "
            "Use <think> ... </think> para inspecionar alinhamento de stack frame, convenções de chamada (System V AMD64 ABI), "
            "proteções de binário (NX, ASLR, Stack Canary, PIE, Full RELRO) e invariantes de segurança em blocos unsafe."
        ),
    ),
}


def get_data_dir() -> Path:
    """Retorna o diretório de dados locais (~/.cyberllm ou $CYBERLLM_HOME)."""
    env_dir = os.environ.get("CYBERLLM_HOME")
    base = Path(env_dir).expanduser() if env_dir else (Path.home() / ".cyberllm")
    base.mkdir(parents=True, exist_ok=True)
    return base


def normalize_api_base(url: str) -> str:
    """Normaliza a URL base do servidor vLLM garantindo esquema HTTP(S) e sufixo /v1."""
    cleaned = (url or "").strip().rstrip("/")
    if not cleaned:
        return "http://localhost:8000/v1"
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"http://{cleaned}"
    # Se o usuário digitou apenas host:porta sem caminho, adiciona /v1 automaticamente
    after_scheme = cleaned.split("://", 1)[1]
    if "/" not in after_scheme:
        cleaned = f"{cleaned}/v1"
    return cleaned


@dataclass
class CyberLLMConfig:
    """Configuração de conexão com o servidor vLLM e hiperparâmetros de inferência."""

    api_base: str = "http://localhost:8000/v1"
    api_key: str = "EMPTY"
    model: str = "qwen32b-cyber"
    temperature: float = 0.1
    top_p: float = 0.9
    max_tokens: int = 4096
    timeout_seconds: float = 180.0
    system_prompt: str = DEFAULT_CYBER_SYSTEM_PROMPT
    auto_collapse_think: bool = False

    def normalized(self) -> "CyberLLMConfig":
        self.api_base = normalize_api_base(self.api_base)
        self.api_key = (self.api_key or "EMPTY").strip()
        self.model = (self.model or "qwen32b-cyber").strip()
        self.temperature = max(0.0, min(2.0, float(self.temperature)))
        self.top_p = max(0.01, min(1.0, float(self.top_p)))
        self.max_tokens = max(64, min(16384, int(self.max_tokens)))
        self.timeout_seconds = max(5.0, min(600.0, float(self.timeout_seconds)))
        if not self.system_prompt.strip():
            self.system_prompt = DEFAULT_CYBER_SYSTEM_PROMPT
        return self


def get_config_path() -> Path:
    return get_data_dir() / "config.json"


def load_config() -> CyberLLMConfig:
    """Carrega a configuração persistida em disco ou retorna os padrões do vLLM."""
    cfg_path = get_config_path()
    if not cfg_path.exists():
        return CyberLLMConfig().normalized()
    try:
        raw = json.loads(cfg_path.read_text(encoding="utf-8"))
        allowed = {f for f in CyberLLMConfig.__dataclass_fields__}
        filtered = {k: v for k, v in raw.items() if k in allowed}
        return CyberLLMConfig(**filtered).normalized()
    except Exception:
        return CyberLLMConfig().normalized()


def save_config(config: CyberLLMConfig) -> Path:
    """Persiste a configuração atual em JSON."""
    config.normalized()
    cfg_path = get_config_path()
    cfg_path.write_text(
        json.dumps(asdict(config), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return cfg_path
