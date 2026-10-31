"""
Aplicação Principal TUI do CyberLLM 32B (Textual 8.x + Rich).
Integra Chat SSE com <think> recolhível, Bancada SAST com Diff & Compilador,
Validador Sintático (src/validators.py), Templates Cyber e Gerenciador vLLM.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    Collapsible,
    Footer,
    Input,
    Label,
    ListItem,
    ListView,
    Markdown,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)

from tui.compiler_bridge import (
    ToolchainInfo,
    ValidationResult,
    detect_installed_toolchains,
    run_compiler_validation,
)
from tui.config import (
    SYSTEM_PROMPT_PRESETS,
    CyberLLMConfig,
    get_data_dir,
    load_config,
    save_config,
)
from tui.sast_engine import (
    SAMPLE_VULNERABLE_TARGETS,
    build_sast_audit_messages,
    detect_language,
    extract_patched_code,
    format_triage_markdown,
    generate_unified_diff,
    run_local_cwe_triage,
)
from tui.storage import SessionStore
from tui.templates import CYBER_TEMPLATES, CyberTemplate
from tui.vllm_client import HealthStatus, VLLMClient
from tui.widgets import (
    ChatMessageCard,
    FilePickerModal,
    SmartPromptInput,
    configure_code_editor,
    set_editor_language,
)

WELCOME_BANNER_MD = """### 🛡️ CYBERLLM 32B // CONSOLE OPERACIONAL ATIVO
Especialista em **Programação de Baixo Nível (C/C++/Rust/ASM)**, **Auditoria SAST (MITRE Top 25 CWEs)** e **Engenharia de Detecção (YARA / Semgrep / Sigma)**.

- **Atalhos Rápidos:** `F1` Chat · `F2` Bancada SAST · `F3` Compiladores · `F4` Templates · `F5` Servidor vLLM
- **Operações:** `Ctrl+N` Nova Sessão · `Ctrl+T` Expandir/Recolher `<think>` · `Ctrl+E` Anexar Código · `Ctrl+X` Exportar `.md` · `Esc` Parar Stream
"""

DEFAULT_VALIDATOR_SAMPLE = """#include <stdio.h>
#include <stdint.h>
#include <string.h>

int copy_packet_header(char *dst, size_t dst_cap, const char *src) {
    if (dst == NULL || src == NULL || dst_cap == 0) {
        return -1;
    }
    int written = snprintf(dst, dst_cap, "%s", src);
    return (written < 0 || (size_t)written >= dst_cap) ? -2 : 0;
}
"""

VLLM_QUICK_GUIDE_MD = """### 🖥️ Guia Rápido de Conexão com Servidor vLLM (Local ou VM Remota)
Inicie o servidor OpenAI-compatível do **CyberLLM 32B** na porta `8000`:
```bash
python3 -m vllm.entrypoints.openai.api_server \\
    --model ~/models/qwen32b_cyber \\
    --served-model-name qwen32b-cyber \\
    --host 0.0.0.0 --port 8000 \\
    --max-model-len 16384 --gpu-memory-utilization 0.92 --dtype bfloat16
```
Se a GPU estiver em uma **VM remota** sem porta pública aberta, crie um túnel SSH local:
```bash
ssh -N -L 8000:localhost:8000 ubuntu@IP_DA_SUA_VM
```
"""


class SessionListItem(ListItem):
    """Item da barra lateral representando uma sessão persistida no SQLite."""

    def __init__(self, session_data: Dict) -> None:
        super().__init__()
        self.session_id: str = session_data["id"]
        self.session_title: str = session_data["title"]
        self.msg_count: int = int(session_data.get("message_count", 0))

    def compose(self) -> ComposeResult:
        short = (
            self.session_title[:21] + "…"
            if len(self.session_title) > 22
            else self.session_title
        )
        yield Label(f"▸ {short} ({self.msg_count})")


class TemplateListItem(ListItem):
    """Item da lista de templates de cibersegurança."""

    def __init__(self, template: CyberTemplate) -> None:
        super().__init__()
        self.template = template

    def compose(self) -> ComposeResult:
        yield Label(f"[{self.template.badge}] {self.template.title}", markup=False)


class CyberLLMApp(App[None]):
    """Interface TUI estilo hacker para o modelo CyberLLM 32B via vLLM."""

    TITLE = "CYBERLLM 32B // TERMINAL OPS"
    CSS_PATH = "theme.tcss"

    BINDINGS = [
        Binding("f1", "switch_tab('tab-chat')", "F1 Chat", show=True, priority=True),
        Binding("f2", "switch_tab('tab-sast')", "F2 SAST", show=True, priority=True),
        Binding("f3", "switch_tab('tab-validator')", "F3 Compilar", show=True, priority=True),
        Binding("f4", "switch_tab('tab-templates')", "F4 Templates", show=True, priority=True),
        Binding("f5", "switch_tab('tab-config')", "F5 vLLM", show=True, priority=True),
        Binding("ctrl+n", "new_session", "Nova Sessão", show=True, priority=True),
        Binding("ctrl+t", "toggle_all_thinking", "Toggle <think>", show=True, priority=True),
        Binding("ctrl+e", "toggle_code_drawer", "Anexar Código", show=False, priority=True),
        Binding("ctrl+b", "toggle_sidebar", "Sidebar", show=False, priority=True),
        Binding("ctrl+x", "export_session", "Exportar .md", show=True, priority=True),
        Binding("escape", "stop_stream", "Parar Stream", show=False),
        Binding("ctrl+q", "quit", "Sair", show=True, priority=True),
    ]

    def __init__(
        self,
        config: Optional[CyberLLMConfig] = None,
        store: Optional[SessionStore] = None,
        client: Optional[VLLMClient] = None,
    ) -> None:
        super().__init__()
        self.config_data: CyberLLMConfig = (config or load_config()).normalized()
        self.store: SessionStore = store or SessionStore()
        self.vllm: VLLMClient = client or VLLMClient()
        self.toolchains: Dict[str, ToolchainInfo] = detect_installed_toolchains()

        self.active_session_id: str = ""
        self._cancel_event: asyncio.Event = asyncio.Event()
        self._is_streaming: bool = False
        self._last_sast_patch: str = ""
        self._selected_template: CyberTemplate = CYBER_TEMPLATES[0]

    def compose(self) -> ComposeResult:
        # Barra superior de telemetria
        with Horizontal(id="top-status-bar"):
            yield Label("🛡️ CYBERLLM // 32B OPS", id="brand-title")
            yield Label(
                f"◌ VERIFICANDO vLLM · {self.config_data.model} @ {self.config_data.api_base}",
                id="vllm-status-pill",
            )
            yield Label(
                f"TTFT: -- ms │ TPS: -- tok/s │ TEMP: {self.config_data.temperature}",
                id="telemetry-readout",
            )

        with Horizontal(id="main-shell"):
            # Barra lateral: Histórico SQLite + Compiladores Locais
            with Vertical(id="sidebar"):
                yield Label("🗂️ OPERAÇÕES (HISTÓRICO)", classes="sidebar-heading")
                with Horizontal(id="session-actions-row"):
                    yield Button("+ Nova", id="btn-new-session", classes="btn-matrix")
                    yield Button("Export", id="btn-export-session", classes="btn-cyan")
                    yield Button("Del", id="btn-delete-session", classes="btn-danger")
                yield ListView(id="session-list")

                yield Label("🔧 COMPILADORES LOCAIS", classes="sidebar-heading")
                yield Static(self._format_toolchains_summary(), id="toolchain-box")

            # Área central com 5 abas especializadas
            with TabbedContent(initial="tab-chat", id="workspace-tabs"):
                # [F1] CHAT SSE + <think>
                with TabPane("💬 F1 · Chat & CoT", id="tab-chat"):
                    with VerticalScroll(id="chat-scroll"):
                        yield Markdown(WELCOME_BANNER_MD, id="chat-welcome-banner")

                    with Vertical(id="chat-code-drawer", classes="hidden"):
                        yield Label(
                            "📎 BLOCO DE CÓDIGO ANEXADO (será enviado junto ao prompt — Ctrl+E para ocultar)",
                            id="chat-code-drawer-header",
                        )
                        yield TextArea(
                            "",
                            id="chat-attached-editor",
                            show_line_numbers=True,
                            tab_behavior="indent",
                        )

                    with Horizontal(id="chat-composer-bar"):
                        yield SmartPromptInput(
                            placeholder="Digite sua instrução técnica ou pergunta (Enter envia | Cole código multi-linha direto aqui)...",
                            id="chat-prompt-input",
                        )
                        yield Button("📎 Código", id="btn-toggle-drawer", classes="btn-cyan")
                        yield Button("▶ ENVIAR", id="btn-send-chat", classes="btn-matrix")
                        yield Button("⏹ PARAR", id="btn-stop-chat", classes="btn-danger")

                    yield Label(
                        "Enter: Enviar │ ↑/↓: Histórico de Comandos │ Ctrl+E: Anexar Código │ Ctrl+T: Recolher/Expandir <think> │ Esc: Abortar Geração",
                        id="chat-hint-line",
                    )

                # [F2] BANCADA DE AUDITORIA SAST
                with TabPane("🛡️ F2 · Bancada SAST", id="tab-sast"):
                    with Horizontal(id="sast-toolbar"):
                        yield Input(
                            placeholder="Caminho do arquivo local (ex: ./alvo.c)...",
                            id="sast-filepath-input",
                        )
                        yield Button("📥 Ler", id="btn-sast-load-path")
                        yield Button("📂 Árvore", id="btn-sast-browse", classes="btn-cyan")
                        yield Select(
                            [
                                ("C (gcc)", "c"),
                                ("C++17 (g++)", "cpp"),
                                ("Rust (rustc)", "rust"),
                                ("Python 3", "python"),
                                ("Golang", "go"),
                                ("Assembly", "asm"),
                            ],
                            value="c",
                            allow_blank=False,
                            id="sast-lang-select",
                        )
                        yield Select(
                            [
                                ("Lab 1: C Stack + CmdInj", "c_stack_cmd"),
                                ("Lab 2: C Heap UAF + IntOvf", "c_heap_uaf"),
                                ("Lab 3: Python SQLi + Pickle", "py_sqli_deser"),
                                ("Lab 4: Rust Unsafe FFI", "rust_unsafe_ffi"),
                            ],
                            value="c_stack_cmd",
                            allow_blank=False,
                            id="sast-sample-select",
                        )

                    with Horizontal(id="sast-split"):
                        with Vertical(id="sast-left-pane"):
                            yield Label("📄 CÓDIGO-FONTE SOB AUDITORIA", classes="section-title")
                            yield TextArea(
                                SAMPLE_VULNERABLE_TARGETS["c_stack_cmd"][2],
                                id="sast-code-editor",
                                show_line_numbers=True,
                                tab_behavior="indent",
                            )
                            with Horizontal(id="sast-action-bar"):
                                yield Button(
                                    "⚡ Triagem CWE Local",
                                    id="btn-sast-triage",
                                    classes="btn-amber",
                                )
                                yield Button(
                                    "🔬 Auditoria vLLM + Patch",
                                    id="btn-sast-deep",
                                    classes="btn-matrix",
                                )
                                yield Button(
                                    "🧪 Compilar Alvo",
                                    id="btn-sast-compile",
                                    classes="btn-cyan",
                                )

                        with Vertical(id="sast-right-pane"):
                            with TabbedContent(
                                initial="sast-subtab-report", id="sast-results-tabs"
                            ):
                                with TabPane(
                                    "📋 Relatório & CWEs", id="sast-subtab-report"
                                ):
                                    with VerticalScroll(id="sast-report-scroll"):
                                        with Collapsible(
                                            title="🧠 <think> Raciocínio Investigativo SAST",
                                            collapsed=False,
                                            id="sast-cot-box",
                                            classes="cot-collapsible hidden",
                                        ):
                                            yield Static(
                                                "",
                                                id="sast-cot-body",
                                                classes="cot-body",
                                                markup=False,
                                            )
                                        yield Markdown(
                                            "Clique em **⚡ Triagem CWE Local** para detecção estática instantânea "
                                            "ou **🔬 Auditoria vLLM + Patch** para análise completa pelo CyberLLM 32B.",
                                            id="sast-report-md",
                                        )

                                with TabPane(
                                    "🔀 Diff & Patch Defensivo", id="sast-subtab-diff"
                                ):
                                    yield Static(
                                        "Nenhum patch defensivo gerado ainda.",
                                        id="sast-patch-status-bar",
                                    )
                                    with Horizontal():
                                        yield Button(
                                            "✅ Aplicar Patch no Editor",
                                            id="btn-sast-apply-patch",
                                            classes="btn-cyan",
                                        )
                                        yield Button(
                                            "💾 Salvar Patch em Disco",
                                            id="btn-sast-save-patch",
                                            classes="btn-matrix",
                                        )
                                    yield RichLog(
                                        id="sast-diff-log",
                                        wrap=True,
                                        highlight=False,
                                        markup=False,
                                    )

                # [F3] COMPILADORES & VALIDADOR SINTÁTICO
                with TabPane("🧪 F3 · Compiladores", id="tab-validator"):
                    with Horizontal(id="validator-split"):
                        with Vertical(id="validator-left"):
                            yield Label(
                                "💻 EDITOR DE VALIDAÇÃO SINTÁTICA (src/validators.py)",
                                classes="section-title",
                            )
                            with Horizontal(id="validator-toolbar"):
                                yield Select(
                                    [
                                        ("C (gcc)", "c"),
                                        ("C++17 (g++)", "cpp"),
                                        ("Python 3 (py_compile)", "python"),
                                        ("Rust (rustc)", "rust"),
                                        ("Regra YARA (.yar)", "yara"),
                                        ("Semgrep / Sigma (YAML)", "yaml"),
                                    ],
                                    value="c",
                                    allow_blank=False,
                                    id="validator-lang-select",
                                )
                                yield Button(
                                    "▶ Validar Sintaxe",
                                    id="btn-val-standard",
                                    classes="btn-matrix",
                                )
                                yield Button(
                                    "🔒 Estrito (-Wall -Wextra)",
                                    id="btn-val-strict",
                                    classes="btn-amber",
                                )
                            yield TextArea(
                                DEFAULT_VALIDATOR_SAMPLE,
                                id="validator-code-editor",
                                show_line_numbers=True,
                                tab_behavior="indent",
                            )

                        with Vertical(id="validator-right"):
                            yield Label(
                                "📟 SAÍDA DO COMPILADOR & DIAGNÓSTICOS",
                                classes="section-subtitle",
                            )
                            yield RichLog(
                                id="validator-output-log",
                                wrap=True,
                                highlight=False,
                                markup=True,
                            )

                # [F4] TEMPLATES RÁPIDOS DE CIBERSEGURANÇA
                with TabPane("⚡ F4 · Templates Cyber", id="tab-templates"):
                    with Horizontal(id="templates-split"):
                        with Vertical(id="templates-list-pane"):
                            yield Label(
                                "🎯 CATÁLOGO DE ENGENHARIA & AUDITORIA",
                                classes="section-title",
                            )
                            yield ListView(
                                *[TemplateListItem(t) for t in CYBER_TEMPLATES],
                                id="templates-list",
                            )

                        with Vertical(id="templates-detail-pane"):
                            yield Label(
                                CYBER_TEMPLATES[0].title,
                                id="tpl-detail-title",
                                classes="section-title",
                            )
                            yield Label(
                                f"Categoria: {CYBER_TEMPLATES[0].category}  │  Tag: {CYBER_TEMPLATES[0].badge}",
                                id="tpl-detail-meta",
                                classes="section-subtitle",
                            )
                            yield Static(
                                CYBER_TEMPLATES[0].description,
                                id="tpl-detail-desc",
                            )
                            yield Label(
                                "Parâmetro / Alvo Específico da Operação:",
                                classes="field-label",
                            )
                            yield Input(
                                value=CYBER_TEMPLATES[0].default_target,
                                placeholder=CYBER_TEMPLATES[0].target_placeholder,
                                id="template-target-input",
                            )
                            yield Label(
                                "Pré-visualização Editável do Prompt:",
                                classes="field-label",
                            )
                            yield TextArea(
                                CYBER_TEMPLATES[0].render(),
                                id="template-preview-editor",
                                soft_wrap=True,
                            )
                            with Horizontal():
                                yield Button(
                                    "🚀 Executar Direto no Chat (F1)",
                                    id="btn-tpl-execute",
                                    classes="btn-matrix",
                                )
                                yield Button(
                                    "✏️ Preparar no Campo do Chat",
                                    id="btn-tpl-stage",
                                    classes="btn-cyan",
                                )

                # [F5] SERVIDOR vLLM & CONFIGURAÇÃO
                with TabPane("⚙️ F5 · Servidor vLLM", id="tab-config"):
                    with VerticalScroll(id="config-scroll"):
                        yield Label(
                            "🔌 CONEXÃO COM SERVIDOR vLLM (API OPENAI-COMPATÍVEL)",
                            classes="section-title",
                        )
                        with Horizontal(classes="config-grid"):
                            with Vertical(classes="config-field"):
                                yield Label(
                                    "URL Base da API vLLM (/v1):", classes="field-label"
                                )
                                yield Input(
                                    value=self.config_data.api_base,
                                    placeholder="http://localhost:8000/v1 ou http://IP_DA_VM:8000/v1",
                                    id="cfg-api-base",
                                )
                            with Vertical(classes="config-field"):
                                yield Label(
                                    "Model ID (--served-model-name):",
                                    classes="field-label",
                                )
                                yield Input(
                                    value=self.config_data.model,
                                    placeholder="qwen32b-cyber",
                                    id="cfg-model",
                                )
                            with Vertical(classes="config-field"):
                                yield Label(
                                    "API Key (padrão vLLM: EMPTY):",
                                    classes="field-label",
                                )
                                yield Input(
                                    value=self.config_data.api_key,
                                    placeholder="EMPTY",
                                    id="cfg-api-key",
                                )
                            with Vertical(classes="config-field"):
                                yield Label(
                                    "Temperatura (0.0 a 2.0 — recomendado 0.1):",
                                    classes="field-label",
                                )
                                yield Input(
                                    value=str(self.config_data.temperature),
                                    id="cfg-temperature",
                                )
                            with Vertical(classes="config-field"):
                                yield Label(
                                    "Top-P (0.01 a 1.0):", classes="field-label"
                                )
                                yield Input(
                                    value=str(self.config_data.top_p),
                                    id="cfg-top-p",
                                )
                            with Vertical(classes="config-field"):
                                yield Label(
                                    "Max Tokens de Resposta (até 16384):",
                                    classes="field-label",
                                )
                                yield Input(
                                    value=str(self.config_data.max_tokens),
                                    id="cfg-max-tokens",
                                )

                        yield Checkbox(
                            "Recolher automaticamente o bloco <think> assim que a resposta final terminar",
                            value=self.config_data.auto_collapse_think,
                            id="cfg-auto-collapse",
                        )

                        yield Label(
                            "Preset de System Prompt Especializado:",
                            classes="field-label",
                        )
                        yield Select(
                            [( title, key ) for key, (title, _) in SYSTEM_PROMPT_PRESETS.items()],
                            value="cyber_full",
                            allow_blank=False,
                            id="cfg-preset-select",
                        )
                        yield Label("System Prompt Ativo:", classes="field-label")
                        yield TextArea(
                            self.config_data.system_prompt,
                            id="cfg-system-prompt",
                            soft_wrap=True,
                        )

                        with Horizontal(id="config-actions-row"):
                            yield Button(
                                "🔌 Testar Conexão & Detectar Modelos (/v1/models)",
                                id="btn-cfg-probe",
                                classes="btn-cyan",
                            )
                            yield Button(
                                "💾 Salvar Configuração",
                                id="btn-cfg-save",
                                classes="btn-matrix",
                            )

                        yield Static("", id="cfg-probe-result")
                        yield Markdown(VLLM_QUICK_GUIDE_MD, id="vllm-guide-box")

        yield Footer()

    async def on_mount(self) -> None:
        # Configura syntax highlighting Tree-Sitter nos editores
        configure_code_editor(self.query_one("#chat-attached-editor", TextArea), "c")
        configure_code_editor(self.query_one("#sast-code-editor", TextArea), "c")
        configure_code_editor(self.query_one("#validator-code-editor", TextArea), "c")
        configure_code_editor(
            self.query_one("#template-preview-editor", TextArea), "markdown"
        )

        self.query_one("#sast-filepath-input", Input).value = SAMPLE_VULNERABLE_TARGETS[
            "c_stack_cmd"
        ][0]

        # Inicializa histórico de sessões SQLite
        sessions = self.store.list_sessions()
        if not sessions:
            created = self.store.create_session(
                title="Nova Operação",
                model=self.config_data.model,
                system_prompt=self.config_data.system_prompt,
            )
            self.active_session_id = created["id"]
        else:
            self.active_session_id = sessions[0]["id"]

        await self._refresh_session_list()
        await self._load_session_into_chat(self.active_session_id)

        # Exibe estado inicial dos compiladores na aba F3
        self._render_validator_welcome()

        # Dispara verificação inicial de saúde do vLLM em background e agenda ping periódico
        self.probe_vllm_server(notify_user=False)
        self.set_interval(20.0, lambda: self.probe_vllm_server(notify_user=False))

        self.query_one("#chat-prompt-input", SmartPromptInput).focus()

    # =========================================================================
    # UTILITÁRIOS DE TELEMETRIA E SESSÕES
    # =========================================================================

    def _format_toolchains_summary(self) -> str:
        lines = []
        for key in ("gcc", "g++", "python3", "rustc", "yara"):
            info = self.toolchains.get(key)
            if info and info.available:
                lines.append(f"✔ {key.upper():<7} ATIVO")
            else:
                lines.append(f"○ {key.upper():<7} ausente")
        return "\n".join(lines)

    def _render_validator_welcome(self) -> None:
        log = self.query_one("#validator-output-log", RichLog)
        table = Table(title="Toolchains Detectadas no Host", expand=True)
        table.add_column("Ferramenta", style="bold cyan")
        table.add_column("Status", style="bold")
        table.add_column("Versão / Binário", style="dim")
        for key, info in self.toolchains.items():
            st = "[bright_green]✔ DISPONÍVEL[/]" if info.available else "[yellow]○ Fallback Léxico[/]"
            table.add_row(key, st, info.version or "Não instalado no PATH")
        log.clear()
        log.write(table)

    def _update_status_bar_health(self, status: HealthStatus) -> None:
        pill = self.query_one("#vllm-status-pill", Label)
        pill.remove_class("online", "offline")
        if status.online:
            pill.add_class("online")
            model_note = self.config_data.model
            if status.models and not status.configured_model_present:
                model_note = f"{self.config_data.model} (servidor expõe: {status.models[0]})"
            pill.update(
                f"● vLLM ONLINE ({status.latency_ms:.0f}ms) · {model_note} @ {status.api_base}"
            )
        else:
            pill.add_class("offline")
            pill.update(
                f"○ vLLM OFFLINE · {self.config_data.model} @ {status.api_base}"
            )

    def _update_telemetry_readout(
        self, ttft_ms: float = 0.0, tps: float = 0.0, tokens: int = 0
    ) -> None:
        lbl = self.query_one("#telemetry-readout", Label)
        ttft_str = f"{ttft_ms:.0f}ms" if ttft_ms > 0 else "-- ms"
        tps_str = f"{tps:.1f} tok/s" if tps > 0 else "-- tok/s"
        lbl.update(
            f"TTFT: {ttft_str} │ TPS: {tps_str} │ TOK: {tokens} │ T={self.config_data.temperature}"
        )

    @work(exclusive=False)
    async def probe_vllm_server(self, notify_user: bool = False) -> None:
        status = await self.vllm.check_health(self.config_data)
        self._update_status_bar_health(status)

        probe_lbl = self.query_one("#cfg-probe-result", Static)
        if status.online:
            models_str = ", ".join(status.models) if status.models else "(nenhum listado)"
            probe_lbl.update(
                f"✔ Conectado a {status.api_base} em {status.latency_ms:.1f} ms. "
                f"Modelos servidos: {models_str}"
            )
            if status.models and not status.configured_model_present and notify_user:
                # Auto-sugere/atualiza o campo caso o usuário tenha apenas 1 modelo servido no vLLM
                self.notify(
                    f"vLLM online! Modelo configurado '{self.config_data.model}' difere de '{status.models[0]}'.",
                    severity="warning",
                )
            elif notify_user:
                self.notify(
                    f"vLLM ONLINE ({status.latency_ms:.0f} ms) — Modelos: {models_str}",
                    severity="information",
                )
        else:
            probe_lbl.update(
                f"✖ Servidor vLLM inacessível em {status.api_base}: {status.error}"
            )
            if notify_user:
                self.notify(
                    f"Servidor vLLM offline em {status.api_base}",
                    severity="error",
                )

    async def _refresh_session_list(self) -> None:
        lv = self.query_one("#session-list", ListView)
        await lv.clear()
        sessions = self.store.list_sessions()
        active_idx = 0
        for idx, sess in enumerate(sessions):
            lv.append(SessionListItem(sess))
            if sess["id"] == self.active_session_id:
                active_idx = idx
        if sessions:
            lv.index = active_idx

    async def _load_session_into_chat(self, session_id: str) -> None:
        self.active_session_id = session_id
        scroll = self.query_one("#chat-scroll", VerticalScroll)
        for card in list(scroll.query(ChatMessageCard)):
            await card.remove()

        messages = self.store.get_messages(session_id)
        for msg in messages:
            ts = ""
            created = msg.get("created_at", "")
            if "T" in created:
                ts = created.split("T", 1)[1][:8]
            telemetry = ""
            if msg["role"] == "assistant" and (msg.get("tokens_est") or msg.get("tps")):
                telemetry = (
                    f"~{msg['tokens_est']} tok · {msg['tps']:.1f} tok/s · "
                    f"TTFT {msg['latency_ms']:.0f}ms"
                )
            card = ChatMessageCard(
                role=msg["role"],
                content=msg["content"],
                thinking=msg.get("thinking", ""),
                model_label=self.config_data.model,
                timestamp=ts,
                collapse_think=self.config_data.auto_collapse_think,
                telemetry_note=telemetry,
            )
            await scroll.mount(card)

        scroll.scroll_end(animate=False)

    # =========================================================================
    # AÇÕES E ATALHOS GLOBAIS
    # =========================================================================

    def action_switch_tab(self, tab_id: str) -> None:
        tabs = self.query_one("#workspace-tabs", TabbedContent)
        tabs.active = tab_id
        focus_targets = {
            "tab-chat": "#chat-prompt-input",
            "tab-sast": "#sast-code-editor",
            "tab-validator": "#validator-code-editor",
            "tab-templates": "#templates-list",
            "tab-config": "#cfg-api-base",
        }
        target_sel = focus_targets.get(tab_id)
        if target_sel:
            self.call_after_refresh(lambda: self.query_one(target_sel).focus())

    def action_toggle_sidebar(self) -> None:
        sidebar = self.query_one("#sidebar", Vertical)
        sidebar.toggle_class("hidden")

    def action_toggle_code_drawer(self) -> None:
        drawer = self.query_one("#chat-code-drawer", Vertical)
        drawer.toggle_class("hidden")
        if not drawer.has_class("hidden"):
            self.query_one("#chat-attached-editor", TextArea).focus()
        else:
            self.query_one("#chat-prompt-input", SmartPromptInput).focus()

    def action_toggle_all_thinking(self) -> None:
        cards = list(self.query(ChatMessageCard))
        toggled = 0
        for card in cards:
            if card.role == "assistant":
                card.toggle_thinking()
                toggled += 1
        # Também alterna na Bancada SAST se estiver visível
        sast_cot = self.query_one("#sast-cot-box", Collapsible)
        if not sast_cot.has_class("hidden"):
            sast_cot.collapsed = not sast_cot.collapsed
            toggled += 1
        if toggled == 0:
            self.notify("Nenhum bloco <think> presente na conversa atual.")

    async def action_new_session(self) -> None:
        if self._is_streaming:
            self.notify("Aguarde ou interrompa (Esc) o stream atual primeiro.", severity="warning")
            return
        created = self.store.create_session(
            title="Nova Operação",
            model=self.config_data.model,
            system_prompt=self.config_data.system_prompt,
        )
        self.active_session_id = created["id"]
        await self._refresh_session_list()
        await self._load_session_into_chat(self.active_session_id)
        self.action_switch_tab("tab-chat")
        self.notify("Nova sessão operacional iniciada.")

    def action_export_session(self) -> None:
        if not self.active_session_id:
            return
        try:
            out_path = self.store.export_session_markdown(self.active_session_id)
            self.notify(f"Relatório Markdown exportado: {out_path}")
        except Exception as exc:
            self.notify(f"Falha ao exportar sessão: {exc}", severity="error")

    def action_stop_stream(self) -> None:
        if self._is_streaming:
            self._cancel_event.set()
            self.notify("Sinal de interrupção enviado ao stream SSE.", severity="warning")

    # =========================================================================
    # EVENTOS DA BARRA LATERAL (HISTÓRICO DE SESSÕES)
    # =========================================================================

    @on(Button.Pressed, "#btn-new-session")
    async def _on_btn_new_sess(self) -> None:
        await self.action_new_session()

    @on(Button.Pressed, "#btn-export-session")
    def _on_btn_export_sess(self) -> None:
        self.action_export_session()

    @on(Button.Pressed, "#btn-delete-session")
    async def _on_btn_delete_sess(self) -> None:
        if self._is_streaming:
            self.notify("Interrompa o stream ativo antes de excluir a sessão.", severity="warning")
            return
        if self.active_session_id:
            self.store.delete_session(self.active_session_id)
        remaining = self.store.list_sessions()
        if not remaining:
            created = self.store.create_session(
                title="Nova Operação",
                model=self.config_data.model,
                system_prompt=self.config_data.system_prompt,
            )
            self.active_session_id = created["id"]
        else:
            self.active_session_id = remaining[0]["id"]
        await self._refresh_session_list()
        await self._load_session_into_chat(self.active_session_id)
        self.notify("Sessão removida do histórico local.")

    @on(ListView.Selected, "#session-list")
    async def _on_session_selected(self, event: ListView.Selected) -> None:
        if self._is_streaming:
            return
        item = event.item
        if isinstance(item, SessionListItem) and item.session_id != self.active_session_id:
            await self._load_session_into_chat(item.session_id)

    # =========================================================================
    # [F1] CHAT COM STREAMING SSE & <think> RECOLHÍVEL
    # =========================================================================

    @on(SmartPromptInput.MultiLinePasted)
    def _on_multiline_code_pasted(self, event: SmartPromptInput.MultiLinePasted) -> None:
        drawer = self.query_one("#chat-code-drawer", Vertical)
        editor = self.query_one("#chat-attached-editor", TextArea)
        drawer.remove_class("hidden")
        existing = editor.text.strip()
        editor.text = f"{existing}\n\n{event.text}".strip() if existing else event.text
        lang = detect_language(code=editor.text)
        set_editor_language(editor, lang)
        self.notify(
            f"Código multi-linha ({len(event.text.splitlines())} linhas) anexado! Digite sua instrução e pressione Enter."
        )
        self.query_one("#chat-prompt-input", SmartPromptInput).focus()

    @on(Button.Pressed, "#btn-toggle-drawer")
    def _on_btn_toggle_drawer(self) -> None:
        self.action_toggle_code_drawer()

    @on(Button.Pressed, "#btn-stop-chat")
    def _on_btn_stop_chat(self) -> None:
        self.action_stop_stream()

    @on(Input.Submitted, "#chat-prompt-input")
    async def _on_prompt_enter(self, event: Input.Submitted) -> None:
        await self._submit_chat_from_composer()

    @on(Button.Pressed, "#btn-send-chat")
    async def _on_btn_send_chat(self) -> None:
        await self._submit_chat_from_composer()

    async def _submit_chat_from_composer(self) -> None:
        if self._is_streaming:
            self.notify("Uma geração já está em curso (pressione Esc para parar).", severity="warning")
            return

        prompt_input = self.query_one("#chat-prompt-input", SmartPromptInput)
        attached_editor = self.query_one("#chat-attached-editor", TextArea)
        drawer = self.query_one("#chat-code-drawer", Vertical)

        question = prompt_input.value.strip()
        attached_code = attached_editor.text.strip() if not drawer.has_class("hidden") else ""

        if not question and not attached_code:
            return

        if question:
            prompt_input.record_history(question)

        if attached_code:
            lang = detect_language(code=attached_code)
            header = question or "Realize uma auditoria técnica completa do código abaixo:"
            full_user_text = f"{header}\n\n```{lang}\n{attached_code}\n```"
        else:
            full_user_text = question

        prompt_input.value = ""
        attached_editor.text = ""
        drawer.add_class("hidden")

        await self.dispatch_chat_message(full_user_text)

    async def dispatch_chat_message(self, user_text: str) -> None:
        """Persiste a mensagem do operador, monta cartões e inicia worker SSE vLLM."""
        self.store.add_message(self.active_session_id, "user", user_text)
        await self._refresh_session_list()

        scroll = self.query_one("#chat-scroll", VerticalScroll)
        user_card = ChatMessageCard(role="user", content=user_text)
        await scroll.mount(user_card)

        assistant_card = ChatMessageCard(
            role="assistant",
            model_label=self.config_data.model,
            collapse_think=False,
        )
        await scroll.mount(assistant_card)
        assistant_card.start_streaming()
        scroll.scroll_end(animate=False)

        # Constrói histórico completo ChatML para enviar ao vLLM
        stored_msgs = self.store.get_messages(self.active_session_id)
        api_messages: List[Dict[str, str]] = [
            {"role": "system", "content": self.config_data.system_prompt}
        ]
        for m in stored_msgs:
            if m["role"] in ("user", "assistant"):
                api_messages.append({"role": m["role"], "content": m["content"]})

        self._stream_chat_worker(api_messages, assistant_card)

    @work(exclusive=True)
    async def _stream_chat_worker(
        self, api_messages: List[Dict[str, str]], card: ChatMessageCard
    ) -> None:
        self._is_streaming = True
        self._cancel_event.clear()
        scroll = self.query_one("#chat-scroll", VerticalScroll)

        acc_thinking = ""
        acc_content = ""
        last_ttft = 0.0
        last_tps = 0.0
        last_tokens = 0
        was_cancelled = False
        err_text = ""

        try:
            async for chunk in self.vllm.stream_chat(
                api_messages, self.config_data, cancel_event=self._cancel_event
            ):
                if chunk.error:
                    err_text = chunk.error
                    break

                if chunk.thinking_delta or chunk.content_delta:
                    acc_thinking += chunk.thinking_delta
                    acc_content += chunk.content_delta
                    await card.append_stream_delta(
                        thinking_delta=chunk.thinking_delta,
                        content_delta=chunk.content_delta,
                        in_thinking=chunk.in_thinking,
                    )
                    scroll.scroll_end(animate=False)

                if chunk.ttft_ms > 0:
                    last_ttft = chunk.ttft_ms
                if chunk.tps > 0:
                    last_tps = chunk.tps
                if chunk.tokens_est > 0:
                    last_tokens = chunk.tokens_est

                self._update_telemetry_readout(last_ttft, last_tps, last_tokens)

                if chunk.cancelled:
                    was_cancelled = True
                    break

            await card.finalize_stream(
                ttft_ms=last_ttft,
                tps=last_tps,
                tokens_est=last_tokens,
                auto_collapse_think=self.config_data.auto_collapse_think,
                cancelled=was_cancelled,
                error_markdown=err_text,
            )
            scroll.scroll_end(animate=False)

            saved_content = acc_content.strip()
            if saved_content or acc_thinking.strip():
                self.store.add_message(
                    self.active_session_id,
                    "assistant",
                    saved_content or "_[Sem resposta final após raciocínio]_",
                    thinking=acc_thinking.strip(),
                    tokens_est=last_tokens,
                    latency_ms=last_ttft,
                    tps=last_tps,
                )
                await self._refresh_session_list()
        finally:
            self._is_streaming = False

    @on(ChatMessageCard.CodeActionRequested)
    def _on_card_code_action(self, event: ChatMessageCard.CodeActionRequested) -> None:
        block = event.block
        lang = block.normalized_lang

        if event.action == "validate":
            val_editor = self.query_one("#validator-code-editor", TextArea)
            val_select = self.query_one("#validator-lang-select", Select)
            supported = {"c", "cpp", "python", "rust", "yara", "yaml"}
            chosen_lang = lang if lang in supported else "c"
            val_select.value = chosen_lang
            set_editor_language(val_editor, chosen_lang)
            val_editor.text = block.code
            self.action_switch_tab("tab-validator")
            self._execute_compiler_check(strict=True)

        elif event.action == "sast":
            sast_editor = self.query_one("#sast-code-editor", TextArea)
            sast_select = self.query_one("#sast-lang-select", Select)
            supported = {"c", "cpp", "rust", "python", "go", "asm"}
            chosen_lang = lang if lang in supported else "c"
            sast_select.value = chosen_lang
            set_editor_language(sast_editor, chosen_lang)
            sast_editor.text = block.code
            self.action_switch_tab("tab-sast")
            self._run_sast_local_triage()

        elif event.action == "save":
            ext_map = {
                "c": ".c",
                "cpp": ".cpp",
                "rust": ".rs",
                "python": ".py",
                "yara": ".yar",
                "yaml": ".yaml",
                "asm": ".s",
                "sql": ".sql",
                "bash": ".sh",
            }
            ext = ext_map.get(lang, ".txt")
            out_dir = get_data_dir() / "exports"
            out_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_file = out_dir / f"snippet_{stamp}_{block.index}{ext}"
            out_file.write_text(block.code + "\n", encoding="utf-8")
            self.notify(f"Bloco de código salvo em: {out_file}")

    # =========================================================================
    # [F2] BANCADA DE AUDITORIA SAST
    # =========================================================================

    @on(Select.Changed, "#sast-lang-select")
    def _on_sast_lang_changed(self, event: Select.Changed) -> None:
        if isinstance(event.value, str):
            set_editor_language(self.query_one("#sast-code-editor", TextArea), event.value)

    @on(Select.Changed, "#sast-sample-select")
    def _on_sast_sample_changed(self, event: Select.Changed) -> None:
        key = str(event.value)
        if key in SAMPLE_VULNERABLE_TARGETS:
            fname, lang, code = SAMPLE_VULNERABLE_TARGETS[key]
            self.query_one("#sast-filepath-input", Input).value = fname
            self.query_one("#sast-lang-select", Select).value = lang
            editor = self.query_one("#sast-code-editor", TextArea)
            set_editor_language(editor, lang)
            editor.text = code

    @on(Button.Pressed, "#btn-sast-load-path")
    @on(Input.Submitted, "#sast-filepath-input")
    def _on_sast_load_typed_path(self) -> None:
        raw_path = self.query_one("#sast-filepath-input", Input).value.strip()
        if not raw_path:
            self.notify("Informe um caminho de arquivo ou use 📂 Árvore.", severity="warning")
            return
        self._load_file_into_sast(raw_path)

    @on(Button.Pressed, "#btn-sast-browse")
    def _on_sast_open_picker(self) -> None:
        def _after_pick(chosen_path: Optional[str]) -> None:
            if chosen_path:
                self._load_file_into_sast(chosen_path)

        self.push_screen(FilePickerModal("."), _after_pick)

    def _load_file_into_sast(self, filepath: str) -> None:
        p = Path(filepath).expanduser()
        if not p.exists() or not p.is_file():
            self.notify(f"Arquivo não encontrado: {p}", severity="error")
            return
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            self.notify(f"Erro ao ler arquivo: {exc}", severity="error")
            return

        lang = detect_language(filename=p.name, code=content)
        self.query_one("#sast-filepath-input", Input).value = str(p)
        lang_sel = self.query_one("#sast-lang-select", Select)
        if lang in ("c", "cpp", "rust", "python", "go", "asm"):
            lang_sel.value = lang
        editor = self.query_one("#sast-code-editor", TextArea)
        set_editor_language(editor, lang)
        editor.text = content
        self.notify(f"Carregado: {p.name} ({len(content.splitlines())} linhas, {lang.upper()})")
        self._run_sast_local_triage()

    @on(Button.Pressed, "#btn-sast-triage")
    def _on_btn_sast_triage(self) -> None:
        self._run_sast_local_triage()

    def _run_sast_local_triage(self) -> None:
        code = self.query_one("#sast-code-editor", TextArea).text
        lang = str(self.query_one("#sast-lang-select", Select).value or "c")
        fname = Path(
            self.query_one("#sast-filepath-input", Input).value.strip() or f"alvo.{lang}"
        ).name
        findings = run_local_cwe_triage(code, lang)
        md_text = format_triage_markdown(findings, fname)

        self.query_one("#sast-cot-box", Collapsible).add_class("hidden")
        self.query_one("#sast-report-md", Markdown).update(md_text)
        self.query_one("#sast-results-tabs", TabbedContent).active = "sast-subtab-report"
        self.notify(f"Triagem estática concluída: {len(findings)} alerta(s) CWE.")

    @on(Button.Pressed, "#btn-sast-compile")
    def _on_btn_sast_compile(self) -> None:
        code = self.query_one("#sast-code-editor", TextArea).text
        lang = str(self.query_one("#sast-lang-select", Select).value or "c")
        val_editor = self.query_one("#validator-code-editor", TextArea)
        val_sel = self.query_one("#validator-lang-select", Select)
        target_lang = lang if lang in ("c", "cpp", "python", "rust") else "c"
        val_sel.value = target_lang
        set_editor_language(val_editor, target_lang)
        val_editor.text = code
        self.action_switch_tab("tab-validator")
        self._execute_compiler_check(strict=True)

    @on(Button.Pressed, "#btn-sast-deep")
    def _on_btn_sast_deep(self) -> None:
        if self._is_streaming:
            self.notify("Já existe uma inferência em andamento (Esc para parar).", severity="warning")
            return
        code = self.query_one("#sast-code-editor", TextArea).text.strip()
        if not code:
            self.notify("Insira ou carregue um código-fonte para auditar.", severity="warning")
            return
        lang = str(self.query_one("#sast-lang-select", Select).value or "c")
        fname = Path(
            self.query_one("#sast-filepath-input", Input).value.strip() or f"target.{lang}"
        ).name
        self._run_deep_sast_worker(code, lang, fname)

    @work(exclusive=True)
    async def _run_deep_sast_worker(
        self, original_code: str, lang: str, filename: str
    ) -> None:
        self._is_streaming = True
        self._cancel_event.clear()

        findings = run_local_cwe_triage(original_code, lang)
        triage_header = format_triage_markdown(findings, filename)

        report_md = self.query_one("#sast-report-md", Markdown)
        cot_box = self.query_one("#sast-cot-box", Collapsible)
        cot_body = self.query_one("#sast-cot-body", Static)
        report_scroll = self.query_one("#sast-report-scroll", VerticalScroll)
        results_tabs = self.query_one("#sast-results-tabs", TabbedContent)
        results_tabs.active = "sast-subtab-report"

        cot_box.add_class("hidden")
        cot_box.collapsed = False
        cot_body.update("")
        await report_md.update(
            f"{triage_header}\n\n---\n### 🔬 Auditoria Profunda CyberLLM 32B em andamento...\n"
        )

        sast_sys_prompt = SYSTEM_PROMPT_PRESETS["sast_compiler"][1]
        messages = build_sast_audit_messages(
            original_code, lang, filename, findings, sast_sys_prompt
        )

        acc_thinking = ""
        acc_content = ""
        ttft = 0.0
        tps = 0.0
        tokens = 0
        err_text = ""

        try:
            async for chunk in self.vllm.stream_chat(
                messages, self.config_data, cancel_event=self._cancel_event
            ):
                if chunk.error:
                    err_text = chunk.error
                    break

                if chunk.thinking_delta:
                    acc_thinking += chunk.thinking_delta
                    cot_box.remove_class("hidden")
                    cot_box.title = (
                        f"🧠 <think> Raciocínio Investigativo SAST ({len(acc_thinking)} chars)"
                    )
                    cot_body.update(acc_thinking)

                if chunk.content_delta:
                    acc_content += chunk.content_delta
                    await report_md.update(
                        f"{triage_header}\n\n---\n{acc_content}"
                    )
                    report_scroll.scroll_end(animate=False)

                if chunk.ttft_ms > 0:
                    ttft = chunk.ttft_ms
                if chunk.tps > 0:
                    tps = chunk.tps
                if chunk.tokens_est > 0:
                    tokens = chunk.tokens_est
                self._update_telemetry_readout(ttft, tps, tokens)

                if chunk.cancelled:
                    acc_content += "\n\n> _⏹ Auditoria SAST interrompida pelo operador._"
                    break

            if err_text:
                await report_md.update(
                    f"{triage_header}\n\n---\n### ⚠️ Servidor vLLM Indisponível para Auditoria Profunda\n{err_text}"
                )
                return

            await report_md.update(f"{triage_header}\n\n---\n{acc_content}")
            if self.config_data.auto_collapse_think and acc_thinking:
                cot_box.collapsed = True

            # Persiste auditoria no histórico SQLite
            self.store.add_message(
                self.active_session_id,
                "user",
                f"[AUDITORIA SAST: {filename}]\n```{lang}\n{original_code}\n```",
            )
            self.store.add_message(
                self.active_session_id,
                "assistant",
                acc_content,
                thinking=acc_thinking,
                tokens_est=tokens,
                latency_ms=ttft,
                tps=tps,
            )
            await self._refresh_session_list()

            # Extrai patch defensivo, gera Diff colorido e valida no compilador real!
            patched = extract_patched_code(acc_content, lang)
            diff_log = self.query_one("#sast-diff-log", RichLog)
            status_bar = self.query_one("#sast-patch-status-bar", Static)
            diff_log.clear()

            if patched:
                self._last_sast_patch = patched
                diff_text, added, removed = generate_unified_diff(
                    original_code, patched, filename
                )
                comp_res = run_compiler_validation(
                    patched, language=lang, strict_security=True
                )
                comp_badge = (
                    f"✔ COMPILADOR APROVOU ({comp_res.compiler_used})"
                    if comp_res.valid
                    else f"⚠ AVISO DO COMPILADOR: {comp_res.output.splitlines()[0][:60]}"
                )
                status_bar.update(
                    f"PATCH DEFENSIVO (+{added} / -{removed} linhas) │ {comp_badge}"
                )
                diff_log.write(
                    Syntax(
                        diff_text,
                        "diff",
                        theme="monokai",
                        word_wrap=True,
                    )
                )
                self.notify(
                    f"Auditoria SAST concluída! Patch extraído (+{added}/-{removed}) — verifique a aba Diff."
                )
            else:
                self._last_sast_patch = ""
                status_bar.update(
                    "Nenhum bloco de código completo foi identificado na resposta para gerar Diff."
                )
        finally:
            self._is_streaming = False

    @on(Button.Pressed, "#btn-sast-apply-patch")
    def _on_sast_apply_patch(self) -> None:
        if not self._last_sast_patch:
            self.notify("Execute uma Auditoria vLLM para gerar um patch primeiro.", severity="warning")
            return
        self.query_one("#sast-code-editor", TextArea).text = self._last_sast_patch
        self.notify("Patch defensivo aplicado no editor da Bancada SAST!")

    @on(Button.Pressed, "#btn-sast-save-patch")
    def _on_sast_save_patch(self) -> None:
        if not self._last_sast_patch:
            self.notify("Nenhum patch disponível para salvar.", severity="warning")
            return
        lang = str(self.query_one("#sast-lang-select", Select).value or "c")
        orig_name = Path(
            self.query_one("#sast-filepath-input", Input).value.strip() or f"target.{lang}"
        ).name
        out_dir = get_data_dir() / "exports"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"patched_{orig_name}"
        out_path.write_text(self._last_sast_patch + "\n", encoding="utf-8")
        self.notify(f"Patch defensivo salvo em: {out_path}")

    # =========================================================================
    # [F3] COMPILADORES & VALIDADOR SINTÁTICO (src/validators.py)
    # =========================================================================

    @on(Select.Changed, "#validator-lang-select")
    def _on_validator_lang_changed(self, event: Select.Changed) -> None:
        if isinstance(event.value, str):
            set_editor_language(
                self.query_one("#validator-code-editor", TextArea), event.value
            )

    @on(Button.Pressed, "#btn-val-standard")
    def _on_btn_val_standard(self) -> None:
        self._execute_compiler_check(strict=False)

    @on(Button.Pressed, "#btn-val-strict")
    def _on_btn_val_strict(self) -> None:
        self._execute_compiler_check(strict=True)

    def _execute_compiler_check(self, strict: bool = False) -> ValidationResult:
        code = self.query_one("#validator-code-editor", TextArea).text
        lang = str(self.query_one("#validator-lang-select", Select).value or "c")
        res = run_compiler_validation(code, language=lang, strict_security=strict)

        log = self.query_one("#validator-output-log", RichLog)
        status_title = (
            "[bold bright_green]✔ SINTAXE & COMPILAÇÃO APROVADAS[/]"
            if res.valid
            else "[bold bright_red]✖ FALHA DE COMPILAÇÃO / ESTRUTURA[/]"
        )
        border_col = "bright_green" if res.valid else "bright_red"
        if res.valid and res.warnings_count > 0:
            status_title = (
                f"[bold yellow]⚠ COMPILÁVEL COM {res.warnings_count} AVISO(S) DE SEGURANÇA[/]"
            )
            border_col = "yellow"

        meta = Text()
        meta.append(f"Motor: ", style="bold cyan")
        meta.append(f"{res.compiler_used}\n")
        meta.append(f"Modo:  ", style="bold cyan")
        meta.append(
            f"{'Auditoria Estrita (-Wall -Wextra -Wformat-security)' if strict else 'Padrão Pipeline (src/validators.py)'}\n"
        )
        meta.append(f"Tempo: ", style="bold cyan")
        meta.append(f"{res.elapsed_ms:.1f} ms\n\n")
        meta.append(res.output, style="bright_white" if res.valid else "bright_red")

        log.write(Panel(meta, title=status_title, border_style=border_col))
        return res

    # =========================================================================
    # [F4] TEMPLATES RÁPIDOS DE CIBERSEGURANÇA
    # =========================================================================

    @on(ListView.Highlighted, "#templates-list")
    @on(ListView.Selected, "#templates-list")
    def _on_template_chosen(self, event) -> None:
        item = getattr(event, "item", None)
        if not isinstance(item, TemplateListItem):
            return
        tpl = item.template
        self._selected_template = tpl
        self.query_one("#tpl-detail-title", Label).update(tpl.title)
        self.query_one("#tpl-detail-meta", Label).update(
            f"Categoria: {tpl.category}  │  Tag: {tpl.badge}"
        )
        self.query_one("#tpl-detail-desc", Static).update(tpl.description)

        target_inp = self.query_one("#template-target-input", Input)
        target_inp.placeholder = tpl.target_placeholder
        target_inp.value = tpl.default_target
        self.query_one("#template-preview-editor", TextArea).text = tpl.render(
            tpl.default_target
        )

    @on(Input.Changed, "#template-target-input")
    def _on_template_target_edited(self, event: Input.Changed) -> None:
        rendered = self._selected_template.render(event.value)
        self.query_one("#template-preview-editor", TextArea).text = rendered

    @on(Button.Pressed, "#btn-tpl-execute")
    async def _on_btn_tpl_execute(self) -> None:
        if self._is_streaming:
            self.notify("Aguarde ou cancele o stream em andamento.", severity="warning")
            return
        prompt_text = self.query_one("#template-preview-editor", TextArea).text.strip()
        if not prompt_text:
            return
        self.action_switch_tab("tab-chat")
        await self.dispatch_chat_message(prompt_text)

    @on(Button.Pressed, "#btn-tpl-stage")
    def _on_btn_tpl_stage(self) -> None:
        prompt_text = self.query_one("#template-preview-editor", TextArea).text.strip()
        if not prompt_text:
            return
        drawer = self.query_one("#chat-code-drawer", Vertical)
        editor = self.query_one("#chat-attached-editor", TextArea)
        drawer.remove_class("hidden")
        set_editor_language(editor, "markdown")
        editor.text = prompt_text
        self.action_switch_tab("tab-chat")
        self.query_one("#chat-prompt-input", SmartPromptInput).value = (
            f"Execute o template [{self._selected_template.badge}] abaixo:"
        )
        self.notify("Template preparado na gaveta do Chat! Pressione Enter para enviar.")

    # =========================================================================
    # [F5] SERVIDOR vLLM & CONFIGURAÇÃO
    # =========================================================================

    @on(Select.Changed, "#cfg-preset-select")
    def _on_preset_selected(self, event: Select.Changed) -> None:
        key = str(event.value)
        if key in SYSTEM_PROMPT_PRESETS:
            self.query_one("#cfg-system-prompt", TextArea).text = SYSTEM_PROMPT_PRESETS[
                key
            ][1]

    def _collect_config_from_form(self) -> CyberLLMConfig:
        api_base = self.query_one("#cfg-api-base", Input).value
        model = self.query_one("#cfg-model", Input).value
        api_key = self.query_one("#cfg-api-key", Input).value
        sys_prompt = self.query_one("#cfg-system-prompt", TextArea).text
        auto_collapse = self.query_one("#cfg-auto-collapse", Checkbox).value

        try:
            temp = float(self.query_one("#cfg-temperature", Input).value)
        except ValueError:
            temp = 0.1
        try:
            top_p = float(self.query_one("#cfg-top-p", Input).value)
        except ValueError:
            top_p = 0.9
        try:
            max_tok = int(self.query_one("#cfg-max-tokens", Input).value)
        except ValueError:
            max_tok = 4096

        return CyberLLMConfig(
            api_base=api_base,
            api_key=api_key,
            model=model,
            temperature=temp,
            top_p=top_p,
            max_tokens=max_tok,
            system_prompt=sys_prompt,
            auto_collapse_think=auto_collapse,
        ).normalized()

    @on(Button.Pressed, "#btn-cfg-probe")
    def _on_btn_cfg_probe(self) -> None:
        self.config_data = self._collect_config_from_form()
        self.query_one("#cfg-api-base", Input).value = self.config_data.api_base
        self.probe_vllm_server(notify_user=True)

    @on(Button.Pressed, "#btn-cfg-save")
    def _on_btn_cfg_save(self) -> None:
        self.config_data = self._collect_config_from_form()
        self.query_one("#cfg-api-base", Input).value = self.config_data.api_base
        self.query_one("#cfg-temperature", Input).value = str(
            self.config_data.temperature
        )
        self.query_one("#cfg-top-p", Input).value = str(self.config_data.top_p)
        self.query_one("#cfg-max-tokens", Input).value = str(
            self.config_data.max_tokens
        )

        cfg_path = save_config(self.config_data)
        self._update_telemetry_readout()
        self.probe_vllm_server(notify_user=True)
        self.notify(f"Configuração salva em {cfg_path}")
