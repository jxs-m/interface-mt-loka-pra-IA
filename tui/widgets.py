"""
Componentes visuais customizados do CyberLLM TUI (Textual 8.x + Rich).
Inclui cartões de mensagem com bloco recolhível `<think>`, streaming Markdown incremental,
entrada inteligente com detecção de paste multi-linha, registro Tree-Sitter para C/C++
e modal seletor de arquivos para auditoria SAST.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List, Optional

from textual import events, on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Collapsible,
    DirectoryTree,
    Input,
    Label,
    Markdown,
    Static,
    TextArea,
)
from textual.widgets._markdown import MarkdownStream

from tui.cot_parser import CodeBlock, extract_fenced_code_blocks

# Registro opcional de Tree-Sitter C e C++ no TextArea
try:
    import tree_sitter
    import tree_sitter_c
    import tree_sitter_cpp

    _TS_C_LANG = tree_sitter.Language(tree_sitter_c.language())
    _TS_C_QUERY = tree_sitter_c.HIGHLIGHTS_QUERY
    _TS_CPP_LANG = tree_sitter.Language(tree_sitter_cpp.language())
    _TS_CPP_QUERY = tree_sitter_c.HIGHLIGHTS_QUERY + "\n" + tree_sitter_cpp.HIGHLIGHTS_QUERY
    _HAS_TS_C_CPP = True
except Exception:
    _HAS_TS_C_CPP = False


def configure_code_editor(editor: TextArea, language: str = "c") -> TextArea:
    """Registra gramáticas C/C++ no TextArea e aplica tema escuro de alta legibilidade."""
    if _HAS_TS_C_CPP:
        try:
            editor.register_language("c", _TS_C_LANG, _TS_C_QUERY)
            editor.register_language("cpp", _TS_CPP_LANG, _TS_CPP_QUERY)
        except Exception:
            pass
    if "monokai" in editor.available_themes:
        editor.theme = "monokai"
    set_editor_language(editor, language)
    return editor


def set_editor_language(editor: TextArea, language: str) -> None:
    """Altera a linguagem de syntax highlighting do TextArea com fallback seguro."""
    lang_map = {
        "c": "c",
        "cpp": "cpp",
        "c++": "cpp",
        "rust": "rust",
        "rs": "rust",
        "python": "python",
        "py": "python",
        "go": "go",
        "yaml": "yaml",
        "yml": "yaml",
        "semgrep": "yaml",
        "sigma": "yaml",
        "sql": "sql",
        "bash": "bash",
        "json": "json",
        "markdown": "markdown",
    }
    mapped = lang_map.get((language or "").lower().strip())
    if mapped and mapped in editor.available_languages:
        editor.language = mapped
    else:
        editor.language = None


class SmartPromptInput(Input):
    """
    Campo de prompt estilo terminal hacker:
    - `Enter` envia imediatamente;
    - `Up`/`Down` navegam no histórico de comandos enviados na sessão;
    - Colar código multi-linha (`\\n`) transfere automaticamente para a gaveta de código anexado.
    """

    class MultiLinePasted(Message):
        def __init__(self, text: str) -> None:
            super().__init__()
            self.text = text

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cmd_history: List[str] = []
        self._history_idx: int = 0

    def record_history(self, prompt_text: str) -> None:
        cleaned = prompt_text.strip()
        if cleaned and (not self._cmd_history or self._cmd_history[-1] != cleaned):
            self._cmd_history.append(cleaned)
        self._history_idx = len(self._cmd_history)

    def _on_paste(self, event: events.Paste) -> None:
        if "\n" in event.text or "\r" in event.text:
            event.prevent_default()
            event.stop()
            normalized = event.text.replace("\r\n", "\n").replace("\r", "\n")
            self.post_message(self.MultiLinePasted(normalized))
            return
        super()._on_paste(event)

    def _on_key(self, event: events.Key) -> None:
        if event.key == "up" and self._cmd_history:
            event.prevent_default()
            self._history_idx = max(0, self._history_idx - 1)
            self.value = self._cmd_history[self._history_idx]
            self.cursor_position = len(self.value)
            return
        if event.key == "down" and self._cmd_history:
            event.prevent_default()
            self._history_idx = min(len(self._cmd_history), self._history_idx + 1)
            if self._history_idx == len(self._cmd_history):
                self.value = ""
            else:
                self.value = self._cmd_history[self._history_idx]
            self.cursor_position = len(self.value)
            return
        super()._on_key(event)


class ChatMessageCard(Vertical):
    """
    Cartão de mensagem do Chat com suporte a:
    - Bloco `<think> ... </think>` recolhível (`Collapsible`) atualizado em tempo real;
    - Resposta Markdown com código destacado via Pygments e `MarkdownStream`;
    - Botões rápidos para enviar blocos de código da resposta direto ao Compilador ou SAST.
    """

    class CodeActionRequested(Message):
        def __init__(self, action: str, block: CodeBlock) -> None:
            super().__init__()
            self.action = action  # "validate" | "sast" | "save"
            self.block = block

    def __init__(
        self,
        role: str,
        content: str = "",
        thinking: str = "",
        model_label: str = "qwen32b-cyber",
        timestamp: str = "",
        collapse_think: bool = False,
        telemetry_note: str = "",
    ) -> None:
        role_cls = "msg-user" if role == "user" else "msg-assistant"
        super().__init__(classes=f"msg-card {role_cls}")
        self.role = role
        self._content_text = content
        self._thinking_text = thinking
        self._model_label = model_label
        self._timestamp = timestamp or datetime.now().strftime("%H:%M:%S")
        self._collapse_think = collapse_think
        self._telemetry_note = telemetry_note
        self._md_stream: Optional[MarkdownStream] = None
        self._extracted_blocks: List[CodeBlock] = []

    def compose(self) -> ComposeResult:
        if self.role == "user":
            yield Label(
                f"👤 OPERADOR // {self._timestamp}",
                classes="msg-header-user",
            )
            yield Markdown(self._content_text, classes="msg-markdown")
        else:
            header_txt = f"🛡️ CYBERLLM 32B [{self._model_label}] // {self._timestamp}"
            if self._telemetry_note:
                header_txt += f"  │  {self._telemetry_note}"
            yield Label(header_txt, classes="msg-header-assistant", markup=False)

            has_think = bool(self._thinking_text.strip())
            cot_classes = "cot-collapsible" if has_think else "cot-collapsible hidden"
            cot_title = (
                f"🧠 <think> Raciocínio Investigativo ({len(self._thinking_text)} chars)"
                if has_think
                else "🧠 <think> Raciocínio Investigativo..."
            )
            with Collapsible(
                title=cot_title,
                collapsed=self._collapse_think if has_think else False,
                classes=cot_classes,
            ):
                yield Static(self._thinking_text, classes="cot-body", markup=False)

            yield Markdown(self._content_text, classes="msg-markdown")
            yield Horizontal(classes="code-actions-bar hidden")

    def on_mount(self) -> None:
        if self.role == "assistant" and self._content_text.strip():
            self._populate_code_actions()

    def start_streaming(self) -> None:
        """Inicializa o stream incremental do widget Markdown."""
        md_widget = self.query_one(Markdown)
        self._md_stream = Markdown.get_stream(md_widget)

    async def append_stream_delta(
        self,
        thinking_delta: str = "",
        content_delta: str = "",
        in_thinking: bool = False,
    ) -> None:
        """Aplica deltas SSE de `<think>` e conteúdo final sem flicker."""
        if thinking_delta:
            self._thinking_text += thinking_delta
            cot = self.query_one(Collapsible)
            if cot.has_class("hidden"):
                cot.remove_class("hidden")
            cot.title = (
                f"🧠 <think> Raciocínio Investigativo em curso... "
                f"({len(self._thinking_text)} chars)"
            )
            cot_body = self.query_one(".cot-body", Static)
            cot_body.update(self._thinking_text)

        if content_delta:
            if not in_thinking and self._thinking_text:
                cot = self.query_one(Collapsible)
                cot.title = (
                    f"🧠 <think> Raciocínio Investigativo Concluído "
                    f"({len(self._thinking_text)} chars)"
                )
            self._content_text += content_delta
            if self._md_stream is not None:
                await self._md_stream.write(content_delta)
            else:
                await self.query_one(Markdown).update(self._content_text)

    async def finalize_stream(
        self,
        ttft_ms: float = 0.0,
        tps: float = 0.0,
        tokens_est: int = 0,
        auto_collapse_think: bool = False,
        cancelled: bool = False,
        error_markdown: str = "",
    ) -> None:
        """Encerra o stream, atualiza telemetria no cabeçalho e monta botões de código."""
        if self._md_stream is not None:
            await self._md_stream.stop()
            self._md_stream = None

        if error_markdown:
            if self._content_text:
                self._content_text += f"\n\n---\n### ⚠️ Erro de Comunicação vLLM\n{error_markdown}"
            else:
                self._content_text = f"### ⚠️ Servidor vLLM Indisponível\n{error_markdown}"
            await self.query_one(Markdown).update(self._content_text)

        if cancelled:
            self._content_text += "\n\n> _⏹ Geração interrompida pelo operador._"
            await self.query_one(Markdown).update(self._content_text)

        if self._thinking_text:
            cot = self.query_one(Collapsible)
            cot.remove_class("hidden")
            cot.title = (
                f"🧠 <think> Raciocínio Investigativo "
                f"({len(self._thinking_text)} chars — clique ou Ctrl+T)"
            )
            if auto_collapse_think:
                cot.collapsed = True

        header = self.query_one(".msg-header-assistant", Label)
        status_Parts = [f"🛡️ CYBERLLM 32B [{self._model_label}] // {self._timestamp}"]
        if tokens_est > 0 or tps > 0:
            status_Parts.append(
                f"~{tokens_est} tok · {tps:.1f} tok/s · TTFT {ttft_ms:.0f}ms"
            )
        if cancelled:
            status_Parts.append("INTERROMPIDO")
        header.update("  │  ".join(status_Parts))

        self._populate_code_actions()

    def toggle_thinking(self) -> None:
        """Alterna expansão do bloco `<think>` se presente neste cartão."""
        if self.role != "assistant" or not self._thinking_text.strip():
            return
        cot = self.query_one(Collapsible)
        cot.collapsed = not cot.collapsed

    def _populate_code_actions(self) -> None:
        self._extracted_blocks = extract_fenced_code_blocks(self._content_text)
        if not self._extracted_blocks:
            return
        bar = self.query_one(".code-actions-bar", Horizontal)
        bar.remove_children()
        bar.remove_class("hidden")

        # Exibe ações rápidas para até 3 blocos principais do cartão
        for block in self._extracted_blocks[:3]:
            lang_tag = block.normalized_lang.upper()
            bar.mount(
                Button(
                    f"🧪 Compilar #{block.index} ({lang_tag})",
                    name=f"validate:{block.index}",
                    classes="btn-matrix",
                )
            )
            bar.mount(
                Button(
                    f"🛡️ SAST #{block.index}",
                    name=f"sast:{block.index}",
                    classes="btn-cyan",
                )
            )
            bar.mount(
                Button(
                    f"💾 Salvar #{block.index}",
                    name=f"save:{block.index}",
                )
            )

    @on(Button.Pressed)
    def _handle_code_action_btn(self, event: Button.Pressed) -> None:
        btn_name = event.button.name or ""
        if ":" not in btn_name:
            return
        action, idx_str = btn_name.split(":", 1)
        if action not in ("validate", "sast", "save"):
            return
        event.stop()
        try:
            idx = int(idx_str)
        except ValueError:
            return
        for blk in self._extracted_blocks:
            if blk.index == idx:
                self.post_message(self.CodeActionRequested(action, blk))
                break


class FilePickerModal(ModalScreen[Optional[str]]):
    """Modal estilo hacker para selecionar arquivo de código local para auditoria SAST."""

    BINDINGS = [("escape", "cancel", "Cancelar")]

    def __init__(self, root_dir: str = ".") -> None:
        super().__init__()
        self.root_dir = root_dir

    def compose(self) -> ComposeResult:
        with Vertical(id="file-picker-dialog"):
            yield Label(
                "📂 SELECIONAR ARQUIVO DE CÓDIGO-FONTE (Enter para carregar | Esc para fechar)",
                classes="section-title",
            )
            yield DirectoryTree(self.root_dir, id="file-picker-tree")
            with Horizontal():
                yield Button("Cancelar (Esc)", id="btn-cancel-picker", classes="btn-danger")

    @on(DirectoryTree.FileSelected, "#file-picker-tree")
    def _on_file_picked(self, event: DirectoryTree.FileSelected) -> None:
        self.dismiss(str(Path(event.path).resolve()))

    @on(Button.Pressed, "#btn-cancel-picker")
    def _on_cancel_btn(self) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)
