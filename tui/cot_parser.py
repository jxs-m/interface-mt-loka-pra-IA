"""
Parser incremental em tempo real para blocos de raciocínio <think> ... </think>
durante streaming SSE do vLLM, além de extração estruturada de blocos de código Markdown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple

OPEN_TAG = "<think>"
CLOSE_TAG = "</think>"


@dataclass
class CodeBlock:
    """Bloco de código extraído de uma resposta Markdown do modelo."""

    index: int
    language: str
    code: str

    @property
    def normalized_lang(self) -> str:
        lang = (self.language or "").strip().lower()
        aliases = {
            "c++": "cpp",
            "cc": "cpp",
            "cxx": "cpp",
            "h": "c",
            "hpp": "cpp",
            "py": "python",
            "rs": "rust",
            "sh": "bash",
            "shell": "bash",
            "yml": "yaml",
            "semgrep": "yaml",
            "sigma": "yaml",
            "yar": "yara",
            "x86asm": "asm",
            "nasm": "asm",
            "assembly": "asm",
        }
        return aliases.get(lang, lang or "text")


def _trailing_prefix_len(text: str, tag: str) -> int:
    """Retorna o tamanho do maior sufixo de `text` que é prefixo próprio de `tag`."""
    max_check = min(len(text), len(tag) - 1)
    for k in range(max_check, 0, -1):
        if text.endswith(tag[:k]):
            return k
    return 0


class StreamingCoTParser:
    """
    Máquina de estados para separar tokens de `<think>...</think>` do conteúdo final
    em tempo real sem vazar fragmentos parciais de tags durante o streaming SSE.
    Suporta também `reasoning_content` nativo do servidor vLLM.
    """

    def __init__(self) -> None:
        self._state = "OUTSIDE"  # OUTSIDE | INSIDE
        self._buffer = ""
        self._trim_leading_after_open = False
        self._trim_leading_after_close = False
        self.in_thinking: bool = False
        self.full_thinking: str = ""
        self.full_content: str = ""

    def feed(self, content_chunk: str = "", reasoning_chunk: str = "") -> Tuple[str, str]:
        """
        Processa novos fragmentos do SSE e retorna `(thinking_delta, content_delta)`.
        """
        think_out: List[str] = []
        content_out: List[str] = []

        if reasoning_chunk:
            self.in_thinking = True
            think_out.append(reasoning_chunk)

        if content_chunk:
            if reasoning_chunk == "" and self.in_thinking and self._state == "OUTSIDE" and not self._buffer:
                # Se vLLM enviava reasoning_content separado e agora começou content normal
                self.in_thinking = False

            self._buffer += content_chunk

            while self._buffer:
                if self._state == "OUTSIDE":
                    if self._trim_leading_after_close:
                        stripped = self._buffer.lstrip("\r\n ")
                        if not stripped:
                            self._buffer = ""
                            break
                        self._buffer = stripped
                        self._trim_leading_after_close = False

                    idx = self._buffer.find(OPEN_TAG)
                    if idx != -1:
                        if idx > 0:
                            content_out.append(self._buffer[:idx])
                        self._buffer = self._buffer[idx + len(OPEN_TAG) :]
                        self._state = "INSIDE"
                        self.in_thinking = True
                        self._trim_leading_after_open = True
                        continue

                    hold = _trailing_prefix_len(self._buffer, OPEN_TAG)
                    emit_len = len(self._buffer) - hold
                    if emit_len > 0:
                        content_out.append(self._buffer[:emit_len])
                        self._buffer = self._buffer[emit_len:]
                    break

                else:  # INSIDE <think>
                    if self._trim_leading_after_open:
                        stripped_open = self._buffer.lstrip("\r\n")
                        if not stripped_open:
                            self._buffer = ""
                            break
                        self._buffer = stripped_open
                        self._trim_leading_after_open = False

                    idx = self._buffer.find(CLOSE_TAG)
                    if idx != -1:
                        if idx > 0:
                            think_out.append(self._buffer[:idx])
                        self._buffer = self._buffer[idx + len(CLOSE_TAG) :]
                        self._state = "OUTSIDE"
                        self.in_thinking = False
                        self._trim_leading_after_close = True
                        continue

                    hold = _trailing_prefix_len(self._buffer, CLOSE_TAG)
                    emit_len = len(self._buffer) - hold
                    if emit_len > 0:
                        think_out.append(self._buffer[:emit_len])
                        self._buffer = self._buffer[emit_len:]
                    break

        t_delta = "".join(think_out)
        c_delta = "".join(content_out)
        self.full_thinking += t_delta
        self.full_content += c_delta
        return t_delta, c_delta

    def flush(self) -> Tuple[str, str]:
        """Descarrega qualquer sufixo residual ao término do stream."""
        if not self._buffer:
            self.in_thinking = False
            return "", ""

        leftover = self._buffer
        self._buffer = ""
        self.in_thinking = False

        if self._state == "INSIDE":
            self.full_thinking += leftover
            return leftover, ""

        if self._trim_leading_after_close:
            leftover = leftover.lstrip("\r\n ")
            self._trim_leading_after_close = False
        self.full_content += leftover
        return "", leftover


def split_cot_text(raw_text: str, explicit_thinking: str = "") -> Tuple[str, str]:
    """
    Separa `(thinking, clean_content)` de uma resposta completa (útil para histórico ou modo não-streaming).
    Suporta múltiplos blocos `<think>...</think>`, bloco `<think>` não fechado ou sufixo órfão `...</think>`.
    """
    text = raw_text or ""
    thoughts: List[str] = []
    if explicit_thinking.strip():
        thoughts.append(explicit_thinking.strip())

    # Caso 1: pares completos <think>...</think>
    pattern = re.compile(r"<think>(.*?)</think>", re.DOTALL)
    for match in pattern.finditer(text):
        snippet = match.group(1).strip()
        if snippet:
            thoughts.append(snippet)
    cleaned = pattern.sub("", text)

    # Caso 2: tag </think> órfã (quando <think> foi injetado no prompt template)
    if "</think>" in cleaned and "<think>" not in cleaned:
        before, after = cleaned.split("</think>", 1)
        if before.strip():
            thoughts.append(before.strip())
        cleaned = after

    # Caso 3: tag <think> aberta sem fechamento (geração interrompida no meio do CoT)
    if "<think>" in cleaned:
        before, after = cleaned.split("<think>", 1)
        if after.strip():
            thoughts.append(after.strip())
        cleaned = before

    return "\n\n".join(thoughts).strip(), cleaned.strip()


def extract_fenced_code_blocks(markdown_text: str) -> List[CodeBlock]:
    """Extrai todos os blocos de código Markdown ```lang ... ``` de uma resposta."""
    if not markdown_text:
        return []
    pattern = re.compile(r"```([a-zA-Z0-9_\+\-\.]*)[ \t]*\n(.*?)```", re.DOTALL)
    blocks: List[CodeBlock] = []
    for idx, match in enumerate(pattern.finditer(markdown_text), start=1):
        lang = (match.group(1) or "text").strip()
        code = match.group(2).strip()
        if code:
            blocks.append(CodeBlock(index=idx, language=lang, code=code))
    return blocks
