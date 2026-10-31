"""
Suíte completa de testes unitários e de integração E2E (Textual Headless Pilot)
para a Interface TUI do CyberLLM 32B.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Tuple

import pytest
from textual.containers import Vertical
from textual.widgets import Collapsible, Input, Label, Select, Static, TabbedContent, TextArea

from tui.app import CyberLLMApp
from tui.compiler_bridge import run_compiler_validation
from tui.config import CyberLLMConfig, load_config, normalize_api_base, save_config
from tui.cot_parser import StreamingCoTParser, extract_fenced_code_blocks, split_cot_text
from tui.sast_engine import (
    SAMPLE_VULNERABLE_TARGETS,
    extract_patched_code,
    generate_unified_diff,
    run_local_cwe_triage,
)
from tui.storage import SessionStore
from tui.vllm_client import VLLMClient
from tui.widgets import ChatMessageCard


# =============================================================================
# SERVIDOR MOCK SSE vLLM REAL (HTTP/1.1 LOCAL) PARA TESTES DE REDE E TUI
# =============================================================================


async def start_mock_vllm_server() -> Tuple[asyncio.AbstractServer, str]:
    """Inicia um servidor HTTP/1.1 real simulando /v1/models e /v1/chat/completions SSE do vLLM."""

    sse_chunks = [
        {"choices": [{"delta": {"content": "<th"}}]},
        {"choices": [{"delta": {"content": "ink>\n1. Analisando Stack Frame x86_64 e strcpy.\n"}}]},
        {"choices": [{"delta": {"content": "2. Substituindo por snprintf seguro.</thi"}}]},
        {"choices": [{"delta": {"content": "nk>\n\n### Análise SAST Concluída\n"}}]},
        {"choices": [{"delta": {"content": "Detectada **CWE-120** crítica.\n\n```c\n"}}]},
        {
            "choices": [
                {
                    "delta": {
                        "content": (
                            "#include <stdio.h>\n"
                            "int process_telemetry_packet(const char *u, const char *h) {\n"
                            "    char session_tag[64];\n"
                            '    snprintf(session_tag, sizeof(session_tag), "%s", u);\n'
                            '    printf("%s\\n", session_tag);\n'
                            "    (void)h;\n"
                            "    return 0;\n"
                            "}\n"
                        )
                    }
                }
            ]
        },
        {"choices": [{"delta": {"content": "```\n"}}], "usage": {"completion_tokens": 64}},
    ]

    async def handle_client(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            req_line = await reader.readline()
            if not req_line:
                writer.close()
                return
            parts = req_line.decode("utf-8", errors="replace").split()
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            content_length = 0
            while True:
                hline = await reader.readline()
                if not hline or hline in (b"\r\n", b"\n"):
                    break
                decoded = hline.decode("utf-8", errors="replace").lower()
                if decoded.startswith("content-length:"):
                    content_length = int(decoded.split(":", 1)[1].strip())

            if content_length > 0:
                await reader.readexactly(content_length)

            if method == "GET" and path.endswith("/models"):
                body = json.dumps(
                    {
                        "object": "list",
                        "data": [{"id": "qwen32b-cyber", "object": "model"}],
                    }
                ).encode("utf-8")
                headers = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("utf-8")
                writer.write(headers + body)
                await writer.drain()

            elif method == "POST" and path.endswith("/chat/completions"):
                headers = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/event-stream\r\n"
                    "Cache-Control: no-cache\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("utf-8")
                writer.write(headers)
                await writer.drain()

                for item in sse_chunks:
                    frame = f"data: {json.dumps(item, ensure_ascii=False)}\n\n".encode("utf-8")
                    writer.write(frame)
                    await writer.drain()
                    await asyncio.sleep(0.005)

                writer.write(b"data: [DONE]\n\n")
                await writer.drain()
            else:
                writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, f"http://127.0.0.1:{port}/v1"


# =============================================================================
# 1. TESTES UNITÁRIOS: PARSER <think>, COMPILADORES, SAST E SQLITE
# =============================================================================


def test_streaming_cot_parser_fragmented_tags() -> None:
    parser = StreamingCoTParser()
    fragments = [
        "<",
        "th",
        "ink>",
        "\nPasso 1: RBP/RIP.",
        " Passo 2: Patch.",
        "</th",
        "ink>",
        "\n\n### Resposta Final\nOK!",
    ]
    t_parts = []
    c_parts = []
    for frag in fragments:
        td, cd = parser.feed(frag)
        t_parts.append(td)
        c_parts.append(cd)
    td_end, cd_end = parser.flush()
    t_parts.append(td_end)
    c_parts.append(cd_end)

    assert "".join(t_parts) == "Passo 1: RBP/RIP. Passo 2: Patch."
    assert "".join(c_parts) == "### Resposta Final\nOK!"
    assert "<think>" not in parser.full_content
    assert "</think>" not in parser.full_content


def test_split_cot_and_extract_code_blocks() -> None:
    raw = (
        "<think>Inspecionando ponteiro dangling</think>\n"
        "Corrija assim:\n```c\nint main(void) { return 0; }\n```\n"
        "E a regra YARA:\n```yara\nrule ElfProbe { condition: true }\n```"
    )
    thought, clean = split_cot_text(raw)
    assert thought == "Inspecionando ponteiro dangling"
    blocks = extract_fenced_code_blocks(clean)
    assert len(blocks) == 2
    assert blocks[0].normalized_lang == "c"
    assert blocks[1].normalized_lang == "yara"


def test_compiler_bridge_real_toolchains() -> None:
    # C válido (src/validators.py + modo estrito)
    ok_c = run_compiler_validation(
        '#include <stdio.h>\nint add(int a, int b) { return a + b; }',
        language="c",
        strict_security=True,
    )
    assert ok_c.valid is True

    # C inválido
    bad_c = run_compiler_validation(
        "int broken_func( { return ; }",
        language="c",
        strict_security=False,
    )
    assert bad_c.valid is False

    # Python válido e inválido
    assert run_compiler_validation("def f(x: int) -> int:\n    return x * 2\n", "python").valid
    assert not run_compiler_validation("def f(x):\nreturn x\n", "python").valid

    # YARA e Semgrep/Sigma YAML
    yara_rule = """
    rule CyberLLM_Test {
        meta:
            author = "CyberLLM"
        strings:
            $mz = { 4D 5A }
        condition:
            $mz at 0
    }
    """
    assert run_compiler_validation(yara_rule, "yara").valid

    semgrep_yaml = """
rules:
  - id: c-unsafe-strcpy
    message: Uso inseguro de strcpy (CWE-120)
    severity: ERROR
    languages: [c]
    pattern: strcpy($DST, $SRC)
"""
    assert run_compiler_validation(semgrep_yaml, "yaml").valid


def test_sast_local_triage_and_diff() -> None:
    _, lang, vuln_c = SAMPLE_VULNERABLE_TARGETS["c_stack_cmd"]
    findings = run_local_cwe_triage(vuln_c, lang)
    cwe_ids = {f.cwe_id for f in findings}
    assert "CWE-120" in cwe_ids
    assert "CWE-134" in cwe_ids
    assert "CWE-78" in cwe_ids

    _, _, uaf_c = SAMPLE_VULNERABLE_TARGETS["c_heap_uaf"]
    uaf_cwes = {f.cwe_id for f in run_local_cwe_triage(uaf_c, "c")}
    assert "CWE-416" in uaf_cwes
    assert "CWE-190" in uaf_cwes
    assert "CWE-476" in uaf_cwes

    patched = vuln_c.replace("strcpy(session_tag, untrusted_user);", 'snprintf(session_tag, sizeof(session_tag), "%s", untrusted_user);')
    diff_txt, added, removed = generate_unified_diff(vuln_c, patched, "auth_agent.c")
    assert added >= 1 and removed >= 1
    assert "snprintf" in diff_txt

    extracted = extract_patched_code(f"Segue correção:\n```c\n{patched}\n```", "c")
    assert extracted is not None and "snprintf" in extracted


def test_sqlite_session_store_and_export(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CYBERLLM_HOME", str(tmp_path))
    assert normalize_api_base("10.0.0.5:8000") == "http://10.0.0.5:8000/v1"

    cfg = CyberLLMConfig(api_base="10.0.0.5:8000", model="qwen32b-cyber", temperature=0.15)
    save_config(cfg)
    loaded = load_config()
    assert loaded.api_base == "http://10.0.0.5:8000/v1"
    assert loaded.temperature == 0.15

    store = SessionStore()
    sess = store.create_session()
    store.add_message(sess["id"], "user", "Explique corrupção de Saved RIP em x86_64")
    store.add_message(
        sess["id"],
        "assistant",
        "O endereço de retorno fica acima do Saved RBP.",
        thinking="Verificando layout System V AMD64 ABI...",
        tokens_est=42,
        latency_ms=18.5,
        tps=51.2,
    )

    updated = store.get_session(sess["id"])
    assert updated is not None
    assert "Explique corrupção" in updated["title"]
    assert updated["message_count"] == 2

    md_file = store.export_session_markdown(sess["id"])
    assert md_file.exists()
    md_text = md_file.read_text(encoding="utf-8")
    assert "Verificando layout System V AMD64 ABI..." in md_text
    assert "Saved RBP" in md_text


# =============================================================================
# 2. TESTE E2E HEADLESS DO TUI TEXTUAL COM SERVIDOR SSE vLLM REAL
# =============================================================================


@pytest.mark.asyncio
async def test_tui_end_to_end_pilot(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CYBERLLM_HOME", str(tmp_path))
    server, api_base = await start_mock_vllm_server()

    try:
        cfg = CyberLLMConfig(
            api_base=api_base,
            model="qwen32b-cyber",
            api_key="EMPTY",
            temperature=0.1,
        )
        # Verifica cliente vLLM isoladamente primeiro
        client = VLLMClient()
        health = await client.check_health(cfg)
        assert health.online is True
        assert "qwen32b-cyber" in health.models

        app = CyberLLMApp(config=cfg)
        async with app.run_test(size=(135, 42)) as pilot:
            await pilot.pause(0.15)

            # 1) Status bar deve indicar vLLM ONLINE
            pill_text = str(app.query_one("#vllm-status-pill", Label).render())
            assert "ONLINE" in pill_text

            # 2) Envia pergunta no Chat [F1] e valida streaming SSE + bloco <think>
            prompt_inp = app.query_one("#chat-prompt-input", Input)
            prompt_inp.value = "Audite strcpy em x86_64"
            await pilot.click("#btn-send-chat")

            # Aguarda término do worker SSE
            for _ in range(40):
                await pilot.pause(0.05)
                if not app._is_streaming:
                    break

            cards = list(app.query(ChatMessageCard))
            assert len(cards) == 2
            assistant_card = cards[1]
            assert "Analisando Stack Frame" in assistant_card._thinking_text
            assert "CWE-120" in assistant_card._content_text
            assert len(assistant_card._extracted_blocks) == 1

            # Testa atalho Ctrl+T para recolher/expandir <think>
            cot_widget = assistant_card.query_one(Collapsible)
            initial_state = cot_widget.collapsed
            await pilot.press("ctrl+t")
            await pilot.pause(0.05)
            assert cot_widget.collapsed is not initial_state

            # 3) Alterna para Bancada SAST [F2], roda triagem local e auditoria profunda vLLM
            await pilot.press("f2")
            await pilot.pause(0.05)
            assert app.query_one("#workspace-tabs", TabbedContent).active == "tab-sast"

            app._run_sast_local_triage()
            await pilot.pause(0.05)

            app._on_btn_sast_deep()
            for _ in range(40):
                await pilot.pause(0.05)
                if not app._is_streaming:
                    break

            assert "snprintf" in app._last_sast_patch
            patch_status = str(app.query_one("#sast-patch-status-bar", Static).render())
            assert "PATCH DEFENSIVO" in patch_status
            assert "COMPILADOR APROVOU" in patch_status

            # 4) Alterna para Compiladores [F3] e executa validação estrita gcc
            await pilot.press("f3")
            await pilot.pause(0.05)
            assert app.query_one("#workspace-tabs", TabbedContent).active == "tab-validator"
            res = app._execute_compiler_check(strict=True)
            assert res.valid is True

            # 5) Alterna para Templates [F4], altera alvo e prepara no Chat
            await pilot.press("f4")
            await pilot.pause(0.05)
            tpl_input = app.query_one("#template-target-input", Input)
            tpl_input.value = "Shellcode ELF x86_64 memfd_create"
            await pilot.pause(0.05)
            preview_txt = app.query_one("#template-preview-editor", TextArea).text
            assert "Shellcode ELF x86_64 memfd_create" in preview_txt

            app._on_btn_tpl_stage()
            await pilot.pause(0.05)
            assert app.query_one("#workspace-tabs", TabbedContent).active == "tab-chat"
            assert not app.query_one("#chat-code-drawer", Vertical).has_class("hidden")

            # 6) Alterna para Config vLLM [F5] e salva configuração
            await pilot.press("f5")
            await pilot.pause(0.05)
            app.query_one("#cfg-preset-select", Select).value = "detection_eng"
            await pilot.pause(0.05)
            assert "YARA" in app.query_one("#cfg-system-prompt", TextArea).text
            app._on_btn_cfg_save()
            await pilot.pause(0.05)
            assert (tmp_path / "config.json").exists()

    finally:
        server.close()
        await server.wait_closed()
