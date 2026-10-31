"""
Persistência local de sessões e histórico de conversas / auditorias SAST via SQLite.
Salva dados localmente em ~/.cyberllm/history.db e permite exportação em Markdown.
"""

from __future__ import annotations

import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from tui.config import DEFAULT_CYBER_SYSTEM_PROMPT, get_data_dir


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class SessionStore:
    """Armazenamento transacional SQLite para sessões de conversa e relatórios."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or (get_data_dir() / "history.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    model TEXT NOT NULL,
                    system_prompt TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    thinking TEXT NOT NULL DEFAULT '',
                    tokens_est INTEGER NOT NULL DEFAULT 0,
                    latency_ms REAL NOT NULL DEFAULT 0.0,
                    tps REAL NOT NULL DEFAULT 0.0,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_messages_session
                ON messages(session_id, id);
                """
            )

    def create_session(
        self,
        title: str = "Nova Operação",
        model: str = "qwen32b-cyber",
        system_prompt: str = DEFAULT_CYBER_SYSTEM_PROMPT,
    ) -> Dict[str, Any]:
        session_id = f"op-{uuid.uuid4().hex[:10]}"
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO sessions (id, title, model, system_prompt, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session_id, title.strip() or "Nova Operação", model, system_prompt, now, now),
            )
        return {
            "id": session_id,
            "title": title.strip() or "Nova Operação",
            "model": model,
            "system_prompt": system_prompt,
            "created_at": now,
            "updated_at": now,
            "message_count": 0,
        }

    def list_sessions(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT s.*,
                       COUNT(m.id) AS message_count
                FROM sessions s
                LEFT JOIN messages m ON m.session_id = s.id
                GROUP BY s.id
                ORDER BY s.updated_at DESC, s.rowid DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT s.*,
                       (SELECT COUNT(*) FROM messages m WHERE m.session_id = s.id) AS message_count
                FROM sessions s
                WHERE s.id = ?
                """,
                (session_id,),
            ).fetchone()
            return dict(row) if row else None

    def rename_session(self, session_id: str, new_title: str) -> None:
        cleaned = re.sub(r"\s+", " ", new_title).strip()[:64] or "Operação CyberLLM"
        with self._connect() as conn:
            conn.execute(
                "UPDATE sessions SET title = ?, updated_at = ? WHERE id = ?",
                (cleaned, _now_iso(), session_id),
            )

    def delete_session(self, session_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))

    def add_message(
        self,
        session_id: str,
        role: str,
        content: str,
        thinking: str = "",
        tokens_est: int = 0,
        latency_ms: float = 0.0,
        tps: float = 0.0,
    ) -> Dict[str, Any]:
        now = _now_iso()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO messages (session_id, role, content, thinking, tokens_est, latency_ms, tps, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, role, content, thinking, tokens_est, latency_ms, tps, now),
            )
            msg_id = cur.lastrowid

            # Auto-nomeia a sessão a partir da primeira mensagem do usuário
            if role == "user":
                sess = conn.execute(
                    "SELECT title FROM sessions WHERE id = ?", (session_id,)
                ).fetchone()
                if sess and sess["title"] == "Nova Operação":
                    first_line = content.strip().splitlines()[0] if content.strip() else ""
                    first_line = re.sub(r"^\[.*?\]\s*", "", first_line)
                    auto_title = re.sub(r"\s+", " ", first_line).strip()[:44]
                    if auto_title:
                        conn.execute(
                            "UPDATE sessions SET title = ?, updated_at = ? WHERE id = ?",
                            (auto_title, now, session_id),
                        )
                    else:
                        conn.execute(
                            "UPDATE sessions SET updated_at = ? WHERE id = ?",
                            (now, session_id),
                        )
                else:
                    conn.execute(
                        "UPDATE sessions SET updated_at = ? WHERE id = ?",
                        (now, session_id),
                    )
            else:
                conn.execute(
                    "UPDATE sessions SET updated_at = ? WHERE id = ?",
                    (now, session_id),
                )

        return {
            "id": msg_id,
            "session_id": session_id,
            "role": role,
            "content": content,
            "thinking": thinking,
            "tokens_est": tokens_est,
            "latency_ms": latency_ms,
            "tps": tps,
            "created_at": now,
        }

    def get_messages(self, session_id: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM messages WHERE session_id = ? ORDER BY id ASC",
                (session_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def export_session_markdown(
        self, session_id: str, export_dir: Optional[Path] = None
    ) -> Path:
        """Exporta toda a sessão (incluindo blocos <think>) para um relatório Markdown."""
        sess = self.get_session(session_id)
        if not sess:
            raise ValueError(f"Sessão {session_id} não encontrada.")
        messages = self.get_messages(session_id)

        out_dir = export_dir or (get_data_dir() / "exports")
        out_dir.mkdir(parents=True, exist_ok=True)

        safe_slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", sess["title"]).strip("_")[:36] or "sessao"
        out_path = out_dir / f"{sess['id']}_{safe_slug}.md"

        lines = [
            f"# 🛡️ Relatório CyberLLM: {sess['title']}",
            "",
            f"- **ID da Operação:** `{sess['id']}`",
            f"- **Modelo:** `{sess['model']}`",
            f"- **Criado em:** `{sess['created_at']}`",
            f"- **Atualizado em:** `{sess['updated_at']}`",
            "",
            "---",
            "",
        ]

        for msg in messages:
            role_badge = "👤 OPERADOR" if msg["role"] == "user" else "🛡️ CYBERLLM 32B"
            lines.append(f"## {role_badge} _({msg['created_at']})_")
            lines.append("")
            if msg["thinking"]:
                lines.append("<details>")
                lines.append("<summary>🧠 Raciocínio Investigativo (&lt;think&gt;)</summary>")
                lines.append("")
                lines.append("```text")
                lines.append(msg["thinking"].strip())
                lines.append("```")
                lines.append("</details>")
                lines.append("")
            lines.append(msg["content"].strip())
            if msg["role"] == "assistant" and (msg["tokens_est"] or msg["tps"]):
                lines.append("")
                lines.append(
                    f"> _Telemetria: ~{msg['tokens_est']} tokens | "
                    f"{msg['tps']:.1f} tok/s | TTFT/Latência: {msg['latency_ms']:.0f} ms_"
                )
            lines.append("")
            lines.append("---")
            lines.append("")

        out_path.write_text("\n".join(lines), encoding="utf-8")
        return out_path
