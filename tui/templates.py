"""
Catálogo de Templates Rápidos de Cibersegurança, Engenharia de Detecção e Baixo Nível.
Permite gerar regras YARA, Semgrep, Sigma e auditorias Assembly/Memória com parâmetros customizáveis.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class CyberTemplate:
    """Template operacional parametrizável para envio rápido ao CyberLLM."""

    id: str
    title: str
    category: str
    badge: str
    target_placeholder: str
    default_target: str
    description: str
    prompt_template: str

    def render(self, custom_target: str = "") -> str:
        target = (custom_target or "").strip() or self.default_target
        return self.prompt_template.replace("{TARGET}", target)


CYBER_TEMPLATES: List[CyberTemplate] = [
    CyberTemplate(
        id="yara_binary_sig",
        title="Regra YARA — Assinatura de Malware / Shellcode ELF & PE",
        category="Engenharia de Detecção",
        badge="YARA",
        target_placeholder="Descreva o artefato/comportamento binário (ex: loader ELF x86_64 com memfd_create e ptrace anti-debug)",
        default_target="Loader ELF x86_64 fileless que invoca syscalls memfd_create + fexecve, cifra strings com XOR e verifica TracerPid em /proc/self/status",
        description="Gera regra YARA de alta precisão com verificação de magic bytes ELF/PE, opcodes hexadecimais, entropia e controle estrito de falsos positivos.",
        prompt_template=(
            "Desenvolva uma **regra YARA de produção** para detectar o seguinte artefato ou técnica:\n"
            "**Alvo:** {TARGET}\n\n"
            "Requisitos técnicos obrigatórios:\n"
            "1. Use `<think> ... </think>` para planejar os indicadores de maior fidelidade e evitar falsos positivos em binários legítimos do sistema.\n"
            "2. Inclua seção `meta:` completa (`author`, `description`, `severity`, `mitre_attack`, `date`).\n"
            "3. Combine strings ASCII/wide relevantes com sequências hexadecimais de opcodes/syscalls (com wildcards cirúrgicos).\n"
            "4. Na `condition:`, valide magic header (`uint32(0) == 0x464c457f` para ELF ou `uint16(0) == 0x5A4D` para PE), faixa de `filesize` realista e limiar lógico das strings.\n"
            "5. Explique como validar e testar a regra sem degradar performance de scanning."
        ),
    ),
    CyberTemplate(
        id="semgrep_ast_rule",
        title="Regra Semgrep (YAML AST) — Detecção Estática de CWE",
        category="Engenharia de Detecção",
        badge="SEMGREP",
        target_placeholder="Padrão vulnerável e linguagem (ex: CWE-416 Use-After-Free em C ou SSRF em Python FastAPI)",
        default_target="Uso de ponteiro após free() sem reatribuição para NULL em código C/C++ (CWE-416) e chamadas strcpy/sprintf inseguras (CWE-120)",
        description="Cria regras Semgrep baseadas em AST (`patterns`, `pattern-not`, `taint` mode e `autofix`) prontas para pipeline CI/CD DevSecOps.",
        prompt_template=(
            "Escreva uma **regra Semgrep YAML (AST / Taint Mode)** completa para detectar com precisão:\n"
            "**Alvo:** {TARGET}\n\n"
            "Requisitos técnicos:\n"
            "1. Analise em `<think> ... </think>` os sanitizadores e padrões seguros que devem ser excluídos via `pattern-not` / `pattern-sanitizers`.\n"
            "2. Inclua `id`, `languages`, `severity: ERROR`, `message` detalhada, `metadata` com `cwe`, `owasp` e `confidence: HIGH`.\n"
            "3. Adicione sugestão `fix:` (autofix) quando aplicável.\n"
            "4. Forneça um trecho de código de teste com anotações `# ruleid:` e `# ok:` para validação automatizada com `semgrep --test`."
        ),
    ),
    CyberTemplate(
        id="sigma_siem_rule",
        title="Regra SIEM Sigma — Telemetria Linux Auditd / Sysmon",
        category="Engenharia de Detecção",
        badge="SIGMA",
        target_placeholder="Comportamento pós-exploração (ex: escalada de privilégio Linux via SUID / LD_PRELOAD / reverse shell)",
        default_target="Injeção de biblioteca compartilhada via LD_PRELOAD / /etc/ld.so.preload ou spawn de reverse shell interativo (/bin/bash -i) em Linux Auditd/Process Creation",
        description="Produz regra Sigma padronizada com `logsource`, seleções compostas, filtros de exclusão e mapeamento MITRE ATT&CK.",
        prompt_template=(
            "Construa uma **regra SIEM Sigma** completa em YAML para detectar em telemetria de endpoint:\n"
            "**Alvo:** {TARGET}\n\n"
            "Requisitos técnicos:\n"
            "1. Em `<think> ... </think>`, avalie variações de linha de comando (evasão/obfuscação) e processos administrativos legítimos para compor `filter_*`.\n"
            "2. Preencha todos os campos oficiais Sigma (`title`, `id` UUID, `status`, `description`, `tags` MITRE ATT&CK `attack.tXXXX`, `logsource`, `detection`, `falsepositives`, `level`).\n"
            "3. Forneça também um exemplo da query traduzida para SIEM (Elastic Query DSL / Splunk SPL)."
        ),
    ),
    CyberTemplate(
        id="asm_stack_rop_audit",
        title="Assembly x86_64 / ARM64 — Stack Frame, Saved RIP & Mitigações",
        category="Engenharia Reversa & Binários",
        badge="ASM x86_64",
        target_placeholder="Cenário Assembly/ABI (ex: prólogo/epílogo x86_64 System V ABI com corrupção de RBP/RIP e Stack Canary)",
        default_target="Disassembly x86_64 System V ABI de uma função que lê buffer na pilha sem Stack Canary, demonstrando layout exato do Stack Frame (buffer -> RBP -> Saved RIP) e como -fstack-protector-strong + PIE + NX bloqueiam o desvio",
        description="Inspeciona layout de memória de pilha/registradores em nível de instrução Assembly e detalha proteções modernas de compilador.",
        prompt_template=(
            "Conduza uma análise técnica profunda em nível de **Assembly e Arquitetura de Computadores**:\n"
            "**Cenário:** {TARGET}\n\n"
            "Requisitos:\n"
            "1. Raciocine em `<think> ... </think>` sobre offsets exatos em bytes, alinhamento de 16 bytes da pilha (ABI x86_64) e registradores afetados (`RSP`, `RBP`, `RIP`, `RDI`, `RSI`, `RDX`).\n"
            "2. Desenhe o diagrama ASCII do Stack Frame com offsets hexadecimais.\n"
            "3. Compare o Assembly gerado sem proteções vs. compilado com `-fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -pie -Wl,-z,relro,-z,now`."
        ),
    ),
    CyberTemplate(
        id="c_memory_uaf_lab",
        title="Auditoria de Memória C/C++ — Heap Use-After-Free & Integer Overflow",
        category="Baixo Nível & Memória",
        badge="C / HEAP",
        target_placeholder="Estrutura C/C++ alvo (ex: parser de pacotes de rede em C com realloc/free em cache concorrente)",
        default_target="Parser binário TLV (Type-Length-Value) em C para pacotes de rede de alta performance resistente a CWE-190 (Integer Overflow), CWE-125/787 (OOB Read/Write) e CWE-416 (Use-After-Free)",
        description="Projeta ou audita estruturas críticas em C/C++17/20 garantindo aritmética segura, ownership explícito e compilação limpa.",
        prompt_template=(
            "Projete e audite em detalhes de baixo nível o seguinte componente C/C++:\n"
            "**Componente:** {TARGET}\n\n"
            "Requisitos:\n"
            "1. Em `<think> ... </think>`, modele todos os casos extremos de aritmética inteira (`SIZE_MAX`, truncamento 64->32 bits) e ciclo de vida no alocador `ptmalloc2`/`jemalloc`.\n"
            "2. Implemente o código completo, limpo e **100% compilável** com `gcc -Wall -Wextra -Werror`.\n"
            "3. Inclua um `main()` de teste de estresse (fuzz/boundary cases) compatível com execução sob `AddressSanitizer (-fsanitize=address,undefined)`."
        ),
    ),
    CyberTemplate(
        id="rust_unsafe_soundness",
        title="Auditoria Rust `unsafe` & FFI — Verificação de Soundness e Aliasing",
        category="Baixo Nível & Memória",
        badge="RUST FFI",
        target_placeholder="Cenário Rust unsafe/FFI (ex: wrapper seguro sobre biblioteca C zero-copy com ponteiros brutos)",
        default_target="Wrapper Rust zero-copy sobre buffer FFI recebido do C (`*const u8`, `len: usize`), garantindo ausência de Undefined Behavior (UB), validação de null/alinhamento/aliasing e lifetimes seguros",
        description="Audita invariantes do modelo de memória Rust (Stacked/Tree Borrows, `Send`/`Sync`, alinhamento e lifetimes em fronteiras C-ABI).",
        prompt_template=(
            "Realize uma **Auditoria de Soundness em Rust (`unsafe` / FFI)** para:\n"
            "**Alvo:** {TARGET}\n\n"
            "Requisitos:\n"
            "1. Em `<think> ... </think>`, verifique todas as condições de Undefined Behavior (UB) segundo a referência oficial do Rust e Miri (`null`, alinhamento, `isize::MAX`, aliasing `&mut` vs `&`, inicialização de bytes).\n"
            "2. Escreva o código Rust seguro encapsulando o bloco `unsafe` mínimo com comentários `// SAFETY:` formais.\n"
            "3. Indique como validar com `cargo miri test`."
        ),
    ),
    CyberTemplate(
        id="sql_hardening_explain",
        title="Hardening Relacional SQL — Eliminação de CWE-89 & Índices EXPLAIN",
        category="Hardening & DevSecOps",
        badge="SQL / DB",
        target_placeholder="Endpoint/query alvo (ex: busca dinâmica multi-filtro em PostgreSQL + Python/Go sem SQL Injection)",
        default_target="Endpoint de busca multi-filtro com ordenação dinâmica (`ORDER BY` / paginação cursor-based) em PostgreSQL + Python, eliminando 100% de risco de CWE-89 (SQL Injection) e otimizando índices compostos para `EXPLAIN ANALYZE`",
        description="Combina blindagem contra SQL Injection (mesmo em `ORDER BY`/identificadores dinâmicos) com otimização de plano de execução.",
        prompt_template=(
            "Desenvolva uma solução blindada e otimizada de banco de dados relacional para:\n"
            "**Alvo:** {TARGET}\n\n"
            "Requisitos:\n"
            "1. Em `<think> ... </think>`, identifique por que prepared statements comuns não parametrizam nomes de colunas em `ORDER BY` e como aplicar allowlist estrita.\n"
            "2. Forneça o código completo parametrizado e seguro contra `CWE-89`.\n"
            "3. Inclua DDL dos índices recomendados e análise do plano esperado no `EXPLAIN (ANALYZE, BUFFERS)`."
        ),
    ),
    CyberTemplate(
        id="asan_valgrind_decoder",
        title="Diagnóstico de Crash — AddressSanitizer (ASan) / Valgrind / GDB",
        category="Hardening & DevSecOps",
        badge="ASAN / GDB",
        target_placeholder="Cole ou descreva o stack trace ASan/Valgrind/SIGSEGV para análise de causa-raiz",
        default_target="ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014 at pc 0x555555555289 bp 0x7fffffffdc10 sp 0x7fffffffdc00 WRITE of size 4 (alocação de 16 bytes em parser de cabeçalho de rede)",
        description="Decodifica relatórios do AddressSanitizer, UBSan, Valgrind ou registradores GDB identificando a causa-raiz exata e o patch.",
        prompt_template=(
            "Analise o seguinte relatório de falha de memória / crash dump e determine a causa-raiz e correção definitiva:\n"
            "**Relatório / Cenário:**\n{TARGET}\n\n"
            "Requisitos:\n"
            "1. Em `<think> ... </think>`, correlacione o tamanho da escrita/leitura inválida, endereço da shadow memory/chunk alocado e stack de alocação vs. acesso.\n"
            "2. Classifique a CWE correspondente e avalie a explorabilidade (DoS vs. corrupção de metadados/execução de código).\n"
            "3. Apresente o padrão de código que causa esse trace e o patch defensivo exato."
        ),
    ),
]
