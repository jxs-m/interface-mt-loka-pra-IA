# 🚀 Guia de Execução de Alta Capacidade: IA em Cibersegurança no Google Colab
## Infraestrutura Alvo: 1x GPU 96 GB VRAM + 180 GB RAM

Este guia acompanha a execução dos dois documentos mestres:
1. `Plano Diretor de Treinamento e Datasets para IA em Cibersegurança.pdf`
2. `Guia de Aquisição e Mineração de Datasets para IA em Cibersegurança.pdf`

Com o seu acesso a instâncias dotadas de **96 GB de VRAM e 180 GB de Memória RAM**, o plano original dos PDFs pode ser executado em sua **plenitude técnica máxima, sem concessões nem reduções de tamanho**!

---

## 1. Capacidades Desbloqueadas com 96 GB de VRAM e 180 GB de RAM

| Componente | Configuração Desbloqueada | Benefício Técnico |
| :--- | :--- | :--- |
| **Modelo Base Alvo** | **`Qwen/Qwen2.5-Coder-32B-Instruct`** em **BF16 Nativo** | Sem necessidade de quantização 4-bit (NF4). Elimina ruídos numéricos nos tensores de projeção, garantindo precisão cirúrgica em ponteiros C/Rust, rastreamento de stack frame e formatação estrita. |
| **Adaptadores LoRA** | **$r=64, \alpha=128$** em todas as camadas lineares | Injeção em `q_proj`, `k_proj`, `v_proj`, `o_proj`, `gate_proj`, `up_proj`, `down_proj`. Pesos em BF16 ocupam ~64 GB de VRAM; os 32 GB restantes acomodam gradientes e o otimizador Paged AdamW. |
| **Janela de Contexto** | **16.384 tokens** com **FlashAttention-2** | O modelo analisa repositórios de software inteiros e múltiplos arquivos interligados de código em vez de funções isoladas. |
| **Compilação Paralela** | **Multiprocessamento com todos os núcleos da CPU** | Os 180 GB de RAM permitem que milhares de amostras em C/C++, Rust e Python sejam compiladas com `gcc` e `py_compile` em paralelo sem estrangular o sistema operacional. |
| **Síntese de CoT (70B)** | **vLLM FP8 na mesma GPU de 96 GB** | O modelo Teacher 70B em FP8 ocupa ~70 GB de VRAM. É possível rodá-lo localmente na GPU para sintetizar os pensamentos `<think>` a mais de 100 tokens/s antes do treino! |

---

## 2. Visão Geral dos 4 Notebooks Atualizados

Os notebooks foram calibrados especificamente para a sua GPU de 96 GB e RAM de 180 GB:

| Notebook | Objetivo | Configuração Ativa |
| :--- | :--- | :--- |
| **`01_colab_mineracao_e_aquisicao.ipynb`** | Coleta dos 4 Pilares | Streaming e download em escala total de **60.000 a 70.000 amostras** (`DiverseVul`, `PrimeVul`, `Magicoder`, regras `Semgrep` e assinaturas `YARA`). |
| **`02_colab_curadoria_validacao_cot.ipynb`** | Curadoria & CoT | Deduplicação MinHash LSH instantânea nos 180 GB de RAM, validação sintática massiva em paralelo via `gcc` e injeção do raciocínio reflexivo `<think>`. |
| **`03_colab_treinamento_qlora.ipynb`** | Treinamento 32B | Carregamento do **Qwen 2.5 Coder 32B em BF16 nativo**, LoRA ($r=64, \alpha=128$), FlashAttention-2 (16k context), Paged AdamW e checkpoints no Google Drive a cada 100 passos. |
| **`04_colab_avaliacao_merge_exportacao.ipynb`** | Avaliação & vLLM | Benchmark de recusas falsas, **fusão matemática (merge) dos pesos em BF16**, exportação GGUF e servidor local vLLM (porta 8000) pronto para VS Code e MCP. |

---

## 3. Passo a Passo de Execução no Google Colab

### Passo 1: Fazer Upload dos Notebooks para o Colab
1. Abra o navegador e acesse: [colab.research.google.com](https://colab.research.google.com)
2. Clique na aba **Upload** (ou salve os arquivos `.ipynb` na sua pasta do Google Drive).
3. Selecione os 4 arquivos `.ipynb` gerados nesta pasta.

### Passo 2: Ativar a GPU no Colab
Em cada notebook aberto:
1. No menu superior, clique em **Ambiente de execução** (Runtime) -> **Alterar tipo de ambiente de execução** (Change runtime type).
2. Em **Acelerador de hardware**, selecione:
   - **T4 GPU** (se estiver no plano gratuito).
   - **A100 GPU** ou **L4 GPU** (se for assinante Colab Pro).
3. Clique em **Salvar**.

### Passo 3: Executar em Ordem Sequencial
Execute as células uma a uma ou use `Ctrl + F9` (Executar tudo):
1. **Execute o Notebook 01**: Ele montará seu Google Drive e baixará as ~60.000 amostras brutas em minutos.
2. **Execute o Notebook 02**: Ele instalará os compiladores (`gcc`, etc.), validará o código, adicionará o raciocínio investigativo `<think>` e deixará o `train.parquet` pronto no Drive.
3. **Execute o Notebook 03**: O treinamento iniciará. Acompanhe a curva de perda (loss). A cada 100 passos, um checkpoint é gravado com segurança no Drive.
4. **Execute o Notebook 04**: Teste as respostas do modelo para vulnerabilidades e gere o arquivo `.gguf`.

---

## 4. Como Usar o Modelo Treinado no seu Computador

Após a exportação no Notebook 04:
1. Acesse o seu Google Drive na pasta `cyber_llm_project/exported_models/` e faça o download do arquivo `qwen_cyber_q4_k_m.gguf`.
2. Para rodar com o **Ollama**:
   Crie um arquivo chamado `Modelfile` no mesmo diretório:
   ```dockerfile
   FROM ./qwen_cyber_q4_k_m.gguf
   PARAMETER temperature 0.2
   PARAMETER stop "<|im_end|>"
   SYSTEM "Você é um auditor sênior de segurança e especialista em programação defensiva."
   ```
3. No seu terminal:
   ```bash
   ollama create qwen-cyber -f Modelfile
   ollama run qwen-cyber
   ```
4. Para usar no **VS Code** com **Continue.dev** ou **Cline**:
   Basta apontar para o modelo `qwen-cyber` do Ollama local (`http://localhost:11434`).

---

## 5. Estrutura Modular de Scripts Locais (`src/`)

Caso prefira inspecionar ou executar os scripts de apoio:
- [src/config.py](file:///home/rodnei/Área de trabalho/plano da ia super poderosa caseira/src/config.py): Hiperparâmetros, diretórios e detecção de GPU.
- [src/miners.py](file:///home/rodnei/Área de trabalho/plano da ia super poderosa caseira/src/miners.py): Funções de streaming de HuggingFace e clonagem de regras.
- [src/validators.py](file:///home/rodnei/Área de trabalho/plano da ia super poderosa caseira/src/validators.py): Compiladores reais em C/C++, Rust e Python.
- [src/dedup.py](file:///home/rodnei/Área de trabalho/plano da ia super poderosa caseira/src/dedup.py): Motor MinHash LSH.
- [src/cot_generator.py](file:///home/rodnei/Área de trabalho/plano da ia super poderosa caseira/src/cot_generator.py): Síntese de raciocínio investigativo `<think>`.
- [src/dataset_formatter.py](file:///home/rodnei/Área de trabalho/plano da ia super poderosa caseira/src/dataset_formatter.py): Empacotador ChatML oficial.

