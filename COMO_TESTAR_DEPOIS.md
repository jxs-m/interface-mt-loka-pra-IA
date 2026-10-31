# 🚀 Guia Rápido: Como Retomar e Testar a sua IA

Tudo o que fizemos foi **100% persistido no seu Google Drive** (`cyber_llm_project/`).
Pode desligar a VM do Google Colab com total tranquilidade: **nada será perdido**, pois o Google Drive é armazenamento persistente e independente do ciclo de vida da máquina.

---

## 📂 O que está salvo e seguro no seu Google Drive

Local: `/content/drive/MyDrive/cyber_llm_project/`

```text
cyber_llm_project/
├── raw_sources/                      <- Datasets brutos coletados (~29k amostras)
│   ├── sast_patches_raw.parquet
│   ├── magicoder_code.parquet
│   └── detection_rules.parquet
│
├── training_ready/                   <- Datasets curados, validados por GCC e com CoT
│   ├── train.parquet                 <- 26.129 amostras de treino
│   └── validation.parquet            <- 1.376 amostras de validação
│
├── model_checkpoints/
│   ├── checkpoint-100/ a 1000/       <- Checkpoints intermediários a cada 100 passos
│   └── qwen32b_cyber_lora_final/     <- Adaptadores LoRA finais consolidados
│       ├── adapter_config.json
│       ├── adapter_model.safetensors
│       └── tokenizer.json
│
└── exported_models/
    └── qwen32b_cyber_merged_bf16/    <- Modelo 32B completo em BF16 unificado
```

---

## 🛠️ Como Testar Quando Você Voltar

### Cenário 1: Testar no Google Colab (Quando reabrir a VM)

1. Abra um notebook no Colab, conecte sua GPU e monte o Google Drive:
   ```python
   from google.colab import drive
   drive.mount('/content/drive')
   ```

2. Instale o Unsloth:
   ```python
   !pip install --no-deps -q 'unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git'
   !pip install --no-deps -q 'xformers<0.0.29' trl peft accelerate bitsandbytes
   ```

3. Carregue o modelo treinado direto do Drive em segundos:
   ```python
   from unsloth import FastLanguageModel

   model_path = "/content/drive/MyDrive/cyber_llm_project/model_checkpoints/qwen32b_cyber_lora_final"
   model, tokenizer = FastLanguageModel.from_pretrained(
       model_name=model_path,
       max_seq_length=16384,
       load_in_4bit=False, # ou True se estiver em GPU menor
   )
   FastLanguageModel.for_inference(model)

   # Faça uma pergunta de auditoria
   prompt = "Audite a função: void vuln(char *src) { char b[16]; strcpy(b, src); }"
   msgs = [
       {"role": "system", "content": "Você é um auditor sênior de segurança e compiladores."},
       {"role": "user", "content": prompt}
   ]
   inputs = tokenizer.apply_chat_template(msgs, tokenize=True, add_generation_prompt=True, return_tensors="pt").to("cuda")
   outputs = model.generate(input_ids=inputs, max_new_tokens=400, temperature=0.1)
   print(tokenizer.decode(outputs[0][inputs.shape[1]:], skip_special_tokens=True))
   ```

---

### Cenário 2: Iniciar Servidor vLLM de Produção (Na VM ou Servidor)

```bash
python3 -m vllm.entrypoints.openai.api_server \
    --model /caminho/para/cyber_llm_project/exported_models/qwen32b_cyber_merged_bf16 \
    --served-model-name qwen32b-cyber \
    --host 0.0.0.0 --port 8000 \
    --max-model-len 16384 \
    --enable-prefix-caching \
    --gpu-memory-utilization 0.92 \
    --dtype bfloat16
```

Depois basta apontar o **VS Code (Continue.dev / Cline)** para `http://IP_DA_VM:8000/v1`!

---

### Cenário 3: Rodar Localmente no seu PC com Ollama

Caso queira rodar offline sem nuvem, utilize o arquivo `.gguf` salvo na pasta `exported_models/` do seu Drive:
```bash
ollama create qwen-cyber -f Modelfile
ollama run qwen-cyber
```

