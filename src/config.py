"""
Configurações Globais do Pipeline de IA em Cibersegurança para Google Colab.
Mapeia caminhos locais, Google Drive, detecção de GPU e hiperparâmetros.
"""

import os
import torch

# Caminhos no Google Colab
COLAB_DRIVE_BASE = "/content/drive/MyDrive/cyber_llm_project"
LOCAL_CACHE_DIR = "/content/cyber_cache"

# Subdiretórios no Google Drive
DIR_RAW_SOURCES = os.path.join(COLAB_DRIVE_BASE, "raw_sources")
DIR_PROCESSED = os.path.join(COLAB_DRIVE_BASE, "processed_data")
DIR_COT_ENRICHED = os.path.join(COLAB_DRIVE_BASE, "cot_enriched")
DIR_TRAINING_READY = os.path.join(COLAB_DRIVE_BASE, "training_ready")
DIR_CHECKPOINTS = os.path.join(COLAB_DRIVE_BASE, "model_checkpoints")
DIR_FINAL_MODEL = os.path.join(DIR_CHECKPOINTS, "qwen_cyber_lora_final")

# Diretórios locais para processamento de alta velocidade
LOCAL_TMP_CODE = os.path.join(LOCAL_CACHE_DIR, "syntax_checks")

# Lista de CWEs críticas prioritárias (Pilar SAST)
CRITICAL_CWES = {
    "CWE-119",  # Buffer Overflow (Improper Restriction of Operations within Bounds)
    "CWE-120",  # Classic Buffer Overflow
    "CWE-125",  # Out-of-bounds Read
    "CWE-787",  # Out-of-bounds Write
    "CWE-416",  # Use After Free
    "CWE-476",  # NULL Pointer Dereference
    "CWE-190",  # Integer Overflow or Wraparound
    "CWE-89",   # SQL Injection
    "CWE-78",   # OS Command Injection
    "CWE-22",   # Path Traversal
    "CWE-918",  # Server-Side Request Forgery (SSRF)
    "CWE-502",  # Deserialization of Untrusted Data
    "CWE-79",   # Cross-Site Scripting (XSS)
    "CWE-287",  # Improper Authentication
    "CWE-863",  # Incorrect Authorization
}

def detect_colab_hardware():
    """
    Detecta a GPU disponível no Colab e calibra o treinamento para a infraestrutura
    de alta capacidade (96 GB VRAM + 180 GB RAM).
    """
    if not torch.cuda.is_available():
        return {
            "gpu_name": "CPU",
            "vram_gb": 0,
            "recommended_model": "Qwen/Qwen2.5-Coder-7B-Instruct",
            "load_in_4bit": True,
            "batch_size": 1,
            "max_seq_length": 2048,
            "tier": "CPU Debug"
        }
    
    device_name = torch.cuda.get_device_name(0)
    vram_bytes = torch.cuda.get_device_properties(0).total_memory
    vram_gb = vram_bytes / (1024 ** 3)
    
    # Detecção de GPU de 96 GB (NVIDIA Blackwell / RTX 6000 Ada / H100 / A100-SXM)
    if vram_gb >= 75.0:
        return {
            "gpu_name": device_name,
            "vram_gb": round(vram_gb, 2),
            "recommended_model": "Qwen/Qwen2.5-Coder-32B-Instruct",
            "precision": "bfloat16",
            "load_in_4bit": False, # Treinamento nativo em BF16 sem ruído numérico de quantização!
            "batch_size": 2,
            "grad_accum_steps": 8,
            "max_seq_length": 16384, # Janela completa de 16k tokens com FlashAttention-2
            "use_flash_attn_2": True,
            "lora_r": 64,
            "lora_alpha": 128,
            "tier": "Enterprise / 96 GB VRAM",
            "description": f"Infraestrutura de Elite: {device_name} ({round(vram_gb)} GB VRAM). Fine-tuning em BF16 nativo do Qwen 2.5 Coder 32B com contexto de 16k tokens!"
        }
    elif vram_gb >= 35.0:
        return {
            "gpu_name": device_name,
            "vram_gb": round(vram_gb, 2),
            "recommended_model": "Qwen/Qwen2.5-Coder-32B-Instruct",
            "precision": "4bit",
            "load_in_4bit": True,
            "batch_size": 2,
            "grad_accum_steps": 4,
            "max_seq_length": 8192,
            "use_flash_attn_2": True,
            "lora_r": 64,
            "lora_alpha": 128,
            "tier": "Pro / 40 GB VRAM",
            "description": f"{device_name} ({round(vram_gb)} GB VRAM). Qwen 32B em 4-bit QLoRA."
        }
    else:
        return {
            "gpu_name": device_name,
            "vram_gb": round(vram_gb, 2),
            "recommended_model": "Qwen/Qwen2.5-Coder-7B-Instruct",
            "precision": "4bit",
            "load_in_4bit": True,
            "batch_size": 2,
            "grad_accum_steps": 8,
            "max_seq_length": 4096,
            "use_flash_attn_2": False,
            "lora_r": 32,
            "lora_alpha": 64,
            "tier": "Standard / 16 GB VRAM",
            "description": f"{device_name} ({round(vram_gb)} GB VRAM). Qwen 7B QLoRA."
        }

def ensure_colab_directories():
    """Garante que todos os diretórios necessários no Google Drive e no cache local existam."""
    dirs = [
        COLAB_DRIVE_BASE,
        DIR_RAW_SOURCES,
        DIR_PROCESSED,
        DIR_COT_ENRICHED,
        DIR_TRAINING_READY,
        DIR_CHECKPOINTS,
        DIR_FINAL_MODEL,
        LOCAL_CACHE_DIR,
        LOCAL_TMP_CODE
    ]
    for d in dirs:
        try:
            os.makedirs(d, exist_ok=True)
        except Exception as e:
            print(f"[Aviso] Não foi possível criar {d} (o Google Drive pode não estar montado ainda): {e}")

