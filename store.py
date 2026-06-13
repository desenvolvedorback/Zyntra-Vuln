"""
Banco de dados temporário em memória + JSON local.
Dados são perdidos quando o servidor Render hiberna — comportamento esperado.
"""
import json
import os
from datetime import datetime
from typing import List, Dict

DB_PATH = "scans_temp.json"
_cache: List[Dict] = []

def _carregar():
    global _cache
    if os.path.exists(DB_PATH):
        try:
            with open(DB_PATH, "r", encoding="utf-8") as f:
                _cache = json.load(f)
        except Exception:
            _cache = []

def _persistir():
    try:
        with open(DB_PATH, "w", encoding="utf-8") as f:
            json.dump(_cache[-100:], f, ensure_ascii=False, indent=2)
    except Exception:
        pass

_carregar()

def salvar_scan(entrada: str, resultado: dict) -> str:
    scan_id = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    registro = {
        "id": scan_id,
        "entrada_resumida": entrada[:200],
        "resultado": resultado,
        "criado_em": datetime.utcnow().isoformat()
    }
    _cache.append(registro)
    _persistir()
    return scan_id

def buscar_recentes(limite: int = 20) -> List[Dict]:
    return list(reversed(_cache[-limite:]))
