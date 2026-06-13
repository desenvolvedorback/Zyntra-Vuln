from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from services.gemini_service import analisar
from services.store import salvar_scan, buscar_recentes
import os

load_dotenv()

app = FastAPI(title="VulnScan", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")


class ScanRequest(BaseModel):
    entrada: str


@app.get("/")
def index():
    return FileResponse("static/index.html")


@app.post("/api/scan")
async def scan(body: ScanRequest):
    entrada = body.entrada.strip()
    if not entrada or len(entrada) < 3:
        raise HTTPException(status_code=400, detail="Entrada inválida.")
    if len(entrada) > 50000:
        raise HTTPException(status_code=400, detail="Entrada muito grande (máx 50.000 chars).")
    try:
        resultado = analisar(entrada)
        scan_id = salvar_scan(entrada, resultado)
        resultado["scan_id"] = scan_id
        return resultado
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro interno: {str(e)}")


@app.get("/api/recentes")
def recentes(limite: int = 10):
    return buscar_recentes(min(limite, 50))


@app.get("/health")
def health():
    return {"status": "online"}
