# ZyntraVuln — Security Intelligence Engine

Ferramenta de análise de vulnerabilidades com IA (Gemini) + interface web.

## Estrutura
```

├── main.py                  # FastAPI + roteamento
├── requirements.txt
├── .env.example
├── services/
│   ├── gemini_service.py    # Análise com Gemini (prompt técnico profundo)
│   └── store.py             # Banco temporário em memória + JSON local
└── static/
    └── index.html           # Interface completa (azul/preto)
```

## Rodando local
```bash
pip install -r requirements.txt
cp .env.example .env        # Preencha GEMINI_API_KEY
uvicorn main:app --reload
# Acesse http://localhost:8000
```

## Deploy no Render
1. Suba no GitHub
2. New Web Service → conecte o repositório
3. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Environment variable: `GEMINI_API_KEY = sua_chave`

## Observação sobre o banco temporário
O arquivo `scans_temp.json` é criado em memória/disco local do Render.
Quando o servidor hiberna (plano free), os dados são perdidos — comportamento esperado.
Use `/api/recentes` para ver scans da sessão atual.

## Endpoints da API
- `GET  /`              → Interface web
- `POST /api/scan`      → { "entrada": "url, ip ou código" }
- `GET  /api/recentes`  → últimos scans da sessão
- `GET  /health`        → status do servidor
