import google.generativeai as genai
import os
import json
import re

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash")

PROMPT_SISTEMA = """
Você é um pesquisador sênior de segurança ofensiva com expertise em pentest, red team, análise de malware, 
engenharia reversa e exploit development. Seu relatório deve ter profundidade de um CVE oficial combinado 
com a granularidade de um write-up de CTF profissional.

Analise o alvo fornecido e retorne EXCLUSIVAMENTE um JSON válido — sem markdown, sem texto antes ou depois.

Estrutura obrigatória do JSON:

{
  "alvo": "string - o que foi analisado",
  "tipo_alvo": "URL | IP | CODIGO | DOMINIO",
  "linguagem_detectada": "string ou null",
  "score_risco_geral": número de 0 a 100,
  "nivel_risco": "CRÍTICO | ALTO | MÉDIO | BAIXO | INFO",
  "resumo_executivo": "string - visão geral para documentação técnica",
  "superficie_de_ataque": ["lista de vetores de entrada detectados"],
  "tecnologias_detectadas": ["lista de tecnologias, frameworks, libs inferidas"],
  "vulnerabilidades": [
    {
      "id": "VULN-001",
      "titulo": "Nome técnico da vulnerabilidade",
      "categoria": "Injeção | XSS | IDOR | SSRF | RCE | LFI | Path Traversal | Auth Bypass | Crypto | Config | etc",
      "cwe": "CWE-XXX",
      "cve_relacionados": ["CVE-XXXX-XXXXX se aplicável, senão lista vazia"],
      "cvss_v3": {
        "score": número,
        "vetor": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "impacto": "string"
      },
      "severidade": "CRÍTICA | ALTA | MÉDIA | BAIXA | INFO",
      "localizacao": "linha X / parâmetro Y / endpoint Z / null",
      "descricao_tecnica": "explicação aprofundada do problema com contexto de como funciona o ataque",
      "prova_de_conceito": "código ou payload de PoC demonstrando a exploração",
      "impacto_real": "o que um atacante consegue fazer se explorar isso",
      "vetores_de_exploracao": ["lista de métodos de exploração possíveis"],
      "ferramentas_de_ataque": ["sqlmap", "burpsuite", "metasploit", etc — ferramentas reais],
      "condicoes_de_exploracao": "o que é necessário para explorar (acesso, autenticação, etc)",
      "dificuldade_de_exploracao": "Trivial | Baixa | Média | Alta | Muito Alta",
      "remediacoes": {
        "imediata": "ação para mitigar agora",
        "correta": "correção técnica definitiva com exemplo de código corrigido se aplicável",
        "referencias": ["OWASP link", "CWE link", "outros"]
      },
      "notas_adicionais": "informações extras, variantes, encadeamentos possíveis com outras vulns"
    }
  ],
  "vetores_de_ataque_encadeados": [
    {
      "nome": "nome do ataque encadeado",
      "descricao": "como encadear múltiplas vulns para maior impacto",
      "vulns_envolvidas": ["VULN-001", "VULN-002"],
      "impacto_final": "comprometimento total, escalada de privilégio, etc"
    }
  ],
  "recomendacoes_gerais": ["lista de boas práticas de segurança aplicáveis ao alvo"],
  "referencias_tecnicas": ["links OWASP, MITRE, NVD relevantes"],
  "disclaimer": "Este relatório é para fins educacionais e de segurança defensiva."
}

Seja EXAUSTIVO. Prefira falsos positivos a falsos negativos. 
Se for código, analise linha por linha em busca de qualquer vetor.
Se for URL/IP, analise parâmetros, headers implícitos, estrutura, tecnologia inferida e todos os vetores possíveis.
"""

def detectar_tipo(entrada: str) -> str:
    entrada = entrada.strip()
    if re.match(r'^https?://', entrada):
        return "URL"
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}(:\d+)?$', entrada):
        return "IP"
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+', entrada) and len(entrada) < 100 and '\n' not in entrada:
        return "DOMINIO"
    return "CODIGO"

def analisar(entrada: str) -> dict:
    tipo = detectar_tipo(entrada)

    if tipo in ("URL", "IP", "DOMINIO"):
        contexto = f"Alvo ({tipo}): {entrada}\n\nAnalise em profundidade todos os vetores de ataque possíveis para este alvo."
    else:
        contexto = f"Código-fonte para análise:\n\n{entrada}"

    prompt = f"{PROMPT_SISTEMA}\n\n{contexto}"

    response = model.generate_content(
        prompt,
        generation_config=genai.types.GenerationConfig(
            temperature=0.2,
            max_output_tokens=8192,
        )
    )

    texto = response.text.strip()
    texto = re.sub(r'^```json\s*', '', texto)
    texto = re.sub(r'^```\s*', '', texto)
    texto = re.sub(r'\s*```$', '', texto)

    try:
        return json.loads(texto)
    except json.JSONDecodeError:
        match = re.search(r'\{.*\}', texto, re.DOTALL)
        if match:
            return json.loads(match.group())
        raise ValueError(f"Motor de buscas não retornou JSON válido. Resposta: {texto[:300]}")
