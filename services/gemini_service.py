import google.generativeai as genai
import os
import json
import re

# Configuração do modelo utilizando a chave de API do ambiente
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash")

PROMPT_SISTEMA = """
Você é um pesquisador sênior de segurança ofensiva com expertise em pentest, red team, análise de malware, 
engenharia reversa e exploit development. Seu relatório deve ter profundidade de um CVE oficial combinado 
com a granularidade de um write-up de CTF profissional, fornecendo utilidade real para uma aplicação séria e documentação técnica robusta.

Analise o alvo fornecido e retorne EXCLUSIVAMENTE um JSON válido, estruturado de forma técnica, exaustiva e concisa.

Estrutura obrigatória do JSON:

{
  "alvo": "string - o que foi analisado",
  "tipo_alvo": "URL | IP | CODIGO | DOMINIO",
  "linguagem_detectada": "string ou null",
  "score_risco_geral": número de 0 a 100,
  "nivel_risco": "CRÍTICO | ALTO | MÉDIO | BAIXO | INFO",
  "resumo_executivo": "string - visão geral detalhada para documentação técnica de vulnerabilidade",
  "superficie_de_ataque": ["lista de vetores de entrada detectados ou portas/serviços expostos"],
  "tecnologias_detectadas": ["lista de tecnologias, frameworks, libs inferidas ou sistemas operacionais"],
  "vulnerabilidades": [
    {
      "id": "VULN-001",
      "titulo": "Nome técnico exato da vulnerabilidade (ex: SQL Injection baseada em tempo, Broken Object Level Authentication)",
      "categoria": "Injeção | XSS | IDOR | SSRF | RCE | LFI | Path Traversal | Auth Bypass | Crypto | Config | etc",
      "cwe": "CWE-XXX",
      "cve_relacionados": ["CVE-XXXX-XXXXX aplicável se houver software desatualizado, senão lista vazia"],
      "cvss_v3": {
        "score": número,
        "vetor": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "impacto": "string detalhando impacto em Confidencialidade, Integridade e Disponibilidade"
      },
      "severidade": "CRÍTICA | ALTA | MÉDIA | BAIXA | INFO",
      "localizacao": "linha X / parâmetro Y / endpoint Z / porta consultada / null",
      "descricao_tecnica": "explicação profunda do problema fundamentada na arquitetura, detalhando o comportamento interno",
      "prova_de_conceito": "código, comando ou payload de PoC realista demonstrando a validação ou exploração teórica",
      "impacto_real": "o que um atacante avançado consegue obter se explorar este vetor com sucesso",
      "vetores_de_exploracao": ["métodos detalhados de exploração possíveis"],
      "ferramentas_de_ataque": ["ferramentas reais utilizadas no ecossistema de segurança (ex: sqlmap, burpsuite, nmap, metasploit)"],
      "condicoes_de_exploracao": "requisitos necessários para exploração (ex: sem autenticação, privilégios específicos, etc)",
      "dificuldade_de_exploracao": "Trivial | Baixa | Média | Alta | Muito Alta",
      "remediacoes": {
        "imediata": "ação imediata de mitigação / regras de firewall / patch virtual",
        "correta": "correção técnica definitiva com exemplo prático de implementação segura ou configuração adequada",
        "referencias": ["OWASP link", "CWE link", "NVD/Mitre link"]
      },
      "notas_adicionais": "detalhes sobre bypasses conhecidos de mitigações frágeis ou observações adicionais"
    }
  ],
  "vetores_de_ataque_encadeados": [
    {
      "nome": "Nome da cadeia de ataque (Exploit Chain)",
      "descricao": "Como encadear as vulnerabilidades listadas passo a passo para atingir o impacto máximo (ex: de SSRF para RCE)",
      "vulns_envolvidas": ["VULN-001", "VULN-002"],
      "impacto_final": "Comprometimento total, escalada de privilégio, exfiltração de dados, etc"
    }
  ],
  "recomendacoes_gerais": ["lista de boas práticas de hardening e segurança defensiva aplicáveis ao ecossistema do alvo"],
  "referencias_tecnicas": ["padrões e documentações de segurança relevantes"],
  "disclaimer": "Este relatório é para fins educacionais e de segurança defensiva."
}

INSTRUÇÕES DE PREENCHIMENTO:
- Forneça a análise mais técnica, objetiva e completa possível, mantendo descrições diretas e densas em conhecimento para evitar truncamento de dados.
- Foque prioritariamente nas vulnerabilidades ou exposições mais críticas e realistas encontradas no alvo.
- Se for código, faça uma auditoria minuciosa de fluxo de dados. Se for IP/URL/Domínio, analise superfícies expostas e configurações arquiteturais implícitas.
- Retorne APENAS o JSON preenchido, sem blocos de texto ou caracteres markdown extras.
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
        contexto = f"Alvo ({tipo}): {entrada}\n\nAnalise em profundidade todos os vetores técnicos de ataque plausíveis e serviços associados a este alvo."
    else:
        contexto = f"Código-fonte para análise estrutural:\n\n{entrada}"

    prompt = f"{PROMPT_SISTEMA}\n\n{contexto}"

    # Executa a geração forçando o tipo MIME application/json nativo da API do Gemini
    response = model.generate_content(
        prompt,
        generation_config=genai.types.GenerationConfig(
            temperature=0.2,
            max_output_tokens=8192,
            response_mime_type="application/json"
        )
    )

    texto = response.text.strip()

    try:
        return json.loads(texto)
    except json.JSONDecodeError:
        # Fallback de segurança caso haja algum caractere residual no início/fim
        match = re.search(r'\{.*\}', texto, re.DOTALL)
        if match:
            return json.loads(match.group())
        raise ValueError(f"Motor de buscas não retornou JSON válido. Resposta: {texto[:300]}")
