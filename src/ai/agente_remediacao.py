import os
import json
import logging
from groq_client import gerar_json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("AgenteRemediacaoTier3")

def executar_agente_remediacao(dados_tier1: dict, dados_tier2: dict, so_alvo: str = "Ubuntu Linux") -> dict:
    """
    Executa a remediação automática de Tier 3 (SOAR) gerando comandos Bash estritamente
    determinísticos e seguros utilizando a API do Groq (openai/gpt-oss-20b) com temperatura
    estrita (0.0) e garantia nativa de JSON.

    LEMBRETE DE SEGURANÇA: o `comando_bash` retornado aqui é apenas REGISTRADO pelo
    engine.py — nunca é executado automaticamente. Se decidir executar comandos
    gerados pela IA no futuro, adicione uma allowlist estrita antes.
    """
    instrucao_sistema = (
        f"Você é um Engenheiro de Resposta a Incidentes e Automação SOAR Sênior.\n"
        f"Com base na triagem do SOC (Tier 1) e na auditoria de Compliance (Tier 2), gere estritamente o comando Bash atômico e seguro para mitigar a ameaça no SO ({so_alvo}).\n"
        "Retorne ESTRITAMENTE um objeto JSON válido, sem explicações textuais ou blocos fora do JSON."
    )

    prompt = f"""
    DADOS DE TRIAGEM (TIER 1):
    {json.dumps(dados_tier1, ensure_ascii=False)}

    AVALIAÇÃO DE COMPLIANCE (TIER 2):
    {json.dumps(dados_tier2, ensure_ascii=False)}

    SCHEMA DE SAÍDA:
    {{
        "raciocinio_cot": "string resumida",
        "acao_mitigacao": "string descritiva",
        "comando_bash": "string executavel segura",
        "nivel_risco_execucao": "Baixo | Medio | Alto"
    }}
    """

    resposta_texto = "{}"
    try:
        logger.info("Enviando dados consolidados para geração de remediação no Tier 3 via Groq (openai/gpt-oss-20b)")

        resposta_texto = gerar_json(instrucao_sistema, prompt, temperatura=0.0, max_tokens=300)
        dados_estruturados = json.loads(resposta_texto)

        logger.info("Remediação de Tier 3 gerada com sucesso via Groq")
        return dados_estruturados

    except json.JSONDecodeError as je:
        logger.error(f"Erro de decodificação JSON no Agente de Remediação: {str(je)}")
        return {
            "erro_parser": "JSONDecodeError",
            "detalhes": str(je),
            "resposta_bruta": resposta_texto
        }
    except Exception as e:
        logger.error(f"Falha crítica no Agente de Remediação via Groq: {str(e)}")
        return {
            "erro_sistema": str(e)
        }
