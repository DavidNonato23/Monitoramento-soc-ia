import os
import json
import logging
from groq_client import gerar_json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("AgenteThreatIntel")

def executar_agente_threat_intel(indicadores: str) -> dict:
    """
    Executa a análise de Inteligência de Ameaças (Threat Intelligence Enrichment)
    utilizando a API do Groq (openai/gpt-oss-20b) com temperatura estrita (0.0)
    e garantia nativa de JSON.
    """
    instrucao_sistema = (
        "Você é um Analista de Inteligência de Ameaças (Threat Intel) Sênior.\n"
        "Analise o indicador ou artefato de comprometimento abaixo.\n"
        "Retorne ESTRITAMENTE um objeto JSON válido, sem comentários ou texto adicional fora do bloco."
    )

    prompt = f"""
    INDICADOR / ARTEFATO:
    {indicadores}

    SCHEMA DE SAÍDA:
    {{
        "indicador": "string",
        "reputacao": "Malicioso | Suspeito | Limpo | Desconhecido",
        "familia_malware": "string ou null",
        "campanha_associada": "string ou null",
        "nivel_confianca": "Alta | Media | Baixa"
    }}
    """

    resposta_texto = "{}"
    try:
        logger.info("Enviando indicador para análise de Threat Intelligence via Groq (openai/gpt-oss-20b)")

        resposta_texto = gerar_json(instrucao_sistema, prompt, temperatura=0.0, max_tokens=300)
        dados_estruturados = json.loads(resposta_texto)

        logger.info("Análise de Threat Intelligence concluída com sucesso via Groq")
        return dados_estruturados

    except json.JSONDecodeError as je:
        logger.error(f"Erro de decodificação JSON no Agente Threat Intel: {str(je)}")
        return {
            "erro_parser": "JSONDecodeError",
            "detalhes": str(je),
            "resposta_bruta": resposta_texto
        }
    except Exception as e:
        logger.error(f"Falha crítica no Agente Threat Intel via Groq: {str(e)}")
        return {
            "erro_sistema": str(e)
        }

def gerar_estatisticas_globais() -> dict:
    """Retorna estatísticas globais de inteligência de ameaças para o ecossistema."""
    return {
        "status": "ativo",
        "modulo": "Threat Intelligence",
        "total_iocs_monitorados": 0
    }
