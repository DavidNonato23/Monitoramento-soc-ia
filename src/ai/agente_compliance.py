import os
import json
import logging
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from groq_client import gerar_json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("AgenteComplianceTier2")

RAIZ_PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASTA_POLITICAS = os.path.join(RAIZ_PROJETO, "politicas")

def carregar_politicas_locais() -> str:
    """
    Lê todos os arquivos .txt e .md da pasta 'politicas/' para injetar
    as diretrizes internas da empresa na análise do agente.
    """
    if not os.path.exists(PASTA_POLITICAS):
        return "Nenhuma política local personalizada encontrada."

    conteudo_politicas = []
    for arquivo in os.listdir(PASTA_POLITICAS):
        if arquivo.endswith(".txt") or arquivo.endswith(".md"):
            caminho_completo = os.path.join(PASTA_POLITICAS, arquivo)
            try:
                with open(caminho_completo, "r", encoding="utf-8") as f:
                    conteudo_politicas.append(f"=== POLÍTICA: {arquivo} ===\n{f.read().strip()}")
            except Exception as e:
                logger.warning(f"Falha ao ler o arquivo de política {arquivo}: {str(e)}")

    if not conteudo_politicas:
        return "Nenhum arquivo de texto (.txt ou .md) encontrado na pasta de políticas."

    return "\n\n".join(conteudo_politicas)


def executar_agente_compliance(dados_tier1: dict, so_alvo: str = "Ubuntu Linux") -> dict:
    """
    Executa a auditoria de conformidade cruzando as políticas internas da empresa (pasta politicas/)
    com as normas globais (LGPD, ISO 27001, NIST CSF, PCI-DSS, CIS Controls e HIPAA).
    """
    politicas_empresa = carregar_politicas_locais()

    instrucao_sistema = (
        "Você é um Auditor Sênior de Compliance, Governança e Cibersegurança Multi-Normas.\n"
        "Com base na triagem do SOC (Tier 1) e nas POLÍTICAS INTERNAS DA EMPRESA fornecidas, "
        "avalie as violações tanto nas regras da empresa quanto nas normas: "
        "LGPD, ISO 27001, NIST CSF/SP 800-53, PCI-DSS, CIS Controls e HIPAA.\n"
        "Retorne ESTRITAMENTE um objeto JSON válido, sem explicações textuais ou blocos fora do JSON."
    )

    prompt = f"""
    SISTEMA OPERACIONAL ALVO:
    {so_alvo}

    POLÍTICAS INTERNAS CARREGADAS DA PASTA 'politicas/':
    {politicas_empresa}

    DADOS DE TRIAGEM SOC (TIER 1):
    {json.dumps(dados_tier1, ensure_ascii=False)}

    SCHEMA DE SAÍDA:
    {{
        "raciocinio_cot": "string resumida",
        "violacao_politica_interna": "string destacando qual documento da empresa foi violado",
        "artigo_lgpd": "string (ex: Art. 46 LGPD - Segurança dos Dados)",
        "controle_iso": "string (ex: ISO 27001 A.12.6 - Gestão de Vulnerabilidades)",
        "categoria_nist": "string (ex: NIST CSF DE.CM-1 - Monitoramento contínuo / PR.AC-7)",
        "requisito_pci_dss": "string (ex: PCI-DSS Requisito 10.2 - Logs de Acesso)",
        "controle_cis": "string (ex: CIS Control 8.2 - Coleta e Auditoria de Logs)",
        "salvaguarda_hipaa": "string (ex: HIPAA 164.312(b) - Controles de Auditoria)",
        "risco_normativo": "string descritiva do impacto regulatório",
        "nivel_conformidade": "Conforme | Em Risco | Nao Conforme"
    }}
    """

    resposta_texto = "{}"
    try:
        logger.info("Enviando triagem SOC e políticas internas para avaliação via Groq (openai/gpt-oss-20b)")

        resposta_texto = gerar_json(instrucao_sistema, prompt, temperatura=0.0, max_tokens=450)
        dados_estruturados = json.loads(resposta_texto)

        logger.info("Avaliação de compliance e políticas concluída com sucesso via Groq")
        return dados_estruturados

    except json.JSONDecodeError as je:
        logger.error(f"Erro de decodificação JSON no Agente de Compliance: {str(je)}")
        return {
            "erro_parser": "JSONDecodeError",
            "detalhes": str(je),
            "resposta_bruta": resposta_texto
        }
    except Exception as e:
        logger.error(f"Falha crítica no Agente de Compliance via Groq: {str(e)}")
        return {
            "erro_sistema": str(e)
        }
