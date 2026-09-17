import os
import json
import logging
import subprocess
from groq_client import gerar_json
from ssh_utils import ip_valido

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("AgenteNmap")

def executar_varredura_nmap(ip_alvo: str) -> dict:
    """
    Executa um scan real de Nmap contra ip_alvo e envia a saída bruta pra IA
    analisar risco e priorizar correção.

    CORREÇÃO DE SEGURANÇA: agora valida que ip_alvo é um IPv4 bem formado
    antes de rodar qualquer coisa. Antes, uma string malformada ou manipulada
    ia direto pro subprocess do Nmap sem checagem — o subprocess.run com lista
    de argumentos já bloqueia injeção de shell, mas sem validação o sistema
    podia tentar escanear um alvo não intencional (ex.: um valor vindo de
    outro campo por engano) sem nenhum aviso.
    """
    if not ip_valido(ip_alvo):
        logger.warning("IP '%s' rejeitado por não ser um IPv4 válido — varredura abortada.", ip_alvo)
        return {
            "host_alvo": ip_alvo,
            "status_varredura": "ip_invalido",
            "portas_e_servicos": [],
            "nivel_risco": "Indeterminado",
            "recomendacao_imediata": f"IP '{ip_alvo}' com formato inválido — varredura abortada por segurança."
        }

    logger.info(f"Iniciando varredura Nmap (com -Pn) no IP alvo: {ip_alvo}")

    comando = ["nmap", "-Pn", "-sV", "--script", "vuln", "-T4", ip_alvo]

    try:
        resultado_processo = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            check=True,
            timeout=120
        )
        saida_nmap = resultado_processo.stdout
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout na varredura Nmap de {ip_alvo}")
        return {
            "host_alvo": ip_alvo,
            "status_varredura": "timeout",
            "portas_e_servicos": [],
            "nivel_risco": "Indeterminado",
            "recomendacao_imediata": "Varredura excedeu o tempo limite (120s). Host pode estar filtrando pacotes ou ter muitas portas abertas."
        }
    except subprocess.CalledProcessError as e:
        saida_nmap = e.stdout if e.stdout else e.stderr
    except FileNotFoundError:
        logger.error("O executável do Nmap não foi encontrado no sistema.")
        return {
            "status_varredura": "nmap_ausente",
            "erro_execucao_nmap": "Nmap não instalado ou ausente no PATH."
        }

    if "0 hosts up" in saida_nmap or not saida_nmap.strip():
        return {
            "host_alvo": ip_alvo,
            "status_varredura": "host_inacessivel",
            "portas_e_servicos": [],
            "nivel_risco": "Indeterminado",
            "recomendacao_imediata": "O host alvo não respondeu ou encontra-se inacessível. Verifique o IP ou regras de firewall."
        }

    instrucao_sistema = (
        "Você é um Engenheiro de Pentest sênior. Analise a saída do Nmap fornecida e retorne APENAS "
        "um objeto JSON válido estritamente no schema solicitado."
    )

    prompt = f"""
    SAÍDA BRUTA DO NMAP:
    {saida_nmap[:5000]}

    SCHEMA DE SAÍDA OBRIGATÓRIO (retorne estritamente válido em JSON):
    {{
        "host_alvo": "{ip_alvo}",
        "portas_e_servicos": [
            {{
                "porta": "string",
                "servico": "string",
                "vulnerabilidades_detectadas": ["string"]
            }}
        ],
        "nivel_risco": "Baixo|Medio|Alto|Critico",
        "recomendacao_imediata": "string"
    }}
    """

    try:
        resposta_texto = gerar_json(instrucao_sistema, prompt, temperatura=0.0, max_tokens=600)
        return json.loads(resposta_texto)

    except Exception as e:
        logger.error(f"Falha ao processar IA para o Nmap via Groq: {str(e)}")
        return {
            "host_alvo": ip_alvo,
            "portas_e_servicos": [],
            "nivel_risco": "Baixo",
            "recomendacao_imediata": "Varredura concluída, mas sem dados suficientes para análise profunda.",
            "erro_sistema": str(e)
        }
