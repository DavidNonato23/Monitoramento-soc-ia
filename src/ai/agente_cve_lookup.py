import os
import json
import logging
import requests
import paramiko
from groq_client import gerar_json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("AgenteCVELookup")

OSV_API_URL = "https://api.osv.dev/v1/query"

def coletar_pacotes_sistema_ssh(host: str, porta: int, usuario: str, senha: str) -> list[dict]:
    """
    Conecta ao servidor via SSH e extrai os principais pacotes instalados e suas versões.
    """
    pacotes = []
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=porta, username=usuario, password=senha, timeout=5)

        cmd = "dpkg-query -W -f='${Package} ${Version}\n' | grep -E 'openssh-server|openssl|nginx|apache2|python3|sudo|ufw|kernel' | head -n 15"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        linhas = stdout.read().decode('utf-8', errors='ignore').splitlines()
        ssh.close()

        for linha in linhas:
            partes = linha.strip().split()
            if len(partes) >= 2:
                pacotes.append({"package": partes[0], "version": partes[1]})

    except Exception as e:
        logger.error(f"Falha ao coletar pacotes do sistema via SSH: {str(e)}")

    return pacotes


def consultar_osv_dev(nome_pacote: str, versao: str) -> list[dict]:
    """
    Consulta a API pública da OSV.dev para identificar CVEs vinculadas ao pacote e versão.
    """
    payload = {
        "version": versao,
        "package": {
            "name": nome_pacote,
            "ecosystem": "Debian"
        }
    }
    vulnerabilidades = []
    try:
        res = requests.post(OSV_API_URL, json=payload, timeout=5)
        if res.status_code == 200:
            dados = res.json()
            vulns = dados.get("vulns", [])
            for v in vulns[:3]:
                vulnerabilidades.append({
                    "id": v.get("id"),
                    "cve": next((alias for alias in v.get("aliases", []) if alias.startswith("CVE-")), v.get("id")),
                    "resumo": v.get("summary", "Sem descrição disponível.")
                })
    except Exception as e:
        logger.warning(f"Erro ao consultar OSV.dev para {nome_pacote}: {str(e)}")

    return vulnerabilidades


def executar_auditoria_cve(host: str, porta: int, usuario: str, senha: str) -> dict:
    """
    Executa a coleta de pacotes, pesquisa de CVEs e gera a análise executiva via Groq.
    """
    pacotes = coletar_pacotes_sistema_ssh(host, porta, usuario, senha)
    relatorio_cves = []

    logger.info(f"Analisando {len(pacotes)} pacotes no host {host}...")
    for pkg in pacotes:
        cves = consultar_osv_dev(pkg["package"], pkg["version"])
        if cves:
            relatorio_cves.append({
                "pacote": pkg["package"],
                "versao_instalada": pkg["version"],
                "vulnerabilidades_encontradas": cves
            })

    instrucao_sistema = (
        "Você é um Especialista em Gestão de Vulnerabilidades e Análise de CVEs.\n"
        "Com base nos pacotes e CVEs identificadas na infraestrutura, elabore um parecer executivo "
        "com a matriz de risco e ações de atualização prioritárias.\n"
        "Retorne ESTRITAMENTE um objeto JSON válido."
    )

    prompt = f"""
    DADOS DE VARREDURA DE CVEs:
    {json.dumps(relatorio_cves, ensure_ascii=False)}

    SCHEMA DE SAÍDA:
    {{
        "total_pacotes_vulneraveis": 0,
        "nivel_risco_global": "BAIXO | MEDIO | ALTO | CRITICO",
        "cves_criticas": [
            {{
                "cve_id": "string",
                "pacote_afetado": "string",
                "impacto_estimado": "string",
                "comando_mitigacao": "string (ex: apt-get update && apt-get install --only-upgrade pacote)"
            }}
        ],
        "parecer_executivo": "string"
    }}
    """

    try:
        resposta_texto = gerar_json(instrucao_sistema, prompt, temperatura=0.0, max_tokens=1000)
        return json.loads(resposta_texto)

    except Exception as e:
        logger.error(f"Erro na análise de CVEs via Groq: {str(e)}")
        return {
            "erro": str(e),
            "dados_brutos_cve": relatorio_cves
        }
