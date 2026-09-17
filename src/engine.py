import os
import sys
import re
import json
import time
import logging
import hashlib
import sqlite3
import requests
from datetime import datetime
import paramiko
import dotenv

# =============================================================================
# VANGUARD_SEC_ENGINE_VERSAO_GROQ_2026
# =============================================================================

# -----------------------------------------------------------------------------
# Resolução de Caminhos do Projeto & Importação dos Agentes de IA
# -----------------------------------------------------------------------------
RAIZ_PROJETO = os.path.dirname(os.path.abspath(__file__))
if RAIZ_PROJETO not in sys.path:
    sys.path.insert(0, RAIZ_PROJETO)

PASTA_AGENTES = os.path.join(RAIZ_PROJETO, "ai")
if PASTA_AGENTES not in sys.path:
    sys.path.insert(0, PASTA_AGENTES)

from ai.agente_auditor import executar_agente_auditor
from ai.agente_compliance import executar_agente_compliance
from ai.agente_remediacao import executar_agente_remediacao
from ai.agente_threat_intel import executar_agente_threat_intel
from ssh_utils import conectar_ssh_verificado, ip_valido, executar_comando_sudo
from soar.coletor_winrm import coletar_dados_windows

dotenv.load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("VanguardSecEngine")

RAIZ_GERAL = os.path.dirname(RAIZ_PROJETO)
PASTA_DATA = os.path.join(RAIZ_GERAL, "data")
PASTA_POLITICAS = os.path.join(RAIZ_GERAL, "politicas")
PASTA_RELATORIOS = os.path.join(RAIZ_GERAL, "outputs", "relatorios_pdf")
PASTA_PROMPTS = os.path.join(RAIZ_GERAL, "prompts")
PASTA_DOCS = os.path.join(RAIZ_GERAL, "docs")

for pasta in (PASTA_DATA, PASTA_POLITICAS, PASTA_RELATORIOS, PASTA_PROMPTS, PASTA_DOCS):
    os.makedirs(pasta, exist_ok=True)

DB_NAME = os.path.join(PASTA_DATA, "vanguard_sec.db")

MODELO_IA = "openai/gpt-oss-20b"

SSH_HOST = os.getenv("SSH_HOST")
SSH_PORT = int(os.getenv("SSH_PORT", "22"))
SSH_USER = os.getenv("SSH_USER")
SSH_PASSWORD = os.getenv("SSH_PASSWORD")
MONITORAMENTO_PROTOCOLO = os.getenv("MONITORAMENTO_PROTOCOLO", "ssh").lower()

AUTO_REMEDIATION = os.getenv("AUTO_REMEDIATION", "true").lower() == "true"
ACTIVE_DEFENSE = os.getenv("ACTIVE_DEFENSE", "true").lower() == "true"
SSH_HOST_KEY_FINGERPRINT = os.getenv("SSH_HOST_KEY_FINGERPRINT")
GERAR_PDF = os.getenv("GERAR_PDF", "true").lower() == "true"

_ULTIMO_HASH_LOG = None


def obter_credenciais_ssh() -> tuple[str, int, str, str]:
    """
    Valida e retorna (host, porta, usuario, senha) como strings garantidamente
    não-nulas. Levanta RuntimeError se alguma variável de ambiente estiver
    ausente no .env.
    """
    faltando = [
        nome for nome, valor in (
            ("SSH_HOST", SSH_HOST), ("SSH_USER", SSH_USER), ("SSH_PASSWORD", SSH_PASSWORD)
        ) if not valor
    ]
    if faltando:
        raise RuntimeError(
            f"Variáveis de ambiente ausentes no .env: {', '.join(faltando)}. "
            "Configure-as antes de iniciar o motor de varredura."
        )
    assert SSH_HOST is not None and SSH_USER is not None and SSH_PASSWORD is not None
    return SSH_HOST, SSH_PORT, SSH_USER, SSH_PASSWORD


def _validar_credenciais_ssh() -> None:
    obter_credenciais_ssh()


def inicializar_banco() -> None:
    """
    Cria a tabela `scans` com o schema completo (14 colunas de dados).
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            severidade TEXT,
            tipo_evento TEXT,
            status_sistema TEXT,
            ip_origem TEXT,
            parecer_soc TEXT,
            compliance_lgpd TEXT,
            acao_soar_gerada TEXT,
            analise_trafego TEXT,
            modelo_ia_utilizado TEXT,
            relatorio_normativo TEXT,
            log_raw TEXT,
            origem TEXT
        )
    ''')
    conn.commit()
    conn.close()


def contar_reincidencia_ip(ip: str) -> int:
    if not os.path.exists(DB_NAME):
        return 0
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scans WHERE ip_origem = ?", (ip,))
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except Exception:
        logger.exception("Falha ao consultar reincidência do IP %s", ip)
        return 0


def aplicar_bloqueio_ufw_temporal(ip_atacante: str) -> str:
    if not AUTO_REMEDIATION:
        return f"[SOAR SIMULAÇÃO] Regra UFW pendente para {ip_atacante}"

    if not ip_atacante or ip_atacante in ["127.0.0.1", "0.0.0.0", SSH_HOST]:
        return f"[SOAR SAFEGUARD] Bloqueio ignorado para IP local/servidor '{ip_atacante}'."

    if not ip_valido(ip_atacante):
        logger.warning("IP '%s' rejeitado por não ser um IPv4 válido — bloqueio abortado.", ip_atacante)
        return f"[SOAR SAFEGUARD] IP '{ip_atacante}' com formato inválido — bloqueio abortado por segurança."

    reincidencias = contar_reincidencia_ip(ip_atacante)
    if reincidencias < 2:
        return f"[SOAR THRESHOLD] IP {ip_atacante} sob observação ({reincidencias}ª ocorrência)."

    try:
        host, porta, usuario, senha = obter_credenciais_ssh()
        ssh = conectar_ssh_verificado(
            host, porta, usuario, senha, SSH_HOST_KEY_FINGERPRINT, timeout=3
        )
        _, err = executar_comando_sudo(ssh, f"ufw insert 1 deny from {ip_atacante} to any", senha)
        ssh.close()
        if "Rule inserted" in err or "Rules updated" in err or not err.strip():
            return f"[SOAR SUCCESS] IP {ip_atacante} bloqueado com sucesso no UFW."
        return f"[SOAR ERROR] Falha na injeção UFW: {err}"
    except Exception as e:
        logger.exception("Erro SSH ao aplicar bloqueio UFW para %s", ip_atacante)
        return f"[SOAR CRITICAL] Erro SSH UFW: {str(e)}"


def derrubar_sessao_ssh_ativa(ip_atacante: str) -> str:
    if not ip_atacante or ip_atacante in ["127.0.0.1", SSH_HOST]:
        return "[KILL SWITCH] IP inválido."

    if not ip_valido(ip_atacante):
        logger.warning("IP '%s' rejeitado por não ser um IPv4 válido — kill switch abortado.", ip_atacante)
        return f"[KILL SWITCH] IP '{ip_atacante}' com formato inválido — ação abortada por segurança."

    comando_find = f"ps aux | grep 'sshd:.*@{ip_atacante}' | grep -v grep | awk '{{print $2}}'"
    try:
        host, porta, usuario, senha = obter_credenciais_ssh()
        ssh = conectar_ssh_verificado(
            host, porta, usuario, senha, SSH_HOST_KEY_FINGERPRINT, timeout=3
        )
        stdin, stdout, _ = ssh.exec_command(comando_find)
        pids = [p for p in stdout.read().decode('utf-8', errors='ignore').splitlines() if p.strip().isdigit()]
        if pids:
            for pid in pids:
                executar_comando_sudo(ssh, f"kill -9 {pid}", senha)
            ssh.close()
            return f"[KILL SWITCH] Processos {pids} encerrados para o IP {ip_atacante}."
        ssh.close()
        return "[KILL SWITCH] Nenhuma sessão ativa."
    except Exception as e:
        logger.exception("Erro no kill switch para %s", ip_atacante)
        return f"[KILL SWITCH ERROR] {str(e)}"


def extrair_ip_do_log(log_texto: str, ip_servidor_padrao: str) -> str:
    match = re.search(r'(?:from|invalid user\s+\S+|-)\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', log_texto)
    if match:
        ip_encontrado = match.group(1)
        if ip_encontrado != ip_servidor_padrao:
            return ip_encontrado
    match_generico = re.search(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', log_texto)
    if match_generico:
        ip_encontrado = match_generico.group(1)
        if ip_encontrado != ip_servidor_padrao and not ip_encontrado.startswith("127."):
            return ip_encontrado
    return ip_servidor_padrao


def classificar_vetor_ataque(log_lower: str) -> str:
    if "invalid user" in log_lower:
        return "User Enumeration / Brute Force"
    if "failed" in log_lower or "unix_chkpwd" in log_lower:
        return "Brute Force (Força Bruta)"
    if "sql" in log_lower or "union" in log_lower or "select" in log_lower or "%27" in log_lower:
        return "Web Attack / SQL Injection"
    if "eval" in log_lower or r"\.\./" in log_lower:
        return "Web Attack / Path Traversal & XSS"
    return "Anomalia de Sistema"


def coletar_logs_multi_servico() -> dict:
    try:
        host, porta, usuario, senha = obter_credenciais_ssh()
    except RuntimeError:
        logger.exception("Credenciais SSH ausentes — não é possível coletar logs.")
        return {"is_ataque": False, "log_raw": "", "ip": SSH_HOST or ""}

    if MONITORAMENTO_PROTOCOLO == "winrm":
        telemetria_windows = coletar_dados_windows(host, usuario, senha)
        linhas_relevantes = [
            linha for linha in telemetria_windows.splitlines()
            if any(palavra in linha.lower() for palavra in ("failure", "failed", "audit failure"))
        ]
        log_windows = linhas_relevantes[-1].strip() if linhas_relevantes else ""
        if log_windows:
            return {
                "origem": "Windows Security / WinRM",
                "severidade": "ALTO",
                "tipo": "Falha de autenticação Windows",
                "ip": extrair_ip_do_log(log_windows, host),
                "status": "ALERTA",
                "log_raw": log_windows,
                "is_ataque": True,
            }
        return {"is_ataque": False, "log_raw": "", "ip": host}

    ssh = conectar_ssh_verificado(
        host, porta, usuario, senha, SSH_HOST_KEY_FINGERPRINT, timeout=2
    )
    try:
        ssh.connect(host, port=porta, username=usuario, password=senha, timeout=2)
        log_ssh, _ = executar_comando_sudo(
            ssh,
            "journalctl -u ssh -n 15 --no-pager 2>/dev/null | grep -iE 'Failed|Invalid|error|unix_chkpwd' | tail -n 1",
            senha
        )
        log_ssh = log_ssh.strip()
        if log_ssh and len(log_ssh) > 5:
            ssh.close()
            return {
                "origem": "SSH Service", "severidade": "ALTO",
                "tipo": classificar_vetor_ataque(log_ssh.lower()),
                "ip": extrair_ip_do_log(log_ssh, host),
                "status": "ALERTA", "log_raw": log_ssh, "is_ataque": True
            }
        ssh.close()
    except Exception:
        logger.exception("Falha ao coletar logs via SSH de %s", host)
    return {"is_ataque": False, "log_raw": "", "ip": host}


def consultar_geoip(ip: str) -> dict:
    if not ip or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127.0.0.1"):
        return {"pais": "Rede Privada", "cidade": "LAN", "provedor": "Interno"}
    try:
        res = requests.get(f"https://ip-api.com/json/{ip}?fields=status,country,city,isp", timeout=2)
        if res.status_code == 200:
            dados = res.json()
            if dados.get("status") == "success":
                return {"pais": dados.get("country"), "cidade": dados.get("city"), "provedor": dados.get("isp")}
    except Exception:
        logger.exception("Falha ao consultar GeoIP para %s", ip)
    return {"pais": "Desconhecido", "cidade": "Desconhecido", "provedor": "Desconhecido"}


def processar_esteira_completa(log_bruto: str, so_alvo: str = "Ubuntu Linux") -> dict:
    """
    Função orquestradora que executa todos os agentes em cadeia para o laboratório web e motor.
    """
    res_t1 = executar_agente_auditor(log_bruto, so_alvo)

    ip_detectado = None
    try:
        ip_detectado = res_t1.get("indicadores_ioc", {}).get("ip_origem")
    except Exception:
        pass

    alvo_intel = ip_detectado if ip_detectado else log_bruto
    res_t3_intel = executar_agente_threat_intel(str(alvo_intel))
    res_t2 = executar_agente_compliance(res_t1, so_alvo)
    res_t3_soar = executar_agente_remediacao(res_t1, res_t2, so_alvo)

    return {
        "status_geral": "concluido",
        "log_original": log_bruto,
        "modelo_execucao": MODELO_IA,
        "tier1_soc": res_t1,
        "threat_intel": res_t3_intel,
        "tier2_compliance": res_t2,
        "tier3_soar": res_t3_soar
    }


def executar_ciclo_varredura() -> None:
    global _ULTIMO_HASH_LOG
    timestamp_atual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    evento = coletar_logs_multi_servico()
    log_raw = evento.get("log_raw", "")

    hash_atual = hashlib.md5(log_raw.encode('utf-8')).hexdigest()
    if hash_atual == _ULTIMO_HASH_LOG or not evento.get("is_ataque"):
        return
    _ULTIMO_HASH_LOG = hash_atual

    ip_atacante = evento.get("ip", SSH_HOST)
    info_geo = consultar_geoip(ip_atacante)

    resultado_esteira = processar_esteira_completa(log_raw)
    severidade = str(resultado_esteira["tier1_soc"].get("severidade", "ALTO"))
    parecer_ia = str(resultado_esteira["tier1_soc"].get("acao_recomendada", "Análise executada."))

    resultado_soar = "Monitorado"
    if ACTIVE_DEFENSE and severidade in ["ALTO", "CRITICA", "Alta", "Crítica"] and AUTO_REMEDIATION:
        res_kill = derrubar_sessao_ssh_ativa(ip_atacante)
        res_ufw = aplicar_bloqueio_ufw_temporal(ip_atacante)
        resultado_soar = f"{res_kill} | {res_ufw}"

    dados_consolidados = {
        "timestamp": timestamp_atual,
        "severidade": severidade,
        "tipo_evento": evento.get("tipo"),
        "status_sistema": "ALERTA",
        "ip_origem": ip_atacante,
        "parecer_soc": parecer_ia,
        "compliance_lgpd": f"{resultado_esteira['tier2_compliance'].get('artigo_lgpd', 'Art. 46')} / {resultado_esteira['tier2_compliance'].get('controle_iso', 'ISO 27001')}",
        "acao_soar_gerada": resultado_soar,
        "analise_trafego": f"Provedor: {info_geo.get('provedor')} (País: {info_geo.get('pais')})",
        "modelo_ia_utilizado": MODELO_IA,
        "relatorio_normativo": f"Comando: {resultado_esteira['tier3_soar'].get('comando_bash', '')}",
        "log_raw": log_raw,
        "origem": evento.get("origem")
    }

    inicializar_banco()
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scans (
                timestamp, severidade, tipo_evento, status_sistema, ip_origem,
                parecer_soc, compliance_lgpd, acao_soar_gerada, analise_trafego,
                modelo_ia_utilizado, relatorio_normativo, log_raw, origem
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', tuple(dados_consolidados.values()))
        conn.commit()
        conn.close()
    except Exception:
        logger.exception("Falha ao gravar evento consolidado no banco de dados.")


if __name__ == "__main__":
    print("Motor VanguardSec AI (Groq LPU) iniciado.")
    try:
        _validar_credenciais_ssh()
    except RuntimeError as e:
        print(f"[ERRO FATAL] {e}")
        sys.exit(1)

    while True:
        try:
            executar_ciclo_varredura()
        except KeyboardInterrupt:
            break
        time.sleep(3)