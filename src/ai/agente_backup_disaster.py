import os
import json
import logging
import paramiko
from typing import Any
from groq_client import gerar_json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("AgenteBackupDisaster")


def inspecionar_backup_ssh(host: str, porta: int, usuario: str, senha: str) -> dict[str, Any]:
    """
    Conecta ao servidor remoto via SSH para coletar evidências sobre
    rotinas de backup, crontab, logs de backup e montagens de disco.
    """
    dados_coletados = {
        "host": host,
        "crontab_root": "",
        "backups_locais_encontrados": [],
        "espaco_disco": "",
        "ponto_montagem_remoto": False
    }

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=porta, username=usuario, password=senha, timeout=5)

        _, stdout, _ = ssh.exec_command("crontab -l 2>/dev/null || cat /etc/crontab")
        dados_coletados["crontab_root"] = stdout.read().decode('utf-8', errors='ignore').strip() or "Nenhuma rotina agendada no crontab."

        cmd_find = r"find /var/backups /tmp /opt /home -maxdepth 2 -type f \( -name '*.tar*' -o -name '*.bak' -o -name '*.sql' \) -mtime -30 2>/dev/null | head -n 10"
        _, stdout, _ = ssh.exec_command(cmd_find)
        arquivos = stdout.read().decode('utf-8', errors='ignore').splitlines()
        dados_coletados["backups_locais_encontrados"] = arquivos

        _, stdout, _ = ssh.exec_command("df -h /")
        dados_coletados["espaco_disco"] = stdout.read().decode('utf-8', errors='ignore').strip()

        _, stdout, _ = ssh.exec_command("mount | grep -E 'nfs|cifs|smb|sshfs'")
        mounts = stdout.read().decode('utf-8', errors='ignore').strip()
        dados_coletados["ponto_montagem_remoto"] = bool(mounts)

        ssh.close()

    except Exception as e:
        logger.error(f"Falha na inspeção SSH de backup em {host}: {str(e)}")
        dados_coletados["erro_ssh"] = str(e)

    return dados_coletados


def executar_auditoria_backup(host: str, porta: int, usuario: str, senha: str) -> dict[str, Any]:
    """
    Executa a auditoria de backup/DRP e submete as evidências ao Groq para avaliação do Plano de Desastre.
    """
    dados_evidencia = inspecionar_backup_ssh(host, porta, usuario, senha)

    instrucao_sistema = (
        "Você é um Especialista em Continuidade de Negócios, Backup e Plano de Recuperação de Desastre (DRP).\n"
        "Avalie as evidências de rotinas agendadas, retenção de cópias de segurança, redundância e riscos de RPO/RTO.\n"
        "Retorne ESTRITAMENTE um objeto JSON válido."
    )

    prompt = f"""
    EVIDÊNCIAS DE BACKUP COLETADAS NO SERVIDOR:
    {json.dumps(dados_evidencia, ensure_ascii=False)}

    SCHEMA DE SAÍDA:
    {{
        "politica_backup_ativa": true,
        "frequencia_identificada": "string (ex: Diária via Cron | Nenhuma)",
        "risco_rpo_rto": "BAIXO | MEDIO | ALTO | CRITICO",
        "redundancia_offsite": "Presente | Ausente | Parcial",
        "vulnerabilidades_drp": [
            "string"
        ],
        "recomendacoes_melhoria": [
            "string"
        ],
        "parecer_executivo": "string"
    }}
    """

    try:
        resposta_texto = gerar_json(instrucao_sistema, prompt, temperatura=0.0, max_tokens=400)
        return json.loads(resposta_texto)

    except Exception as e:
        logger.error(f"Erro na análise de Backup/DRP via Groq: {str(e)}")
        return {
            "erro": str(e),
            "dados_evidencia": dados_evidencia
        }
