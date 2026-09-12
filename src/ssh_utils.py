"""
Utilitários compartilhados para execução remota via SSH.

Correções de segurança em relação à versão anterior:
- A senha de sudo deixa de ser embutida na string do comando
  (`echo 'senha' | sudo -S ...`), que a expunha em texto plano para
  qualquer processo local no host remoto via `ps aux` / `/proc`.
  Agora ela é enviada via stdin do canal, após o sudo já ter sido
  invocado, o que não aparece na lista de processos.
- IPs são validados com uma regex estrita de IPv4 antes de entrarem
  em qualquer comando remoto, como defesa em profundidade contra
  injeção de comando via valores extraídos de logs.
"""
import re

IPV4_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)


def ip_valido(ip: str) -> bool:
    """Retorna True apenas se a string for um IPv4 bem formado (0-255 em cada octeto)."""
    return bool(ip) and bool(IPV4_REGEX.match(ip))


def executar_comando_sudo(ssh, comando: str, senha: str, timeout: int = 8):
    """
    Executa `comando` remotamente com privilégios de sudo, enviando a senha
    via stdin do canal (não pela linha de comando).

    Retorna (saida, erro) como strings decodificadas.
    """
    stdin, stdout, stderr = ssh.exec_command(
        f"sudo -S -p '' {comando}", get_pty=True, timeout=timeout
    )
    stdin.write(senha + "\n")
    stdin.flush()
    saida = stdout.read().decode("utf-8", errors="ignore")
    erro = stderr.read().decode("utf-8", errors="ignore")
    return saida, erro
