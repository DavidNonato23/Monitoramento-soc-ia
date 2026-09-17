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
import base64
import hashlib
import paramiko
import re


class HostKeyNaoAprovada(Exception):
    """Indica que a chave SSH do host ainda não foi aprovada ou mudou."""

    def __init__(self, host: str, fingerprint: str):
        super().__init__(f"Chave SSH não aprovada para {host}: {fingerprint}")
        self.host = host
        self.fingerprint = fingerprint

IPV4_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)


def ip_valido(ip: str) -> bool:
    """Retorna True apenas se a string for um IPv4 bem formado (0-255 em cada octeto)."""
    return bool(ip) and bool(IPV4_REGEX.match(ip))


def fingerprint_chave_host(chave: paramiko.PKey) -> str:
    """Retorna a impressão SHA-256 compatível com o formato do OpenSSH."""
    digest = hashlib.sha256(chave.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def obter_fingerprint_host(host: str, porta: int = 22, timeout: int = 5) -> str:
    """Obtém a chave pública do host sem autenticar o usuário."""
    transporte = paramiko.Transport((host, int(porta)))
    try:
        transporte.start_client(timeout=timeout)
        return fingerprint_chave_host(transporte.get_remote_server_key())
    finally:
        transporte.close()


def conectar_ssh_verificado(
    host: str,
    porta: int,
    usuario: str,
    senha: str,
    fingerprint_aprovado: str | None,
    timeout: int = 5,
):
    """Autentica via SSH somente depois de validar a chave pública pinada."""
    if not fingerprint_aprovado:
      raise HostKeyNaoAprovada(host, obter_fingerprint_host(host, porta, timeout))

    transporte = paramiko.Transport((host, int(porta)))
    try:
        transporte.start_client(timeout=timeout)
        chave_remota = transporte.get_remote_server_key()
        fingerprint_atual = fingerprint_chave_host(chave_remota)
        if fingerprint_atual != fingerprint_aprovado:
            raise HostKeyNaoAprovada(host, fingerprint_atual)
        transporte.auth_password(usuario, senha)
        if not transporte.is_authenticated():
            raise paramiko.AuthenticationException("Falha na autenticação SSH.")

        cliente = paramiko.SSHClient()
        cliente._transport = transporte
        return cliente
    except Exception:
        transporte.close()
        raise


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
