"""
Criptografia simétrica (Fernet) para as senhas de servidores salvas no SQLite.

Antes, `servidores.senha` era gravada em texto plano no banco — o que
contradiz diretamente o discurso de compliance LGPD/ISO 27001 do próprio
produto. Agora ela é criptografada antes de ir pro banco e descriptografada
apenas no momento de abrir a conexão SSH.

IMPORTANTE:
- Isso protege a senha "em repouso" (se alguém copiar o arquivo .db ou
  fizer backup dele, não lê a senha em claro). Não protege contra alguém
  com acesso ao processo Python rodando (que tem a chave em memória).
- Para uma solução mais robusta a médio prazo, prefira autenticação via
  chave SSH (par de chaves) em vez de senha, eliminando esse problema
  por completo.
"""
import os
from cryptography.fernet import Fernet, InvalidToken

_CHAVE = os.getenv("VANGUARD_ENCRYPTION_KEY")

if not _CHAVE:
    raise RuntimeError(
        "VANGUARD_ENCRYPTION_KEY não definida no .env.\n"
        "Gere uma chave com:\n"
        "  python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"\n"
        "e adicione ao seu .env como VANGUARD_ENCRYPTION_KEY=<chave gerada> antes de rodar a aplicação.\n"
        "Guarde essa chave com cuidado: se ela for perdida, as senhas já salvas no banco "
        "não poderão mais ser descriptografadas."
    )

_fernet = Fernet(_CHAVE.encode())


def criptografar(texto_plano: str) -> str:
    return _fernet.encrypt(texto_plano.encode()).decode()


def descriptografar(texto_cifrado: str) -> str:
    try:
        return _fernet.decrypt(texto_cifrado.encode()).decode()
    except InvalidToken:
        # Compatibilidade: se já existir senha antiga gravada em texto plano
        # no banco (de antes dessa correção), tenta usar como está em vez
        # de quebrar a aplicação inteira.
        return texto_cifrado
