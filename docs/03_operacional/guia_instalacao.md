# Guia de Instalação e Execução

## Pré-requisitos
* **Python:** versão compatível com o ambiente do projeto; Python 3.10+ é recomendado.
* **Dependências:** instalar `requirements.txt` no ambiente virtual.
* **Nmap:** necessário para a auditoria Nmap/NSE e disponível no `PATH`.
* **Acesso remoto:** SSH habilitado no Linux ou WinRM configurado no Windows.
* **Groq:** `GROQ_API_KEY` obrigatória para os agentes de IA.

## Execução Automatizada (Windows)
No PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python src/app.py
```

O Flask atende por padrão em `http://127.0.0.1:5000`. O motor contínuo é executado separadamente:

```powershell
python src/engine.py
```

## Configuração do `.env`

Defina, no mínimo:

```env
VANGUARD_ADMIN_USER=admin
VANGUARD_ADMIN_PASSWORD=uma-senha-forte
GROQ_API_KEY=sua-chave
SSH_HOST=192.168.15.6
SSH_PORT=22
SSH_USER=usuario
SSH_PASSWORD=senha
SSH_HOST_KEY_FINGERPRINT=SHA256:...
```

Opcionalmente, use `GROQ_MODEL`, `MONITORAMENTO_PROTOCOLO`, `ACTIVE_DEFENSE`, `AUTO_REMEDIATION` e `GERAR_PDF`. Não versione o `.env`.

## Cadastro do fingerprint

O cadastro de um servidor obtém a chave pública antes de gravar o ativo. Confirme o fingerprint por um canal confiável. Não desative a validação de host key para contornar erro de conexão.