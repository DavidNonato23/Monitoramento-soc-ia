# VanguardSec AI — Plataforma SOC, SOAR & Active Defense para Pequenas Empresas

Plataforma de segurança cibernética *on-premise* que monitora servidores Linux em tempo real, executa varreduras de pentest e auditorias de conformidade, decide a severidade de eventos por **regras determinísticas** (não só por IA), bloqueia atacantes automaticamente no firewall (SOAR) e gera laudos executivos em PDF (LGPD, ISO 27001 e outras normas).

A análise em linguagem natural é feita via **Groq LPU API** (`openai/gpt-oss-20b`), o que permite rodar em hardware modesto no cliente — a inferência pesada de IA acontece na nuvem, o servidor local só coleta, decide via regras e age.

> **Nota de transparência:** este README reflete o estado real e testado do código nesta data. Seções marcadas como "Roadmap" são planejadas, não implementadas.

---

## Diagrama da Arquitetura e Fluxo de Dados

```text
+-------------------------------------------------------------------------+
|                      FROTA DE SERVIDORES (Ubuntu Linux)                 |
|              cadastrados e criptografados via Painel Web                |
+-------------------------------------------------------------------------+
                                    |
                     Coleta Agentless (SSH via Paramiko)
                                    |
                                    v
+-------------------------------------------------------------------------+
|                    VANGUARDSEC ENGINE (Core, on-premise)                |
|  - Leitura de logs (auth.log / journalctl)                              |
|  - TIER 0: regras_deteccao.py decide a SEVERIDADE REAL (determinístico) |
|  - Criptografia de credenciais (Fernet) e persistência SQLite           |
+-------------------------------------------------------------------------+
                                    |
                  Envio da telemetria já triada (JSON / Prompt)
                                    |
                                    v
+-------------------------------------------------------------------------+
|                    GROQ LPU API (Nuvem) — explicação, não decisão       |
|                       Modelo: openai/gpt-oss-20b                        |
|                                                                          |
|   [Agente Auditor] -> [Threat Intel] -> [Compliance] -> [Remediação]    |
+-------------------------------------------------------------------------+
                                    |
                    Retorno estruturado (json_object garantido)
                                    |
                                    v
+-------------------------------------------------------------------------+
|                     AÇÕES SOAR (gatilho = Tier 0, não a IA)             |
|   - Active Defense: bloqueio UFW e Kill Switch (encerra sessão SSH)     |
|   - Interface Web Flask: Command Center + Laboratório de IA             |
|   - Relatórios PDF e exportação CSV / Power BI                          |
+-------------------------------------------------------------------------+
```

**Por que a decisão de agir não vem da IA:** modelos de linguagem podem ser inconsistentes na mesma entrada. Quem decide se um evento é grave o suficiente pra acionar bloqueio automático é o `regras_deteccao.py` (contagem de tentativas numa janela de tempo + tipo de ataque) — auditável e reprodutível. A IA (Groq) entra depois, só para **explicar** o evento em linguagem natural e apoiar a auditoria de compliance.

---

## O que o sistema faz hoje

- **Monitoramento agentless (SSH/Linux):** conecta via SSH pra ler logs em tempo real, sem instalar nada no servidor monitorado.
- **Decisão de severidade por regras, não só IA:** `regras_deteccao.py` decide o gatilho de ação; o Groq complementa com explicação.
- **Análise por IA de baixa latência (Groq):** `openai/gpt-oss-20b`, temperatura 0.0, saída `json_object` garantida nativamente.
- **Auditoria de vulnerabilidades sob demanda (4 módulos reais):**
  - Nmap real (scripts NSE) — `agente_nmap.py`
  - Cruzamento de CVEs via API pública OSV.dev — `agente_cve_lookup.py`
  - Auditoria de certificado TLS/SSL real (handshake de verdade) — `agente_tls_audit.py`
  - Auditoria de backup/DRP (crontab, mounts, retenção) — `agente_backup_disaster.py`
- **Hardening determinístico** (`pentest_scanner.py`): checagens somente-leitura de configuração SSH, firewall, contas suspeitas, portas sensíveis.
- **Bloqueio automático no firewall (SOAR):** regra UFW + kill switch de sessão SSH, acionados pela severidade real (Tier 0), não pela IA.
- **Laudos executivos em PDF** e **exportação CSV para Power BI**.
- **Painel Web Flask** com autenticação obrigatória (HTTP Basic Auth), gestão de frota multi-servidor com senha criptografada (Fernet) por host.

---

## Módulos e Agentes

| Módulo | Status | O que faz |
| --- | --- | --- |
| `regras_deteccao.py` | ✅ Ativo (Tier 0) | Decide a severidade real por regras auditáveis — não é um agente de IA. |
| `pentest_scanner.py` | ✅ Ativo (Tier 0.5) | Hardening determinístico + backup/DR, somente leitura. |
| `agente_auditor.py` | ✅ Ativo (Tier 1) | Triagem inicial via IA, extrai IoCs. |
| `agente_threat_intel.py` | ✅ Ativo | Enriquecimento de reputação de IP/indicador. |
| `agente_compliance.py` | ✅ Ativo (Tier 2) | LGPD, ISO 27001, NIST CSF, PCI-DSS, CIS, HIPAA + políticas internas (`politicas/`). |
| `agente_remediacao.py` | ✅ Ativo (Tier 3) | Gera comando de mitigação sugerido (**apenas registrado, nunca executado automaticamente**). |
| `agente_nmap.py` | ✅ Ativo | Scan real via Nmap + análise de risco por IA. Valida IP antes de escanear. |
| `agente_cve_lookup.py` | ✅ Ativo | Coleta pacotes via SSH, consulta real na OSV.dev. |
| `agente_tls_audit.py` | ✅ Ativo | Handshake TLS real, analisa certificado e cifras. |
| `agente_backup_disaster.py` | ✅ Ativo | Audita crontab/backup/mounts via SSH real. |




---

## Segurança do próprio sistema

- Senhas de servidores criptografadas (Fernet) no SQLite — nunca em texto plano
- Senha de sudo nunca aparece na linha de comando (evita vazamento via `ps aux` no host remoto)
- Painel exige autenticação; recusa iniciar sem `.env` configurado (sem credencial padrão previsível)
- IP validado antes de qualquer ação de bloqueio/kill switch ou varredura Nmap (defesa contra injeção)
- Cliente Groq com retry/backoff para rate limit e validação antecipada de chave de API
- Dados de prompt/resposta **não são retidos nem usados para treino** pela Groq (confirmado na política oficial deles)

**Pendências conhecidas** (não resolvidas ainda, listadas por transparência):
- SSH usa `AutoAddPolicy` — aceita qualquer host key sem verificação (sem proteção contra MITM)
- Ações do SOAR não têm atribuição de usuário/auditoria individual ainda
- `agente_trafego.py` segue não integrado a nenhum pipeline

---

## Estrutura do Repositório

```text
VanguardSec-AI/
├── data/                     # Banco SQLite (vanguard_sec.db)
├── outputs/
│   ├── relatorios_pdf/
│   └── lab_logs/
├── politicas/                # Políticas internas da empresa (.txt/.md) lidas pelo Tier 2
├── src/
│   ├── ai/
│   │   ├── agente_auditor.py
│   │   ├── agente_backup_disaster.py
│   │   ├── agente_compliance.py
│   │   ├── agente_cve_lookup.py
│   │   ├── agente_nmap.py
│   │   ├── agente_remediacao.py
│   │   ├── agente_threat_intel.py
│   │   ├── agente_tls_audit.py
│   │   └── agente_trafego.py      # órfão, não integrado
│   ├── app.py                 # Painel Web Flask
│   ├── engine.py              # Motor multi-servidor
│   ├── groq_client.py         # Cliente Groq compartilhado (retry/backoff)
│   ├── regras_deteccao.py     # Tier 0 — severidade determinística
│   ├── pentest_scanner.py     # Tier 0.5 — hardening/backup somente leitura
│   ├── crypto_utils.py        # Criptografia Fernet
│   └── ssh_utils.py           # Execução SSH segura + validação de IP
├── .env.example
└── requirements.txt
```

---

## Pré-requisitos

- **Sistema operacional do host VanguardSec:** Linux, Windows ou macOS (é uma aplicação Python).
- **Servidor(es) monitorado(s):** Ubuntu Linux com SSH ativo e usuário com permissão de `sudo` pra `ufw`.
- **Python:** 3.10+
- **Chave de API do Groq:** gerada em [console.groq.com/keys](https://console.groq.com/keys)
- **Nmap** instalado no host que roda o VanguardSec, se for usar o `agente_nmap.py`.

---

## Como Instalar e Configurar

### 1. Clonar o repositório e criar o ambiente virtual

```bash
git clone https://github.com/DavidNonato23/vanguardsec-ai.git
cd vanguardsec-ai

python -m venv venv

# Windows (PowerShell)
.\venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

### 2. Instalar as dependências

```bash
pip install -r requirements.txt
```

### 3. Configurar o `.env`

Copie `.env.example` para `.env` na raiz do projeto e preencha:

```env
# --- Groq (API oficial) ---
GROQ_API_KEY=gsk_seu_token_aqui
GROQ_MODEL=openai/gpt-oss-20b

# --- Automação ---
AUTO_REMEDIATION=true
ACTIVE_DEFENSE=true

# --- Painel Web ---
VANGUARD_ADMIN_USER=admin
VANGUARD_ADMIN_PASSWORD=troque_por_uma_senha_forte

# --- Criptografia das senhas de servidor no banco ---
VANGUARD_ENCRYPTION_KEY=gere_com_o_comando_abaixo
```

Gere a chave de criptografia com:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Sem essas variáveis preenchidas, o sistema **recusa iniciar** de propósito — é uma proteção contra rodar com configuração insegura.

### 4. Cadastrar servidores

Servidores são adicionados pelo próprio painel web (`/servidores`), não pelo `.env` — cada um com IP, usuário e senha SSH próprios, salvos criptografados.

---

## Como Executar

```bash
python src/app.py
```
Acesse `http://localhost:5000` (peça o usuário/senha que você configurou no `.env`).

Pra rodar o motor de varredura contínua em paralelo:
```bash
python src/engine.py
```

---

## Roadmap (planejado, não implementado ainda)

- Suporte a Windows Server via WinRM
- Integração real do `agente_trafego.py` ao pipeline automático
- Verificação de host key SSH (substituir `AutoAddPolicy`)
- Auditoria de ações do SOAR com atribuição de usuário
- Autenticação SSH por chave, como alternativa à senha

---

## Autor e Desenvolvedor

**Idealização, Arquitetura & Engenharia:** David Nonato
- **GitHub:** [@DavidNonato23](https://github.com/DavidNonato23)
