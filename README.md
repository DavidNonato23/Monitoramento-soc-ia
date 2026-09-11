# VanguardSec AI - Plataforma Autônoma SOC, SOAR & Active Defense

Plataforma de segurança cibernética que monitora servidores Linux e Windows Server em tempo real, analisa ataques de invasão usando Inteligência Artificial de ultra-baixa latência via Groq LPU API (`openai/gpt-oss-20b`), bloqueia os atacantes automaticamente no firewall (SOAR) e gera laudos executivos em PDF para auditoria (LGPD e ISO 27001).

O ecossistema foi projetado sob uma arquitetura híbrida: a coleta de logs e as ações de contenção são mantidas *on-premise*, enquanto o processamento pesado de IA é feito via nuvem da Groq. Isso permite que a aplicação execute com alta performance mesmo em servidores com hardware limitado (4 GB de RAM).

---

## Diagrama da Arquitetura e Fluxo de Dados

```text
+-------------------------------------------------------------------------+
|                         SERVIDORES MONITORADOS                          |
|                  (Ubuntu Linux / Windows Server)                        |
+-------------------------------------------------------------------------+
                                    |
                       Coleta Agentless (SSH / WinRM)
                                    |
                                    v
+-------------------------------------------------------------------------+
|                        VANGUARDSEC ENGINE (Core)                        |
|   - Leitura de Logs (auth.log / journalctl)                             |
|   - Criptografia de Dados (Fernet) e Persistência SQLite                |
+-------------------------------------------------------------------------+
                                    |
                  Envio da Telemetria (JSON / Prompt)
                                    |
                                    v
+-------------------------------------------------------------------------+
|                         GROQ LPU API (Nuvem)                            |
|                       Modelo: openai/gpt-oss-20b                        |
|                                                                         |
|  [Agente Auditor] -> [Agente Trafego] -> [Agente Threat Intel]          |
|                           |                         |                   |
|                           v                         v                   |
|                 [Agente Compliance] -> [Agente Remediacao]              |
+-------------------------------------------------------------------------+
                                    |
                  Retorno Estruturado (json_object)
                                    |
                                    v
+-------------------------------------------------------------------------+
|                     AÇÕES SOAR & EXPOSIÇÃO DE DADOS                     |
|   - Active Defense: Injeção UFW e Encerramento de Sessões (Kill Switch) |
|   - Interface Web Flask: Control Center & Laboratório de IA             |
|   - Relatórios PDF e Exportação de Métricas em CSV / Power BI           |
+-------------------------------------------------------------------------+

```

---

## O que o sistema faz

* **Monitoramento Sem Agente (Agentless):** Conecta via SSH (Linux) e WinRM (Windows Server) para ler logs em tempo real sem a necessidade de instalar programas adicionais no servidor alvo.
* **Análise por IA de Alta Performance (Groq LPU):** Processa os logs com o modelo `openai/gpt-oss-20b` utilizando resposta determinística (`temperature=0.0`) e suporte nativo ao formato `json_object`.
* **Bloqueio Automático no Firewall (SOAR):** Aplica regras de bloqueio no `UFW` e encerra sessões SSH ativas de atacantes (Kill Switch) instantaneamente.
* **Geolocalização & Defesa Ativa:** Descobre a origem do IP invasor (País, Cidade e Provedor) e enriquece a análise com agentes dedicados de Threat Intelligence.
* **Laudos Executivos em PDF:** Gera certificados e relatórios de conformidade formatados na pasta `outputs/relatorios_pdf/`.
* **Painel Web Flask & Power BI Data:** Interface gráfica completa em Flask com suporte a HTTP Basic Auth, monitoramento de frota e exportação de dados para Power BI.

---

## Módulos e Agentes da Esteira Multi-Tier

| Módulo / Agente | O que ele exibe / faz |
| --- | --- |
| **Agente Nmap (`agente_nmap.py`)** | Reconhecimento de ativos, varredura de portas abertas e vulnerabilidades via scripts NSE. |
| **Agente Auditor (`agente_auditor.py`)** | Tier 1 SOC: Análise primária de logs e extração de Indicadores de Comprometimento (IoCs). |
| **Agente de Tráfego (`agente_trafego.py`)** | Tier 1.5: Inspeção de fluxo de rede e identificação de anomalias. |
| **Agente Compliance (`agente_compliance.py`)** | Tier 2: Avaliação regulatória de riscos sob a LGPD (Art. 46) e norma ISO 27001. |
| **Agente Remediação (`agente_remediacao.py`)** | Tier 3 SOAR: Geração determinística de comandos Bash atômicos para mitigação. |
| **Agente Threat Intel (`agente_threat_intel.py`)** | Análise de reputação de IoCs e enriquecimento de inteligência de ameaças. |

---

## Principais Destaques

* **Baixíssimo Consumo de Hardware:** Compatível com ambientes restritos a partir de 4 GB de RAM, pois toda a inferência de IA é realizada na nuvem via Groq LPU API.
* **Respostas em JSON Estruturado Garantido:** Todos os agentes operam com a configuração `response_format={"type": "json_object"}`, evitando falhas de parsing.
* **Suporte Dual-Platform:** Monitoramento centralizado de servidores Ubuntu (Linux) e Windows Server.
* **Kill Switch & SOAR Automático:** Atuação ativa em tempo real via UFW e encerramento automático de processos `sshd` maliciosos.
* **Exportação para Power BI:** Histórico mantido em banco SQLite (`data/vanguard_sec.db`) e exportável via endpoint `/data/vanguard_powerbi_data.csv`.

---

## Estrutura do Repositório

```text
VanguardSec-AI/
├── data/                  # Banco de dados SQLite (vanguard_sec.db)
├── outputs/               # Laudos em PDF e logs do laboratório de IA
│   ├── relatorios_pdf/
│   └── lab_logs/
├── src/
│   ├── ai/                # Agentes de IA Refatorados (Groq API / openai/gpt-oss-20b)
│   │   ├── agente_auditor.py
│   │   ├── agente_compliance.py
│   │   ├── agente_nmap.py
│   │   ├── agente_remediacao.py
│   │   ├── agente_threat_intel.py
│   │   └── agente_trafego.py
│   ├── app.py             # Painel Web Flask e Endpoints de Controle
│   ├── crypto_utils.py    # Criptografia de senhas salvas
│   ├── engine.py          # Motor orquestrador do SOAR e varredura ativa
│   └── ssh_utils.py       # Utilitários de comunicação SSH
├── .env                   # Configuração de chaves e credenciais
└── requirements.txt       # Dependências atualizadas (Groq, Flask, Paramiko, etc.)

```

---

## Pré-requisitos

* **Sistema Operacional:** Linux, Windows ou macOS.
* **Python:** Versão 3.10 ou superior.
* **Groq API Key:** Chave de API gerada no console do Groq.
* **Servidor Alvo Linux:** Ubuntu Server com SSH ativo e permissão de execução para o utilitário `ufw`.

---

## Como Instalar e Configurar

### 1. Clonar o repositório e criar o ambiente virtual

```bash
git clone https://github.com/DavidNonato23/vanguardsec-ai.git
cd vanguardsec-ai

# Criar ambiente virtual
python -m venv venv

# Ativar no Windows (PowerShell)
.\venv\Scripts\activate

# Ativar no Linux/macOS
source venv/bin/activate

```

### 2. Instalar as dependências

```bash
pip install -r requirements.txt

```

### 3. Configurar o arquivo .env

Crie ou edite o arquivo `.env` na raiz do projeto com as credenciais do ambiente:

```env
# --- Provedor de IA (Groq API) ---
GROQ_API_KEY=gsk_SEU_TOKEN_AQUI_GROQ

# --- Credenciais SSH do Servidor Monitorado ---
SSH_HOST=192.168.15.10
SSH_PORT=22
SSH_USER=servidor
SSH_PASSWORD=sua_senha_ssh_aqui

# --- Automações e Segurança ---
AUTO_REMEDIATION=true
ACTIVE_DEFENSE=true

# --- Credenciais do Painel Web (app.py) ---
VANGUARD_ADMIN_USER=admin
VANGUARD_ADMIN_PASSWORD=sua_senha_admin_aqui

# --- Criptografia SQLite ---
VANGUARD_ENCRYPTION_KEY=SuaChaveFernetGeradaAqui

```

---

## Como Executar

* **Iniciando o Motor Orquestrador SOAR (engine.py):**

```bash
python src/engine.py

```

* **Iniciando o Painel Web Command Center (Flask em http://localhost:5000):**

```bash
python src/app.py

```

---

## Autor e Desenvolvedor

**Idealização, Arquitetura & Engenharia:** David Nonato

* **GitHub:** [@DavidNonato23](https://github.com/DavidNonato23)
