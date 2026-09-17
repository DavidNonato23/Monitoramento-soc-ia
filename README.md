# VanguardSec AI — Manual Técnico Atualizado

## 1. Objetivo e estado atual

O VanguardSec AI é uma aplicação web Flask para monitoramento de servidores por SSH, análise de eventos de segurança com agentes de IA, auditorias de infraestrutura, resposta SOAR e geração de relatórios.

O caminho principal atualmente implementado é:

```text
Navegador
  -> src/app.py (Flask + HTTP Basic Auth)
  -> SQLite (data/vanguard_sec.db)
  -> Paramiko/SSH (servidores cadastrados)
  -> src/engine.py (coleta, regras, agentes e SOAR)
  -> Groq API (JSON estruturado)
  -> dashboards, auditoria, CSV e PDF
```

O sistema não depende de Streamlit ou Ollama para o fluxo principal. A IA dos agentes usa `src/groq_client.py`, com o modelo definido por `GROQ_MODEL` e, por padrão, `openai/gpt-oss-20b`.

### Diagrama da arquitetura

![Diagrama da arquitetura do VanguardSec AI](assets/diagrama.png)

## 2. Estrutura do repositório

```text
Monitoramento SSH/
├── .env                         # segredos e configuração local; não versionar
├── requirements.txt             # dependências Python
├── README.md                    # visão geral do produto
├── manual-vanguard.md           # este manual
├── verificar_sistema.py         # verificação de ambiente, imports e rotas
├── temperatura_agentes.py       # utilitário legado/de teste de temperatura
├── testar_agente.py             # utilitário legado de teste
├── atualiza orquestrador master # artefato/nota de trabalho
├── assets/                      # imagens e recursos visuais
├── data/                        # SQLite, CSV e bases de inteligência
├── docs/                        # documentação comercial, arquitetural e operacional
├── outputs/                     # backups, logs e relatórios PDF
├── politicas/                   # PDFs normativos e playbooks
├── prompts/                     # schemas JSON e testes de prompts
├── scripts/                     # inicialização, setup Linux e runner legado
├── src/
│   ├── app.py                   # aplicação Flask e endpoints
│   ├── engine.py                # motor de coleta, decisão e SOAR
│   ├── ssh_utils.py             # SSH, sudo e verificação de host key
│   ├── crypto_utils.py          # Fernet para senhas em repouso
│   ├── groq_client.py           # cliente Groq compartilhado com retry
│   ├── regras_deteccao.py       # severidade determinística e reincidência
│   ├── auditoria_utils.py       # trilha de auditoria
│   ├── database.py              # esquema legado de incidentes
│   ├── reports/ e database/     # geradores de PDF auxiliares
│   ├── soar/ e telemetry/       # módulos auxiliares SOAR/telemetria
│   ├── ai/                      # agentes especializados
│   └── templates/               # páginas Jinja2 do painel
└── tests/                       # testes automatizados
```

## 3. Documentação

### Comercial

- [Especificação dos agentes](docs/01_comercial/especificacao_agentes.md)
- [Modelo de relatório executivo](docs/01_comercial/modelo_relatorio_executivo.md)
- [Posicionamento comercial](docs/01_comercial/posicionamento_comercial.md)
- [Proposta de SLA](docs/01_comercial/proposta_sla.md)

### Arquitetura

- [Arquitetura](docs/02_arquitetura/ARQUITETURA.md)
- [Engenharia de prompts](docs/02_arquitetura/engenharia_prompts.md)
- [Visão geral](docs/02_arquitetura/visao_geral.md)

### Operacional e compliance

- [Guia de instalação](docs/03_operacional/guia_instalacao.md)
- [Adequação à LGPD](docs/04_compliance/adeq_lgpd.md)

### Diagramas de fluxo

- [Fluxo da arquitetura geral](docs/diagramas/fluxos/arquitetura_geral.md)
- [Fluxo do agente de tráfego](docs/diagramas/fluxos/agente_trafego.md)
- [Fluxo de Threat Intelligence](docs/diagramas/fluxos/threat_intel.md)
- [Fluxo Tier 1 SOC](docs/diagramas/fluxos/tier1_soc.md)
- [Fluxo Tier 2 Compliance](docs/diagramas/fluxos/tier2_compliance.md)
- [Fluxo Tier 3 SOAR](docs/diagramas/fluxos/tier3_soar.md)

### Schemas dos agentes

- [Schema do agente de tráfego](docs/diagramas/schemas/agente_trafego.md)
- [Schema de Threat Intelligence](docs/diagramas/schemas/threat_intel.md)
- [Schema Tier 1 SOC](docs/diagramas/schemas/tier1_soc.md)
- [Schema Tier 2 Compliance](docs/diagramas/schemas/tier2_compliance.md)
- [Schema Tier 3 SOAR](docs/diagramas/schemas/tier3_soar.md)

## 4. Componentes principais

### 4.1 `src/app.py`

É o ponto de entrada do painel web. Ele carrega `.env`, valida `VANGUARD_ADMIN_PASSWORD`, cria/migra tabelas SQLite, aplica HTTP Basic Auth, gerencia a frota, executa comandos SSH, expõe auditorias e gera PDFs.

```powershell
python src/app.py
```

O servidor escuta por padrão em `0.0.0.0:5000`. Acesse `http://localhost:5000`.

### 4.2 `src/engine.py`

É o motor de monitoramento contínuo. Cada ciclo:

1. lê servidores ativos de `servidores`;
2. descriptografa a senha em memória;
3. exige fingerprint de host key aprovado;
4. conecta por SSH verificado;
5. consulta eventos relevantes de `journalctl -u ssh`;
6. classifica o vetor localmente;
7. evita duplicatas por hash MD5 do log por servidor;
8. aplica `regras_deteccao.avaliar_severidade()`;
9. chama os agentes Groq;
10. coleta fluxo de rede quando a severidade é `Alta` ou `Critica`;
11. executa Kill Switch e bloqueio UFW quando habilitados;
12. grava o evento em `scans`.

```powershell
Push-Location src
python engine.py
Pop-Location
```

O ciclo aguarda 3 segundos entre varreduras. O coletor usa SSH/journalctl por padrão e pode usar WinRM com `MONITORAMENTO_PROTOCOLO=winrm`; outros vetores permanecem auxiliares.

### 4.3 `src/groq_client.py`

Centraliza chamadas ao Groq com JSON estruturado, temperatura por chamada, retry para rate limit/conexão/erro transitório e backoff de 2, 4 e 8 segundos. Erro de autenticação não é repetido.

## 5. Agentes de IA

| Arquivo | Responsabilidade |
| --- | --- |
| `agente_auditor.py` | Tier 1 SOC: IoCs, categoria, severidade e ação recomendada. |
| `agente_trafego.py` | Analisa fluxo de rede coletado por `ss`/`netstat`. |
| `agente_compliance.py` | Relaciona eventos com LGPD, ISO e controles normativos. |
| `agente_remediacao.py` | Gera recomendação/comando de remediação SOAR. |
| `agente_threat_intel.py` | Enriquece IP ou artefato com reputação e contexto. |
| `agente_nmap.py` | Executa Nmap com validação de IPv4 e analisa a saída. |
| `agente_cve_lookup.py` | Consulta vulnerabilidades de pacotes do host. |
| `agente_tls_audit.py` | Audita certificado e parâmetros TLS. |
| `agente_backup_disaster.py` | Audita backup e recuperação de desastre. |

Os agentes são importados por `app.py`/`engine.py` e usam o cliente compartilhado `groq_client.py`.

## 6. SSH, host key e segurança

### 6.1 Fluxo de host key

1. o cadastro obtém a chave pública do host sem autenticar;
2. o cadastro salva `host_key_fingerprint` no banco operacional;
3. conexões do painel usam `conectar_ssh_verificado()` e recusam chave ausente ou divergente;
4. o motor usa `SSH_HOST_KEY_FINGERPRINT` para validar o host monitorado.

Fingerprint ausente ou divergente gera `HostKeyNaoAprovada` e a conexão é recusada.

### 6.2 Credenciais

As senhas dos servidores são criptografadas com Fernet antes de serem gravadas em `servidores.senha`. A chave fica em `VANGUARD_ENCRYPTION_KEY` e a senha é descriptografada somente em memória durante uma ação SSH.

Isso protege o dado em repouso, mas não contra alguém que controle o processo Python. A recomendação futura é autenticação por chave SSH.

### 6.3 SOAR

As ações automáticas dependem de severidade `Alta`/`Critica`, `ACTIVE_DEFENSE` e `AUTO_REMEDIATION`:

- `derrubar_sessao_ssh_ativa()` procura sessões `sshd` associadas ao IP e usa `kill -9`;
- `aplicar_bloqueio_ufw_temporal()` executa `ufw insert 1 deny from IP to any`;
- ações tentam ser registradas em `auditoria_acoes`.

Use `AUTO_REMEDIATION=false` em laboratório.

## 7. Banco de dados

O banco operacional principal é `data/vanguard_sec.db`, inicializado por `app.py` e pelo motor.

### `scans`

Eventos consolidados: `id`, `timestamp`, `severidade`, `tipo_evento`, `status_sistema`, `ip_origem`, `parecer_soc`, `compliance_lgpd`, `acao_soar_gerada`, `analise_trafego`, `modelo_ia_utilizado`, `relatorio_normativo`, `log_raw`, `origem`, `severidade_ia_bruta` e `servidor_nome`.

### `servidores`

Frota monitorada: `id`, `nome`, `ip`, `porta`, `usuario`, `senha`, `funcao`, `status` e `host_key_fingerprint`.

### `agentes_logs`

Status e logs auxiliares dos agentes exibidos no painel.

### `auditoria_acoes`

Trilha de ações: `id`, `timestamp`, `ator`, `acao`, `alvo`, `justificativa` e `servidor_nome`.

Existem também `data/vanguardsec.db` e `src/database.py`, que representam um esquema legado (`incidentes`). O fluxo atual usa `vanguard_sec.db` e `scans`; não misture os dois bancos sem migração explícita.

## 8. Páginas do painel

Os templates HTML atuais herdam de `src/templates/base.html`, exceto o arquivo JSON `threat_intel.json`.

| Template | Rota | Função |
| --- | --- | --- |
| `index.html` | `/` | Visão geral, KPIs, incidentes, threat intel e gráficos. |
| `dashboard_soc.html` | `/dashboard-soc` | Dashboard SOC com eventos, servidores e agentes reais. |
| `servidores.html` | `/servidores` | Cadastro, exclusão e status da frota. |
| `servidor_detalhes.html` | `/servidor/<id>` | Comandos SSH, auditorias, host key e laudo. |
| `agentes.html` | `/agentes` | Estado dos agentes e métricas operacionais. |
| `soar.html` | `/soar` | Área de resposta e automações SOAR. |
| `laboratorio.html` | `/laboratorio-ia` | Teste de prompts e esteira de agentes. |
| `auditoria.html` | `/auditoria` | Trilha de auditoria. |
| `base.html` | compartilhado | Layout, menu, relógio e scripts comuns. |

O dashboard SOC consulta `/data/vanguard_powerbi_data.csv`, `/data/servidores.json` e `/data/agentes_status.json`. O endpoint de frota coleta CPU/load, RAM, disco e uptime por SSH verificado quando o host está online.

## 9. Rotas Flask

### Navegação

```text
GET  /
GET  /dashboard-soc
GET  /servidores
GET  /agentes
GET  /soar
GET  /laboratorio-ia
GET  /auditoria
GET  /servidor/<id>
```

### Frota e SSH

```text
POST /api/servidor/fingerprint
POST /servidor/<id>/aprovar-host-key
POST /adicionar-servidor
POST /excluir-servidor/<id>
POST /servidor/<id>/executar
GET|POST /servidor/<id>/backup
GET /servidor/<id>/certificado-pdf
```

### Agentes e auditorias

```text
POST /testar-temperatura
POST /testar-e-salvar
POST /testar-agente-auditor
POST /testar-agente-compliance
POST /testar-agente-remediacao
GET|POST /api/pentest-nmap
GET|POST /api/pentest-cve-lookup/<id>
GET|POST /api/pentest-tls-audit/<id>
GET|POST /api/pentest-backup-audit/<id>
GET|POST /api/pentest-openvas/<id>
POST /executar-esteira
```

### Dados e exportação

```text
POST /limpar-historico
GET  /data/vanguard_powerbi_data.csv
GET  /data/agentes_status.json
GET  /data/servidores.json
GET  /data/roi_metrics.json
GET  /data/threat_intel.json
GET  /download-pdf
```

As rotas operacionais são protegidas por HTTP Basic Auth.

## 10. Configuração `.env`

```env
GROQ_API_KEY=gsk_sua_chave
GROQ_MODEL=openai/gpt-oss-20b
VANGUARD_ADMIN_USER=admin
VANGUARD_ADMIN_PASSWORD=uma_senha_forte
VANGUARD_ENCRYPTION_KEY=chave_fernet_base64
AUTO_REMEDIATION=false
ACTIVE_DEFENSE=false
SSH_HOST_KEY_FINGERPRINT=SHA256:impressao_do_host_monitorado
MONITORAMENTO_PROTOCOLO=ssh
FLASK_DEBUG=false
```

Gere uma chave Fernet com:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Nunca publique `.env`, bancos, PDFs com dados reais, senhas ou logs de telemetria.

## 11. Instalação e execução

### Windows PowerShell

```powershell
cd "C:\Users\david\Desktop\Monitoramento SSH"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python src/app.py
```

Em outro terminal, para o monitor:

```powershell
cd "C:\Users\david\Desktop\Monitoramento SSH"
.\.venv\Scripts\Activate.ps1
Push-Location src
python engine.py
Pop-Location
```

### Linux/Debian

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python scripts/init_db.py
python src/app.py
```

`scripts/setup.sh` é destinado a Linux/Debian: instala Python, pip, venv, UFW, dependências e inicializa o banco.

## 12. Verificação e testes

Verificação recomendada:

```powershell
python verificar_sistema.py
```

Ela confere variáveis obrigatórias, imports dos agentes, import do motor, renderização real dos templates e rotas Flask básicas.

Testes unitários existentes:

```powershell
python -m pytest tests/test_engine.py -q
```

Os testes atuais cobrem a contagem de reincidência de IP, o agente de Threat Intelligence e o dashboard com dados reais. A suíte pode ser executada com `pytest -q`.

`scripts/run_tests.py` procura `test_prompts.py` na raiz, mas esse arquivo não está presente; o runner precisa ser atualizado antes de ser usado como suíte oficial.

## 13. Relatórios e artefatos

- `outputs/relatorios_pdf/`: certificados e laudos do painel.
- `outputs/backups/`: arquivos baixados por SSH/SFTP.
- `outputs/lab_logs/`: respostas de prompts e esteiras.
- `data/vanguard_powerbi_data.csv`: exportação consumida pelos dashboards/Power BI.
- `data/cisa_kev.json` e `data/threat_intel.json`: bases auxiliares.
- `politicas/`: PDFs de ISO 27001, LGPD e playbooks.
- `prompts/`: schemas e prompts versionados.

Os geradores em `src/reports/`, `src/database/` e `src/soar/` são auxiliares. A geração de certificado usada diretamente pelo painel está em `app.py`.

## 14. Limitações e pontos de atenção

1. O monitor principal coleta apenas o último evento relevante de `journalctl -u ssh`; não é correto afirmar que o ciclo atual monitora Nginx, FTP, Postfix e UFW simultaneamente.
2. O ciclo principal suporta SSH por padrão e WinRM quando `MONITORAMENTO_PROTOCOLO=winrm`; a coleta Windows depende de conectividade WinRM e permissões no log Security.
3. O dashboard usa dados reais de eventos, frota e agentes e coleta CPU/load, RAM, disco e uptime por host online via SSH verificado.
4. `executar_acao_servidor()`, o backup do painel e os caminhos de contenção do motor usam `conectar_ssh_verificado()`. Módulos auxiliares legados ainda podem usar `AutoAddPolicy()` e precisam ser migrados antes de serem tratados como caminhos ativos.
5. A contenção principal exige `ACTIVE_DEFENSE=true`, `AUTO_REMEDIATION=true` e severidade alta ou crítica.
6. `nmap` precisa estar instalado no sistema operacional.
7. GeoIP depende de `ip-api.com` por HTTPS e de rede externa.
8. Chamadas Groq enviam telemetria a serviço externo; revise LGPD, retenção e anonimização antes de usar logs sensíveis.
9. `database.py`, `vanguardsec.db`, `app_backup.py` e alguns geradores PDF são legados/auxiliares e não devem ser tratados como caminhos ativos sem validação.

## 15. Checklist operacional

- [ ] `.env` configurado e fora do Git.
- [ ] `VANGUARD_ADMIN_PASSWORD` forte definido.
- [ ] `VANGUARD_ENCRYPTION_KEY` armazenada com segurança.
- [ ] `GROQ_API_KEY` válida e limites conhecidos.
- [ ] servidor cadastrado com IP/porta corretos.
- [ ] fingerprint SSH conferido por canal confiável.
- [ ] `AUTO_REMEDIATION=false` durante homologação.
- [ ] permissões SSH e `sudo` revisadas.
- [ ] UFW e comandos de contenção testados em ambiente controlado.
- [ ] backup de `data/vanguard_sec.db` protegido.
- [ ] `python verificar_sistema.py` executado.
- [ ] rotas e dashboards testados com autenticação.
- [ ] política de envio de logs para Groq aprovada.

## 16. Referências internas

- [README.md](README.md): visão geral e instalação resumida.
- [docs/02_arquitetura/ARQUITETURA.md](docs/02_arquitetura/ARQUITETURA.md): arquitetura documentada.
- [docs/03_operacional/guia_instalacao.md](docs/03_operacional/guia_instalacao.md): instalação e operação.
- [src/app.py](src/app.py): aplicação Flask e rotas.
- [src/engine.py](src/engine.py): motor de monitoramento.
- [src/ssh_utils.py](src/ssh_utils.py): SSH e TOFU.
- [src/groq_client.py](src/groq_client.py): cliente de IA.
- [verificar_sistema.py](verificar_sistema.py): verificação automatizada.
