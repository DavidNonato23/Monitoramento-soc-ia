# VanguardSec AI — Manual Técnico e Arquitetural Completo (Expandido)

## 1. Visão Geral da Arquitetura

O **VanguardSec AI** é um sistema automatizado de SOC (Security Operations Center) e SOAR (Security Orchestration, Automation, and Response) integrado com Inteligência Artificial local. Ele foi estruturado em módulos independentes e desacoplados para garantir resiliência, modularidade e observabilidade em tempo real. O fluxo operacional interliga a coleta de telemetria em servidores-alvo até a tomada de decisão autônoma e a persistência em banco de dados centralizado.

* **Motor de Varredura (`engine.py`)**: O núcleo de processamento responsável pelo polling cíclico de logs, filtragem de eventos, invocação paralela de agentes de IA e execução de contramedidas SOAR.
* **Painel de Observabilidade (`dashboard.py`)**: Interface gráfica interativa baseada em Streamlit para auditoria visual de incidentes, filtragem por severidade/vetor e acompanhamento métrico.
* **Persistência Centralizada (`vanguard_sec.db`)**: Banco de dados SQLite unificado que armazena o histórico completo dos incidentes na tabela padronizada `scans`.

---

## 2. Camada de Coleta Multi-Vetor Expandida

O motor realiza varreduras periódicas na máquina alvo Linux Ubuntu (`192.168.15.7`) via protocolo SSH (`Paramiko`), capturando eventos de um conjunto ampliado de serviços críticos de infraestrutura e rede:

### 2.1. Vetor SSH (`journalctl`)

* **Mecanismo:** Executa comandos remotos filtrando o diário do sistema (`journalctl -u ssh`).
* **Assinaturas monitoradas:** Tentativas de autenticação falhas (`Failed`), usuários inválidos (`Invalid user`), erros de verificação de senha do sistema (`unix_chkpwd`) e falhas gerais de criptografia.

### 2.2. Vetor Web (Nginx Access Log)

* **Mecanismo:** Realiza a leitura das linhas recentes do log de acesso do servidor web (`/var/log/nginx/access.log`).
* **Assinaturas monitoradas:** Requisições contendo padrões suspeitos de ataques a aplicações web, tais como *SQL Injection* (`sql`, `union`, `select`, `%27`), execução remota de código (`eval`, `script`) e tentativas de *Path Traversal* (`\.\./`).

### 2.3. Vetor FTP (`vsftpd`)

* **Mecanismo:** Monitora o diário de eventos do servidor de transferência de arquivos (`journalctl -u vsftpd`).
* **Assinaturas monitoradas:** Erros de login, acessos negados (`denied`) e falhas de autenticação de usuários.

### 2.4. Vetor de E-mail (Postfix / SMTP)

* **Mecanismo:** Monitora os logs do serviço de corre 전자 (Postfix) via `journalctl -u postfix`.
* **Assinaturas monitoradas:** Avisos de segurança, rejeições de relay e abusos ou falhas de autenticação via SASL.

### 2.5. Vetor de Rede e Varredura de Portas (Port Scan / UFW Kernel)

* **Mecanismo:** Executa auditoria no buffer do kernel do sistema (`dmesg`) filtrando eventos do firewall.
* **Assinaturas monitoradas:** Bloqueios de pacotes pelo UFW, varreduras de portas (*portscan*) e tentativas de inundação (*SYN flood*).

---

## 3. Esteira de Inteligência Artificial Multi-Tier (Ollama LLM)

Quando um evento malicioso é identificado e validado por hash MD5 anti-duplicidade, o motor aciona de forma paralela (**`ThreadPoolExecutor`**) uma esteira com três agentes especializados executando o modelo local **`qwen2.5:3b`** via API do Ollama:

### 3.1. Tier 1 — SOC Agent

* **Função:** Atua como um analista de segurança de plantão.
* **Entrada:** Log bruto coletado.
* **Saída:** Classificação rigorosa de severidade (*ALTO*, *CRITICA*) e parecer técnico justificando a anomalia identificada.

### 3.2. Tier 2 — Compliance Agent

* **Função:** Auditoria regulatória e de conformidade normativa.
* **Entrada:** Log bruto e trechos normativos carregados da pasta de políticas (Norma ISO/IEC 27001).
* **Saída:** Identificação de artigos de conformidade violados, com destaque para a adequação à LGPD (ex: *Artigo 46*) e controles de segurança da informação.

### 3.3. Tier 3 — SOAR Agent

* **Função:** Tomada de decisão automatizada de resposta a incidentes.
* **Entrada:** Log bruto e identificação do IP de origem.
* **Saída:** Definição do comando de mitigação e mitigação corretiva baseada em scripts Bash (ex: regras de bloqueio de firewall).

---

## 4. Camada de Resposta Ativa SOAR (Automação de Defesa)

O subsistema SOAR do VanguardSec AI executa contramedidas de forma autônoma com base na severidade do incidente e no histórico de reincidências do invasor armazenado no SQLite:

* **Verificação de Reincidência (`contar_reincidencia_ip`)**: Consulta a base de dados para contabilizar quantas vezes o IP de origem já tentou violar o perímetro do servidor.
* **Bloqueio Temporal no Firewall UFW (`aplicar_bloqueio_ufw_temporal`)**: Se o IP atingir o **limiar de reincidências ($\ge 2$ ocorrências)**, o motor injeta dinamicamente uma regra de negação de tráfego na primeira posição da tabela de regras do UFW no alvo:

$$\text{sudo ufw insert 1 deny from } \text{IP\_ATACANTE} \text{ to any}$$


* **Kill Switch (`derrubar_sessao_ssh_ativa`)**: Localiza processos ativos associados ao IP invasor no subsistema SSH (`sshd:...@IP`) e encerra forçadamente os PIDs correspondentes (`kill -9 PID`), cortando conexões persistentes em andamento.

---

## 5. Persistência, Enriquecimento e Relatoria

### 5.1. Enriquecimento de GeoIP

* Consulta a API pública de geolocalização (`ip-api.com`) para mapear metadados do IP de origem (País, Cidade e Provedor de Internet/ISP), agregando contexto forense ao incidente.

### 5.2. Persistência de Dados (`vanguard_sec.db`)

* Todos os dados consolidados do ciclo de varredura são gravados na tabela unificada **`scans`**, estruturada com as seguintes colunas principais:
* `timestamp`: Data e hora exata do registro.
* `severidade`: Nível de criticidade atribuído pela IA.
* `tipo_evento`: Vetor e categoria do ataque classificado.
* `ip_origem`: Endereço de rede do invasor.
* `parecer_soc`: Análise detalhada gerada pelo Agente SOC.
* `compliance_lgpd`: Mapeamento normativo (LGPD / ISO 27001).
* `acao_soar_gerada`: Resultado das ações de bloqueio (UFW e Kill Switch).
* `log_raw`: O registro bruto original capturado.
* `origem`: Identificação do serviço afetado (SSH, Nginx, FTP, Postfix ou Kernel/UFW).



### 5.3. Relatórios Forenses em PDF (`gerar_relatorio_pdf`)

* Utiliza a biblioteca `reportlab` para gerar laudos executivos individuais em formato PDF na pasta `./relatorios_pdf/`, contendo o resumo tabular do ataque, severidade, parecer da IA e ações executadas pelo SOAR.

---

## 6. Painel de Observabilidade (Dashboard Streamlit)

O painel interativo (executado na porta `8501`) serve como interface central para os operadores de segurança:

* **Filtros Dinâmicos:** Permite segmentar os incidentes em tempo real por *Severidade*, *Tipo de Ataque* e *Serviço/Origem*.
* **KPIs Executivos:** Exibe métricas consolidadas de total de incidentes, contagem de IPs únicos maliciosos, volume de alertas críticos e status operacional do motor.
* **Visualizações Gráficas:** Gráficos de barras que mapeiam a frequência de ataques por IP de origem e a distribuição de eventos por vetor de infraestrutura.
* **Tabela de Auditoria Detalhada:** Exibição completa do banco de dados `scans` em formato tabular para rastreabilidade de ponta a ponta.

---

## 7. Escopo de Resolução Integral do VanguardSec AI

### O que o sistema resolve atualmente (Cobertura Total Implementada)

* Monitoramento automatizado multi-vetor cobrindo **SSH, Nginx (Web), FTP (vsftpd), E-mail (Postfix) e Varredura de Portas (Kernel/UFW)**.
* Detecção avançada de Força Bruta, Enumeração de Usuários, *Password Spraying*, *SQL Injection*, *Path Traversal & XSS*, Anomalias de Correio e Sondagens de Rede (*Port Scans*).
* Esteira paralela de IA local para triagem técnica e conformidade regulatória (LGPD / ISO 27001).
* Mitigação automatizada com *Kill Switch* e bloqueio dinâmico via UFW condicionado a limiar de reincidência.
* Centralização de dados em SQLite, painel Streamlit e exportação de laudos forenses em PDF.