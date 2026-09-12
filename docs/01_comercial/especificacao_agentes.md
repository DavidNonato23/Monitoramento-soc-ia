
```markdown
# 🤖 Especificação Técnica dos Agentes de IA (`src/ai/`)

O VanguardSec AI delega a inteligência de segurança a agentes modulares especializados. Cada agente opera com escopo restrito, garantindo previsibilidade e alto desempenho local.

## 1. Agente Auditor (Tier 1 - SOC Core)
* **Arquivo:** `src/ai/agente_auditor.py`
* **Objetivo:** Realizar a triagem inicial de logs brutos de serviços (Auth, SSH, Syslog).
* **Parâmetros de Inferência:** Temperatura `0.1` (foco em extração estruturada).
* **Schema de Saída (JSON):**
  ```json
  {
    "severidade": "BAIXO | MEDIO | ALTO | CRITICO",
    "tipo_evento": "Descrição da anomalia",
    "indicadores_ioc": {
      "ip_origem": "0.0.0.0",
      "usuario_alvo": "root",
      "servico": "ssh"
    },
    "acao_recomendada": "Ação analítica inicial"
  }

```

## 2. Agente de Tráfego (Tier 1.5 - Rede)

* **Arquivo:** `src/ai/agente_trafego.py`
* **Objetivo:** Analisar anomalias de largura de banda, conexões suspeitas e varreduras de porta.
* **Schema de Saída (JSON):**
```json
{
  "anomalia_detectada": true,
  "padrao_trafego": "SYN Flood / Port Scan / Normal",
  "score_risco": 8.5
}

```



## 3. Agente de Threat Intelligence

* **Arquivo:** `src/ai/agente_threat_intel.py`
* **Objetivo:** Cruzar indicadores de comprometimento com bases de inteligência e histórico local.
* **Schema de Saída (JSON):}**
```json
{
  "reputacao": "Malicioso | Conhecido | Confiável",
  "campanha_associada": "Brute Force Botnet",
  "contexto_historico": "Reincidente na base local"
}

```



## 4. Agente de Compliance (Tier 2 - Governança)

* **Arquivo:** `src/ai/agente_compliance.py`
* **Objetivo:** Mapear o impacto regulatório frente à **LGPD (Art. 46)** e diretrizes da **ISO 27001**.
* **Schema de Saída (JSON):**
```json
{
  "artigo_lgpd": "Artigo 46 - Segurança e Privacidade",
  "controle_iso": "Controle A.12.6 - Gestão de Vulnerabilidades",
  "risco_normativo": "Moderado a Alto"
}

```



## 5. Agente de Remediação (Tier 3 - SOAR)

* **Arquivo:** `src/ai/agente_remediacao.py`
* **Objetivo:** Gerar comandos de mitigação atômicos. Opera obrigatoriamente com **temperatura `0.0**` para eliminar alucinações.
* **Schema de Saída (JSON):**
```json
{
  "comando_bash": "sudo ufw deny from 192.168.1.50 to any",
  "acao_soar": "Bloqueio de IP e Kill Switch SSH"
}

```



```

---

### 2. `docs/03_operacional/manual_api_flask.md`
```markdown
# 🔌 Manual de Referência da API & Rotas do Flask (`src/app.py`)

O painel web e o motor do VanguardSec AI comunicam-se através de rotas RESTful integradas no ecossistema Flask.

## Endpoints de Teste de Laboratório (POST)
* **/testar-agente-auditor**
  * *Payload Form:* `prompt` (String contendo o log bruto).
  * *Retorno:* JSON com o laudo de extração de IoCs do Tier 1.
* **/testar-agente-compliance**
  * *Retorno:* Avaliação regulatória simulada baseada em normas LGPD/ISO.
* **/testar-agente-remediacao**
  * *Retorno:* Script Bash seguro de bloqueio de perímetro.
* **/executar-esteira**
  * *Payload Form:* `prompt` (log bruto), `system` (sistema operacional alvo).
  * *Retorno:* JSON consolidado com o pipeline de ponta a ponta (Tier 1 ao Tier 3) e salvamento automático em `outputs/lab_logs/`.

## Endpoints de Monitoramento e Métricas (GET)
* **/data/agentes_status.json**
  * *Retorno:* Status em tempo real dos agentes da frota e verificação de conectividade dos hosts via socket TCP.
* **/data/roi_metrics.json**
  * *Retorno:* Métricas consolidadas de economia de horas de análise humana, MTTR e estimativa de economia financeira.
* **/data/vanguard_powerbi_data.csv**
  * *Retorno:* Exportação completa do banco de dados SQLite (`scans`) formatada em CSV para consumo em ferramentas de BI.
* **/servidor/<int:id>/certificado-pdf**
  * *Retorno:* Download imediato do laudo oficial de conformidade em PDF gerado dinamicamente via ReportLab.

```

---

### 3. `docs/03_operacional/playbooks_incidentes.md`

```markdown
# 🚨 Playbooks de Resposta a Incidentes (SOAR)

Procedimentos operacionais padronizados executados de forma autônoma ou via ChatOps pelo VanguardSec AI diante de eventos críticos.

## Playbook 1: Ataque de Força Bruta / Enumeração SSH
1. **Detecção (Tier 1):** Múltiplas falhas de autenticação (`Failed password` ou `Invalid user`) originadas de um mesmo IP em curto espaço de tempo.
2. **Enriquecimento (Threat Intel):** Validação de reincidência na tabela local `scans`. Se o IP ultrapassar o limiar de ocorrências:
3. **Contenção Automática (Tier 3):**
   - Encerramento imediato de sessões ativas do atacante via script Kill Switch (`kill -9 PID` em processos `sshd`).
   - Inserção prioritária de regra restritiva no firewall do sistema (`sudo ufw insert 1 deny from <IP> to any`).
4. **Governança (Tier 2):** Registro do incidente com menção direta à violação das diretrizes de controle de acesso da LGPD e ISO 27001, gerando log em auditoria e laudo PDF.

## Playbook 2: Varredura de Portas / Anomalia de Rede
1. **Detecção:** Alertas capturados via logs do kernel/UFW (`dmesg` ou tráfego suspeito mapeado pelo Agente de Tráfego).
2. **Mitigação:** Isolação preventiva do host ou bloqueio temporário do sub-rede de origem, com notificação síncrona gerada no painel de controle e persistência em banco de dados relacional.

```

---

### 4. `docs/01_comercial/proposta_valor_completa.md`

```markdown
# 💼 Proposta de Valor e Posicionamento Comercial

## Para Quem É o Produto?
* **Empresas de Médio e Grande Porte (Mid-Market / Enterprise):** Que precisam cumprir rigorosamente as exigências da LGPD e normas internacionais (ISO 27001), mas não possuem orçamento para manter um SOC tradicional 24/7 com dezenas de analistas humanos.
* **Provedores de Serviços de TI e MSPs:** Que desejam ofertar um serviço de monitoramento de segurança gerenciado (Managed Security Services) com alta margem de lucro e automação por IA.

## Retorno Sobre o Investimento (ROI)
O sistema calcula dinamicamente as métricas de economia com base no volume de eventos mitigados:
* **Redução de MTTR:** De horas de triagem manual para frações de segundo (`0.4s`).
* **Eliminação de Falsos Positivos:** Graças à validação em múltiplas camadas especializadas.
* **Custo Operacional Zero em Nuvem:** Operação 100% on-premise com modelos locais, eliminando custos recorrentes de tokens de APIs comerciais (como OpenAI ou Anthropic).

```