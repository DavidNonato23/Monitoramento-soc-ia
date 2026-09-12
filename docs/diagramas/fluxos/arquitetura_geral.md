# Arquitetura Geral - Pipeline Multi-Agente (SOC)

​```mermaid
flowchart TD
    subgraph ING["Ingestão"]
        L["Logs de Sistema<br/>(Syslog, Auth.log, Web)"]
        N["Netflow / Tráfego de Rede"]
        I["IoCs / Artefatos Isolados"]
    end

    T1["Tier 1 - SOC Core<br/>Qwen 2.5:3b · temp=0.1"]
    TR["Agente de Tráfego<br/>Qwen 2.5:3b · temp=0.1"]
    TI["Threat Intelligence<br/>Qwen 2.5:3b · temp=0.1"]
    T2["Tier 2 - Compliance<br/>Qwen 2.5:3b · temp=0.2"]
    T3["Tier 3 - SOAR<br/>Qwen 2.5:3b · temp=0.0"]

    OUT["Saída Consolidada<br/>(Dashboard / Alerta / Ticket)"]

    L --> T1
    N --> TR
    I --> TI

    T1 --> T2
    TR --> T2
    TI --> T2

    T1 --> T3
    T2 --> T3
    TI --> T3

    T3 --> OUT
​```

**Leitura do pipeline:**
1. **Ingestão paralela** — três fontes de dados diferentes (logs de sistema, netflow, IoCs) alimentam três agentes especializados de triagem (Tier 1, Tráfego, Threat Intel).
2. **Consolidação normativa** — as saídas de triagem convergem para o Tier 2, que reavalia o evento sob a ótica de compliance (LGPD/ISO).
3. **Decisão final** — Tier 3 (SOAR) recebe o contexto técnico bruto (Tier 1, Threat Intel) somado à leitura normativa (Tier 2) e decide, com temperatura zero, a ação de mitigação.
4. **Human-in-the-loop obrigatório** antes de qualquer `comando_bash` do Tier 3 ser executado.