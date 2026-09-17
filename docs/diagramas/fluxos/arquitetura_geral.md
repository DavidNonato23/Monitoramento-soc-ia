# Arquitetura Geral - Pipeline Multi-Agente (SOC)

```mermaid
flowchart TD
    subgraph ING["Ingestão"]
        L["Logs de autenticação SSH/Windows"]
        N["Dados de tráfego fornecidos"]
        I["IoCs e artefatos"]
    end

    T1["Tier 1 - SOC Core<br/>Cliente Groq · JSON"]
    TR["Agente de Tráfego<br/>Cliente Groq · auxiliar"]
    TI["Threat Intelligence<br/>Cliente Groq · JSON"]
    T2["Tier 2 - Compliance<br/>Cliente Groq · JSON"]
    T3["Tier 3 - SOAR<br/>Cliente Groq · recomendação"]
    OUT["Saída<br/>Dashboard / SQLite / PDF"]

    L --> T1
    N --> TR
    I --> TI
    T1 --> TI
    T1 --> T2
    TI --> T2
    T1 --> T3
    T2 --> T3
    T3 --> OUT
```

## Leitura do fluxo

1. O `engine.py` coleta `journalctl -u ssh` via SSH verificado ou eventos Windows via WinRM.
2. O Tier 1 extrai IoCs e classifica o evento.
3. Threat Intelligence enriquece o IP/artefato identificado.
4. Compliance produz o enquadramento operacional LGPD/ISO.
5. SOAR gera uma recomendação de resposta.
6. Eventos confirmados são persistidos em SQLite e apresentados no painel Flask.

O comando do Tier 3 é uma recomendação. A execução automática, quando habilitada, é limitada às ações implementadas e deve seguir política operacional e allowlist.
