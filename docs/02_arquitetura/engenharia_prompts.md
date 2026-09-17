
```text
[ Documentação do Projeto: VanguardSec AI ]
       │
       ├─► [ docs/02_arquitetura/ARQUITETURA.md ] ──► Fluxo de coleta, agentes e persistência
       └─► [ docs/02_arquitetura/engenharia_prompts.md ] ──► Contratos de saída dos agentes
                                                        │
                                                        ▼
                                         [ Status Atual Consolidado ]
                                                        │
                                                        ├─► Motor de monitoramento (src/engine.py)
                                                        ├─► Persistência SQLite (data/vanguard_sec.db)
                                                        └─► Agentes JSON via cliente Groq (src/ai/groq_client.py)

```

Basta colar o texto acima dentro de crases triplas no seu editor que ele assume o formato de diagrama estruturado em árvore.