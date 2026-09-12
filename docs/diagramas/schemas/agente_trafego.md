# Schema JSON - Agente de Tráfego

​```json
{
  "analise_trafego": {
    "ip_origem": "STRING | null",
    "porta_destino": "STRING | null",
    "protocolo": "STRING"
  },
  "padrao_anomalia": "STRING",
  "classificacao_risco": "Baixa | Media | Alta | Critica",
  "acao_recomendada": "STRING"
}
​```

| Campo | Tipo | Descrição |
|---|---|---|
| `analise_trafego.ip_origem` | string \| null | IP de origem do fluxo |
| `analise_trafego.porta_destino` | string \| null | Porta de destino observada |
| `analise_trafego.protocolo` | string | Protocolo (TCP/UDP/ICMP etc.) |
| `padrao_anomalia` | string | Padrão de anomalia identificado (ex: port scan) |
| `classificacao_risco` | enum | `Baixa` \| `Media` \| `Alta` \| `Critica` |
| `acao_recomendada` | string | Ação sugerida em texto livre |