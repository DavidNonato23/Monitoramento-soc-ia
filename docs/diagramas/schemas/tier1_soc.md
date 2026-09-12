# Schema JSON - Agente Tier 1 (SOC Core)

​```json
{
  "indicadores_ioc": {
    "ip_origem": "STRING | null",
    "usuario_alvo": "STRING | null",
    "servico": "STRING"
  },
  "categoria_ameaca": "STRING",
  "severidade": "Baixa | Media | Alta | Critica",
  "acao_recomendada": "STRING"
}
​```

| Campo | Tipo | Descrição |
|---|---|---|
| `indicadores_ioc.ip_origem` | string \| null | IP de origem do evento, se identificado |
| `indicadores_ioc.usuario_alvo` | string \| null | Usuário/conta associada ao evento |
| `indicadores_ioc.servico` | string | Serviço/porta/protocolo envolvido |
| `categoria_ameaca` | string | Classificação livre da ameaça (ex: brute-force, scan) |
| `severidade` | enum | `Baixa` \| `Media` \| `Alta` \| `Critica` |
| `acao_recomendada` | string | Ação sugerida em texto livre |