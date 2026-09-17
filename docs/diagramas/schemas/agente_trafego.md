# Schema JSON - Agente de Tráfego

```json
{
  "analise_trafego": {
    "ip_origem": "192.0.2.10",
    "porta_destino": "22",
    "protocolo": "TCP"
  },
  "padrao_anomalia": "Port scan",
  "classificacao_risco": "Baixa | Media | Alta | Critica",
  "acao_recomendada": "Ação sugerida"
}
```

O agente depende de dados de tráfego fornecidos por outra coleta; ele não captura NetFlow no fluxo principal.
