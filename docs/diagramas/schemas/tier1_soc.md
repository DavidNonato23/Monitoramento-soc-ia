# Schema JSON - Agente Tier 1 (SOC Core)

O agente deve retornar um objeto JSON com os campos consumidos por `src/engine.py`:

```json
{
  "severidade": "BAIXO | MEDIO | ALTO | CRITICO",
  "tipo_evento": "Descrição da anomalia",
  "indicadores_ioc": {
    "ip_origem": "192.0.2.10",
    "usuario_alvo": "root",
    "servico": "ssh"
  },
  "acao_recomendada": "Ação analítica inicial"
}
```

`indicadores_ioc.ip_origem` pode ser nulo. O código trata campos ausentes com valores padrão.
