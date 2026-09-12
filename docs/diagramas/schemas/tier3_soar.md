# Schema JSON - Agente Tier 3 (SOAR)

​```json
{
  "raciocinio_cot": "STRING (resumido)",
  "acao_mitigacao": "STRING",
  "comando_bash": "STRING (executável)",
  "nivel_risco_execucao": "Baixo | Medio | Alto"
}
​```

| Campo | Tipo | Descrição |
|---|---|---|
| `raciocinio_cot` | string | Cadeia de raciocínio resumida (chain-of-thought) |
| `acao_mitigacao` | string | Ação de mitigação recomendada |
| `comando_bash` | string | Comando sugerido para execução (requer aprovação/sandbox) |
| `nivel_risco_execucao` | enum | `Baixo` \| `Medio` \| `Alto` |

> ⚠️ **Nota de segurança:** `comando_bash` nunca deve ser executado automaticamente a partir da saída do LLM. Recomenda-se um humano-no-loop (ou allowlist rígida de comandos) antes de qualquer execução, dado o `nivel_risco_execucao`.