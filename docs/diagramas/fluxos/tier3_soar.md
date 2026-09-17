# Fluxo de Execução - Agente Tier 3 (SOAR)

```mermaid
flowchart TD
    A["1. Tier 1 + Tier 2"]
    B["2. Prompt com restrições de segurança"]
    C["3. Cliente Groq / GROQ_MODEL"]
    D["4. Ação e comando recomendado"]
    A --> B --> C --> D
```

O agente sugere ações de mitigação. A saída do LLM não é confiável por padrão; validação, allowlist e configuração de defesa são necessárias antes da execução.
