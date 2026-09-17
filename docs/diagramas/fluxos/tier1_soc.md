# Fluxo de Execução - Agente Tier 1 (SOC Core)

```mermaid
flowchart TD
    A["1. Log bruto de autenticação"]
    B["2. Prompt com guardrails e schema JSON"]
    C["3. Cliente Groq / GROQ_MODEL"]
    D["4. IoCs, categoria, severidade e ação"]
    A --> B --> C --> D
```

O Tier 1 é a primeira camada analítica. O resultado é consumido por Threat Intelligence, Compliance e SOAR. Temperatura e limite de saída são definidos pelo agente e pelo cliente compartilhado.
