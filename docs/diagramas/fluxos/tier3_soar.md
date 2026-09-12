# Fluxo de Execução - Agente Tier 3 (SOAR)

​```mermaid
flowchart TD
    A["1. Entrada Consolidada<br/>(Dados de IoC + Compliance dos Tiers 1 e 2)"]
    B["2. Camada de Prompt Tier 3<br/>Restrições Absolutas<br/><b>max_tokens=80 · temperatura=0.0</b>"]
    C["3. Motor de Inferência (Ollama)<br/><b>Qwen 2.5:3b (Fast)</b><br/>Parâmetro crítico: Temperatura=0.0"]
    D["4. Saída Estruturada (JSON)"]

    A --> B --> C
    C -->|"Zero criatividade / 100% Determinístico"| D
​```

**Características do Tier 3:**
- Único agente com acesso à camada de ação (comando bash sugerido).
- Temperatura 0.0 é obrigatória: qualquer alucinação aqui vira uma execução real.
- Consolida contexto dos dois tiers anteriores antes de decidir a ação de mitigação.