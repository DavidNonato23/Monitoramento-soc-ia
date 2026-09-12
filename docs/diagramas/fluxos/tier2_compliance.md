# Fluxo de Execução - Agente Tier 2 (Compliance)

​```mermaid
flowchart TD
    A["1. Ingestão de Log Bruto<br/>(Ex: Tentativa de Brute-Force SSH na borda)"]
    B["2. Camada de Prompt Tier 2<br/>Role Playing: Auditor Sênior de Compliance<br/><b>max_tokens=120 · top_p=0.1</b>"]
    C["3. Motor de Inferência (Ollama)<br/><b>Qwen 2.5:3b (Fast)</b><br/>Parâmetro crítico: Temperatura=0.2"]
    D["4. Saída Estruturada (JSON)"]

    A --> B --> C
    C -->|"Equilíbrio: Rigor Técnico vs Schema"| D
​```

**Características do Tier 2:**
- Recebe o mesmo log bruto do Tier 1, mas sob uma persona de auditoria normativa.
- Temperatura ligeiramente mais alta (0.2) que o Tier 1 para permitir raciocínio jurídico/normativo sem perder aderência ao schema.
- Mapeia o evento para artigos da LGPD e controles ISO.