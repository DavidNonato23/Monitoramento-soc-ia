# Fluxo de Execução - Agente de Tráfego (Tier 1.5)

​```mermaid
flowchart TD
    A["1. Ingestão de Netflow / Logs de Rede<br/>(Conexões TCP/UDP, Port Scans, Fluxos)"]
    B["2. Camada de Prompt & Guardrails<br/>Especialista em Tráfego<br/>Enforced JSON Schema"]
    C["3. Motor de Inferência (Ollama)<br/><b>Qwen 2.5:3b</b><br/>Temperatura=0.1 · num_predict"]
    D["4. Sanitização e Parse Dinâmico"]

    A --> B --> C --> D
​```

**Características do Agente de Tráfego:**
- Opera em paralelo ao Tier 1, focado exclusivamente em metadados de rede (não payload de log).
- Enforced JSON Schema reduz a necessidade de reparo de saída na etapa de parse.