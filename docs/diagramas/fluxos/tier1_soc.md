# Fluxo de Execução - Agente Tier 1 (SOC Core)

​```mermaid
flowchart TD
    A["1. Ingestão de Log Bruto<br/>(Syslog, Auth.log, Firewall, Web Server)"]
    B["2. Camada de Prompt Tier 1<br/>Guardrails Anti-Injection (Filtro de Ruído)<br/><b>max_tokens=150 · temperatura=0.1</b>"]
    C["3. Motor de Inferência (Ollama)<br/><b>Qwen 2.5:3b (Fast)</b><br/>Foco: Velocidade e Extração de IoCs"]
    D["4. Saída Estruturada (JSON)"]

    A --> B --> C --> D
​```

**Características do Tier 1:**
- Camada de triagem rápida, primeira linha de defesa contra ruído.
- Temperatura baixa (0.1) prioriza extração literal de IoCs sobre criatividade.
- Saída alimenta o Tier 2 (Compliance) e/ou o Tier 3 (SOAR), conforme severidade.