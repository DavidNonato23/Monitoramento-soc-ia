# Fluxo de Execução - Agente de Threat Intelligence

​```mermaid
flowchart TD
    A["1. Ingestão de IoCs e Artefatos<br/>(IPs, Hashes, Domínios Isolados)"]
    B["2. Camada de Prompt & Contextualização<br/>Analista Threat Intel<br/>Enforced JSON Schema"]
    C["3. Motor de Inferência (Ollama)<br/><b>Qwen 2.5:3b</b><br/>Temperatura=0.1 · num_predict"]
    D["4. Sanitização e Parse Dinâmico"]

    A --> B --> C --> D
​```

**Características do Agente de Threat Intel:**
- Recebe IoCs já extraídos (não logs brutos), tipicamente vindos do Tier 1 ou do Agente de Tráfego.
- Enriquece com reputação, família de malware e campanha associada, quando aplicável.