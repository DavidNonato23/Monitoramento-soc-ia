# 🗺️ Arquitetura do Sistema & Esteira Multi-Tier

## Fluxo Operacional (Multi-Tier Pipeline)
O motor do VanguardSec AI processa os eventos de segurança em camadas sequenciais:

1. **Coleta Telemétrica (*Agentless* Inbound):** 
   - Captura logs de autenticação (`/var/log/auth.log`, `journalctl`) via SSH[cite: 3, 5].
   - Monitora métricas locais de hardware e portas abertas (`LISTEN`) via `psutil`[cite: 1, 2].
2. **Tier 1 — Analista SOC (`agente_auditor.py`):**
   - Extrai Indicadores de Comprometimento (IoCs), IPs de origem e calcula a severidade inicial do evento[cite: 1, 2].
3. **Tier 2 — Compliance & Governança (`agente_compliance.py`):**
   - Cruza o evento com as diretrizes normativas (LGPD e ISO 27001) armazenadas na pasta `./politicas/`[cite: 1, 3, 5].
4. **Tier 3 — Engenheiro SOAR (`agente_remediacao.py`):**
   - Compila o playbook de resposta automatizada e gera o comando de contenção seguro[cite: 1, 2].

## Persistência e Apresentação
* **Banco de Dados Relacional:** SQLite (`vanguard_sec.db`) para armazenamento estruturado de todos os scans[cite: 3, 5].
* **Exportação para BI:** Arquivo CSV (`vanguard_powerbi_data.csv`) para compatibilidade com relatórios externos[cite: 3, 5].
* **Interfaces Outbound:** Dashboard interativo em Streamlit, relatórios executivos em PDF (`ReportLab`) e alertas interativos no Telegram[cite: 1, 2, 5].