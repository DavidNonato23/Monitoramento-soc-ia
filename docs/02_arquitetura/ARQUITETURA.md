# Arquitetura do Sistema e Esteira Multi-Tier

## Fluxo Operacional (Multi-Tier Pipeline)
O VanguardSec AI é uma aplicação Flask com persistência SQLite e coleta remota. O fluxo principal do motor (`src/engine.py`) é:

1. **Coleta:** `journalctl -u ssh` via SSH verificado no Linux ou eventos de falha via WinRM quando `MONITORAMENTO_PROTOCOLO=winrm`.
2. **Tier 1:** `agente_auditor.py` extrai IoCs, categoria, severidade e ação recomendada.
3. **Threat Intelligence:** `agente_threat_intel.py` recebe o IP/artefato identificado e gera enriquecimento.
4. **Tier 2:** `agente_compliance.py` relaciona o evento a LGPD/ISO.
5. **Tier 3:** `agente_remediacao.py` gera a recomendação SOAR.
6. **Persistência:** eventos confirmados são gravados na tabela `scans` do SQLite.

## Persistência e Apresentação
* **Banco de dados:** SQLite em `data/vanguard_sec.db`, com tabelas `scans`, `servidores` e `agentes_logs`.
* **Interface:** páginas Flask/Jinja em `src/templates/`, protegidas por HTTP Basic Auth.
* **IA:** cliente compartilhado em `src/ai/groq_client.py`, usando `GROQ_MODEL` ou `openai/gpt-oss-20b` por padrão.
* **Relatórios:** PDFs gerados com ReportLab; exportação CSV é disponibilizada pela aplicação quando configurada.
* **Ações SOAR:** Kill Switch e bloqueio UFW dependem de `ACTIVE_DEFENSE` e `AUTO_REMEDIATION`.

## Limites e segurança

O fingerprint SSH precisa estar aprovado antes da autenticação. Ausência ou divergência gera `HostKeyNaoAprovada`. O comando produzido por um agente não deve ser tratado como confiável sem validação; use `AUTO_REMEDIATION=false` em laboratório.