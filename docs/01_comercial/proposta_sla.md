# Acordo de Nível de Serviço (SLA) e Suporte

## 1. Métricas de Desempenho do Sistema
Os valores abaixo são metas de referência, não garantias do código sem instrumentação e acordo operacional:
* **MTTD:** depende do intervalo de 3 segundos do loop do `engine.py`, do SSH e da leitura do journal.
* **MTTR:** depende de autenticação SSH, sudo, firewall, reincidência e configuração de defesa ativa.
* **Disponibilidade:** deve ser medida pelo ambiente de implantação; o projeto não inclui cluster ou failover automático.

## 2. Categorização de Severidade & Suporte
* **CRÍTICO:** invasão confirmada ou força bruta massiva — revisão e ação conforme política aprovada.
* **ALTO/MÉDIO:** tentativas reincidentes — triagem registrada e ação sujeita a `ACTIVE_DEFENSE`, `AUTO_REMEDIATION` e limiar configurado.

Qualquer SLA contratual deve definir janela de suporte, responsáveis, retenção, canais de escalonamento e critérios de manutenção.