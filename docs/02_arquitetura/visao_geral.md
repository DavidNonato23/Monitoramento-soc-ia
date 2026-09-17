# VanguardSec AI — Visão Geral

## O Que É o VanguardSec AI?
O **VanguardSec AI** é uma aplicação Flask para monitoramento SSH/WinRM, triagem de eventos, enriquecimento de ameaças, compliance e ações SOAR. Os agentes usam o cliente Groq configurado em `GROQ_API_KEY` e `GROQ_MODEL`; portanto, os dados enviados à IA não são exclusivamente locais.

## O Problema Resolvido
Operações de segurança tradicionais sofrem com gargalos críticos:
* **Fatiga de Alertas (*Alert Fatigue*):** Analistas perdem tempo triando falsos positivos repetitivos.
* **MTTR Elevado:** O tempo entre a detecção e o bloqueio de uma ameaça costuma ser lento.
* **Complexidade Regulatória:** Cruzar logs de segurança com normas como **LGPD (Art. 46)** e **ISO 27001** manualmente é ineficiente.

## Nossos Diferenciais
* **Coleta agentless:** Paramiko para SSH e WinRM para Windows, sem instalar agente no servidor monitorado.
* **Host key pinning:** a conexão só autentica quando o fingerprint aprovado coincide.
* **Pipeline estruturado:** agentes retornam JSON e o resultado é salvo no SQLite quando há evento de ataque.
* **SOAR controlável:** bloqueio UFW e encerramento de sessão são condicionados por configuração e limiar de reincidência.

Telegram, Ollama e processamento exclusivamente local não fazem parte do fluxo atual documentado.