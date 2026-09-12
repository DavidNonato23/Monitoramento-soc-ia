# 🛡️ VanguardSec AI — Visão Geral & Proposta de Valor

## O Que É o VanguardSec AI?
O **VanguardSec AI** é uma plataforma autônoma de *SecOps*, *Threat Intelligence* e resposta a incidentes de nível corporativo. Ele opera de forma integrada utilizando inteligência artificial local (**Ollama** com o modelo `qwen2.5:3b`)[cite: 2, 5], garantindo total soberania e privacidade dos dados corporativos sem envio de informações para APIs de terceiros.

## O Problema Resolvido
Operações de segurança tradicionais sofrem com gargalos críticos:
* **Fatiga de Alertas (*Alert Fatigue*):** Analistas perdem tempo triando falsos positivos repetitivos.
* **MTTR Elevado:** O tempo entre a detecção e o bloqueio de uma ameaça costuma ser lento.
* **Complexidade Regulatória:** Cruzar logs de segurança com normas como **LGPD (Art. 46)** e **ISO 27001** manualmente é ineficiente.

## Nossos Diferenciais
* **Abordagem *Agentless*:** Conexão direta e segura via SSH (Paramiko) para Linux e WinRM para Windows, sem poluir os servidores monitorados com agentes pesados[cite: 1, 2].
* **Governança de Temperatura Determinística:** Uso de temperatura `0.0` em módulos críticos de remediação para evitar alucinações ao gerar códigos de infraestrutura.
* **Automação Completa via ChatOps e SOAR:** Resposta a incidentes automatizada com 1 clique pelo Telegram ou pelo painel web[cite: 1, 2].