# VanguardSec V2 — Arquitetura

## Princípio central

A IA **analisa e recomenda**. O Policy Engine **autoriza ou nega**. O SOAR **executa somente ações previamente cadastradas**.

```text
Collector
   |
   v
Event -> Detection -> Correlation -> Incident
                              |
                              v
                         AI Analysis
                              |
                              v
                        Policy Engine
                              |
                    +---------+---------+
                    |                   |
                 DENY/PENDING        ALLOW
                    |                   |
                    v                   v
                 Audit             SOAR Worker
                                        |
                                        v
                                  Audit + Result
```

## Estrutura da V2

- `src/v2/config.py`: configuração centralizada; defesa ativa e remediação automática desligadas por padrão.
- `src/v2/security/ip_policy.py`: validação de IP e proteção de alvos.
- `src/v2/security/action_policy.py`: autorização determinística de ações SOAR.
- `src/v2/security/command_catalog.py`: catálogo fechado de ações; não aceita comandos arbitrários vindos da IA.
- `tests/v2/`: testes das políticas de segurança.

## Migração planejada

1. Consolidar eventos, incidentes e ações em um modelo de dados único.
2. Extrair serviços do `src/app.py`.
3. Separar coleta, detecção, correlação e orquestração do `src/engine.py`.
4. Migrar os agentes de IA para schemas validados.
5. Conectar o SOAR somente ao catálogo de ações e ao Policy Engine.
6. Introduzir workers assíncronos depois que o fluxo síncrono estiver coberto por testes.
7. Migrar de SQLite para PostgreSQL somente quando o modelo e as necessidades de escala justificarem.

## Regra operacional

`ACTIVE_DEFENSE=false` e `AUTO_REMEDIATION=false` são os padrões. Produção exige aprovação humana para ações defensivas até que uma política explícita de automação seja criada e testada.
