# Especificação Técnica dos Agentes de IA

Os agentes em `src/ai/` são módulos especializados. O cliente compartilhado está em `src/ai/groq_client.py`; `GROQ_API_KEY` é obrigatória e `GROQ_MODEL` permite escolher o modelo. As respostas JSON devem ser tratadas como dados não confiáveis e validadas antes de ações.

## Agentes do pipeline

### Tier 1: Auditor SOC

Arquivo: `src/ai/agente_auditor.py`.

Triagem de logs de autenticação e extração de IoCs, categoria, severidade e ação recomendada.

```json
{
  "severidade": "BAIXO | MEDIO | ALTO | CRITICO",
  "tipo_evento": "Descrição da anomalia",
  "indicadores_ioc": {
    "ip_origem": "192.0.2.10",
    "usuario_alvo": "root",
    "servico": "ssh"
  },
  "acao_recomendada": "Ação analítica inicial"
}
```

### Threat Intelligence

Arquivo: `src/ai/agente_threat_intel.py`.

Recebe um IP ou artefato e gera contexto de reputação, campanha e confiança. O resultado é um sinal analítico, não prova isolada.

### Tier 2: Compliance

Arquivo: `src/ai/agente_compliance.py`.

Relaciona o resultado do Tier 1 a LGPD e ISO em uma avaliação operacional.

```json
{
  "artigo_lgpd": "Artigo 46 - Segurança e Privacidade",
  "controle_iso": "Controle ISO relacionado",
  "risco_normativo": "Descrição do risco regulatório"
}
```

### Tier 3: Remediação SOAR

Arquivo: `src/ai/agente_remediacao.py`.

Sugere ação e comando de mitigação. O comando exige validação e política de execução antes de ser usado.

```json
{
  "comando_bash": "sudo ufw deny from 192.0.2.10 to any",
  "acao_soar": "Bloqueio de IP e encerramento de sessão"
}
```

## Agentes de auditoria preventiva

* `agente_nmap.py`: executa `nmap -Pn -sV --script vuln -T4`, valida IPv4 e informa estados como `host_inacessivel`, `timeout`, `ip_invalido` e conclusão normal.
* `agente_cve_lookup.py`: consulta vulnerabilidades para o ativo.
* `agente_tls_audit.py`: audita certificado e parâmetros TLS.
* `agente_backup_disaster.py`: verifica backup e recuperação.
* `agente_trafego.py`: analisa dados de tráfego fornecidos por outra coleta.

## Regras operacionais

* Ausência de `GROQ_API_KEY` impede a inicialização dos agentes.
* O cliente Groq usa JSON estruturado e retry para erros transitórios.
* O motor só deve executar ações SOAR quando `ACTIVE_DEFENSE` e `AUTO_REMEDIATION` estiverem habilitados e as condições de reincidência forem atendidas.
* Em laboratório, use `AUTO_REMEDIATION=false`.
