# Padrão de Relatórios Executivos

## 1. Identidade Visual do Cliente (White-Label)
O projeto possui geradores PDF em `src/reports/`, `src/database/` e no fluxo de certificado em `src/app.py`. A personalização de logo e hash de integridade não deve ser considerada disponível sem implementação/configuração específica.

## 2. Estrutura do Laudo Gerado
1. **Cabeçalho:** ativo, IP, função e data de emissão.
2. **Resumo Executivo (Metadata):** Severidade do ataque, IP atacante, servidor afetado e status de mitigação.
3. **Seção Tier 1 (SOC):** Leitura de IoCs e gravidade.
4. **Seção Tier 2 (Compliance):** Artigos da LGPD e ISO 27001 violados.
5. **Seção Tier 3 (SOAR):** comando recomendado e resultado, quando presentes.
6. **Evidência:** log bruto registrado no banco e incluído quando o gerador utilizado o suporta.

Relatório PDF é evidência operacional; retenção, assinatura e cadeia de custódia devem ser definidas pelo cliente.