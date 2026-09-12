# Schema JSON - Agente Tier 2 (Compliance)

​```json
{
  "raciocinio_cot": "STRING (resumido)",
  "artigo_lgpd": "STRING",
  "controle_iso": "STRING",
  "risco_normativo": "STRING"
}
​```

| Campo | Tipo | Descrição |
|---|---|---|
| `raciocinio_cot` | string | Cadeia de raciocínio resumida (chain-of-thought) |
| `artigo_lgpd` | string | Artigo da LGPD mais aderente ao evento |
| `controle_iso` | string | Controle ISO 27001/27002 relacionado |
| `risco_normativo` | string | Descrição do risco regulatório identificado |