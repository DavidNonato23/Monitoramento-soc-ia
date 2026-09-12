# Schema JSON - Threat Intelligence

​```json
{
  "indicador": "STRING",
  "reputacao": "Malicioso | Suspeito | Limpo | Desconhecido",
  "familia_malware": "STRING | null",
  "campanha_associada": "STRING | null",
  "nivel_confianca": "Alta | Media | Baixa"
}
​```

| Campo | Tipo | Descrição |
|---|---|---|
| `indicador` | string | O IoC analisado (IP, hash, domínio) |
| `reputacao` | enum | `Malicioso` \| `Suspeito` \| `Limpo` \| `Desconhecido` |
| `familia_malware` | string \| null | Família de malware associada, se houver |
| `campanha_associada` | string \| null | Campanha/ator de ameaça associado, se houver |
| `nivel_confianca` | enum | `Alta` \| `Media` \| `Baixa` |