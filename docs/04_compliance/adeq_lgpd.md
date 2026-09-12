# 🔒 Adequação Normativa: LGPD & ISO 27001

## O Papel do Tier 2 na Governança
O módulo de compliance do VanguardSec AI atua diretamente sobre os requisitos da **Lei Geral de Proteção de Dados (LGPD - Artigo 46)**, que obriga a adoção de medidas de segurança, técnicas e administrativas aptas a proteger os dados pessoais de acessos não autorizados.

## Cruzamento com RAG Normativo
* A engine lê dinamicamente os documentos normativos em PDF inseridos na pasta `./politicas/` (como diretrizes da ISO 27001 e manuais de incidentes)[cite: 3, 5].
* Durante a triagem de um incidente (por exemplo, uma falha de autenticação SSH via senha em vez de chave criptográfica), a IA gera um parecer técnico detalhando o desvio normativo e sugerindo ações corretivas imediatas[cite: 7].