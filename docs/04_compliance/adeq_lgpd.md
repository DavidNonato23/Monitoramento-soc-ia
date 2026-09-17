# Adequação Normativa: LGPD e ISO 27001

## O Papel do Tier 2 na Governança
O módulo de compliance do VanguardSec AI atua diretamente sobre os requisitos da **Lei Geral de Proteção de Dados (LGPD - Artigo 46)**, que obriga a adoção de medidas de segurança, técnicas e administrativas aptas a proteger os dados pessoais de acessos não autorizados.

## Cruzamento com RAG Normativo
* A aplicação mantém políticas e prompts no repositório, mas o fluxo atual não deve ser descrito como RAG automático de PDFs.
* O agente de compliance recebe o resultado do Tier 1 e produz um mapeamento textual para LGPD/ISO.
* O parecer é apoio operacional, não certificação jurídica nem evidência suficiente, sozinho, de conformidade.

## Controles técnicos documentados

* Autenticação HTTP Basic no painel.
* Senhas de servidores cifradas antes de serem gravadas no SQLite.
* Fingerprint de host key obrigatório para conexões SSH.
* Validação estrita de IPv4 antes de comandos remotos e Nmap.
* Senha de sudo enviada pelo canal SSH, sem compor a linha do processo remoto.
* Registro dos eventos processados na tabela `scans`.

## Responsabilidades e lacunas

O operador deve proteger `.env`, `VANGUARD_ENCRYPTION_KEY`, banco e logs, restringir a rede do painel, revisar comandos SOAR e definir retenção. A aplicação não substitui DPIA, gestão de acesso, backup, monitoramento de disponibilidade ou revisão jurídica.