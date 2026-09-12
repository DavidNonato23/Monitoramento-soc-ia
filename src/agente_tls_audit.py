import os
import json
import socket
import ssl
import logging
from typing import Any
import dotenv
from groq import Groq

dotenv.load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("AgenteTLSAudit")


def _extrair_tuplas_rdn(rdn_sequence: Any) -> dict[str, str]:
    """
    Auxiliar para converter com segurança a estrutura RDNSequence do cert SSL em dict
    evitando erros de tipagem no Pylance.
    """
    resultado: dict[str, str] = {}
    if not rdn_sequence:
        return resultado
    
    for rdn in rdn_sequence:
        for chave, valor in rdn:
            resultado[str(chave)] = str(valor)
            
    return resultado


def analisar_certificado_tls(host: str, porta: int = 443) -> dict[str, Any]:
    """
    Conecta ao host via SSL/TLS para extrair informações do certificado
    e verificar protocolos de criptografia suportados.
    """
    contexto = ssl.create_default_context()
    contexto.check_hostname = False
    contexto.verify_mode = ssl.CERT_NONE

    dados_tls: dict[str, Any] = {
        "host": host,
        "porta": porta,
        "status_conexao": "Sucesso",
        "certificado": {},
        "protocolo_versao": "",
        "cipher_suportado": ""
    }

    try:
        with socket.create_connection((host, porta), timeout=5) as sock:
            with contexto.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False) or {}
                dados_tls["protocolo_versao"] = ssock.version() or "Desconhecido"
                cipher = ssock.cipher()
                dados_tls["cipher_suportado"] = cipher[0] if cipher else "Desconhecido"

                # Extração tipada com segurança para o Pylance
                sujeito_dict = _extrair_tuplas_rdn(cert.get("subject"))
                emissor_dict = _extrair_tuplas_rdn(cert.get("issuer"))

                dados_tls["certificado"] = {
                    "sujeito": sujeito_dict,
                    "emissor": emissor_dict,
                    "valido_de": str(cert.get("notBefore", "N/A")),
                    "valido_ate": str(cert.get("notAfter", "N/A")),
                    "versao": str(cert.get("version", "N/A"))
                }
    except Exception as e:
        logger.warning(f"Falha ou ausência de serviço TLS/HTTPS na porta {porta} de {host}: {str(e)}")
        dados_tls["status_conexao"] = f"Inacessível ou sem TLS (Porta {porta}): {str(e)}"

    return dados_tls


def executar_auditoria_tls(host: str, porta: int = 443) -> dict[str, Any]:
    """
    Realiza a inspeção técnica de TLS e submete os dados ao Groq LPU para parecer de segurança.
    """
    dados_inspecao = analisar_certificado_tls(host, porta)

    if "Inacessível" in str(dados_inspecao["status_conexao"]):
        return {
            "status": "aviso",
            "mensagem": f"O serviço na porta {porta} de {host} não respondeu com suporte a TLS/HTTPS.",
            "dados_inspecao": dados_inspecao
        }

    client = Groq(api_key=os.getenv("GROQ_API_KEY"))

    instrucao_sistema = (
        "Você é um Especialista em Criptografia, TLS/SSL e Segurança de Perímetro Web.\n"
        "Avalie as configurações do certificado digital, protocolos suportados e ciphers.\n"
        "Identifique fragilidades (ex: TLS 1.0/1.1 descontinuados, expiração de certificado ou ciphers fracos).\n"
        "Retorne ESTRITAMENTE um objeto JSON válido."
    )

    prompt = f"""
    DADOS DE INSPEÇÃO TLS/SSL:
    {json.dumps(dados_inspecao, ensure_ascii=False)}

    SCHEMA DE SAÍDA:
    {{
        "servico_tls_ativo": true,
        "status_certificado": "Valido | Expirado | Proximo da Expiracao | Inseguro",
        "conformidade_protocolo": "string (ex: Conforme - TLS 1.3 em uso)",
        "risco_criptografico": "NENHUM | BAIXO | MEDIO | ALTO | CRITICO",
        "vulnerabilidades_identificadas": [
            "string"
        ],
        "recomendacoes_hardening": [
            "string"
        ],
        "parecer_executivo": "string"
    }}
    """

    try:
        resposta_ia = client.chat.completions.create(
            model="openai/gpt-oss-20b",
            messages=[
                {"role": "system", "content": instrucao_sistema},
                {"role": "user", "content": prompt}
            ],
            temperature=0.0,
            response_format={"type": "json_object"}
        )

        conteudo = resposta_ia.choices[0].message.content or "{}"
        return json.loads(conteudo)

    except Exception as e:
        logger.error(f"Erro na análise de TLS via Groq: {str(e)}")
        return {
            "erro": str(e),
            "dados_inspecao": dados_inspecao
        }