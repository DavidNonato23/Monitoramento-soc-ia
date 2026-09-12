"""
Cliente compartilhado da API do Groq (openai/gpt-oss-20b).

Todos os agentes de IA chamam esta função em vez de instanciar seu próprio
cliente Groq. Centraliza:

- Validação antecipada da chave de API (falha rápido e com mensagem clara
  na inicialização, em vez de um erro confuso no meio da primeira chamada)
- Retry com backoff exponencial para rate limit (HTTP 429) e erros
  transitórios de servidor/conexão — o tier gratuito do Groq tem limite de
  30 requisições/minuto, que pode estourar numa rajada de eventos reais
- Um único ponto para trocar o nome do modelo no futuro
"""
import os
import time
import logging
from dotenv import load_dotenv
from groq import (
    Groq,
    RateLimitError,
    APIConnectionError,
    InternalServerError,
    AuthenticationError,
)

# Força o carregamento do .env a partir da raiz do projeto (independente de onde o script rode)
caminho_raiz = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.env'))
load_dotenv(caminho_raiz)

# Fallback alternativo caso o .env esteja na mesma pasta ou na raiz absoluta
load_dotenv()

logger = logging.getLogger("VanguardSecGroqClient")

_API_KEY = os.getenv("GROQ_API_KEY")
_MODELO_PADRAO = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")

if not _API_KEY:
    raise RuntimeError(
        "GROQ_API_KEY não definida no .env. Gere uma chave em "
        "https://console.groq.com/keys e adicione ao .env como "
        "GROQ_API_KEY=<sua_chave>."
    )

_client = Groq(api_key=_API_KEY)


def gerar_json(system_prompt: str, user_prompt: str, temperatura: float = 0.0,
               max_tokens: int = 300, tentativas: int = 3) -> str:
    """
    Chama o Groq em modo JSON garantido (response_format json_object) e
    retorna o texto da resposta (já deve ser um JSON válido, mas quem chama
    ainda deve validar com json.loads — a garantia do provedor não substitui
    a checagem local).

    Faz retry com backoff exponencial (2s, 4s, 8s...) para rate limit e
    erros transitórios de servidor/conexão. Erro de autenticação (chave
    inválida) não é re-tentado — sobe na hora com mensagem clara.
    """
    ultimo_erro: Exception | None = None

    for tentativa in range(1, tentativas + 1):
        try:
            resposta = _client.chat.completions.create(
                model=_MODELO_PADRAO,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=temperatura,
                max_completion_tokens=max_tokens,
                response_format={"type": "json_object"},
            )
            return resposta.choices[0].message.content or "{}"

        except RateLimitError as e:
            ultimo_erro = e
            espera = 2 ** tentativa
            logger.warning(
                "Rate limit do Groq (tentativa %d/%d). Aguardando %ds antes de tentar de novo.",
                tentativa, tentativas, espera
            )
            time.sleep(espera)
            continue

        except (APIConnectionError, InternalServerError) as e:
            ultimo_erro = e
            espera = 2 ** tentativa
            logger.warning(
                "Erro de conexão/servidor do Groq (tentativa %d/%d). Aguardando %ds.",
                tentativa, tentativas, espera
            )
            time.sleep(espera)
            continue

        except AuthenticationError as e:
            # Chave inválida/revogada — não adianta re-tentar.
            raise RuntimeError(
                "GROQ_API_KEY inválida ou sem permissão. Verifique a chave em "
                "https://console.groq.com/keys"
            ) from e

    raise RuntimeError(
        f"Groq API: falha persistente após {tentativas} tentativas."
    ) from ultimo_erro