import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock

# Adiciona a raiz do projeto ao path do Python para encontrar o engine.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Importa as funções principais do motor e dos agentes
from src.engine import extrair_json_defensivo, contar_reincidencia_ip
from src.ai.agente_threat_intel import executar_agente_threat_intel

def test_extrair_json_defensivo_valido():
    """Valida se o parser extrai corretamente um JSON limpo ou envelopado em blocos markdown."""
    payload_markdown = "```json\n{\n  \"severidade\": \"Alta\",\n  \"status\": \"Bloqueado\"\n}\n```"
    resultado = extrair_json_defensivo(payload_markdown)
    
    assert isinstance(resultado, dict)
    assert resultado.get("severidade") == "Alta"
    assert resultado.get("status") == "Bloqueado"


def test_extrair_json_defensivo_invalido():
    """Garante que o parser retorna um dicionário vazio caso o JSON esteja corrompido."""
    payload_ruim = "Isso não é um json válido de forma alguma."
    resultado = extrair_json_defensivo(payload_ruim)
    
    assert isinstance(resultado, dict)
    assert resultado == {}


@patch("src.ai.agente_threat_intel.OllamaLLM")
def test_agente_threat_intel_mock(mock_ollama_llm):
    """Testa o agente de Threat Intelligence utilizando mock do LLM para evitar dependência de rede/local."""
    mock_instance = MagicMock()
    mock_instance.invoke.return_value = json.dumps({
        "indicador": "185.220.101.5",
        "reputacao": "Malicioso",
        "familia_malware": "Mirai",
        "campanha_associada": "BruteForce Botnet",
        "nivel_confianca": "Alta"
    })
    mock_ollama_llm.return_value = mock_instance

    resposta = executar_agente_threat_intel("185.220.101.5")

    assert isinstance(resposta, dict)
    assert resposta.get("reputacao") == "Malicioso"
    assert resposta.get("nivel_confianca") == "Alta"
    assert "familia_malware" in resposta