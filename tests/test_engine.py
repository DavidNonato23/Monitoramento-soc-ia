import os
import sys
import json
from unittest.mock import patch

# Adiciona a raiz do projeto ao path do Python para encontrar o engine.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Importa as funções principais do motor e dos agentes
from src.engine import contar_reincidencia_ip
from src.ai.agente_threat_intel import executar_agente_threat_intel

def test_contar_reincidencia_ip_inexistente():
    """IPs sem eventos registrados não possuem reincidência."""
    assert contar_reincidencia_ip("203.0.113.10") == 0


@patch("src.ai.agente_threat_intel.gerar_json")
def test_agente_threat_intel_mock(mock_gerar_json):
    """Testa Threat Intelligence sem depender da API externa do Groq."""
    mock_gerar_json.return_value = json.dumps({
        "indicador": "185.220.101.5",
        "reputacao": "Malicioso",
        "familia_malware": "Mirai",
        "campanha_associada": "BruteForce Botnet",
        "nivel_confianca": "Alta"
    })

    resposta = executar_agente_threat_intel("185.220.101.5")

    assert isinstance(resposta, dict)
    assert resposta.get("reputacao") == "Malicioso"
    assert resposta.get("nivel_confianca") == "Alta"
    assert "familia_malware" in resposta