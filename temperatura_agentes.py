import requests

url = "http://localhost:5000/testar-temperatura"
dados = {"prompt": "Analise o log de falha de SSH e indique apenas a severidade: BAIXO, MEDIO, ALTO ou CRITICO."}

resposta = requests.post(url, data=dados)
print(resposta.json())