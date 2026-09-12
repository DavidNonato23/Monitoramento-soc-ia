import json
import sys
from src.ai.agente_nmap import executar_varredura_nmap

if __name__ == "__main__":
    if len(sys.argv) > 1:
        ip_teste = sys.argv[1]
    else:
        ip_teste = input("Digite o IP ou hostname do alvo para a varredura Nmap (ex: 127.0.0.1): ").strip()
        if not ip_teste:
            print("[-] Nenhum alvo fornecido. Encerrando.")
            sys.exit(1)
    
    print(f"\n[*] Disparando varredura Nmap e análise de IA no alvo: {ip_teste}...")
    relatorio = executar_varredura_nmap(ip_teste)
    
    print("\n[+] Resultado estruturado recebido do Gemini 2.5 Flash:")
    print(json.dumps(relatorio, indent=4, ensure_ascii=False))