# 🚀 Guia de Instalação e Execução

## Pré-requisitos
* **Python:** Versão 3.10 ou superior[cite: 2].
* **Ollama Engine:** Instalado e executando localmente na porta padrão (`http://localhost:11434`) com o modelo `qwen2.5:3b` baixado[cite: 2, 5].
* **Acesso Remoto:** SSH habilitado nos servidores alvo[cite: 2].

## Execução Automatizada (Windows)
Basta utilizar o script `start.bat` localizado na raiz do repositório[cite: 2]. Ele executa automaticamente as seguintes etapas:
1. Validação do ambiente Python.
2. Criação e ativação do ambiente virtual (`venv`)[cite: 2].
3. Instalação das dependências listadas em `requirements.txt`[cite: 2].
4. Inicialização do painel Streamlit na porta `8501`[cite: 2].

## Configuração do ChatOps (Telegram)
Para habilitar os alertas interativos e bloqueios por 1 clique no celular:
1. Configure as variáveis de ambiente ou insira os dados na aba de configurações do painel[cite: 2]:
   - `TELEGRAM_BOT_TOKEN` (gerado pelo `@BotFather`)[cite: 2]
   - `TELEGRAM_ALLOWED_USER_ID` (seu ID de usuário obtido no `@userinfobot`)[cite: 2]