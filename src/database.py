import os
import sqlite3
import logging

__all__ = ["inicializar_banco", "salvar_incidente", "contar_reincidencia_ip"]

logger = logging.getLogger("DatabaseManager")

DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "vanguardsec.db")

def inicializar_banco():
    os.makedirs(DB_DIR, exist_ok=True)
    conexao = sqlite3.connect(DB_PATH)
    cursor = conexao.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidentes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip_origem TEXT NOT NULL,
            usuario TEXT,
            severidade TEXT,
            status_acao TEXT,
            detalhes_ia TEXT
        )
    """)
    conexao.commit()
    conexao.close()

def salvar_incidente(ip: str, usuario: str, severidade: str, status_acao: str, detalhes_ia: str):
    try:
        conexao = sqlite3.connect(DB_PATH)
        cursor = conexao.cursor()
        cursor.execute("""
            INSERT INTO incidentes (ip_origem, usuario, severidade, status_acao, detalhes_ia)
            VALUES (?, ?, ?, ?, ?)
        """, (ip, usuario, severidade, status_acao, detalhes_ia))
        conexao.commit()
        conexao.close()
    except Exception as e:
        logger.error("Erro ao salvar incidente: %s", str(e))

def contar_reincidencia_ip(ip: str) -> int:
    try:
        conexao = sqlite3.connect(DB_PATH)
        cursor = conexao.cursor()
        cursor.execute("SELECT COUNT(*) FROM incidentes WHERE ip_origem = ?", (ip,))
        row = cursor.fetchone()
        conexao.close()
        return row[0] if row else 0
    except Exception:
        return 0