"""
CASO 3 — SEGURO: Uso de consultas parametrizadas (prepared statements).
Sistema: Mismo login gubernamental, ahora correctamente saneado.

La consulta parametrizada separa el código SQL de los datos:
el driver de base de datos maneja el escape automáticamente.
El taint analysis detecta que el query_string es constante (no tainted)
y los datos tainted van como parámetros separados → no hay SQLi.
"""

import sqlite3
from flask import Flask, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("ciudadanos.db")


@app.route("/login", methods=["POST"])
def login_seguro():
    # SOURCE: datos del usuario (siguen siendo tainted)
    username = request.form.get("username")
    password = request.form.get("password")

    conn   = get_db()
    cursor = conn.cursor()

    # SEGURO: query_string es una constante, los parámetros van separados.
    # El motor de taint detecta: args[0] no tainted, args[1]=(username, password)
    # → consulta parametrizada → NO reporta vulnerabilidad.
    query_string = "SELECT * FROM usuarios WHERE username=? AND password=?"
    cursor.execute(query_string, (username, password))   # ← parametrizado

    row = cursor.fetchone()
    if row:
        return "Acceso concedido"
    return "Acceso denegado"


@app.route("/buscar_ciudadano", methods=["GET"])
def buscar_ciudadano_seguro():
    # SOURCE: aún tainted
    dni = request.args.get("dni")

    # SEGURO: validación + consulta parametrizada
    dni_limpio = int(dni)         # int() es sanitizador: valida formato numérico

    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT nombre, direccion FROM ciudadanos WHERE dni=?",
        (dni_limpio,)
    )

    resultado = cursor.fetchone()
    return str(resultado)
