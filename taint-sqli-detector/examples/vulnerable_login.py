"""
CASO 1 — Vulnerable: Concatenación directa de entrada del usuario en consulta SQL.
Sistema: Login de portal gubernamental peruano (DNI + contraseña).

Ataque posible:
    username = "admin' OR '1'='1' --"
    → SELECT * FROM usuarios WHERE username='admin' OR '1'='1' --' AND password='...'
    → Autentica sin credenciales válidas.
"""

import sqlite3
from flask import Flask, request, redirect

app = Flask(__name__)


def get_db():
    return sqlite3.connect("ciudadanos.db")


@app.route("/login", methods=["POST"])
def login():
    # SOURCE: datos provistos por el usuario a través del formulario
    username = request.form.get("username")
    password = request.form.get("password")

    conn = get_db()
    cursor = conn.cursor()

    # VULNERABILIDAD: concatenación directa → SQL Injection (CWE-89)
    query = "SELECT * FROM usuarios WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)          # ← SINK: argumento contaminado

    row = cursor.fetchone()
    if row:
        return "Acceso concedido"
    return "Acceso denegado"


@app.route("/buscar_ciudadano", methods=["GET"])
def buscar_ciudadano():
    # SOURCE: parámetro de URL
    dni = request.args.get("dni")

    conn = get_db()
    cursor = conn.cursor()

    # VULNERABILIDAD: f-string con dato no saneado
    sql = f"SELECT nombre, direccion FROM ciudadanos WHERE dni='{dni}'"
    cursor.execute(sql)            # ← SINK

    resultado = cursor.fetchone()
    return str(resultado)
