"""
CASO 3 — Sistema Gubernamental Peruano (RENIEC/SUNAT simulado)
Búsqueda de ciudadano por DNI con múltiples vulnerabilidades SQLi.

Escenario:
  Portal de consulta ciudadana donde un funcionario ingresa el DNI
  de un ciudadano para obtener sus datos del padrón electoral.

Vectores de ataque documentados:
  1. Búsqueda por DNI: inyección directa en cláusula WHERE
     DNI = 12345678' OR '1'='1
     → Devuelve toda la tabla de ciudadanos

  2. Reporte por apellido (f-string):
     apellido = "García' UNION SELECT username,password FROM admin--"
     → Exfiltra tabla de administradores

  3. Búsqueda por rango de fechas (concatenación de múltiples sources):
     fecha_inicio = "2020-01-01' OR 1=1 --"
     → Omite filtros temporales y retorna todos los registros

Referencia: CWE-89 — Improper Neutralization of Special Elements
            used in an SQL Command (SQL Injection)
"""

from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)
DB_PATH = "padron_electoral.db"


def get_conexion():
    return sqlite3.connect(DB_PATH)


# ─── Endpoint 1: Búsqueda por DNI ────────────────────────────────────────────

@app.route("/ciudadano/buscar", methods=["GET"])
def buscar_por_dni():
    # SOURCE: parámetro GET proporcionado por el usuario
    dni = request.args.get("dni")

    conn   = get_conexion()
    cursor = conn.cursor()

    # VULNERABILIDAD 1: concatenación directa del DNI en la consulta SQL
    # Un DNI como "12345678' OR '1'='1" devuelve TODOS los registros.
    sql = "SELECT nombre, apellido FROM ciudadanos WHERE dni = '" + dni + "'"
    cursor.execute(sql)          # ← SINK (CWE-89)

    row = cursor.fetchone()
    return str(row)


# ─── Endpoint 2: Reporte por apellido (f-string) ─────────────────────────────

@app.route("/ciudadano/reporte", methods=["GET"])
def reporte_por_apellido():
    # SOURCE: parámetro GET del apellido del ciudadano
    apellido = request.args.get("apellido")

    conn   = get_conexion()
    cursor = conn.cursor()

    # VULNERABILIDAD 2: f-string con dato no saneado
    # Ataque: apellido = "García' UNION SELECT user,pass FROM admin--"
    consulta = f"SELECT * FROM ciudadanos WHERE apellido LIKE '{apellido}%'"
    cursor.execute(consulta)     # ← SINK (CWE-89)

    filas = cursor.fetchall()
    return str(filas)


# ─── Endpoint 3: Búsqueda por rango de fechas ────────────────────────────────

@app.route("/ciudadano/por_fecha", methods=["GET"])
def buscar_por_fecha():
    # SOURCE: parámetros GET de rango temporal (dos sources independientes)
    fecha_inicio = request.args.get("desde")
    fecha_fin    = request.args.get("hasta")

    conn   = get_conexion()
    cursor = conn.cursor()

    # VULNERABILIDAD 3: construcción por concatenación de múltiples sources
    inicio_sql = "SELECT dni, nombre FROM ciudadanos WHERE fecha_nacimiento >= '"
    fin_sql    = "' AND fecha_nacimiento <= '"
    query      = inicio_sql + fecha_inicio + fin_sql + fecha_fin + "'"
    cursor.execute(query)        # ← SINK (CWE-89)

    filas = cursor.fetchall()
    return str(filas)


if __name__ == "__main__":
    app.run(debug=False)
