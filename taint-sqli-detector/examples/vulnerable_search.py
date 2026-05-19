"""
CASO 2 — Vulnerable: Flujo de datos complejo a través de múltiples variables.
Sistema: Módulo de búsqueda de trámites del Estado peruano.

Demuestra que el taint analysis rastrea la contaminación incluso cuando
el dato pasa por varias asignaciones antes de llegar al sink.
"""

import sqlite3
from flask import Flask, request

app = Flask(__name__)

PREFIJO_TABLA = "tramites_"


@app.route("/buscar_tramite")
def buscar_tramite():
    # SOURCE #1
    codigo = request.args.get("codigo")
    # SOURCE #2
    tipo   = request.args.get("tipo")

    # El taint se propaga a través de concatenaciones y asignaciones
    tabla       = PREFIJO_TABLA + tipo          # tabla ← tainted (hereda de tipo)
    where_cond  = "codigo = '" + codigo + "'"   # where_cond ← tainted (hereda de codigo)
    consulta    = f"SELECT * FROM {tabla} WHERE {where_cond}"  # consulta ← tainted

    conn   = sqlite3.connect("tramites.db")
    cur    = conn.cursor()
    cur.execute(consulta)          # ← SINK: consulta es tainted

    filas = cur.fetchall()
    return str(filas)


@app.route("/reporte")
def reporte():
    region    = request.args.get("region")
    año       = request.args.get("anio")

    # Taint fluye a través de operación de módulo de strings
    filtro    = "region='%s' AND año=%s" % (region, año)   # tainted
    sql_base  = "SELECT COUNT(*) FROM padron WHERE "
    sql_final = sql_base + filtro                           # tainted

    conn = sqlite3.connect("padron.db")
    cur  = conn.cursor()
    cur.execute(sql_final)         # ← SINK

    return str(cur.fetchone())
