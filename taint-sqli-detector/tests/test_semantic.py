"""
Tests del Analizador Semántico — Fase 3 del Compilador.
Ejecutar: python3 -m pytest tests/test_semantic.py -v
"""
import pytest
from analyzer.parser import parse
from analyzer.semantic import (
    SemanticAnalyzer, SymbolTable, SymbolKind, Symbol, SemanticDiagnostic,
)


def _analyze(src: str) -> SemanticAnalyzer:
    tree, _ = parse(src)
    sem = SemanticAnalyzer()
    sem.analyze(tree)
    return sem


def _sym_table(src: str) -> SymbolTable:
    return _analyze(src).symbol_table


# ════════════════════════════════════════════════════════════════════════════
#  Tabla de símbolos — registro de variables
# ════════════════════════════════════════════════════════════════════════════

class TestRegistroVariables:

    def test_variable_simple(self):
        sem = _analyze("x = 42\n")
        sym = sem.symbol_table.lookup("x")
        assert sym is not None
        assert sym.kind == SymbolKind.VARIABLE

    def test_variable_string(self):
        sem = _analyze('query = "SELECT * FROM t"\n')
        sym = sem.symbol_table.lookup("query")
        assert sym is not None
        assert sym.type_hint == "str"

    def test_variable_entero(self):
        sem = _analyze("n = 10\n")
        sym = sem.symbol_table.lookup("n")
        assert sym.type_hint == "int"

    def test_variable_float(self):
        sem = _analyze("pi = 3.14\n")
        sym = sem.symbol_table.lookup("pi")
        assert sym.type_hint == "float"

    def test_variable_booleana(self):
        sem = _analyze("activo = True\n")
        sym = sem.symbol_table.lookup("activo")
        assert sym.type_hint == "bool"

    def test_multiples_variables(self):
        src = "a = 1\nb = 2\nc = 3\n"
        sem = _analyze(src)
        for name in ("a", "b", "c"):
            assert sem.symbol_table.lookup(name) is not None

    def test_asignacion_encadenada(self):
        sem = _analyze("a = b = 0\n")
        assert sem.symbol_table.lookup("a") is not None
        assert sem.symbol_table.lookup("b") is not None


# ════════════════════════════════════════════════════════════════════════════
#  Tabla de símbolos — funciones y parámetros
# ════════════════════════════════════════════════════════════════════════════

class TestFuncionesParametros:

    def test_funcion_registrada(self):
        src = "def login(usuario, password):\n    pass\n"
        sem = _analyze(src)
        sym = sem.symbol_table.lookup("login")
        assert sym is not None
        assert sym.kind == SymbolKind.FUNCTION

    def test_parametros_en_ambito_funcion(self):
        src = "def buscar(dni):\n    sql = dni\n"
        tree, _ = parse(src)
        sem = SemanticAnalyzer()
        sem.analyze(tree)
        # Los parámetros solo existen en el ámbito de la función;
        # no deberían estar en el ámbito global.
        global_sym = sem.symbol_table.global_scope.lookup_local("dni")
        assert global_sym is None

    def test_funcion_duplicada_es_warning(self):
        src = "def f():\n    pass\ndef f():\n    pass\n"
        sem = _analyze(src)
        assert any("redefinida" in w.message or "f" in w.message
                   for w in sem.warnings)

    def test_sin_errores_funcion_unica(self):
        src = "def g():\n    pass\n"
        sem = _analyze(src)
        assert not sem.errors


# ════════════════════════════════════════════════════════════════════════════
#  Tabla de símbolos — imports
# ════════════════════════════════════════════════════════════════════════════

class TestImports:

    def test_import_registrado(self):
        sem = _analyze("import sqlite3\n")
        sym = sem.symbol_table.lookup("sqlite3")
        assert sym is not None
        assert sym.kind == SymbolKind.MODULE

    def test_from_import_registrado(self):
        sem = _analyze("from flask import request\n")
        sym = sem.symbol_table.lookup("request")
        assert sym is not None
        assert sym.kind == SymbolKind.IMPORT

    def test_from_import_multiple(self):
        sem = _analyze("from flask import Flask, request\n")
        assert sem.symbol_table.lookup("Flask") is not None
        assert sem.symbol_table.lookup("request") is not None


# ════════════════════════════════════════════════════════════════════════════
#  Inferencia de tipos
# ════════════════════════════════════════════════════════════════════════════

class TestInferenciaTipos:

    def test_suma_ints(self):
        sem = _analyze("x = 1 + 2\n")
        sym = sem.symbol_table.lookup("x")
        assert sym.type_hint == "int"

    def test_concatenacion_strings(self):
        sem = _analyze('s = "hola" + " mundo"\n')
        sym = sem.symbol_table.lookup("s")
        assert sym.type_hint == "str"

    def test_comparacion_es_bool(self):
        sem = _analyze("ok = 1 == 1\n")
        sym = sem.symbol_table.lookup("ok")
        assert sym.type_hint == "bool"

    def test_anotacion_respetada(self):
        sem = _analyze("nombre: str = 'test'\n")
        sym = sem.symbol_table.lookup("nombre")
        assert sym.type_hint == "str"


# ════════════════════════════════════════════════════════════════════════════
#  Detección de errores semánticos
# ════════════════════════════════════════════════════════════════════════════

class TestErroresSemanticos:

    def test_break_fuera_de_bucle(self):
        sem = _analyze("break\n")
        assert any("break" in e.message for e in sem.errors)

    def test_continue_fuera_de_bucle(self):
        sem = _analyze("continue\n")
        assert any("continue" in e.message for e in sem.errors)

    def test_return_fuera_de_funcion(self):
        sem = _analyze("return 42\n")
        assert any("return" in e.message for e in sem.errors)

    def test_break_dentro_de_while_ok(self):
        src = "while True:\n    break\n"
        sem = _analyze(src)
        assert not any("break" in e.message for e in sem.errors)

    def test_return_dentro_de_funcion_ok(self):
        src = "def f():\n    return 1\n"
        sem = _analyze(src)
        assert not sem.errors


# ════════════════════════════════════════════════════════════════════════════
#  Marcado de variables tainted (source tracking)
# ════════════════════════════════════════════════════════════════════════════

class TestTaintTracking:

    def test_input_marca_variable_tainted(self):
        sem = _analyze('username = input("Usuario: ")\n')
        sym = sem.symbol_table.lookup("username")
        assert sym is not None
        assert sym.is_tainted

    def test_request_form_get_tainted(self):
        sem = _analyze('dato = request.form.get("campo")\n')
        sym = sem.symbol_table.lookup("dato")
        assert sym is not None
        assert sym.is_tainted

    def test_constante_no_tainted(self):
        sem = _analyze('sql = "SELECT COUNT(*) FROM t"\n')
        sym = sem.symbol_table.lookup("sql")
        assert sym is not None
        assert not sym.is_tainted

    def test_concatenacion_con_tainted_propaga(self):
        src = (
            'raw = request.args.get("q")\n'
            'query = "SELECT * FROM t WHERE x=" + raw\n'
        )
        sem = _analyze(src)
        query_sym = sem.symbol_table.lookup("query")
        assert query_sym is not None
        # La concatenación con tainted también es tainted
        assert query_sym.is_tainted

    def test_variable_limpia_no_tainted(self):
        sem = _analyze("x = 42\n")
        sym = sem.symbol_table.lookup("x")
        assert not sym.is_tainted


# ════════════════════════════════════════════════════════════════════════════
#  Código real del proyecto
# ════════════════════════════════════════════════════════════════════════════

class TestCodigoReal:

    def test_login_vulnerable(self):
        src = """
username = request.form.get("username")
password = request.form.get("password")
query = "SELECT * FROM usuarios WHERE username='" + username + "'"
"""
        sem = _analyze(src)
        # username y password deben estar marcados como tainted
        u = sem.symbol_table.lookup("username")
        p = sem.symbol_table.lookup("password")
        assert u and u.is_tainted
        assert p and p.is_tainted
        # query también debe ser tainted (concatenación con username)
        q = sem.symbol_table.lookup("query")
        assert q and q.is_tainted

    def test_funcion_buscar_dni(self):
        src = """
def buscar_ciudadano(dni):
    sql = "SELECT nombre FROM ciudadanos WHERE dni='" + dni + "'"
    return sql
"""
        sem = _analyze(src)
        # No debe haber errores reales
        assert not sem.errors

    def test_sin_errores_en_consulta_segura(self):
        src = """
from flask import request
username = request.form.get("username")
cursor.execute("SELECT * FROM users WHERE name=?", (username,))
"""
        sem = _analyze(src)
        assert not sem.errors

    def test_numeros_linea_correctos(self):
        src = "x = 1\ny = 2\nz = 3\n"
        sem = _analyze(src)
        assert sem.symbol_table.lookup("x").line == 1
        assert sem.symbol_table.lookup("y").line == 2
        assert sem.symbol_table.lookup("z").line == 3
