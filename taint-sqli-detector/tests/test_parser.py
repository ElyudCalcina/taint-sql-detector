"""
Tests del Analizador Sintáctico (avance).
Ejecutar: python3 -m pytest tests/test_parser.py -v
"""
import pytest
from analyzer.parser import (
    parse, Parser,
    Program, FuncDef, IfStmt, WhileStmt, ForStmt,
    AssignStmt, AugAssignStmt, ReturnStmt, ExprStmt,
    ImportStmt, FromImportStmt, PassStmt,
    Call, Attribute, Subscript, BinOp, UnaryOp, BoolOp,
    Compare, Name, Constant, ListExpr, DictExpr,
    IfExpr, TupleExpr,
)
from analyzer.lexer import tokenize


def ast(src: str) -> Program:
    tree, errors = parse(src)
    return tree


def first_stmt(src: str):
    return ast(src).body[0]


# ════════════════════════════════════════════════════════════════════════════
#  Literales
# ════════════════════════════════════════════════════════════════════════════

class TestLiterales:

    def test_entero(self):
        node = first_stmt("42\n")
        assert isinstance(node, ExprStmt)
        assert isinstance(node.value, Constant)
        assert node.value.value == 42
        assert node.value.kind  == "int"

    def test_flotante(self):
        node = first_stmt("3.14\n")
        assert isinstance(node.value, Constant)
        assert abs(node.value.value - 3.14) < 1e-10

    def test_string(self):
        node = first_stmt('"hola"\n')
        assert isinstance(node.value, Constant)
        assert node.value.kind == "str"

    def test_true_false_none(self):
        for src, expected in [("True\n", True), ("False\n", False), ("None\n", None)]:
            node = first_stmt(src)
            assert isinstance(node.value, Constant)
            assert node.value.value == expected


# ════════════════════════════════════════════════════════════════════════════
#  Asignaciones
# ════════════════════════════════════════════════════════════════════════════

class TestAsignaciones:

    def test_asignacion_simple(self):
        node = first_stmt("x = 42\n")
        assert isinstance(node, AssignStmt)
        assert isinstance(node.targets[0], Name)
        assert node.targets[0].id == "x"
        assert isinstance(node.value, Constant)
        assert node.value.value == 42

    def test_asignacion_string(self):
        node = first_stmt('query = "SELECT * FROM t"\n')
        assert isinstance(node, AssignStmt)
        assert node.targets[0].id == "query"

    def test_asignacion_aumentada_plus(self):
        node = first_stmt("x += 1\n")
        assert isinstance(node, AugAssignStmt)
        assert node.op == "+="

    def test_asignacion_aumentada_minus(self):
        node = first_stmt("n -= 2\n")
        assert isinstance(node, AugAssignStmt)
        assert node.op == "-="

    def test_asignacion_encadenada(self):
        node = first_stmt("a = b = 0\n")
        assert isinstance(node, AssignStmt)
        assert len(node.targets) == 2


# ════════════════════════════════════════════════════════════════════════════
#  Expresiones
# ════════════════════════════════════════════════════════════════════════════

class TestExpresiones:

    def test_suma(self):
        node = first_stmt("1 + 2\n")
        assert isinstance(node.value, BinOp)
        assert node.value.op == "+"

    def test_concatenacion_strings(self):
        node = first_stmt('"a" + "b"\n')
        assert isinstance(node.value, BinOp)

    def test_operador_not(self):
        node = first_stmt("not True\n")
        assert isinstance(node.value, UnaryOp)
        assert node.value.op == "not"

    def test_operador_and(self):
        node = first_stmt("a and b\n")
        assert isinstance(node.value, BoolOp)
        assert node.value.op == "and"

    def test_operador_or(self):
        node = first_stmt("a or b\n")
        assert isinstance(node.value, BoolOp)
        assert node.value.op == "or"

    def test_comparacion_igual(self):
        node = first_stmt("x == y\n")
        assert isinstance(node.value, Compare)
        assert node.value.comparators[0][0] == "=="

    def test_comparacion_menor(self):
        node = first_stmt("a < b\n")
        assert isinstance(node.value, Compare)
        assert node.value.comparators[0][0] == "<"

    def test_expresion_condicional(self):
        node = first_stmt("1 if x else 0\n")
        assert isinstance(node.value, IfExpr)

    def test_potencia(self):
        node = first_stmt("2 ** 10\n")
        assert isinstance(node.value, BinOp)
        assert node.value.op == "**"

    def test_negacion_unaria(self):
        node = first_stmt("-x\n")
        assert isinstance(node.value, UnaryOp)
        assert node.value.op == "-"


# ════════════════════════════════════════════════════════════════════════════
#  Acceso a atributos, subscripts y llamadas
# ════════════════════════════════════════════════════════════════════════════

class TestTrailers:

    def test_acceso_atributo(self):
        node = first_stmt("request.form\n")
        assert isinstance(node.value, Attribute)
        assert node.value.attr == "form"

    def test_acceso_atributo_anidado(self):
        node = first_stmt("a.b.c\n")
        outer = node.value
        assert isinstance(outer, Attribute)
        assert outer.attr == "c"
        assert isinstance(outer.obj, Attribute)
        assert outer.obj.attr == "b"

    def test_subscript(self):
        node = first_stmt("d['key']\n")
        assert isinstance(node.value, Subscript)

    def test_llamada_sin_args(self):
        node = first_stmt("f()\n")
        assert isinstance(node.value, Call)
        assert len(node.value.args) == 0

    def test_llamada_con_args(self):
        node = first_stmt("f(1, 2, 3)\n")
        assert isinstance(node.value, Call)
        assert len(node.value.args) == 3

    def test_llamada_con_kwarg(self):
        node = first_stmt("f(x=1)\n")
        assert isinstance(node.value, Call)
        assert len(node.value.keywords) == 1
        assert node.value.keywords[0].key == "x"

    def test_llamada_metodo(self):
        node = first_stmt('request.form.get("username")\n')
        assert isinstance(node.value, Call)
        func = node.value.func
        assert isinstance(func, Attribute)
        assert func.attr == "get"

    def test_execute_con_query(self):
        node = first_stmt("cursor.execute(query)\n")
        assert isinstance(node.value, Call)
        assert isinstance(node.value.func, Attribute)
        assert node.value.func.attr == "execute"


# ════════════════════════════════════════════════════════════════════════════
#  Sentencias de control
# ════════════════════════════════════════════════════════════════════════════

class TestControl:

    def test_if_simple(self):
        src = "if x:\n    pass\n"
        node = first_stmt(src)
        assert isinstance(node, IfStmt)
        assert isinstance(node.condition, Name)

    def test_if_else(self):
        src = "if a:\n    x = 1\nelse:\n    x = 2\n"
        node = first_stmt(src)
        assert isinstance(node, IfStmt)
        assert node.else_body is not None

    def test_if_elif_else(self):
        src = "if a:\n    x = 1\nelif b:\n    x = 2\nelse:\n    x = 3\n"
        node = first_stmt(src)
        assert isinstance(node, IfStmt)
        assert len(node.elif_clauses) == 1

    def test_while(self):
        src = "while i < 10:\n    i += 1\n"
        node = first_stmt(src)
        assert isinstance(node, WhileStmt)
        assert isinstance(node.condition, Compare)

    def test_for(self):
        src = "for item in lista:\n    pass\n"
        node = first_stmt(src)
        assert isinstance(node, ForStmt)
        assert isinstance(node.target, Name)
        assert isinstance(node.iterable, Name)

    def test_return_con_valor(self):
        src = "def f():\n    return 42\n"
        func = first_stmt(src)
        ret = func.body[0]
        assert isinstance(ret, ReturnStmt)
        assert isinstance(ret.value, Constant)

    def test_pass(self):
        src = "if True:\n    pass\n"
        node = first_stmt(src)
        assert isinstance(node.then_body[0], PassStmt)


# ════════════════════════════════════════════════════════════════════════════
#  Definición de funciones
# ════════════════════════════════════════════════════════════════════════════

class TestFuncDef:

    def test_funcion_sin_params(self):
        src = "def f():\n    pass\n"
        node = first_stmt(src)
        assert isinstance(node, FuncDef)
        assert node.name == "f"
        assert node.params == []

    def test_funcion_con_params(self):
        src = "def login(username, password):\n    pass\n"
        node = first_stmt(src)
        assert isinstance(node, FuncDef)
        assert len(node.params) == 2
        assert node.params[0].name == "username"
        assert node.params[1].name == "password"

    def test_funcion_con_default(self):
        src = "def f(x=10):\n    pass\n"
        node = first_stmt(src)
        assert node.params[0].default is not None

    def test_funcion_con_anotacion_retorno(self):
        src = "def f() -> str:\n    pass\n"
        node = first_stmt(src)
        assert node.return_ann is not None


# ════════════════════════════════════════════════════════════════════════════
#  Imports
# ════════════════════════════════════════════════════════════════════════════

class TestImports:

    def test_import_simple(self):
        node = first_stmt("import sqlite3\n")
        assert isinstance(node, ImportStmt)
        assert node.module == "sqlite3"

    def test_from_import(self):
        node = first_stmt("from flask import request\n")
        assert isinstance(node, FromImportStmt)
        assert node.module == "flask"
        assert "request" in node.names

    def test_from_import_multiple(self):
        node = first_stmt("from flask import Flask, request\n")
        assert isinstance(node, FromImportStmt)
        assert len(node.names) == 2


# ════════════════════════════════════════════════════════════════════════════
#  Colecciones
# ════════════════════════════════════════════════════════════════════════════

class TestColecciones:

    def test_lista_vacia(self):
        node = first_stmt("[]\n")
        assert isinstance(node.value, ListExpr)
        assert len(node.value.elts) == 0

    def test_lista_con_elementos(self):
        node = first_stmt("[1, 2, 3]\n")
        assert isinstance(node.value, ListExpr)
        assert len(node.value.elts) == 3

    def test_tupla(self):
        node = first_stmt("(1, 2)\n")
        assert isinstance(node.value, TupleExpr)

    def test_dict_vacio(self):
        node = first_stmt("{}\n")
        assert isinstance(node.value, DictExpr)

    def test_dict_con_pares(self):
        node = first_stmt('{"k": 1}\n')
        assert isinstance(node.value, DictExpr)
        assert len(node.value.keys) == 1


# ════════════════════════════════════════════════════════════════════════════
#  Código real del proyecto
# ════════════════════════════════════════════════════════════════════════════

class TestCodigoReal:

    def test_parsea_login_vulnerable(self):
        src = """
username = request.form.get("username")
password = request.form.get("password")
query = "SELECT * FROM usuarios WHERE username='" + username + "'"
cursor.execute(query)
"""
        tree, errors = parse(src)
        assert isinstance(tree, Program)
        assert len(tree.body) >= 3
        assert not errors, f"Errores inesperados: {errors}"

    def test_parsea_consulta_parametrizada(self):
        src = 'cursor.execute("SELECT * FROM t WHERE id=?", (user_id,))\n'
        tree, errors = parse(src)
        assert not errors

    def test_numero_linea_correcto(self):
        src = "x = 1\ny = 2\nz = 3\n"
        tree, _ = parse(src)
        assert tree.body[0].line == 1
        assert tree.body[1].line == 2
        assert tree.body[2].line == 3
