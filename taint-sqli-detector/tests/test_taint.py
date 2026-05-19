"""
Tests unitarios para el motor de taint analysis.
Ejecutar con: python -m pytest tests/ -v
"""

import pytest
from analyzer.cfg_builder import build_cfg_from_source
from analyzer.taint_engine import TaintEngine


def _analyze(source: str, taint_params: bool = False):
    _, cfg = build_cfg_from_source(source)
    engine = TaintEngine(cfg, func_params_tainted=taint_params)
    return engine.analyze()


# ════════════════════════════════════════════════════════════════════════════
#  Casos positivos (debe detectar vulnerabilidad)
# ════════════════════════════════════════════════════════════════════════════

class TestVulnerableCases:

    def test_direct_input_to_execute(self):
        """Concatenación directa de input() en execute()."""
        code = """
username = input("Usuario: ")
query = "SELECT * FROM users WHERE name='" + username + "'"
cursor.execute(query)
"""
        vulns = _analyze(code)
        assert len(vulns) >= 1
        assert any(v.sink_name.endswith("execute") for v in vulns)

    def test_fstring_in_execute(self):
        """F-string con dato tainted en execute()."""
        code = """
from flask import request
user_id = request.args.get("id")
sql = f"SELECT * FROM registros WHERE id={user_id}"
cursor.execute(sql)
"""
        vulns = _analyze(code)
        assert len(vulns) >= 1

    def test_taint_through_multiple_assignments(self):
        """Taint se propaga a través de cadena de asignaciones."""
        code = """
from flask import request
raw   = request.form.get("nombre")
paso1 = raw
paso2 = paso1 + " extra"
paso3 = paso2
cursor.execute("SELECT * FROM t WHERE n=" + paso3)
"""
        vulns = _analyze(code)
        assert len(vulns) >= 1

    def test_taint_via_function_param(self):
        """Parámetro de función tratado como tainted (modo --taint-params)."""
        code = """
def buscar(dni):
    sql = "SELECT * FROM ciudadanos WHERE dni='" + dni + "'"
    cursor.execute(sql)
"""
        vulns = _analyze(code, taint_params=True)
        assert len(vulns) >= 1

    def test_taint_in_conditional_branch(self):
        """Taint en una rama de condicional llega al sink."""
        code = """
from flask import request
user_input = request.args.get("q")
if user_input:
    sql = "SELECT * FROM tabla WHERE col='" + user_input + "'"
    cursor.execute(sql)
"""
        vulns = _analyze(code)
        assert len(vulns) >= 1


# ════════════════════════════════════════════════════════════════════════════
#  Casos negativos (NO debe detectar vulnerabilidad)
# ════════════════════════════════════════════════════════════════════════════

class TestSafeCases:

    def test_parametrized_query(self):
        """Consulta parametrizada con placeholder → segura."""
        code = """
from flask import request
username = request.form.get("username")
cursor.execute("SELECT * FROM users WHERE name=?", (username,))
"""
        vulns = _analyze(code)
        assert len(vulns) == 0

    def test_int_sanitizer(self):
        """Conversión a int() elimina la contaminación."""
        code = """
from flask import request
raw_id = request.args.get("id")
safe_id = int(raw_id)
cursor.execute("SELECT * FROM t WHERE id=" + str(safe_id))
"""
        vulns = _analyze(code)
        # int() descontamina, aunque str() vuelve a concatenar,
        # el análisis ve safe_id como clean después del int()
        assert len(vulns) == 0

    def test_constant_query_no_taint(self):
        """Consulta con sólo constantes → no hay taint."""
        code = """
cursor.execute("SELECT COUNT(*) FROM usuarios")
"""
        vulns = _analyze(code)
        assert len(vulns) == 0

    def test_unrelated_function_calls(self):
        """Llamadas que no son sources, sinks ni sanitizadores → sin falso positivo."""
        code = """
x = len("hola")
y = str(42)
z = x + y
print(z)
"""
        vulns = _analyze(code)
        assert len(vulns) == 0


# ════════════════════════════════════════════════════════════════════════════
#  Cobertura de CFG
# ════════════════════════════════════════════════════════════════════════════

class TestCFGStructure:

    def test_if_else_generates_multiple_blocks(self):
        """Un if/else debe generar al menos 3 bloques básicos."""
        code = """
x = 1
if x > 0:
    y = 2
else:
    y = 3
z = y
"""
        _, cfg = build_cfg_from_source(code)
        assert len(cfg.all_blocks()) >= 3

    def test_while_generates_back_edge(self):
        """Un bucle while debe generar un bloque con back-edge (predecesor con id mayor)."""
        code = """
i = 0
while i < 10:
    i = i + 1
"""
        _, cfg = build_cfg_from_source(code)
        # Verificar que existe al menos un ciclo (bloque que tiene sucesor anterior)
        block_ids = {blk.bid: idx for idx, blk in enumerate(cfg.all_blocks())}
        has_back_edge = False
        for blk in cfg.all_blocks():
            for succ in blk.successors:
                if block_ids.get(succ.bid, 999) < block_ids.get(blk.bid, 0):
                    has_back_edge = True
        assert has_back_edge
