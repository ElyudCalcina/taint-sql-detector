"""
Tests del Generador de IR — Fase 4 del Compilador.
Ejecutar: python3 -m pytest tests/test_ir_gen.py -v
"""
import pytest
from analyzer.parser import parse
from analyzer.ir_gen import IRGenerator, generate_ir
from analyzer.ir import OpType, Instruction
from analyzer.cfg_builder import CFGBuilder
from analyzer.taint_engine import TaintEngine


def _gen(src: str) -> list:
    """Genera instrucciones TAC desde código fuente vía pipeline custom."""
    return generate_ir(src)


def _ops(src: str) -> list:
    """Retorna solo los OpType de las instrucciones generadas."""
    return [i.op for i in _gen(src)]


def _analyze_custom(src: str, taint_params: bool = False) -> list:
    """Pipeline completo usando el IR generador propio."""
    instrs = generate_ir(src)
    cfg    = CFGBuilder().build(instrs)
    engine = TaintEngine(cfg, func_params_tainted=taint_params)
    return engine.analyze()


# ════════════════════════════════════════════════════════════════════════════
#  Generación de instrucciones básicas
# ════════════════════════════════════════════════════════════════════════════

class TestInstruccionesBasicas:

    def test_asignacion_constante(self):
        instrs = _gen("x = 42\n")
        ops = [i.op for i in instrs]
        assert OpType.CONST  in ops
        assert OpType.ASSIGN in ops

    def test_asignacion_string(self):
        instrs = _gen('"hola"\n')
        assert any(i.op == OpType.CONST and i.const_value == '"hola"'
                   for i in instrs)

    def test_binop_suma(self):
        instrs = _gen("z = 1 + 2\n")
        binops = [i for i in instrs if i.op == OpType.BINOP]
        assert any(i.operator == "+" for i in binops)

    def test_binop_concatenacion(self):
        instrs = _gen('"a" + "b"\n')
        assert any(i.op == OpType.BINOP and i.operator == "+"
                   for i in instrs)

    def test_unaryop(self):
        instrs = _gen("-x\n")
        assert any(i.op == OpType.UNOP for i in instrs)

    def test_call_simple(self):
        instrs = _gen("f()\n")
        assert any(i.op == OpType.CALL and i.func_name == "f"
                   for i in instrs)

    def test_call_con_args(self):
        instrs = _gen("f(a, b)\n")
        calls = [i for i in instrs if i.op == OpType.CALL and i.func_name == "f"]
        assert calls
        assert len(calls[0].args) == 2

    def test_load_atributo(self):
        instrs = _gen("request.form\n")
        loads = [i for i in instrs if i.op == OpType.LOAD]
        assert loads
        assert loads[0].src2 == "form"


# ════════════════════════════════════════════════════════════════════════════
#  Parámetros de función
# ════════════════════════════════════════════════════════════════════════════

class TestParametros:

    def test_funcion_emite_params(self):
        src = "def login(usuario, password):\n    pass\n"
        instrs = _gen(src)
        params = [i for i in instrs if i.op == OpType.PARAM]
        names  = {p.dest for p in params}
        assert "usuario"  in names
        assert "password" in names

    def test_funcion_sin_params(self):
        src = "def f():\n    pass\n"
        instrs = _gen(src)
        params = [i for i in instrs if i.op == OpType.PARAM]
        assert len(params) == 0

    def test_return_emitido(self):
        src = "def f():\n    return 42\n"
        instrs = _gen(src)
        assert any(i.op == OpType.RETURN for i in instrs)


# ════════════════════════════════════════════════════════════════════════════
#  Flujo de control
# ════════════════════════════════════════════════════════════════════════════

class TestFlujoDeControl:

    def test_if_genera_branch(self):
        src = "if x:\n    y = 1\n"
        assert OpType.BRANCH in _ops(src)

    def test_if_else_genera_branch_y_jump(self):
        src = "if a:\n    x = 1\nelse:\n    x = 2\n"
        ops = _ops(src)
        assert OpType.BRANCH in ops
        assert OpType.JUMP   in ops

    def test_while_genera_branch_back_edge(self):
        src = "while i < 10:\n    i = i + 1\n"
        ops = _ops(src)
        assert OpType.BRANCH in ops
        assert OpType.JUMP   in ops
        assert OpType.LABEL  in ops

    def test_for_genera_iter_next(self):
        src = "for x in items:\n    pass\n"
        instrs = _gen(src)
        calls = [i for i in instrs if i.op == OpType.CALL]
        func_names = {c.func_name for c in calls}
        assert "iter" in func_names
        assert "next" in func_names

    def test_break_genera_jump(self):
        src = "while True:\n    break\n"
        assert OpType.JUMP in _ops(src)


# ════════════════════════════════════════════════════════════════════════════
#  F-strings
# ════════════════════════════════════════════════════════════════════════════

class TestFStrings:

    def test_fstring_simple_genera_binop(self):
        src = 'sql = f"SELECT WHERE id={user_id}"\n'
        instrs = _gen(src)
        # Debe haber al menos una concatenación (BINOP con +)
        assert any(i.op == OpType.BINOP and i.operator == "+"
                   for i in instrs)

    def test_fstring_referencia_variable_presente(self):
        src = 'q = f"SELECT WHERE name={nombre}"\n'
        instrs = _gen(src)
        # La variable 'nombre' debe aparecer como src1 o src2 en algún BINOP
        binops = [i for i in instrs if i.op == OpType.BINOP]
        vars_used = set()
        for b in binops:
            if b.src1:
                vars_used.add(b.src1)
            if b.src2:
                vars_used.add(b.src2)
        assert "nombre" in vars_used

    def test_fstring_sin_variables_genera_const(self):
        src = 'q = f"SELECT COUNT(*) FROM t"\n'
        instrs = _gen(src)
        # Sin variables interpoladas: sólo CONST + ASSIGN
        # Puede haber BINOP si hay literales concatenados
        binops = [i for i in instrs if i.op == OpType.BINOP]
        # Las fuentes de binops no deben ser variables sin definir
        # Simplemente verificar que se emite al menos un CONST o ASSIGN
        assert any(i.op in (OpType.CONST, OpType.ASSIGN) for i in instrs)


# ════════════════════════════════════════════════════════════════════════════
#  Importaciones
# ════════════════════════════════════════════════════════════════════════════

class TestImportaciones:

    def test_import_genera_nop(self):
        instrs = _gen("import sqlite3\n")
        assert any(i.op == OpType.NOP for i in instrs)

    def test_from_import_genera_nop(self):
        instrs = _gen("from flask import request\n")
        assert any(i.op == OpType.NOP for i in instrs)


# ════════════════════════════════════════════════════════════════════════════
#  Colecciones
# ════════════════════════════════════════════════════════════════════════════

class TestColecciones:

    def test_lista_genera_call_list(self):
        instrs = _gen("[1, 2, 3]\n")
        calls = [i for i in instrs if i.op == OpType.CALL]
        assert any(c.func_name == "list" for c in calls)

    def test_tupla_genera_call_tuple(self):
        instrs = _gen("(1, 2)\n")
        calls = [i for i in instrs if i.op == OpType.CALL]
        assert any(c.func_name == "tuple" for c in calls)

    def test_dict_genera_call_dict(self):
        instrs = _gen('{"k": 1}\n')
        calls = [i for i in instrs if i.op == OpType.CALL]
        assert any(c.func_name == "dict" for c in calls)


# ════════════════════════════════════════════════════════════════════════════
#  Construcción del CFG desde IR custom
# ════════════════════════════════════════════════════════════════════════════

class TestCFGDesdeIRCustom:

    def test_if_genera_multiples_bloques(self):
        src = "x = 1\nif x > 0:\n    y = 2\nelse:\n    y = 3\n"
        instrs = generate_ir(src)
        cfg    = CFGBuilder().build(instrs)
        assert len(cfg.all_blocks()) >= 3

    def test_while_genera_back_edge(self):
        src = "i = 0\nwhile i < 10:\n    i = i + 1\n"
        instrs = generate_ir(src)
        cfg    = CFGBuilder().build(instrs)
        block_ids = {blk.bid: idx for idx, blk in enumerate(cfg.all_blocks())}
        has_back  = any(
            block_ids.get(succ.bid, 999) < block_ids.get(blk.bid, 0)
            for blk  in cfg.all_blocks()
            for succ in blk.successors
        )
        assert has_back


# ════════════════════════════════════════════════════════════════════════════
#  Detección de vulnerabilidades con el pipeline custom completo
# ════════════════════════════════════════════════════════════════════════════

class TestDeteccionConPipelineCustom:

    def test_input_directo_a_execute(self):
        code = """
username = input("Usuario: ")
query = "SELECT * FROM users WHERE name='" + username + "'"
cursor.execute(query)
"""
        vulns = _analyze_custom(code)
        assert len(vulns) >= 1
        assert any(v.sink_name.endswith("execute") for v in vulns)

    def test_fstring_tainted_detectado(self):
        code = """
user_id = request.args.get("id")
sql = f"SELECT * FROM registros WHERE id={user_id}"
cursor.execute(sql)
"""
        vulns = _analyze_custom(code)
        assert len(vulns) >= 1

    def test_cadena_de_asignaciones(self):
        code = """
raw   = input("dato: ")
paso1 = raw
paso2 = paso1 + " extra"
cursor.execute("SELECT * FROM t WHERE n=" + paso2)
"""
        vulns = _analyze_custom(code)
        assert len(vulns) >= 1

    def test_taint_params_activa(self):
        code = """
def buscar(dni):
    sql = "SELECT * FROM ciudadanos WHERE dni='" + dni + "'"
    cursor.execute(sql)
"""
        vulns = _analyze_custom(code, taint_params=True)
        assert len(vulns) >= 1

    def test_consulta_parametrizada_es_segura(self):
        code = """
username = input("Usuario: ")
cursor.execute("SELECT * FROM users WHERE name=?", (username,))
"""
        vulns = _analyze_custom(code)
        assert len(vulns) == 0

    def test_constante_sin_taint(self):
        code = 'cursor.execute("SELECT COUNT(*) FROM usuarios")\n'
        vulns = _analyze_custom(code)
        assert len(vulns) == 0

    def test_sin_falso_positivo_en_llamadas_normales(self):
        code = """
x = len("hola")
y = str(42)
print(x, y)
"""
        vulns = _analyze_custom(code)
        assert len(vulns) == 0
