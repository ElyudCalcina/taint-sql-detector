"""
Generador de Representación Intermedia — Fase 4 del Compilador
==============================================================
Traduce el AST propio (parser.py) a instrucciones de Código de Tres
Direcciones (TAC), definidas en ir.py.

Implementa el patrón Visitor sobre los nodos del AST propio, a diferencia
del módulo cfg_builder.py que opera sobre el AST del módulo 'ast' de Python.
Esto cierra el pipeline completo: lexer → parser → semantic → ir_gen → CFG.

Funcionalidades especiales:
  - Resolución de f-strings: extrae las variables interpoladas {var} y genera
    instrucciones BINOP de concatenación para propagar el taint.
  - Soporte de break/continue mediante pila de etiquetas de bucle.
  - Representación de colecciones (list, tuple, dict, set) como CALL.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from .ir import Instruction, OpType, BasicBlock, CFG
from .parser import (
    Node, Program, FuncDef, Param, IfStmt, ElifClause,
    WhileStmt, ForStmt, ReturnStmt, AssignStmt, AugAssignStmt,
    AnnAssignStmt, ExprStmt, ImportStmt, FromImportStmt,
    PassStmt, BreakStmt, ContinueStmt, GlobalStmt, NonlocalStmt,
    RaiseStmt,
    BinOp, UnaryOp, BoolOp, Compare, IfExpr, Call, Keyword,
    Attribute, Subscript, Name, Constant, ListExpr, TupleExpr,
    DictExpr, SetExpr, StarredExpr,
)


# ════════════════════════════════════════════════════════════════════════════
#  GENERADORES DE TEMPORALES Y ETIQUETAS
# ════════════════════════════════════════════════════════════════════════════

class _Gen:
    def __init__(self):
        self._t = 0
        self._l = 0

    def temp(self) -> str:
        self._t += 1
        return f"t{self._t}"

    def label(self) -> str:
        self._l += 1
        return f"L{self._l}"


# ════════════════════════════════════════════════════════════════════════════
#  GENERADOR DE IR
# ════════════════════════════════════════════════════════════════════════════

_FVAR = re.compile(r'\{([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\}')


class IRGenerator:
    """
    Genera código de tres direcciones (TAC) a partir del AST propio.

    Patrón de uso::

        gen    = IRGenerator()
        instrs = gen.generate(program_ast)
        cfg    = CFGBuilder().build(instrs)
    """

    def __init__(self):
        self._gen         = _Gen()
        self._instrs:     List[Instruction] = []
        self._attr_names: Dict[str, str]    = {}   # temp → nombre semántico
        self._break_lbl:  List[str]         = []   # pila etiquetas break
        self._cont_lbl:   List[str]         = []   # pila etiquetas continue

    # ── API pública ──────────────────────────────────────────────────────────

    def generate(self, program: Program) -> List[Instruction]:
        """Genera y retorna la lista de instrucciones TAC del programa."""
        self._instrs     = []
        self._attr_names = {}
        self._break_lbl  = []
        self._cont_lbl   = []
        self._gen        = _Gen()
        self._visit_stmts(program.body)
        return self._instrs

    # ── helpers ──────────────────────────────────────────────────────────────

    def _emit(self, instr: Instruction) -> None:
        self._instrs.append(instr)

    def _t(self) -> str:
        return self._gen.temp()

    def _l(self) -> str:
        return self._gen.label()

    def _lbl(self, name: str, line: int = 0) -> Instruction:
        return Instruction(op=OpType.LABEL, label=name, line_no=line)

    # ── visitores de sentencias ──────────────────────────────────────────────

    def _visit_stmts(self, stmts: List[Node]) -> None:
        for s in stmts:
            self._visit_stmt(s)

    def _visit_stmt(self, node: Node) -> None:
        """Dispatcher de sentencias vía nombre de clase."""
        name = type(node).__name__
        handler = getattr(self, f"_stmt_{name}", None)
        if handler:
            handler(node)

    # ─── sentencias concretas ────────────────────────────────────────────────

    def _stmt_FuncDef(self, node: FuncDef) -> None:
        for p in node.params:
            if p.name in ("*", "separator"):
                continue
            self._emit(Instruction(op=OpType.PARAM, dest=p.name,
                                   line_no=node.line))
        self._visit_stmts(node.body)

    def _stmt_IfStmt(self, node: IfStmt) -> None:
        cond    = self._expr(node.condition)
        l_true  = self._l()
        l_end   = self._l()

        if not node.elif_clauses and not node.else_body:
            self._emit(Instruction(op=OpType.BRANCH, src1=cond,
                                   true_label=l_true, false_label=l_end,
                                   line_no=node.line))
            self._emit(self._lbl(l_true))
            self._visit_stmts(node.then_body)
            self._emit(self._lbl(l_end))
            return

        # Con elif/else: crear cadena de etiquetas
        chain: List[str] = [l_true]
        for _ in node.elif_clauses:
            chain.append(self._l())
        l_else = self._l() if node.else_body else l_end
        chain.append(l_else)

        self._emit(Instruction(op=OpType.BRANCH, src1=cond,
                               true_label=l_true, false_label=chain[1],
                               line_no=node.line))
        self._emit(self._lbl(l_true))
        self._visit_stmts(node.then_body)
        self._emit(Instruction(op=OpType.JUMP, label=l_end))

        for i, elif_ in enumerate(node.elif_clauses):
            self._emit(self._lbl(chain[i + 1]))
            elif_cond = self._expr(elif_.condition)
            l_elif_true = self._l()
            next_false  = chain[i + 2]
            self._emit(Instruction(op=OpType.BRANCH, src1=elif_cond,
                                   true_label=l_elif_true,
                                   false_label=next_false,
                                   line_no=elif_.line))
            self._emit(self._lbl(l_elif_true))
            self._visit_stmts(elif_.body)
            self._emit(Instruction(op=OpType.JUMP, label=l_end))

        if node.else_body:
            self._emit(self._lbl(l_else))
            self._visit_stmts(node.else_body)

        self._emit(self._lbl(l_end))

    def _stmt_WhileStmt(self, node: WhileStmt) -> None:
        l_cond = self._l()
        l_body = self._l()
        l_end  = self._l()

        self._break_lbl.append(l_end)
        self._cont_lbl.append(l_cond)

        self._emit(self._lbl(l_cond))
        cond = self._expr(node.condition)
        self._emit(Instruction(op=OpType.BRANCH, src1=cond,
                               true_label=l_body, false_label=l_end,
                               line_no=node.line))
        self._emit(self._lbl(l_body))
        self._visit_stmts(node.body)
        self._emit(Instruction(op=OpType.JUMP, label=l_cond))
        self._emit(self._lbl(l_end))

        self._break_lbl.pop()
        self._cont_lbl.pop()

        if node.else_body:
            self._visit_stmts(node.else_body)

    def _stmt_ForStmt(self, node: ForStmt) -> None:
        iterable = self._expr(node.iterable)
        l_cond   = self._l()
        l_body   = self._l()
        l_end    = self._l()

        iter_var = node.target.id if isinstance(node.target, Name) else self._t()
        t_iter   = self._t()
        self._emit(Instruction(op=OpType.CALL, dest=t_iter,
                               func_name="iter", args=[iterable],
                               line_no=node.line))

        self._break_lbl.append(l_end)
        self._cont_lbl.append(l_cond)

        self._emit(self._lbl(l_cond))
        t_next = self._t()
        self._emit(Instruction(op=OpType.CALL, dest=t_next,
                               func_name="next", args=[t_iter],
                               line_no=node.line))
        self._emit(Instruction(op=OpType.ASSIGN, dest=iter_var, src1=t_next,
                               line_no=node.line))
        self._emit(Instruction(op=OpType.BRANCH, src1=t_next,
                               true_label=l_body, false_label=l_end,
                               line_no=node.line))
        self._emit(self._lbl(l_body))
        self._visit_stmts(node.body)
        self._emit(Instruction(op=OpType.JUMP, label=l_cond))
        self._emit(self._lbl(l_end))

        self._break_lbl.pop()
        self._cont_lbl.pop()

        if node.else_body:
            self._visit_stmts(node.else_body)

    def _stmt_ReturnStmt(self, node: ReturnStmt) -> None:
        val = self._expr(node.value) if node.value else None
        self._emit(Instruction(op=OpType.RETURN, src1=val,
                               line_no=node.line))

    def _stmt_AssignStmt(self, node: AssignStmt) -> None:
        val = self._expr(node.value)
        for target in node.targets:
            if isinstance(target, Name):
                self._emit(Instruction(op=OpType.ASSIGN,
                                       dest=target.id, src1=val,
                                       line_no=node.line))
            elif isinstance(target, Attribute):
                obj = self._expr(target.obj)
                self._emit(Instruction(op=OpType.STORE,
                                       dest=obj, src2=target.attr, src1=val,
                                       line_no=node.line))

    def _stmt_AugAssignStmt(self, node: AugAssignStmt) -> None:
        val = self._expr(node.value)
        if isinstance(node.target, Name):
            name   = node.target.id
            op_sym = node.op[:-1]   # "+=" → "+"
            t      = self._t()
            self._emit(Instruction(op=OpType.BINOP, dest=t,
                                   src1=name, src2=val, operator=op_sym,
                                   line_no=node.line))
            self._emit(Instruction(op=OpType.ASSIGN, dest=name, src1=t,
                                   line_no=node.line))

    def _stmt_AnnAssignStmt(self, node: AnnAssignStmt) -> None:
        if node.value and isinstance(node.target, Name):
            val = self._expr(node.value)
            self._emit(Instruction(op=OpType.ASSIGN,
                                   dest=node.target.id, src1=val,
                                   line_no=node.line))

    def _stmt_ExprStmt(self, node: ExprStmt) -> None:
        self._expr(node.value)

    def _stmt_ImportStmt(self, node: ImportStmt) -> None:
        self._emit(Instruction(op=OpType.NOP, line_no=node.line))

    def _stmt_FromImportStmt(self, node: FromImportStmt) -> None:
        self._emit(Instruction(op=OpType.NOP, line_no=node.line))

    def _stmt_PassStmt(self, node: PassStmt) -> None:
        self._emit(Instruction(op=OpType.NOP, line_no=node.line))

    def _stmt_BreakStmt(self, node: BreakStmt) -> None:
        if self._break_lbl:
            self._emit(Instruction(op=OpType.JUMP,
                                   label=self._break_lbl[-1],
                                   line_no=node.line))

    def _stmt_ContinueStmt(self, node: ContinueStmt) -> None:
        if self._cont_lbl:
            self._emit(Instruction(op=OpType.JUMP,
                                   label=self._cont_lbl[-1],
                                   line_no=node.line))

    def _stmt_GlobalStmt(self, node: GlobalStmt) -> None:
        self._emit(Instruction(op=OpType.NOP, line_no=node.line))

    def _stmt_NonlocalStmt(self, node: NonlocalStmt) -> None:
        self._emit(Instruction(op=OpType.NOP, line_no=node.line))

    def _stmt_RaiseStmt(self, node: RaiseStmt) -> None:
        if node.exc:
            self._expr(node.exc)
        self._emit(Instruction(op=OpType.NOP, line_no=node.line))

    # ── visitores de expresiones (retornan nombre del temp) ──────────────────

    def _expr(self, node: Node) -> str:
        """Genera código para una expresión y retorna el temp que guarda su valor."""
        name = type(node).__name__
        handler = getattr(self, f"_expr_{name}", None)
        if handler:
            result = handler(node)
            return result if result is not None else self._t()
        return self._t()

    def _expr_Name(self, node: Name) -> str:
        return node.id

    def _expr_Constant(self, node: Constant) -> str:
        val = node.value
        if isinstance(val, str) and len(val) >= 3 and val[0] == "f" \
                and val[1] in ('"', "'"):
            return self._fstring(val, node.line)
        t = self._t()
        self._emit(Instruction(op=OpType.CONST, dest=t,
                               const_value=val, line_no=node.line))
        return t

    def _fstring(self, raw: str, line: int) -> str:
        """
        Expande un f-string extrayendo las variables interpoladas {var}
        y generando instrucciones BINOP de concatenación.

        Soporta referencias simples y con atributos: {var}, {obj.attr}.
        El primer segmento de cada referencia (la variable raíz) se usa
        en el IR para que el taint engine pueda rastrear la contaminación.
        """
        if raw.startswith('f"""') or raw.startswith("f'''"):
            inner = raw[4:-3]
        else:
            inner = raw[2:-1]

        parts: List[str] = []
        last  = 0

        for m in _FVAR.finditer(inner):
            if m.start() > last:
                tc = self._t()
                self._emit(Instruction(op=OpType.CONST, dest=tc,
                                       const_value=inner[last:m.start()],
                                       line_no=line))
                parts.append(tc)
            root_var = m.group(1).split(".")[0]
            parts.append(root_var)
            last = m.end()

        if last < len(inner):
            tc = self._t()
            self._emit(Instruction(op=OpType.CONST, dest=tc,
                                   const_value=inner[last:], line_no=line))
            parts.append(tc)

        if not parts:
            t = self._t()
            self._emit(Instruction(op=OpType.CONST, dest=t,
                                   const_value=raw, line_no=line))
            return t

        result = parts[0]
        for p in parts[1:]:
            t = self._t()
            self._emit(Instruction(op=OpType.BINOP, dest=t,
                                   src1=result, src2=p,
                                   operator="+", line_no=line))
            result = t
        return result

    def _expr_BinOp(self, node: BinOp) -> str:
        left  = self._expr(node.left)
        right = self._expr(node.right)
        t     = self._t()
        self._emit(Instruction(op=OpType.BINOP, dest=t,
                               src1=left, src2=right,
                               operator=node.op, line_no=node.line))
        return t

    def _expr_UnaryOp(self, node: UnaryOp) -> str:
        operand = self._expr(node.operand)
        t       = self._t()
        self._emit(Instruction(op=OpType.UNOP, dest=t,
                               src1=operand, operator=node.op,
                               line_no=node.line))
        return t

    def _expr_BoolOp(self, node: BoolOp) -> str:
        result = self._expr(node.values[0])
        for v in node.values[1:]:
            right = self._expr(v)
            t     = self._t()
            self._emit(Instruction(op=OpType.BINOP, dest=t,
                                   src1=result, src2=right,
                                   operator=node.op, line_no=node.line))
            result = t
        return result

    def _expr_Compare(self, node: Compare) -> str:
        left = self._expr(node.left)
        for op, right_node in node.comparators:
            right = self._expr(right_node)
            t     = self._t()
            self._emit(Instruction(op=OpType.BINOP, dest=t,
                                   src1=left, src2=right,
                                   operator=op, line_no=node.line))
            left = t
        return left

    def _expr_IfExpr(self, node: IfExpr) -> str:
        cond    = self._expr(node.condition)
        l_true  = self._l()
        l_false = self._l()
        l_end   = self._l()
        result  = self._t()

        self._emit(Instruction(op=OpType.BRANCH, src1=cond,
                               true_label=l_true, false_label=l_false,
                               line_no=node.line))
        self._emit(self._lbl(l_true))
        vt = self._expr(node.then_val)
        self._emit(Instruction(op=OpType.ASSIGN, dest=result, src1=vt,
                               line_no=node.line))
        self._emit(Instruction(op=OpType.JUMP, label=l_end))
        self._emit(self._lbl(l_false))
        vf = self._expr(node.else_val)
        self._emit(Instruction(op=OpType.ASSIGN, dest=result, src1=vf,
                               line_no=node.line))
        self._emit(self._lbl(l_end))
        return result

    def _expr_Call(self, node: Call) -> str:
        # Resolución del nombre de la función
        if isinstance(node.func, Attribute):
            receiver      = self._expr(node.func.obj)
            receiver_name = self._attr_names.get(receiver, receiver)
            func_name     = f"{receiver_name}.{node.func.attr}"
        elif isinstance(node.func, Name):
            func_name = node.func.id
            receiver  = None
        else:
            func_name = "unknown_func"
            receiver  = None

        # Evaluar argumentos
        arg_temps: List[str] = []
        for a in node.args:
            arg_temps.append(self._expr(a))
        for kw in node.keywords:
            arg_temps.append(self._expr(kw.value))

        t = self._t()
        self._emit(Instruction(op=OpType.CALL, dest=t,
                               func_name=func_name, args=arg_temps,
                               line_no=node.line))
        return t

    def _expr_Attribute(self, node: Attribute) -> str:
        obj      = self._expr(node.obj)
        obj_name = self._attr_names.get(obj, obj)
        full     = f"{obj_name}.{node.attr}"
        t        = self._t()
        self._emit(Instruction(op=OpType.LOAD, dest=t,
                               src1=obj, src2=node.attr,
                               func_name=full, line_no=node.line))
        self._attr_names[t] = full
        return t

    def _expr_Subscript(self, node: Subscript) -> str:
        obj   = self._expr(node.obj)
        index = self._expr(node.index)
        t     = self._t()
        self._emit(Instruction(op=OpType.LOAD, dest=t,
                               src1=obj, src2=index,
                               operator="subscript", line_no=node.line))
        return t

    def _expr_ListExpr(self, node: ListExpr) -> str:
        parts = [self._expr(e) for e in node.elts]
        t     = self._t()
        self._emit(Instruction(op=OpType.CALL, dest=t,
                               func_name="list", args=parts,
                               line_no=node.line))
        return t

    def _expr_TupleExpr(self, node: TupleExpr) -> str:
        parts = [self._expr(e) for e in node.elts]
        t     = self._t()
        self._emit(Instruction(op=OpType.CALL, dest=t,
                               func_name="tuple", args=parts,
                               line_no=node.line))
        return t

    def _expr_DictExpr(self, node: DictExpr) -> str:
        for k in node.keys:
            if k:
                self._expr(k)
        for v in node.values:
            self._expr(v)
        t = self._t()
        self._emit(Instruction(op=OpType.CALL, dest=t,
                               func_name="dict", args=[],
                               line_no=node.line))
        return t

    def _expr_SetExpr(self, node: SetExpr) -> str:
        parts = [self._expr(e) for e in node.elts]
        t     = self._t()
        self._emit(Instruction(op=OpType.CALL, dest=t,
                               func_name="set", args=parts,
                               line_no=node.line))
        return t

    def _expr_StarredExpr(self, node: StarredExpr) -> str:
        return self._expr(node.value)

    def _expr_FuncDef(self, node: FuncDef) -> str:
        t = self._t()
        self._emit(Instruction(op=OpType.CONST, dest=t,
                               const_value=f"<lambda:{node.line}>",
                               line_no=node.line))
        return t


# ════════════════════════════════════════════════════════════════════════════
#  FUNCIÓN DE CONVENIENCIA: pipeline custom completo
# ════════════════════════════════════════════════════════════════════════════

def generate_ir(source: str) -> List[Instruction]:
    """
    Pipeline custom: código fuente → tokens → AST → IR (TAC).

    Usa el lexer y parser propios del proyecto (no ast.parse de Python).
    Retorna la lista de instrucciones TAC lista para CFGBuilder.
    """
    from .lexer import Lexer
    from .parser import Parser

    tokens  = Lexer(source).tokenize()
    parser  = Parser(tokens)
    tree    = parser.parse()
    return IRGenerator().generate(tree)
