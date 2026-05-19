"""
Analizador Semántico — Fase 3 del Compilador
=============================================
Construye la tabla de símbolos con ámbitos anidados y verifica
propiedades semánticas sobre el AST propio generado por parser.py.

Análisis realizados:
  1. Gestión de ámbitos anidados: global → función → bloque
  2. Registro de definiciones: variables, parámetros, funciones, imports
  3. Detección de uso de nombre no definido (warning)
  4. Detección de función duplicada en el mismo ámbito (warning)
  5. Detección de 'break'/'continue' fuera de bucle (error)
  6. Detección de 'return' fuera de función (error)
  7. Inferencia de tipo básica: int, float, str, bool, none, any
  8. Marcado de variables potencialmente tainted (source tracking)

Estrategia de diagnóstico: acumulación de todos los errores y warnings
sin detener el análisis en el primer fallo (report-all).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from .parser import (
    Node, Program, FuncDef, IfStmt, ElifClause,
    WhileStmt, ForStmt, ReturnStmt, AssignStmt, AugAssignStmt,
    AnnAssignStmt, ExprStmt, ImportStmt, FromImportStmt,
    PassStmt, BreakStmt, ContinueStmt, GlobalStmt, NonlocalStmt,
    RaiseStmt,
    BinOp, UnaryOp, BoolOp, Compare, IfExpr, Call, Keyword,
    Attribute, Subscript, Name, Constant, ListExpr, TupleExpr,
    DictExpr, SetExpr, StarredExpr,
)
from .sources_sinks import SOURCE_NAMES


# ════════════════════════════════════════════════════════════════════════════
#  TIPO DE SÍMBOLO
# ════════════════════════════════════════════════════════════════════════════

class SymbolKind(Enum):
    VARIABLE  = "variable"
    FUNCTION  = "function"
    PARAMETER = "parameter"
    IMPORT    = "import"
    MODULE    = "module"


# ════════════════════════════════════════════════════════════════════════════
#  SÍMBOLO
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class Symbol:
    """Entrada en la tabla de símbolos."""
    name:        str
    kind:        SymbolKind
    type_hint:   str  = "any"
    scope_level: int  = 0
    line:        int  = 0
    col:         int  = 0
    is_tainted:  bool = False

    def __repr__(self) -> str:
        taint = " [TAINTED]" if self.is_tainted else ""
        return (f"Symbol({self.name!r}, {self.kind.value}, "
                f"type={self.type_hint}{taint}, L{self.line})")


# ════════════════════════════════════════════════════════════════════════════
#  ÁMBITO (SCOPE)
# ════════════════════════════════════════════════════════════════════════════

class Scope:
    """Un nivel de ámbito (global, función, bloque)."""

    def __init__(self, name: str, parent: Optional["Scope"] = None,
                 level: int = 0):
        self.name   = name
        self.parent = parent
        self.level  = level
        self._table: Dict[str, Symbol] = {}

    def define(self, sym: Symbol) -> None:
        self._table[sym.name] = sym

    def lookup_local(self, name: str) -> Optional[Symbol]:
        return self._table.get(name)

    def lookup(self, name: str) -> Optional[Symbol]:
        """Búsqueda léxica: local → ámbitos externos."""
        node: Optional[Scope] = self
        while node is not None:
            if name in node._table:
                return node._table[name]
            node = node.parent
        return None

    def all_symbols(self) -> Dict[str, Symbol]:
        return dict(self._table)

    def __repr__(self) -> str:
        return f"Scope({self.name!r}, level={self.level}, {len(self._table)} symbols)"


# ════════════════════════════════════════════════════════════════════════════
#  TABLA DE SÍMBOLOS
# ════════════════════════════════════════════════════════════════════════════

class SymbolTable:
    """Gestiona la pila de ámbitos durante el recorrido del AST."""

    def __init__(self):
        self._global  = Scope("global", level=0)
        self._stack:  List[Scope] = [self._global]

    @property
    def current(self) -> Scope:
        return self._stack[-1]

    @property
    def global_scope(self) -> Scope:
        return self._global

    @property
    def depth(self) -> int:
        return len(self._stack) - 1

    def enter_scope(self, name: str) -> Scope:
        s = Scope(name, parent=self._stack[-1], level=len(self._stack))
        self._stack.append(s)
        return s

    def leave_scope(self) -> Scope:
        leaving = self._stack.pop()
        return leaving

    def define(self, sym: Symbol) -> None:
        sym.scope_level = self.depth
        self._stack[-1].define(sym)

    def lookup(self, name: str) -> Optional[Symbol]:
        return self._stack[-1].lookup(name)

    def lookup_local(self, name: str) -> Optional[Symbol]:
        return self._stack[-1].lookup_local(name)


# ════════════════════════════════════════════════════════════════════════════
#  DIAGNÓSTICOS
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class SemanticDiagnostic:
    message: str
    line:    int
    col:     int
    level:   str = "error"   # "error" | "warning"

    def __str__(self) -> str:
        tag = "ERROR" if self.level == "error" else "WARN "
        return f"[{tag}] L{self.line}:C{self.col} — {self.message}"


# ════════════════════════════════════════════════════════════════════════════
#  INFERENCIA DE TIPO BÁSICA
# ════════════════════════════════════════════════════════════════════════════

_BUILTIN_RETURN: Dict[str, str] = {
    "int": "int", "float": "float", "str": "str", "bool": "bool",
    "len": "int", "range": "any", "list": "any", "dict": "any",
    "set": "any", "tuple": "any", "input": "str",
    "print": "none", "type": "any", "isinstance": "bool",
    "issubclass": "bool", "abs": "int", "round": "float",
    "sum": "int", "min": "any", "max": "any",
}


def _infer_binop(op: str, left: str, right: str) -> str:
    if op == "+" and ("str" in (left, right)):
        return "str"
    if op == "%" and left == "str":
        return "str"
    if op in ("+", "-", "*", "**") and left == right == "int":
        return "int"
    if op in ("+", "-", "*", "/", "**", "//") and "float" in (left, right):
        return "float"
    if op in ("==", "!=", "<", ">", "<=", ">=", "in", "not in",
              "is", "is not", "and", "or"):
        return "bool"
    return "any"


# ════════════════════════════════════════════════════════════════════════════
#  NOMBRES PREDEFINIDOS (no se reportan como "no definidos")
# ════════════════════════════════════════════════════════════════════════════

_WELL_KNOWN: Set[str] = {
    "True", "False", "None",
    "int", "float", "str", "bool", "bytes",
    "list", "dict", "set", "tuple", "frozenset",
    "len", "range", "print", "input", "repr", "hash", "id",
    "type", "isinstance", "issubclass", "hasattr", "getattr",
    "setattr", "delattr", "callable", "vars", "dir",
    "open", "close", "enumerate", "zip", "map", "filter",
    "sorted", "reversed", "sum", "min", "max", "abs", "round",
    "divmod", "pow", "iter", "next", "any", "all",
    "super", "object", "classmethod", "staticmethod", "property",
    "Exception", "ValueError", "TypeError", "KeyError", "IndexError",
    "AttributeError", "RuntimeError", "StopIteration",
    "NotImplementedError", "NameError", "ImportError",
    "OSError", "IOError", "PermissionError", "FileNotFoundError",
    # Variables comunes en los ejemplos del proyecto
    "cursor", "conn", "connection", "db",
    "request", "app", "response", "g",
    "sqlite3", "flask", "django", "fastapi",
    "os", "sys", "json", "re", "time", "datetime",
    "__name__", "__doc__", "__file__", "__all__",
    "self", "cls",
}


# ════════════════════════════════════════════════════════════════════════════
#  ANALIZADOR SEMÁNTICO
# ════════════════════════════════════════════════════════════════════════════

def _resolve_name(node: Node) -> str:
    """Resuelve el nombre completo de un nodo Name/Attribute."""
    if isinstance(node, Name):
        return node.id
    if isinstance(node, Attribute):
        return f"{_resolve_name(node.obj)}.{node.attr}"
    return "unknown"


class SemanticAnalyzer:
    """
    Analizador semántico sobre el AST propio.

    Construye la SymbolTable con ámbitos anidados, infiere tipos básicos
    y acumula SemanticDiagnostic sin abortar el análisis.

    Uso::
        sem = SemanticAnalyzer()
        sym_table = sem.analyze(program_node)
        for d in sem.diagnostics:
            print(d)
    """

    def __init__(self):
        self.symbol_table  = SymbolTable()
        self.diagnostics:  List[SemanticDiagnostic] = []
        self._loop_depth   = 0
        self._func_depth   = 0
        self._global_names: Set[str] = set()

    # ── API pública ──────────────────────────────────────────────────────────

    def analyze(self, tree: Program) -> SymbolTable:
        """Recorre el AST completo y construye la tabla de símbolos."""
        self._visit_stmts(tree.body)
        return self.symbol_table

    @property
    def errors(self) -> List[SemanticDiagnostic]:
        return [d for d in self.diagnostics if d.level == "error"]

    @property
    def warnings(self) -> List[SemanticDiagnostic]:
        return [d for d in self.diagnostics if d.level == "warning"]

    # ── internos ─────────────────────────────────────────────────────────────

    def _error(self, msg: str, line: int, col: int) -> None:
        self.diagnostics.append(SemanticDiagnostic(msg, line, col, "error"))

    def _warn(self, msg: str, line: int, col: int) -> None:
        self.diagnostics.append(SemanticDiagnostic(msg, line, col, "warning"))

    # ── sentencias ───────────────────────────────────────────────────────────

    def _visit_stmts(self, stmts: List[Node]) -> None:
        for s in stmts:
            self._visit_stmt(s)

    def _visit_stmt(self, node: Node) -> None:
        match node:
            case FuncDef():
                self._visit_func_def(node)
            case IfStmt():
                self._visit_if(node)
            case WhileStmt():
                self._visit_while(node)
            case ForStmt():
                self._visit_for(node)
            case ReturnStmt():
                self._visit_return(node)
            case AssignStmt():
                self._visit_assign(node)
            case AugAssignStmt():
                self._visit_aug_assign(node)
            case AnnAssignStmt():
                self._visit_ann_assign(node)
            case ExprStmt(value=v):
                self._visit_expr(v)
            case ImportStmt():
                self._visit_import(node)
            case FromImportStmt():
                self._visit_from_import(node)
            case GlobalStmt(names=names):
                for n in names:
                    self._global_names.add(n)
            case NonlocalStmt(names=names):
                for n in names:
                    if not self.symbol_table.lookup(n):
                        self._warn(f"nonlocal '{n}' no hallada en ámbito externo",
                                   node.line, node.col)
            case BreakStmt():
                if self._loop_depth == 0:
                    self._error("'break' fuera de un bucle", node.line, node.col)
            case ContinueStmt():
                if self._loop_depth == 0:
                    self._error("'continue' fuera de un bucle", node.line, node.col)
            case RaiseStmt(exc=exc):
                if exc:
                    self._visit_expr(exc)
            case PassStmt():
                pass
            case _:
                pass

    # ── definición de función ─────────────────────────────────────────────────

    def _visit_func_def(self, node: FuncDef) -> None:
        if node.name != "<lambda>":
            existing = self.symbol_table.lookup_local(node.name)
            if existing and existing.kind == SymbolKind.FUNCTION:
                self._warn(
                    f"función '{node.name}' redefinida "
                    f"(primera en L{existing.line})",
                    node.line, node.col)
            self.symbol_table.define(Symbol(
                name=node.name, kind=SymbolKind.FUNCTION,
                type_hint="callable", line=node.line, col=node.col,
            ))

        self.symbol_table.enter_scope(f"func:{node.name}")
        self._func_depth += 1

        for p in node.params:
            if p.name in ("*", "separator"):
                continue
            self.symbol_table.define(Symbol(
                name=p.name, kind=SymbolKind.PARAMETER,
                type_hint="any", line=p.line, col=p.col,
            ))

        self._visit_stmts(node.body)

        self._func_depth -= 1
        self.symbol_table.leave_scope()

    # ── flujo de control ─────────────────────────────────────────────────────

    def _visit_if(self, node: IfStmt) -> None:
        self._visit_expr(node.condition)
        self._visit_stmts(node.then_body)
        for elif_ in node.elif_clauses:
            self._visit_expr(elif_.condition)
            self._visit_stmts(elif_.body)
        if node.else_body:
            self._visit_stmts(node.else_body)

    def _visit_while(self, node: WhileStmt) -> None:
        self._visit_expr(node.condition)
        self._loop_depth += 1
        self._visit_stmts(node.body)
        self._loop_depth -= 1
        if node.else_body:
            self._visit_stmts(node.else_body)

    def _visit_for(self, node: ForStmt) -> None:
        self._visit_expr(node.iterable)
        if isinstance(node.target, Name):
            self.symbol_table.define(Symbol(
                name=node.target.id, kind=SymbolKind.VARIABLE,
                type_hint="any", line=node.target.line, col=node.target.col,
            ))
        self._loop_depth += 1
        self._visit_stmts(node.body)
        self._loop_depth -= 1
        if node.else_body:
            self._visit_stmts(node.else_body)

    def _visit_return(self, node: ReturnStmt) -> None:
        if self._func_depth == 0:
            self._error("'return' fuera de una función", node.line, node.col)
        if node.value:
            self._visit_expr(node.value)

    # ── asignaciones ─────────────────────────────────────────────────────────

    def _visit_assign(self, node: AssignStmt) -> None:
        rtype   = self._visit_expr(node.value)
        tainted = self._expr_is_tainted(node.value)
        for target in node.targets:
            if isinstance(target, Name):
                existing = self.symbol_table.lookup_local(target.id)
                if existing:
                    existing.type_hint  = rtype
                    existing.is_tainted = tainted
                else:
                    self.symbol_table.define(Symbol(
                        name=target.id, kind=SymbolKind.VARIABLE,
                        type_hint=rtype, line=target.line, col=target.col,
                        is_tainted=tainted,
                    ))
            elif isinstance(target, Attribute):
                self._visit_expr(target.obj)

    def _visit_aug_assign(self, node: AugAssignStmt) -> None:
        self._visit_expr(node.value)
        if isinstance(node.target, Name):
            sym = self.symbol_table.lookup(node.target.id)
            if sym is None and node.target.id not in _WELL_KNOWN:
                self._warn(
                    f"'{node.target.id}' usada en asignación aumentada "
                    f"sin definición previa",
                    node.target.line, node.target.col)

    def _visit_ann_assign(self, node: AnnAssignStmt) -> None:
        ann = "any"
        if isinstance(node.annotation, Name):
            ann = node.annotation.id
        if node.value:
            self._visit_expr(node.value)
        if isinstance(node.target, Name):
            self.symbol_table.define(Symbol(
                name=node.target.id, kind=SymbolKind.VARIABLE,
                type_hint=ann, line=node.target.line, col=node.target.col,
            ))

    # ── imports ───────────────────────────────────────────────────────────────

    def _visit_import(self, node: ImportStmt) -> None:
        name = node.alias or node.module.split(".")[0]
        self.symbol_table.define(Symbol(
            name=name, kind=SymbolKind.MODULE,
            type_hint="module", line=node.line, col=node.col,
        ))

    def _visit_from_import(self, node: FromImportStmt) -> None:
        for name in node.names:
            if name == "*":
                continue
            self.symbol_table.define(Symbol(
                name=name, kind=SymbolKind.IMPORT,
                type_hint="any", line=node.line, col=node.col,
            ))

    # ── expresiones (retornan tipo inferido) ──────────────────────────────────

    def _visit_expr(self, node: Node) -> str:
        match node:
            case Constant(kind=kind):
                return kind
            case Name():
                return self._visit_name(node)
            case BinOp(op=op, left=l, right=r):
                lt = self._visit_expr(l)
                rt = self._visit_expr(r)
                return _infer_binop(op, lt, rt)
            case UnaryOp(operand=operand):
                return self._visit_expr(operand)
            case BoolOp(values=vals):
                for v in vals:
                    self._visit_expr(v)
                return "bool"
            case Compare(left=l, comparators=cmps):
                self._visit_expr(l)
                for _, c in cmps:
                    self._visit_expr(c)
                return "bool"
            case IfExpr(condition=c, then_val=t, else_val=e):
                self._visit_expr(c)
                tt = self._visit_expr(t)
                et = self._visit_expr(e)
                return tt if tt == et else "any"
            case Call():
                return self._visit_call(node)
            case Attribute(obj=obj):
                self._visit_expr(obj)
                return "any"
            case Subscript(obj=obj, index=idx):
                self._visit_expr(obj)
                self._visit_expr(idx)
                return "any"
            case ListExpr(elts=elts):
                for e in elts:
                    self._visit_expr(e)
                return "any"
            case TupleExpr(elts=elts):
                for e in elts:
                    self._visit_expr(e)
                return "any"
            case DictExpr(keys=keys, values=values):
                for k in keys:
                    if k:
                        self._visit_expr(k)
                for v in values:
                    self._visit_expr(v)
                return "any"
            case SetExpr(elts=elts):
                for e in elts:
                    self._visit_expr(e)
                return "any"
            case StarredExpr(value=v):
                return self._visit_expr(v)
            case FuncDef():
                self._visit_func_def(node)
                return "callable"
            case _:
                return "any"

    def _visit_name(self, node: Name) -> str:
        sym = self.symbol_table.lookup(node.id)
        if sym is None and node.id not in _WELL_KNOWN:
            self._warn(
                f"nombre '{node.id}' referenciado sin definición en este ámbito",
                node.line, node.col)
            return "any"
        return sym.type_hint if sym else "any"

    def _visit_call(self, node: Call) -> str:
        for a in node.args:
            self._visit_expr(a)
        for kw in node.keywords:
            self._visit_expr(kw.value)
        func = node.func
        if isinstance(func, Name):
            self._visit_name(func)
            return _BUILTIN_RETURN.get(func.id, "any")
        if isinstance(func, Attribute):
            self._visit_expr(func.obj)
        else:
            self._visit_expr(func)
        return "any"

    # ── heurística de taint ───────────────────────────────────────────────────

    def _expr_is_tainted(self, node: Node) -> bool:
        """¿Esta expresión proviene de una fuente no confiable?"""
        match node:
            case Call(func=func):
                name = _resolve_name(func)
                short = name.split(".")[-1]
                return name in SOURCE_NAMES or short in SOURCE_NAMES
            case Attribute():
                name = _resolve_name(node)
                short = name.split(".")[-1]
                return name in SOURCE_NAMES or short in SOURCE_NAMES
            case BinOp(left=l, right=r):
                return self._expr_is_tainted(l) or self._expr_is_tainted(r)
            case Name(id=id_):
                sym = self.symbol_table.lookup(id_)
                return sym.is_tainted if sym else False
            case _:
                return False

    # ── utilidad de impresión ─────────────────────────────────────────────────

    def print_table(self) -> None:
        """Imprime la tabla de símbolos del ámbito global (para depuración)."""
        scope = self.symbol_table.global_scope
        print(f"\n{'='*60}")
        print(f"  TABLA DE SÍMBOLOS — Ámbito: {scope.name}")
        print(f"{'='*60}")
        print(f"{'NOMBRE':<20} {'TIPO':<12} {'CATEGORÍA':<12} {'TAINTED':<8} {'LÍNEA'}")
        print(f"{'-'*60}")
        for name, sym in sorted(scope.all_symbols().items()):
            taint = "SI" if sym.is_tainted else "no"
            print(f"{sym.name:<20} {sym.type_hint:<12} {sym.kind.value:<12} "
                  f"{taint:<8} L{sym.line}")
        print()
