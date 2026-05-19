"""
Analizador Sintáctico (Parser) — Fase 2 del Compilador
=======================================================
Implementa un parser de descenso recursivo predictivo (LL(1) / LL(k))
para el subconjunto de Python usado en el análisis de taint.

Recibe la secuencia de tokens del lexer y produce un AST propio
(independiente del módulo `ast` de Python), formalizado como nodos
del árbol de sintaxis abstracta.

Gramática simplificada (BNF):
──────────────────────────────
program      → stmt* EOF

stmt         → func_def
             | if_stmt
             | while_stmt
             | for_stmt
             | return_stmt
             | import_stmt
             | expr_stmt
             | pass_stmt

func_def     → 'def' NAME '(' param_list? ')' ['->' expr] ':' suite
if_stmt      → 'if' expr ':' suite ('elif' expr ':' suite)* ['else' ':' suite]
while_stmt   → 'while' expr ':' suite
for_stmt     → 'for' target 'in' expr ':' suite
return_stmt  → 'return' [expr] NEWLINE
import_stmt  → 'import' dotted_name NEWLINE
             | 'from' dotted_name 'import' (NAME | '*') NEWLINE
pass_stmt    → 'pass' NEWLINE
expr_stmt    → expr (assign_op expr | augassign_op expr | ) NEWLINE

suite        → NEWLINE INDENT stmt+ DEDENT

expr         → lambda_expr | or_expr
or_expr      → and_expr ('or' and_expr)*
and_expr     → not_expr ('and' not_expr)*
not_expr     → 'not' not_expr | cmp_expr
cmp_expr     → add_expr (cmp_op add_expr)*
add_expr     → mul_expr (('+' | '-') mul_expr)*
mul_expr     → unary_expr (('*' | '/' | '//' | '%' | '@') unary_expr)*
unary_expr   → ('+' | '-' | '~') unary_expr | power_expr
power_expr   → atom_expr ['**' unary_expr]
atom_expr    → atom trailer*
trailer      → '(' [arglist] ')' | '[' expr ']' | '.' NAME
atom         → NAME | NUMBER | STRING+ | 'True' | 'False' | 'None'
             | '(' [expr | tuple_expr] ')'
             | '[' [expr_list] ']'
             | '{' [dict_or_set] '}'
"""

from __future__ import annotations

from dataclasses import dataclass, field, KW_ONLY
from typing import List, Optional, Union, Any

from .lexer import Lexer, Token, TT, tokenize


# ════════════════════════════════════════════════════════════════════════════
#  NODOS DEL AST PROPIO
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class Node:
    """Clase base de todos los nodos del AST."""
    _: KW_ONLY          # todo lo que sigue es keyword-only (evita conflictos de herencia)
    line: int = 0
    col:  int = 0

    def accept(self, visitor):
        method = f"visit_{type(self).__name__}"
        return getattr(visitor, method, visitor.generic_visit)(self)


# ── Programa ─────────────────────────────────────────────────────────────────

@dataclass
class Program(Node):
    body: List[Node] = field(default_factory=list)


# ── Sentencias ────────────────────────────────────────────────────────────────

@dataclass
class FuncDef(Node):
    name:        str
    params:      List["Param"]
    body:        List[Node]
    return_ann:  Optional[Node] = None

@dataclass
class Param(Node):
    name:        str
    annotation:  Optional[Node] = None
    default:     Optional[Node] = None
    kind:        str = "positional"   # positional | *args | **kwargs

@dataclass
class IfStmt(Node):
    condition:  Node
    then_body:  List[Node]
    elif_clauses: List["ElifClause"] = field(default_factory=list)
    else_body:  Optional[List[Node]] = None

@dataclass
class ElifClause(Node):
    condition: Node
    body:      List[Node]

@dataclass
class WhileStmt(Node):
    condition: Node
    body:      List[Node]
    else_body: Optional[List[Node]] = None

@dataclass
class ForStmt(Node):
    target:    Node
    iterable:  Node
    body:      List[Node]
    else_body: Optional[List[Node]] = None

@dataclass
class ReturnStmt(Node):
    value: Optional[Node] = None

@dataclass
class AssignStmt(Node):
    targets: List[Node]
    value:   Node

@dataclass
class AugAssignStmt(Node):
    target: Node
    op:     str
    value:  Node

@dataclass
class AnnAssignStmt(Node):
    target:     Node
    annotation: Node
    value:      Optional[Node] = None

@dataclass
class ExprStmt(Node):
    value: Node

@dataclass
class ImportStmt(Node):
    module: str
    alias:  Optional[str] = None

@dataclass
class FromImportStmt(Node):
    module: str
    names:  List[str]
    alias:  Optional[str] = None

@dataclass
class PassStmt(Node):
    pass

@dataclass
class BreakStmt(Node):
    pass

@dataclass
class ContinueStmt(Node):
    pass

@dataclass
class GlobalStmt(Node):
    names: List[str]

@dataclass
class NonlocalStmt(Node):
    names: List[str]

@dataclass
class RaiseStmt(Node):
    exc:   Optional[Node] = None
    cause: Optional[Node] = None


# ── Expresiones ───────────────────────────────────────────────────────────────

@dataclass
class BinOp(Node):
    left:  Node
    op:    str
    right: Node

@dataclass
class UnaryOp(Node):
    op:    str
    operand: Node

@dataclass
class BoolOp(Node):
    op:     str          # "and" | "or"
    values: List[Node]

@dataclass
class Compare(Node):
    left:        Node
    comparators: List[tuple]   # lista de (op_str, Node)

@dataclass
class IfExpr(Node):
    condition: Node
    then_val:  Node
    else_val:  Node

@dataclass
class Call(Node):
    func:     Node
    args:     List[Node]
    keywords: List["Keyword"]

@dataclass
class Keyword(Node):
    key:   Optional[str]   # None para **kwargs
    value: Node

@dataclass
class Attribute(Node):
    obj:  Node
    attr: str

@dataclass
class Subscript(Node):
    obj:   Node
    index: Node

@dataclass
class Name(Node):
    id: str

@dataclass
class Constant(Node):
    value: Any
    kind:  str = "generic"   # int | float | str | bool | none

@dataclass
class ListExpr(Node):
    elts: List[Node]

@dataclass
class TupleExpr(Node):
    elts: List[Node]

@dataclass
class DictExpr(Node):
    keys:   List[Optional[Node]]
    values: List[Node]

@dataclass
class SetExpr(Node):
    elts: List[Node]

@dataclass
class StarredExpr(Node):
    value: Node


# ════════════════════════════════════════════════════════════════════════════
#  ERROR DE PARSING
# ════════════════════════════════════════════════════════════════════════════

class ParseError(Exception):
    def __init__(self, msg: str, token: Token):
        super().__init__(
            f"Error sintáctico en L{token.line}:C{token.col} "
            f"[{token.type.name} {token.value!r}] — {msg}"
        )
        self.token = token


# ════════════════════════════════════════════════════════════════════════════
#  ANALIZADOR SINTÁCTICO PRINCIPAL
# ════════════════════════════════════════════════════════════════════════════

class Parser:
    """
    Parser de descenso recursivo predictivo (LL(k), k≤2) para Python.

    Cada método parse_X() corresponde a un no-terminal de la gramática
    y retorna el nodo AST correspondiente.

    Estrategia de recuperación de errores: pánico controlado — al encontrar
    un error se sincronizan en el siguiente NEWLINE o EOF.
    """

    def __init__(self, tokens: List[Token]):
        # Filtra INDENT/DEDENT/NEWLINE del flujo principal (se manejan por separado)
        self._all    = tokens
        self._tokens = tokens
        self._pos    = 0
        self._errors: List[ParseError] = []

    # ── Acceso al token actual ────────────────────────────────────────────────

    @property
    def _cur(self) -> Token:
        return self._tokens[min(self._pos, len(self._tokens) - 1)]

    def _peek(self, offset: int = 1) -> Token:
        idx = self._pos + offset
        return self._tokens[min(idx, len(self._tokens) - 1)]

    def _advance(self) -> Token:
        tok = self._cur
        if self._pos < len(self._tokens) - 1:
            self._pos += 1
        return tok

    def _check(self, *types: TT) -> bool:
        return self._cur.type in types

    def _match(self, *types: TT) -> Optional[Token]:
        if self._check(*types):
            return self._advance()
        return None

    def _expect(self, tt: TT, msg: str = "") -> Token:
        if self._cur.type == tt:
            return self._advance()
        raise ParseError(
            msg or f"se esperaba {tt.name}, se obtuvo {self._cur.type.name!r}",
            self._cur
        )

    def _skip_newlines(self) -> None:
        while self._check(TT.NEWLINE):
            self._advance()

    def _sync_to_next_stmt(self) -> None:
        """Recuperación de error: avanza hasta el siguiente NEWLINE o EOF."""
        while not self._check(TT.NEWLINE, TT.EOF, TT.DEDENT):
            self._advance()
        self._match(TT.NEWLINE)

    # ── API pública ───────────────────────────────────────────────────────────

    def parse(self) -> Program:
        """Punto de entrada: parsea el programa completo."""
        prog = Program(line=1, col=1)
        self._skip_newlines()
        while not self._check(TT.EOF):
            try:
                stmt = self._parse_stmt()
                if stmt:
                    prog.body.append(stmt)
            except ParseError as e:
                self._errors.append(e)
                self._sync_to_next_stmt()
            self._skip_newlines()
        return prog

    @property
    def errors(self) -> List[ParseError]:
        return self._errors

    # ════════════════════════════════════════════════════════════════════════
    #  SENTENCIAS
    # ════════════════════════════════════════════════════════════════════════

    def _parse_stmt(self) -> Optional[Node]:
        cur = self._cur
        match cur.type:
            case TT.KW_DEF:
                return self._parse_func_def()
            case TT.KW_IF:
                return self._parse_if_stmt()
            case TT.KW_WHILE:
                return self._parse_while_stmt()
            case TT.KW_FOR:
                return self._parse_for_stmt()
            case TT.KW_RETURN:
                return self._parse_return_stmt()
            case TT.KW_IMPORT:
                return self._parse_import_stmt()
            case TT.KW_FROM:
                return self._parse_from_import_stmt()
            case TT.KW_PASS:
                self._advance()
                self._expect(TT.NEWLINE)
                return PassStmt(line=cur.line, col=cur.col)
            case TT.KW_BREAK:
                self._advance()
                self._match(TT.NEWLINE)
                return BreakStmt(line=cur.line, col=cur.col)
            case TT.KW_CONTINUE:
                self._advance()
                self._match(TT.NEWLINE)
                return ContinueStmt(line=cur.line, col=cur.col)
            case TT.KW_GLOBAL:
                return self._parse_global_stmt()
            case TT.KW_NONLOCAL:
                return self._parse_nonlocal_stmt()
            case TT.KW_RAISE:
                return self._parse_raise_stmt()
            case TT.AT_OP:
                return self._parse_decorated()
            case TT.DEDENT | TT.EOF:
                return None
            case _:
                return self._parse_expr_stmt()

    # ── decoradores (@) ──────────────────────────────────────────────────────

    def _parse_decorated(self) -> Optional[Node]:
        """
        Parsea uno o más decoradores seguidos de una def/class.
        Los decoradores se ignoran semánticamente (no los añadimos al AST)
        pero se consumen para que el parser no falle en ellos.
        """
        while self._check(TT.AT_OP):
            self._advance()             # consume '@'
            self._parse_primary()       # consume expr del decorador
            self._match(TT.NEWLINE)
        # Tras los decoradores esperamos 'def' o 'class'
        if self._check(TT.KW_DEF):
            return self._parse_func_def()
        if self._check(TT.KW_CLASS):
            # Simplificado: consumir hasta el próximo bloque
            self._sync_to_next_stmt()
            return PassStmt(line=self._cur.line, col=self._cur.col)
        return None

    # ── def ───────────────────────────────────────────────────────────────────

    def _parse_func_def(self) -> FuncDef:
        tok = self._expect(TT.KW_DEF)
        name_tok = self._expect(TT.NAME, "se esperaba nombre de función")
        self._expect(TT.LPAREN)
        params = self._parse_param_list()
        self._expect(TT.RPAREN)

        ret_ann = None
        if self._match(TT.ARROW):
            ret_ann = self._parse_expr()

        self._expect(TT.COLON)
        body = self._parse_suite()
        return FuncDef(name=name_tok.value, params=params, body=body,
                       return_ann=ret_ann, line=tok.line, col=tok.col)

    def _parse_param_list(self) -> List[Param]:
        params: List[Param] = []
        if self._check(TT.RPAREN):
            return params
        while not self._check(TT.RPAREN, TT.EOF):
            kind = "positional"
            if self._match(TT.DOUBLESTAR):
                kind = "**kwargs"
            elif self._match(TT.STAR):
                if self._check(TT.COMMA):    # solo '*'
                    params.append(Param(name="*", kind="separator",
                                        line=self._cur.line, col=self._cur.col))
                    if not self._match(TT.COMMA):
                        break
                    continue
                kind = "*args"
            tok = self._expect(TT.NAME, "nombre de parámetro esperado")
            ann = None
            if self._match(TT.COLON):
                ann = self._parse_expr()
            default = None
            if self._match(TT.ASSIGN):
                default = self._parse_expr()
            params.append(Param(name=tok.value, annotation=ann,
                                default=default, kind=kind,
                                line=tok.line, col=tok.col))
            if not self._match(TT.COMMA):
                break
        return params

    # ── if / elif / else ─────────────────────────────────────────────────────

    def _parse_if_stmt(self) -> IfStmt:
        tok = self._expect(TT.KW_IF)
        cond = self._parse_expr()
        self._expect(TT.COLON)
        then_body = self._parse_suite()

        elif_clauses: List[ElifClause] = []
        while self._check(TT.KW_ELIF):
            elif_tok = self._advance()
            elif_cond = self._parse_expr()
            self._expect(TT.COLON)
            elif_body = self._parse_suite()
            elif_clauses.append(
                ElifClause(condition=elif_cond, body=elif_body,
                           line=elif_tok.line, col=elif_tok.col)
            )

        else_body = None
        if self._check(TT.KW_ELSE):
            self._advance()
            self._expect(TT.COLON)
            else_body = self._parse_suite()

        return IfStmt(condition=cond, then_body=then_body,
                      elif_clauses=elif_clauses, else_body=else_body,
                      line=tok.line, col=tok.col)

    # ── while ────────────────────────────────────────────────────────────────

    def _parse_while_stmt(self) -> WhileStmt:
        tok = self._expect(TT.KW_WHILE)
        cond = self._parse_expr()
        self._expect(TT.COLON)
        body = self._parse_suite()
        else_body = None
        if self._check(TT.KW_ELSE):
            self._advance()
            self._expect(TT.COLON)
            else_body = self._parse_suite()
        return WhileStmt(condition=cond, body=body, else_body=else_body,
                         line=tok.line, col=tok.col)

    # ── for ──────────────────────────────────────────────────────────────────

    def _parse_for_stmt(self) -> ForStmt:
        tok = self._expect(TT.KW_FOR)
        target = self._parse_primary()          # simplificado: solo atom
        self._expect(TT.KW_IN)
        iterable = self._parse_expr()
        self._expect(TT.COLON)
        body = self._parse_suite()
        else_body = None
        if self._check(TT.KW_ELSE):
            self._advance()
            self._expect(TT.COLON)
            else_body = self._parse_suite()
        return ForStmt(target=target, iterable=iterable, body=body,
                       else_body=else_body, line=tok.line, col=tok.col)

    # ── return ───────────────────────────────────────────────────────────────

    def _parse_return_stmt(self) -> ReturnStmt:
        tok = self._expect(TT.KW_RETURN)
        value = None
        if not self._check(TT.NEWLINE, TT.EOF, TT.SEMICOLON):
            value = self._parse_expr()
        self._match(TT.NEWLINE)
        return ReturnStmt(value=value, line=tok.line, col=tok.col)

    # ── import ───────────────────────────────────────────────────────────────

    def _parse_import_stmt(self) -> ImportStmt:
        tok = self._expect(TT.KW_IMPORT)
        module = self._parse_dotted_name()
        alias = None
        if self._match(TT.KW_AS):
            alias = self._expect(TT.NAME).value
        self._match(TT.NEWLINE)
        return ImportStmt(module=module, alias=alias,
                          line=tok.line, col=tok.col)

    def _parse_from_import_stmt(self) -> FromImportStmt:
        tok = self._expect(TT.KW_FROM)
        module = self._parse_dotted_name()
        self._expect(TT.KW_IMPORT)
        names: List[str] = []
        alias = None
        if self._match(TT.LPAREN):
            while not self._check(TT.RPAREN, TT.EOF):
                names.append(self._expect(TT.NAME).value)
                if not self._match(TT.COMMA):
                    break
            self._expect(TT.RPAREN)
        elif self._match(TT.STAR):
            names = ["*"]
        else:
            names.append(self._expect(TT.NAME).value)
            while self._match(TT.COMMA):
                if self._check(TT.NEWLINE, TT.EOF):
                    break
                names.append(self._expect(TT.NAME).value)
            if self._match(TT.KW_AS):
                alias = self._expect(TT.NAME).value
        self._match(TT.NEWLINE)
        return FromImportStmt(module=module, names=names, alias=alias,
                              line=tok.line, col=tok.col)

    def _parse_dotted_name(self) -> str:
        parts = [self._expect(TT.NAME).value]
        while self._check(TT.DOT):
            self._advance()
            parts.append(self._expect(TT.NAME).value)
        return ".".join(parts)

    # ── global / nonlocal ────────────────────────────────────────────────────

    def _parse_global_stmt(self) -> GlobalStmt:
        tok = self._expect(TT.KW_GLOBAL)
        names = [self._expect(TT.NAME).value]
        while self._match(TT.COMMA):
            names.append(self._expect(TT.NAME).value)
        self._match(TT.NEWLINE)
        return GlobalStmt(names=names, line=tok.line, col=tok.col)

    def _parse_nonlocal_stmt(self) -> NonlocalStmt:
        tok = self._expect(TT.KW_NONLOCAL)
        names = [self._expect(TT.NAME).value]
        while self._match(TT.COMMA):
            names.append(self._expect(TT.NAME).value)
        self._match(TT.NEWLINE)
        return NonlocalStmt(names=names, line=tok.line, col=tok.col)

    # ── raise ────────────────────────────────────────────────────────────────

    def _parse_raise_stmt(self) -> RaiseStmt:
        tok = self._expect(TT.KW_RAISE)
        exc = cause = None
        if not self._check(TT.NEWLINE, TT.EOF):
            exc = self._parse_expr()
            if self._match(TT.KW_AS):    # raise X from Y
                cause = self._parse_expr()
        self._match(TT.NEWLINE)
        return RaiseStmt(exc=exc, cause=cause, line=tok.line, col=tok.col)

    # ── sentencia de expresión / asignación ──────────────────────────────────

    def _parse_expr_stmt(self) -> Node:
        tok = self._cur
        expr = self._parse_expr()

        # Asignación con anotación: x: int = valor
        if self._check(TT.COLON):
            self._advance()
            ann = self._parse_expr()
            value = None
            if self._match(TT.ASSIGN):
                value = self._parse_expr()
            self._match(TT.NEWLINE)
            return AnnAssignStmt(target=expr, annotation=ann, value=value,
                                 line=tok.line, col=tok.col)

        # Asignación aumentada: x += valor
        aug_ops = {
            TT.PLUSEQ: "+=", TT.MINUSEQ: "-=", TT.STAREQ: "*=",
            TT.SLASHEQ: "/=", TT.DOUBLESLASHEQ: "//=",
            TT.PERCENTEQ: "%=", TT.DOUBLESTAREQ: "**=",
            TT.AMPEQ: "&=", TT.PIPEEQ: "|=", TT.CARETEQ: "^=",
        }
        if self._cur.type in aug_ops:
            op = aug_ops[self._advance().type]
            value = self._parse_expr()
            self._match(TT.NEWLINE)
            return AugAssignStmt(target=expr, op=op, value=value,
                                 line=tok.line, col=tok.col)

        # Asignación simple (posiblemente múltiple): a = b = valor
        if self._check(TT.ASSIGN):
            targets = [expr]
            while self._match(TT.ASSIGN):
                targets.append(self._parse_expr())
            value  = targets.pop()
            self._match(TT.NEWLINE)
            return AssignStmt(targets=targets, value=value,
                              line=tok.line, col=tok.col)

        # Expresión sola (llamada a función, etc.)
        self._match(TT.NEWLINE)
        return ExprStmt(value=expr, line=tok.line, col=tok.col)

    # ── bloque (suite) ────────────────────────────────────────────────────────

    def _parse_suite(self) -> List[Node]:
        """
        suite → NEWLINE INDENT stmt+ DEDENT
               | stmt               (sentencia simple en misma línea)
        """
        stmts: List[Node] = []
        if self._check(TT.NEWLINE):
            self._advance()
            self._expect(TT.INDENT, "se esperaba bloque indentado")
            self._skip_newlines()
            while not self._check(TT.DEDENT, TT.EOF):
                try:
                    s = self._parse_stmt()
                    if s:
                        stmts.append(s)
                except ParseError as e:
                    self._errors.append(e)
                    self._sync_to_next_stmt()
                self._skip_newlines()
            self._match(TT.DEDENT)
        else:
            # Suite de una sola línea: if x: return y
            s = self._parse_stmt()
            if s:
                stmts.append(s)
        return stmts

    # ════════════════════════════════════════════════════════════════════════
    #  EXPRESIONES  (precedencia ascendente, gramática LL)
    # ════════════════════════════════════════════════════════════════════════

    def _parse_expr(self) -> Node:
        """expr → lambda | if_expr | or_expr"""
        # Expresión lambda
        if self._check(TT.KW_LAMBDA):
            return self._parse_lambda()
        node = self._parse_or_expr()
        # Expresión condicional: X if C else Y
        if self._check(TT.KW_IF):
            tok = self._advance()
            cond = self._parse_or_expr()
            self._expect(TT.KW_ELSE)
            else_val = self._parse_expr()
            return IfExpr(condition=cond, then_val=node, else_val=else_val,
                          line=tok.line, col=tok.col)
        return node

    def _parse_lambda(self) -> Node:
        tok = self._expect(TT.KW_LAMBDA)
        params: List[Param] = []
        while not self._check(TT.COLON, TT.EOF):
            name = self._expect(TT.NAME)
            default = None
            if self._match(TT.ASSIGN):
                default = self._parse_expr()
            params.append(Param(name=name.value, default=default,
                                line=name.line, col=name.col))
            if not self._match(TT.COMMA):
                break
        self._expect(TT.COLON)
        body = self._parse_expr()
        # Representamos lambda como FuncDef sin nombre
        return FuncDef(name="<lambda>", params=params,
                       body=[ReturnStmt(value=body)],
                       line=tok.line, col=tok.col)

    def _parse_or_expr(self) -> Node:
        node = self._parse_and_expr()
        if self._check(TT.KW_OR):
            tok = self._cur
            values = [node]
            while self._match(TT.KW_OR):
                values.append(self._parse_and_expr())
            return BoolOp(op="or", values=values, line=tok.line, col=tok.col)
        return node

    def _parse_and_expr(self) -> Node:
        node = self._parse_not_expr()
        if self._check(TT.KW_AND):
            tok = self._cur
            values = [node]
            while self._match(TT.KW_AND):
                values.append(self._parse_not_expr())
            return BoolOp(op="and", values=values, line=tok.line, col=tok.col)
        return node

    def _parse_not_expr(self) -> Node:
        if self._check(TT.KW_NOT):
            tok = self._advance()
            operand = self._parse_not_expr()
            return UnaryOp(op="not", operand=operand,
                           line=tok.line, col=tok.col)
        return self._parse_compare()

    _CMP_OPS = {
        TT.EQEQ: "==", TT.NEQ: "!=", TT.LT: "<",
        TT.GT:  ">",   TT.LEQ: "<=", TT.GEQ: ">=",
        TT.KW_IN: "in", TT.KW_IS: "is",
    }

    def _parse_compare(self) -> Node:
        left = self._parse_add()
        comparators: List[tuple] = []
        while self._cur.type in self._CMP_OPS or (
            self._check(TT.KW_NOT) and self._peek().type == TT.KW_IN
        ) or (
            self._check(TT.KW_IS) and self._peek().type == TT.KW_NOT
        ):
            if self._check(TT.KW_NOT):
                self._advance(); self._advance()
                op = "not in"
            elif self._check(TT.KW_IS) and self._peek().type == TT.KW_NOT:
                self._advance(); self._advance()
                op = "is not"
            else:
                op = self._CMP_OPS[self._cur.type]
                self._advance()
            right = self._parse_add()
            comparators.append((op, right))
        if comparators:
            return Compare(left=left, comparators=comparators,
                           line=left.line, col=left.col)
        return left

    def _parse_add(self) -> Node:
        node = self._parse_mul()
        while self._check(TT.PLUS, TT.MINUS):
            tok = self._advance()
            right = self._parse_mul()
            node = BinOp(left=node, op=tok.value, right=right,
                         line=tok.line, col=tok.col)
        return node

    def _parse_mul(self) -> Node:
        node = self._parse_unary()
        while self._check(TT.STAR, TT.SLASH, TT.DOUBLESLASH,
                          TT.PERCENT, TT.AT_OP):
            tok = self._advance()
            right = self._parse_unary()
            node = BinOp(left=node, op=tok.value, right=right,
                         line=tok.line, col=tok.col)
        return node

    def _parse_unary(self) -> Node:
        if self._check(TT.MINUS, TT.PLUS, TT.TILDE):
            tok = self._advance()
            operand = self._parse_unary()
            return UnaryOp(op=tok.value, operand=operand,
                           line=tok.line, col=tok.col)
        return self._parse_power()

    def _parse_power(self) -> Node:
        base = self._parse_primary()
        if self._match(TT.DOUBLESTAR):
            tok = self._cur
            exp = self._parse_unary()
            return BinOp(left=base, op="**", right=exp,
                         line=base.line, col=base.col)
        return base

    # ── atom_expr: atom + trailers (llamadas, indexados, atributos) ───────────

    def _parse_primary(self) -> Node:
        node = self._parse_atom()
        while self._check(TT.DOT, TT.LPAREN, TT.LBRACKET):
            tok = self._cur
            if self._match(TT.DOT):
                attr = self._expect(TT.NAME, "nombre de atributo esperado")
                node = Attribute(obj=node, attr=attr.value,
                                 line=tok.line, col=tok.col)
            elif self._match(TT.LPAREN):
                args, kws = self._parse_arglist()
                self._expect(TT.RPAREN)
                node = Call(func=node, args=args, keywords=kws,
                            line=tok.line, col=tok.col)
            elif self._match(TT.LBRACKET):
                idx = self._parse_expr()
                self._expect(TT.RBRACKET)
                node = Subscript(obj=node, index=idx,
                                 line=tok.line, col=tok.col)
        return node

    def _parse_arglist(self):
        """Parsea lista de argumentos de una llamada: f(a, b, key=val, *args)."""
        args: List[Node]    = []
        kws:  List[Keyword] = []
        while not self._check(TT.RPAREN, TT.EOF):
            tok = self._cur
            if self._match(TT.DOUBLESTAR):
                val = self._parse_expr()
                kws.append(Keyword(key=None, value=val,
                                   line=tok.line, col=tok.col))
            elif self._match(TT.STAR):
                val = self._parse_expr()
                args.append(StarredExpr(value=val, line=tok.line, col=tok.col))
            elif (self._check(TT.NAME) and self._peek().type == TT.ASSIGN):
                key = self._advance().value
                self._advance()   # consume '='
                val = self._parse_expr()
                kws.append(Keyword(key=key, value=val,
                                   line=tok.line, col=tok.col))
            else:
                args.append(self._parse_expr())
            if not self._match(TT.COMMA):
                break
        return args, kws

    # ── atom ─────────────────────────────────────────────────────────────────

    def _parse_atom(self) -> Node:
        tok = self._cur
        match tok.type:
            case TT.NAME:
                self._advance()
                return Name(id=tok.value, line=tok.line, col=tok.col)

            case TT.INTEGER:
                self._advance()
                val = tok.value
                base = 10
                if val.startswith("0x") or val.startswith("0X"):
                    base = 16; val = val[2:]
                elif val.startswith("0o") or val.startswith("0O"):
                    base = 8;  val = val[2:]
                elif val.startswith("0b") or val.startswith("0B"):
                    base = 2;  val = val[2:]
                val = val.replace("_", "")
                return Constant(value=int(val, base), kind="int",
                                line=tok.line, col=tok.col)

            case TT.FLOAT:
                self._advance()
                return Constant(value=float(tok.value.replace("_", "")),
                                kind="float", line=tok.line, col=tok.col)

            case TT.STRING:
                self._advance()
                # Concatenación implícita de strings adyacentes
                raw = tok.value
                while self._check(TT.STRING):
                    raw += " " + self._advance().value
                return Constant(value=raw, kind="str",
                                line=tok.line, col=tok.col)

            case TT.KW_TRUE:
                self._advance()
                return Constant(value=True,  kind="bool",
                                line=tok.line, col=tok.col)
            case TT.KW_FALSE:
                self._advance()
                return Constant(value=False, kind="bool",
                                line=tok.line, col=tok.col)
            case TT.KW_NONE:
                self._advance()
                return Constant(value=None, kind="none",
                                line=tok.line, col=tok.col)

            case TT.ELLIPSIS:
                self._advance()
                return Constant(value=..., kind="ellipsis",
                                line=tok.line, col=tok.col)

            case TT.LPAREN:
                return self._parse_paren_expr()

            case TT.LBRACKET:
                return self._parse_list_expr()

            case TT.LBRACE:
                return self._parse_dict_or_set()

            case _:
                raise ParseError(
                    f"expresión inesperada: token {tok.type.name} {tok.value!r}",
                    tok
                )

    def _parse_paren_expr(self) -> Node:
        tok = self._expect(TT.LPAREN)
        if self._check(TT.RPAREN):
            self._advance()
            return TupleExpr(elts=[], line=tok.line, col=tok.col)
        expr = self._parse_expr()
        if self._check(TT.COMMA):
            elts = [expr]
            while self._match(TT.COMMA):
                if self._check(TT.RPAREN):
                    break
                elts.append(self._parse_expr())
            self._expect(TT.RPAREN)
            return TupleExpr(elts=elts, line=tok.line, col=tok.col)
        self._expect(TT.RPAREN)
        return expr

    def _parse_list_expr(self) -> ListExpr:
        tok = self._expect(TT.LBRACKET)
        elts: List[Node] = []
        while not self._check(TT.RBRACKET, TT.EOF):
            elts.append(self._parse_expr())
            if not self._match(TT.COMMA):
                break
        self._expect(TT.RBRACKET)
        return ListExpr(elts=elts, line=tok.line, col=tok.col)

    def _parse_dict_or_set(self) -> Node:
        tok = self._expect(TT.LBRACE)
        if self._check(TT.RBRACE):
            self._advance()
            return DictExpr(keys=[], values=[], line=tok.line, col=tok.col)
        first = self._parse_expr()
        if self._check(TT.COLON):
            # dict
            self._advance()
            keys, values = [first], [self._parse_expr()]
            while self._match(TT.COMMA):
                if self._check(TT.RBRACE):
                    break
                if self._match(TT.DOUBLESTAR):
                    keys.append(None)
                else:
                    keys.append(self._parse_expr())
                    self._expect(TT.COLON)
                values.append(self._parse_expr())
            self._expect(TT.RBRACE)
            return DictExpr(keys=keys, values=values,
                            line=tok.line, col=tok.col)
        else:
            # set
            elts = [first]
            while self._match(TT.COMMA):
                if self._check(TT.RBRACE):
                    break
                elts.append(self._parse_expr())
            self._expect(TT.RBRACE)
            return SetExpr(elts=elts, line=tok.line, col=tok.col)


# ════════════════════════════════════════════════════════════════════════════
#  IMPRESIÓN DEL AST  (útil para depuración y reporte académico)
# ════════════════════════════════════════════════════════════════════════════

class ASTPrinter:
    """Imprime el AST en formato de árbol indentado."""

    def __init__(self, indent_str: str = "  "):
        self._indent = indent_str
        self._depth  = 0

    def print_tree(self, node: Node, label: str = "") -> None:
        prefix = self._indent * self._depth
        tag = f"{label}: " if label else ""
        node_type = type(node).__name__

        match node:
            case Program(body=body):
                print(f"{prefix}{tag}Program")
                self._depth += 1
                for s in body:
                    self.print_tree(s)
                self._depth -= 1

            case FuncDef(name=name, params=params, body=body):
                print(f"{prefix}{tag}FuncDef name={name!r} "
                      f"params=[{', '.join(p.name for p in params)}]")
                self._depth += 1
                for s in body:
                    self.print_tree(s)
                self._depth -= 1

            case IfStmt(condition=cond, then_body=then_, else_body=else_):
                print(f"{prefix}{tag}IfStmt")
                self._depth += 1
                self.print_tree(cond, "condition")
                for s in then_:
                    self.print_tree(s)
                if else_:
                    print(f"{self._indent * self._depth}else:")
                    for s in else_:
                        self.print_tree(s)
                self._depth -= 1

            case WhileStmt(condition=cond, body=body):
                print(f"{prefix}{tag}WhileStmt")
                self._depth += 1
                self.print_tree(cond, "condition")
                for s in body:
                    self.print_tree(s)
                self._depth -= 1

            case ForStmt(target=t, iterable=it, body=body):
                print(f"{prefix}{tag}ForStmt")
                self._depth += 1
                self.print_tree(t, "target")
                self.print_tree(it, "iterable")
                for s in body:
                    self.print_tree(s)
                self._depth -= 1

            case AssignStmt(targets=tgts, value=val):
                tgt_str = ", ".join(
                    n.id if isinstance(n, Name) else repr(n)
                    for n in tgts
                )
                print(f"{prefix}{tag}Assign targets=[{tgt_str}]")
                self._depth += 1
                self.print_tree(val, "value")
                self._depth -= 1

            case AugAssignStmt(target=t, op=op, value=val):
                print(f"{prefix}{tag}AugAssign op={op!r}")
                self._depth += 1
                self.print_tree(t, "target")
                self.print_tree(val, "value")
                self._depth -= 1

            case ReturnStmt(value=val):
                print(f"{prefix}{tag}Return")
                if val:
                    self._depth += 1
                    self.print_tree(val)
                    self._depth -= 1

            case ExprStmt(value=val):
                print(f"{prefix}{tag}ExprStmt")
                self._depth += 1
                self.print_tree(val)
                self._depth -= 1

            case Call(func=func, args=args, keywords=kws):
                print(f"{prefix}{tag}Call")
                self._depth += 1
                self.print_tree(func, "func")
                for i, a in enumerate(args):
                    self.print_tree(a, f"arg{i}")
                for kw in kws:
                    self.print_tree(kw.value, f"kw:{kw.key}")
                self._depth -= 1

            case Attribute(obj=obj, attr=attr):
                print(f"{prefix}{tag}Attribute .{attr}")
                self._depth += 1
                self.print_tree(obj)
                self._depth -= 1

            case Subscript(obj=obj, index=idx):
                print(f"{prefix}{tag}Subscript")
                self._depth += 1
                self.print_tree(obj)
                self.print_tree(idx, "index")
                self._depth -= 1

            case BinOp(left=l, op=op, right=r):
                print(f"{prefix}{tag}BinOp op={op!r}")
                self._depth += 1
                self.print_tree(l, "left")
                self.print_tree(r, "right")
                self._depth -= 1

            case UnaryOp(op=op, operand=operand):
                print(f"{prefix}{tag}UnaryOp op={op!r}")
                self._depth += 1
                self.print_tree(operand)
                self._depth -= 1

            case BoolOp(op=op, values=vals):
                print(f"{prefix}{tag}BoolOp op={op!r}")
                self._depth += 1
                for v in vals:
                    self.print_tree(v)
                self._depth -= 1

            case Compare(left=l, comparators=cmps):
                ops = " ".join(op for op, _ in cmps)
                print(f"{prefix}{tag}Compare ops=[{ops}]")
                self._depth += 1
                self.print_tree(l, "left")
                for op, node in cmps:
                    self.print_tree(node, op)
                self._depth -= 1

            case Name(id=id_):
                print(f"{prefix}{tag}Name {id_!r}")

            case Constant(value=val, kind=kind):
                print(f"{prefix}{tag}Constant({kind}) {val!r}")

            case ImportStmt(module=mod, alias=al):
                al_str = f" as {al}" if al else ""
                print(f"{prefix}{tag}Import {mod}{al_str}")

            case FromImportStmt(module=mod, names=names):
                print(f"{prefix}{tag}FromImport {mod} import {', '.join(names)}")

            case PassStmt():
                print(f"{prefix}{tag}Pass")

            case _:
                print(f"{prefix}{tag}{node_type}")


# ════════════════════════════════════════════════════════════════════════════
#  FUNCIONES DE CONVENIENCIA
# ════════════════════════════════════════════════════════════════════════════

def parse(source: str) -> tuple[Program, List[ParseError]]:
    """
    Pipeline léxico + sintáctico:  código fuente → AST.
    Retorna (ast_root, lista_de_errores).
    """
    tokens = tokenize(source)
    parser = Parser(tokens)
    tree   = parser.parse()
    return tree, parser.errors


def parse_and_print(source: str) -> None:
    """Parsea y muestra el AST en consola (útil para pruebas)."""
    tree, errors = parse(source)
    ASTPrinter().print_tree(tree)
    if errors:
        print(f"\n{len(errors)} error(es) de parsing:")
        for e in errors:
            print(f"  {e}")
