"""
Analizador Léxico (Scanner) — Fase 1 del Compilador
====================================================
Convierte el código fuente en una secuencia lineal de tokens.

Maneja el subconjunto de Python necesario para el análisis de taint:
  - Literales: enteros, flotantes, cadenas (simples, dobles, triples, f-strings)
  - Identificadores y palabras reservadas
  - Operadores aritméticos, relacionales, lógicos y de asignación
  - Puntuación y delimitadores
  - INDENT / DEDENT para bloques de código (indentación significativa)
  - Continuación de línea implícita dentro de (), [], {}
  - Comentarios (#)

Referencia: Python Language Reference §2 (Lexical Analysis)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Iterator, List, Optional


# ════════════════════════════════════════════════════════════════════════════
#  TIPOS DE TOKEN
# ════════════════════════════════════════════════════════════════════════════

class TT(Enum):
    """Token Type — enumeración completa de categorías léxicas."""

    # ── Literales ────────────────────────────────────────────────────────────
    INTEGER = "INTEGER"       # 42, 0xFF, 0b1010, 0o77
    FLOAT   = "FLOAT"         # 3.14, 1e-5, .5
    STRING  = "STRING"        # 'hola', "mundo", '''multi''', f"expresión"
    BYTES   = "BYTES"         # b"data"

    # ── Identificadores ──────────────────────────────────────────────────────
    NAME = "NAME"             # variables, funciones, clases

    # ── Palabras reservadas ──────────────────────────────────────────────────
    KW_FALSE    = "False"
    KW_NONE     = "None"
    KW_TRUE     = "True"
    KW_AND      = "and"
    KW_AS       = "as"
    KW_ASSERT   = "assert"
    KW_ASYNC    = "async"
    KW_AWAIT    = "await"
    KW_BREAK    = "break"
    KW_CLASS    = "class"
    KW_CONTINUE = "continue"
    KW_DEF      = "def"
    KW_DEL      = "del"
    KW_ELIF     = "elif"
    KW_ELSE     = "else"
    KW_EXCEPT   = "except"
    KW_FINALLY  = "finally"
    KW_FOR      = "for"
    KW_FROM     = "from"
    KW_GLOBAL   = "global"
    KW_IF       = "if"
    KW_IMPORT   = "import"
    KW_IN       = "in"
    KW_IS       = "is"
    KW_LAMBDA   = "lambda"
    KW_NONLOCAL = "nonlocal"
    KW_NOT      = "not"
    KW_OR       = "or"
    KW_PASS     = "pass"
    KW_RAISE    = "raise"
    KW_RETURN   = "return"
    KW_TRY      = "try"
    KW_WHILE    = "while"
    KW_WITH     = "with"
    KW_YIELD    = "yield"

    # ── Operadores aritméticos ───────────────────────────────────────────────
    PLUS          = "+"
    MINUS         = "-"
    STAR          = "*"
    SLASH         = "/"
    DOUBLESLASH   = "//"
    PERCENT       = "%"
    DOUBLESTAR    = "**"
    AT_OP         = "@"

    # ── Operadores de bits ───────────────────────────────────────────────────
    AMP    = "&"
    PIPE   = "|"
    CARET  = "^"
    TILDE  = "~"
    LSHIFT = "<<"
    RSHIFT = ">>"

    # ── Operadores de comparación ────────────────────────────────────────────
    EQEQ = "=="
    NEQ  = "!="
    LT   = "<"
    GT   = ">"
    LEQ  = "<="
    GEQ  = ">="

    # ── Operadores de asignación ─────────────────────────────────────────────
    ASSIGN        = "="
    PLUSEQ        = "+="
    MINUSEQ       = "-="
    STAREQ        = "*="
    SLASHEQ       = "/="
    DOUBLESLASHEQ = "//="
    PERCENTEQ     = "%="
    DOUBLESTAREQ  = "**="
    AMPEQ         = "&="
    PIPEEQ        = "|="
    CARETEQ       = "^="
    LSHIFTEQ      = "<<="
    RSHIFTEQ      = ">>="
    ATEQ          = "@="
    WALRUS        = ":="

    # ── Delimitadores y puntuación ───────────────────────────────────────────
    LPAREN    = "("
    RPAREN    = ")"
    LBRACKET  = "["
    RBRACKET  = "]"
    LBRACE    = "{"
    RBRACE    = "}"
    COLON     = ":"
    COMMA     = ","
    DOT       = "."
    SEMICOLON = ";"
    ARROW     = "->"
    ELLIPSIS  = "..."

    # ── Control de estructura de bloques ─────────────────────────────────────
    NEWLINE = "NEWLINE"   # fin de línea lógica
    INDENT  = "INDENT"    # aumento de indentación
    DEDENT  = "DEDENT"    # disminución de indentación

    # ── Fin de archivo ───────────────────────────────────────────────────────
    EOF = "EOF"

    # ── Error léxico ─────────────────────────────────────────────────────────
    ERROR = "ERROR"


# ════════════════════════════════════════════════════════════════════════════
#  TABLA DE PALABRAS RESERVADAS
# ════════════════════════════════════════════════════════════════════════════

KEYWORDS: dict[str, TT] = {
    "False": TT.KW_FALSE, "None": TT.KW_NONE, "True": TT.KW_TRUE,
    "and": TT.KW_AND, "as": TT.KW_AS, "assert": TT.KW_ASSERT,
    "async": TT.KW_ASYNC, "await": TT.KW_AWAIT, "break": TT.KW_BREAK,
    "class": TT.KW_CLASS, "continue": TT.KW_CONTINUE, "def": TT.KW_DEF,
    "del": TT.KW_DEL, "elif": TT.KW_ELIF, "else": TT.KW_ELSE,
    "except": TT.KW_EXCEPT, "finally": TT.KW_FINALLY, "for": TT.KW_FOR,
    "from": TT.KW_FROM, "global": TT.KW_GLOBAL, "if": TT.KW_IF,
    "import": TT.KW_IMPORT, "in": TT.KW_IN, "is": TT.KW_IS,
    "lambda": TT.KW_LAMBDA, "nonlocal": TT.KW_NONLOCAL, "not": TT.KW_NOT,
    "or": TT.KW_OR, "pass": TT.KW_PASS, "raise": TT.KW_RAISE,
    "return": TT.KW_RETURN, "try": TT.KW_TRY, "while": TT.KW_WHILE,
    "with": TT.KW_WITH, "yield": TT.KW_YIELD,
}


# ════════════════════════════════════════════════════════════════════════════
#  ESTRUCTURA TOKEN
# ════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Token:
    """Unidad mínima producida por el analizador léxico."""
    type:    TT
    value:   str
    line:    int     # línea en el fuente (base 1)
    col:     int     # columna de inicio (base 1)

    def __repr__(self) -> str:
        return f"Token({self.type.name}, {self.value!r}, L{self.line}:C{self.col})"

    @property
    def is_keyword(self) -> bool:
        return self.type in {
            TT.KW_IF, TT.KW_ELIF, TT.KW_ELSE, TT.KW_WHILE, TT.KW_FOR,
            TT.KW_IN, TT.KW_RETURN, TT.KW_DEF, TT.KW_CLASS, TT.KW_IMPORT,
            TT.KW_FROM, TT.KW_AND, TT.KW_OR, TT.KW_NOT, TT.KW_TRUE,
            TT.KW_FALSE, TT.KW_NONE, TT.KW_PASS, TT.KW_BREAK,
            TT.KW_CONTINUE, TT.KW_GLOBAL, TT.KW_WITH, TT.KW_AS,
            TT.KW_TRY, TT.KW_EXCEPT, TT.KW_FINALLY, TT.KW_RAISE,
        }


# ════════════════════════════════════════════════════════════════════════════
#  ERROR LÉXICO
# ════════════════════════════════════════════════════════════════════════════

class LexError(Exception):
    def __init__(self, msg: str, line: int, col: int):
        super().__init__(f"Error léxico en L{line}:C{col} — {msg}")
        self.line = line
        self.col  = col


# ════════════════════════════════════════════════════════════════════════════
#  ANALIZADOR LÉXICO PRINCIPAL
# ════════════════════════════════════════════════════════════════════════════

class Lexer:
    """
    Analizador léxico (scanner) para el subconjunto de Python
    utilizado en la detección de inyección SQL.

    Produce una secuencia de tokens incluyendo INDENT, DEDENT y NEWLINE
    para representar la estructura de bloques del lenguaje.

    Invariantes del autómata:
      - _pos  : índice actual en _src
      - _line : línea actual (base 1)
      - _col  : columna actual (base 1)
      - _indent_stack: pila de niveles de indentación
      - _paren_depth: profundidad de (), [], {} para continuación implícita
    """

    # Patrones con prioridad (orden importa):
    _PATTERNS = [
        # Números en notación especial (antes que los decimales)
        ("HEX",   r"0[xX][0-9a-fA-F](_?[0-9a-fA-F])*"),
        ("OCT",   r"0[oO][0-7](_?[0-7])*"),
        ("BIN",   r"0[bB][01](_?[01])*"),
        # Float antes que int (para capturar el punto decimal)
        ("FLOAT",  r"\d+\.\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?|\d+[eE][+-]?\d+"),
        ("INT",    r"\d+"),
        # Cadenas (orden: triple antes que simple)
        ("STR_TRIPLE_DQ", r'"""(?:[^\\]|\\.)*?"""'),
        ("STR_TRIPLE_SQ", r"'''(?:[^\\]|\\.)*?'''"),
        ("FSTR_DQ",       r'f"(?:[^"\\]|\\.)*"'),
        ("FSTR_SQ",       r"f'(?:[^'\\]|\\.)*'"),
        ("BSTR_DQ",       r'b"(?:[^"\\]|\\.)*"'),
        ("BSTR_SQ",       r"b'(?:[^'\\]|\\.)*'"),
        ("RSTR_DQ",       r'r"(?:[^"\\]|\\.)*"'),
        ("RSTR_SQ",       r"r'(?:[^'\\]|\\.)*'"),
        ("STR_DQ",        r'"(?:[^"\\]|\\.)*"'),
        ("STR_SQ",        r"'(?:[^'\\]|\\.)*'"),
        # Identificadores / palabras reservadas
        ("NAME",   r"[A-Za-z_]\w*"),
        # Operadores de asignación compuestos (antes que simples)
        ("DOUBLESLASHEQ", r"//="),
        ("DOUBLESTAREQ",  r"\*\*="),
        ("LSHIFTEQ",      r"<<="),
        ("RSHIFTEQ",      r">>="),
        ("PLUSEQ",   r"\+="), ("MINUSEQ",  r"-="),
        ("STAREQ",   r"\*="), ("SLASHEQ",  r"/="),
        ("PERCENTEQ",r"%="),  ("AMPEQ",    r"&="),
        ("PIPEEQ",   r"\|="), ("CARETEQ",  r"\^="),
        ("ATEQ",     r"@="),  ("WALRUS",   r":="),
        # Operadores de comparación (antes que simples)
        ("EQEQ", r"=="), ("NEQ", r"!="),
        ("LEQ",  r"<="), ("GEQ", r">="),
        ("LSHIFT", r"<<"), ("RSHIFT", r">>"),
        ("ARROW",  r"->"),
        # Operadores simples
        ("DOUBLESLASH", r"//"), ("DOUBLESTAR", r"\*\*"),
        ("ELLIPSIS",    r"\.\.\."),
        ("LT",    r"<"),   ("GT",    r">"),
        ("ASSIGN",r"="),
        ("PLUS",  r"\+"),  ("MINUS", r"-"),
        ("STAR",  r"\*"),  ("SLASH", r"/"),
        ("PERCENT",r"%"),  ("AT_OP", r"@"),
        ("AMP",   r"&"),   ("PIPE",  r"\|"),
        ("CARET", r"\^"),  ("TILDE", r"~"),
        # Delimitadores
        ("LPAREN",   r"\("), ("RPAREN",   r"\)"),
        ("LBRACKET", r"\["), ("RBRACKET", r"\]"),
        ("LBRACE",   r"\{"), ("RBRACE",   r"\}"),
        ("COLON",    r":"),  ("COMMA",    r","),
        ("DOT",      r"\."), ("SEMICOLON",r";"),
        # Espacios (ignorados salvo para indentación al inicio de línea)
        ("SPACE",    r"[ \t]+"),
        # Continuación de línea explícita
        ("BACKSLASH",r"\\[ \t]*\n"),
        # Fin de línea
        ("EOL",      r"\n"),
        # Comentario
        ("COMMENT",  r"#[^\n]*"),
    ]

    _MASTER_RE = re.compile(
        "|".join(f"(?P<{name}>{pat})" for name, pat in _PATTERNS),
        re.DOTALL
    )

    def __init__(self, source: str):
        # Normaliza finales de línea
        self._src   = source.replace("\r\n", "\n").replace("\r", "\n")
        self._pos   = 0
        self._line  = 1
        self._col   = 1
        self._indent_stack: List[int] = [0]  # pila de indentaciones
        self._paren_depth  = 0               # profundidad de (), [], {}
        self._pending: List[Token] = []      # tokens pendientes de emitir
        self._at_line_start = True           # ¿estamos al inicio de línea?
        self._tokens: List[Token] = []

    # ── API pública ──────────────────────────────────────────────────────────

    def tokenize(self) -> List[Token]:
        """
        Ejecuta el análisis léxico completo y retorna la lista de tokens.
        Incluye INDENT, DEDENT, NEWLINE y EOF.
        """
        if self._tokens:
            return self._tokens

        result: List[Token] = []

        for tok in self._scan():
            result.append(tok)

        self._tokens = result
        return result

    # ── escáner principal ────────────────────────────────────────────────────

    def _scan(self) -> Iterator[Token]:
        src  = self._src
        pos  = 0
        line = 1
        col  = 1
        indent_stack = [0]
        paren_depth  = 0
        at_line_start = True

        def make(tt: TT, val: str, ln: int, c: int) -> Token:
            return Token(tt, val, ln, c)

        while pos < len(src):
            # ── Inicio de línea lógica: manejo de indentación ─────────────
            if at_line_start and paren_depth == 0:
                at_line_start = False
                # Calcular nivel de indentación de esta línea
                indent_start = pos
                while pos < len(src) and src[pos] in " \t":
                    pos += 1
                    col += 1
                # Línea en blanco o comentario → ignorar
                if pos >= len(src) or src[pos] in ("\n", "#"):
                    # Avanza hasta fin de línea
                    while pos < len(src) and src[pos] != "\n":
                        pos += 1
                    if pos < len(src):
                        pos += 1
                        line += 1
                        col = 1
                        at_line_start = True
                    continue

                indent_level = pos - indent_start
                top = indent_stack[-1]

                if indent_level > top:
                    indent_stack.append(indent_level)
                    yield make(TT.INDENT, "", line, 1)
                elif indent_level < top:
                    while indent_stack and indent_stack[-1] > indent_level:
                        indent_stack.pop()
                        yield make(TT.DEDENT, "", line, 1)
                    if indent_stack[-1] != indent_level:
                        raise LexError(
                            f"indentación inconsistente (nivel {indent_level})",
                            line, col
                        )
                # Si indent_level == top → no se emite nada

            if pos >= len(src):
                break

            # ── Buscar siguiente token con la regexp maestra ───────────────
            m = self._MASTER_RE.match(src, pos)
            if not m:
                raise LexError(
                    f"carácter inesperado {src[pos]!r}", line, col
                )

            kind  = m.lastgroup
            lexem = m.group()
            tok_line, tok_col = line, col

            # Avanzar posición
            pos = m.end()
            # Actualizar línea/columna según el lexema
            nl_count = lexem.count("\n")
            if nl_count:
                line += nl_count
                col   = len(lexem) - lexem.rfind("\n")
            else:
                col  += len(lexem)

            # ── Clasificar por tipo ────────────────────────────────────────
            match kind:
                case "SPACE":
                    pass  # ignorar espacios internos

                case "COMMENT":
                    pass  # ignorar comentarios

                case "BACKSLASH":
                    # Continuación explícita de línea: unir siguiente línea
                    pass

                case "EOL":
                    if paren_depth == 0:
                        yield make(TT.NEWLINE, "\\n", tok_line, tok_col)
                    at_line_start = True
                    # line y col ya se actualizaron en el bloque general de nl_count

                case "HEX" | "OCT" | "BIN" | "INT":
                    yield make(TT.INTEGER, lexem, tok_line, tok_col)

                case "FLOAT":
                    yield make(TT.FLOAT, lexem, tok_line, tok_col)

                case kind if kind.startswith("STR") or kind.startswith("FSTR") \
                          or kind.startswith("BSTR") or kind.startswith("RSTR"):
                    yield make(TT.STRING, lexem, tok_line, tok_col)

                case "NAME":
                    tt = KEYWORDS.get(lexem, TT.NAME)
                    yield make(tt, lexem, tok_line, tok_col)

                # Operadores compuestos de asignación
                case "DOUBLESLASHEQ": yield make(TT.DOUBLESLASHEQ, lexem, tok_line, tok_col)
                case "DOUBLESTAREQ":  yield make(TT.DOUBLESTAREQ,  lexem, tok_line, tok_col)
                case "LSHIFTEQ":      yield make(TT.LSHIFTEQ,      lexem, tok_line, tok_col)
                case "RSHIFTEQ":      yield make(TT.RSHIFTEQ,      lexem, tok_line, tok_col)
                case "PLUSEQ":        yield make(TT.PLUSEQ,   lexem, tok_line, tok_col)
                case "MINUSEQ":       yield make(TT.MINUSEQ,  lexem, tok_line, tok_col)
                case "STAREQ":        yield make(TT.STAREQ,   lexem, tok_line, tok_col)
                case "SLASHEQ":       yield make(TT.SLASHEQ,  lexem, tok_line, tok_col)
                case "PERCENTEQ":     yield make(TT.PERCENTEQ,lexem, tok_line, tok_col)
                case "AMPEQ":         yield make(TT.AMPEQ,    lexem, tok_line, tok_col)
                case "PIPEEQ":        yield make(TT.PIPEEQ,   lexem, tok_line, tok_col)
                case "CARETEQ":       yield make(TT.CARETEQ,  lexem, tok_line, tok_col)
                case "ATEQ":          yield make(TT.ATEQ,     lexem, tok_line, tok_col)
                case "WALRUS":        yield make(TT.WALRUS,   lexem, tok_line, tok_col)

                # Operadores de comparación
                case "EQEQ":   yield make(TT.EQEQ,   lexem, tok_line, tok_col)
                case "NEQ":    yield make(TT.NEQ,    lexem, tok_line, tok_col)
                case "LEQ":    yield make(TT.LEQ,    lexem, tok_line, tok_col)
                case "GEQ":    yield make(TT.GEQ,    lexem, tok_line, tok_col)
                case "LSHIFT": yield make(TT.LSHIFT, lexem, tok_line, tok_col)
                case "RSHIFT": yield make(TT.RSHIFT, lexem, tok_line, tok_col)
                case "ARROW":  yield make(TT.ARROW,  lexem, tok_line, tok_col)
                case "LT":     yield make(TT.LT,     lexem, tok_line, tok_col)
                case "GT":     yield make(TT.GT,     lexem, tok_line, tok_col)
                case "ASSIGN": yield make(TT.ASSIGN, lexem, tok_line, tok_col)

                # Operadores simples
                case "DOUBLESLASH": yield make(TT.DOUBLESLASH, lexem, tok_line, tok_col)
                case "DOUBLESTAR":  yield make(TT.DOUBLESTAR,  lexem, tok_line, tok_col)
                case "ELLIPSIS":    yield make(TT.ELLIPSIS,    lexem, tok_line, tok_col)
                case "PLUS":   yield make(TT.PLUS,   lexem, tok_line, tok_col)
                case "MINUS":  yield make(TT.MINUS,  lexem, tok_line, tok_col)
                case "STAR":   yield make(TT.STAR,   lexem, tok_line, tok_col)
                case "SLASH":  yield make(TT.SLASH,  lexem, tok_line, tok_col)
                case "PERCENT":yield make(TT.PERCENT,lexem, tok_line, tok_col)
                case "AT_OP":  yield make(TT.AT_OP,  lexem, tok_line, tok_col)
                case "AMP":    yield make(TT.AMP,    lexem, tok_line, tok_col)
                case "PIPE":   yield make(TT.PIPE,   lexem, tok_line, tok_col)
                case "CARET":  yield make(TT.CARET,  lexem, tok_line, tok_col)
                case "TILDE":  yield make(TT.TILDE,  lexem, tok_line, tok_col)

                # Delimitadores — actualizan paren_depth
                case "LPAREN":
                    paren_depth += 1
                    yield make(TT.LPAREN,   lexem, tok_line, tok_col)
                case "RPAREN":
                    paren_depth = max(0, paren_depth - 1)
                    yield make(TT.RPAREN,   lexem, tok_line, tok_col)
                case "LBRACKET":
                    paren_depth += 1
                    yield make(TT.LBRACKET, lexem, tok_line, tok_col)
                case "RBRACKET":
                    paren_depth = max(0, paren_depth - 1)
                    yield make(TT.RBRACKET, lexem, tok_line, tok_col)
                case "LBRACE":
                    paren_depth += 1
                    yield make(TT.LBRACE,   lexem, tok_line, tok_col)
                case "RBRACE":
                    paren_depth = max(0, paren_depth - 1)
                    yield make(TT.RBRACE,   lexem, tok_line, tok_col)

                case "COLON":     yield make(TT.COLON,    lexem, tok_line, tok_col)
                case "COMMA":     yield make(TT.COMMA,    lexem, tok_line, tok_col)
                case "DOT":       yield make(TT.DOT,      lexem, tok_line, tok_col)
                case "SEMICOLON": yield make(TT.SEMICOLON,lexem, tok_line, tok_col)

                case _:
                    yield make(TT.ERROR, lexem, tok_line, tok_col)

        # ── Fin de archivo: emitir DEDENTs pendientes + EOF ───────────────
        if paren_depth == 0:
            yield make(TT.NEWLINE, "", line, col)
        while len(indent_stack) > 1:
            indent_stack.pop()
            yield make(TT.DEDENT, "", line, col)
        yield make(TT.EOF, "", line, col)


# ════════════════════════════════════════════════════════════════════════════
#  FUNCIÓN DE CONVENIENCIA Y UTILIDADES DE DIAGNÓSTICO
# ════════════════════════════════════════════════════════════════════════════

def tokenize(source: str) -> List[Token]:
    """Tokeniza el código fuente y retorna la lista de tokens."""
    return Lexer(source).tokenize()


def print_token_table(tokens: List[Token], max_value_len: int = 30) -> None:
    """Imprime una tabla formateada de tokens (útil para depuración)."""
    header = f"{'#':>4}  {'TIPO':<20}  {'VALOR':<{max_value_len}}  {'LÍNEA':>5}  {'COL':>4}"
    print(header)
    print("─" * len(header))
    for i, tok in enumerate(tokens):
        val = tok.value[:max_value_len].replace("\n", "\\n")
        print(f"{i:>4}  {tok.type.name:<20}  {val:<{max_value_len}}  {tok.line:>5}  {tok.col:>4}")


def token_statistics(tokens: List[Token]) -> dict:
    """Retorna estadísticas del análisis léxico."""
    from collections import Counter
    counts = Counter(t.type for t in tokens)
    return {
        "total_tokens":    len(tokens),
        "unique_types":    len(counts),
        "identifiers":     counts.get(TT.NAME, 0),
        "keywords":        sum(v for k, v in counts.items()
                               if k not in {TT.NAME, TT.INTEGER, TT.FLOAT,
                                            TT.STRING, TT.NEWLINE, TT.INDENT,
                                            TT.DEDENT, TT.EOF}
                               and k.name.startswith("KW_")),
        "string_literals": counts.get(TT.STRING, 0),
        "integers":        counts.get(TT.INTEGER, 0),
        "floats":          counts.get(TT.FLOAT, 0),
        "operators":       sum(v for k, v in counts.items()
                               if k in {TT.PLUS, TT.MINUS, TT.STAR, TT.SLASH,
                                        TT.PERCENT, TT.EQEQ, TT.NEQ, TT.LT,
                                        TT.GT, TT.LEQ, TT.GEQ, TT.ASSIGN,
                                        TT.PLUSEQ, TT.MINUSEQ}),
        "newlines":        counts.get(TT.NEWLINE, 0),
        "indents":         counts.get(TT.INDENT, 0),
        "dedents":         counts.get(TT.DEDENT, 0),
        "errors":          counts.get(TT.ERROR, 0),
        "by_type":         dict(counts),
    }
