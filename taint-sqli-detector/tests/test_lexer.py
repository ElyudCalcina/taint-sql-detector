"""
Tests del Analizador Léxico.
Ejecutar: python3 -m pytest tests/test_lexer.py -v
"""
import pytest
from analyzer.lexer import tokenize, TT, LexError


def types(src: str) -> list:
    return [t.type for t in tokenize(src) if t.type not in (TT.NEWLINE, TT.EOF)]


def values(src: str) -> list:
    return [t.value for t in tokenize(src) if t.type not in (TT.NEWLINE, TT.EOF)]


# ════════════════════════════════════════════════════════════════════════════
#  Literales
# ════════════════════════════════════════════════════════════════════════════

class TestLiterales:

    def test_entero_decimal(self):
        toks = tokenize("42")
        assert toks[0].type  == TT.INTEGER
        assert toks[0].value == "42"

    def test_entero_hexadecimal(self):
        toks = tokenize("0xFF")
        assert toks[0].type == TT.INTEGER

    def test_entero_binario(self):
        toks = tokenize("0b1010")
        assert toks[0].type == TT.INTEGER

    def test_entero_octal(self):
        toks = tokenize("0o77")
        assert toks[0].type == TT.INTEGER

    def test_flotante(self):
        for src in ("3.14", "1e-5", ".5", "2.0e10"):
            toks = tokenize(src)
            assert toks[0].type == TT.FLOAT, f"Fallo con: {src}"

    def test_string_doble(self):
        toks = tokenize('"hola mundo"')
        assert toks[0].type == TT.STRING

    def test_string_simple(self):
        toks = tokenize("'texto'")
        assert toks[0].type == TT.STRING

    def test_string_triple_doble(self):
        toks = tokenize('"""triple\ndoble"""')
        assert toks[0].type == TT.STRING

    def test_fstring(self):
        toks = tokenize('f"valor={x}"')
        assert toks[0].type == TT.STRING

    def test_bstring(self):
        toks = tokenize('b"bytes"')
        assert toks[0].type == TT.STRING


# ════════════════════════════════════════════════════════════════════════════
#  Identificadores y palabras reservadas
# ════════════════════════════════════════════════════════════════════════════

class TestIdentificadores:

    def test_nombre_simple(self):
        toks = tokenize("variable")
        assert toks[0].type  == TT.NAME
        assert toks[0].value == "variable"

    def test_nombre_con_guion_bajo(self):
        toks = tokenize("_privado")
        assert toks[0].type == TT.NAME

    def test_nombre_con_numero(self):
        toks = tokenize("var1")
        assert toks[0].type == TT.NAME

    def test_palabras_reservadas(self):
        keywords = ["if", "else", "elif", "while", "for", "in",
                    "return", "def", "class", "import", "from",
                    "and", "or", "not", "True", "False", "None",
                    "pass", "break", "continue", "global"]
        expected_types = [
            TT.KW_IF, TT.KW_ELSE, TT.KW_ELIF, TT.KW_WHILE, TT.KW_FOR,
            TT.KW_IN, TT.KW_RETURN, TT.KW_DEF, TT.KW_CLASS, TT.KW_IMPORT,
            TT.KW_FROM, TT.KW_AND, TT.KW_OR, TT.KW_NOT, TT.KW_TRUE,
            TT.KW_FALSE, TT.KW_NONE, TT.KW_PASS, TT.KW_BREAK,
            TT.KW_CONTINUE, TT.KW_GLOBAL,
        ]
        for kw, expected in zip(keywords, expected_types):
            toks = tokenize(kw)
            assert toks[0].type == expected, f"Fallo con: {kw!r}"


# ════════════════════════════════════════════════════════════════════════════
#  Operadores
# ════════════════════════════════════════════════════════════════════════════

class TestOperadores:

    def test_aritmeticos(self):
        assert types("+ - * / // % **") == [
            TT.PLUS, TT.MINUS, TT.STAR, TT.SLASH,
            TT.DOUBLESLASH, TT.PERCENT, TT.DOUBLESTAR,
        ]

    def test_comparacion(self):
        assert types("== != < > <= >=") == [
            TT.EQEQ, TT.NEQ, TT.LT, TT.GT, TT.LEQ, TT.GEQ,
        ]

    def test_asignacion_simple(self):
        assert TT.ASSIGN in types("x = 5")

    def test_asignacion_compuesta(self):
        assert types("+= -= *= /= //= **=") == [
            TT.PLUSEQ, TT.MINUSEQ, TT.STAREQ,
            TT.SLASHEQ, TT.DOUBLESLASHEQ, TT.DOUBLESTAREQ,
        ]

    def test_walrus(self):
        assert TT.WALRUS in types("(n := 10)")

    def test_arrow(self):
        assert TT.ARROW in types("-> int")


# ════════════════════════════════════════════════════════════════════════════
#  Delimitadores
# ════════════════════════════════════════════════════════════════════════════

class TestDelimitadores:

    def test_parentesis(self):
        t = types("()")
        assert TT.LPAREN in t and TT.RPAREN in t

    def test_corchetes(self):
        t = types("[]")
        assert TT.LBRACKET in t and TT.RBRACKET in t

    def test_llaves(self):
        t = types("{}")
        assert TT.LBRACE in t and TT.RBRACE in t

    def test_coma_dos_puntos_punto(self):
        t = types(", : .")
        assert TT.COMMA in t
        assert TT.COLON in t
        assert TT.DOT in t


# ════════════════════════════════════════════════════════════════════════════
#  INDENT / DEDENT / NEWLINE
# ════════════════════════════════════════════════════════════════════════════

class TestIndentacion:

    def test_bloque_simple(self):
        src = "if True:\n    x = 1\n"
        tts = [t.type for t in tokenize(src)]
        assert TT.INDENT  in tts, "Debe emitir INDENT"
        assert TT.DEDENT  in tts, "Debe emitir DEDENT"
        assert TT.NEWLINE in tts, "Debe emitir NEWLINE"

    def test_bloque_anidado(self):
        src = "if a:\n    if b:\n        x = 1\n"
        tts = [t.type for t in tokenize(src)]
        assert tts.count(TT.INDENT) == 2, "Dos niveles de INDENT"
        assert tts.count(TT.DEDENT) == 2, "Dos niveles de DEDENT"

    def test_linea_en_blanco_ignorada(self):
        """Líneas en blanco dentro de un bloque no generan INDENT/DEDENT extra."""
        src = "x = 1\n\ny = 2\n"
        tts = [t.type for t in tokenize(src)]
        assert TT.INDENT not in tts
        assert TT.DEDENT not in tts

    def test_continuacion_implicita_en_parentesis(self):
        """Dentro de () no se emiten NEWLINE."""
        src = "x = (\n    1 +\n    2\n)\n"
        tts = [t.type for t in tokenize(src)]
        # Solo debe haber un NEWLINE al final de la sentencia completa
        assert tts.count(TT.NEWLINE) == 1


# ════════════════════════════════════════════════════════════════════════════
#  Números de línea y columna
# ════════════════════════════════════════════════════════════════════════════

class TestPosicion:

    def test_primer_token_linea_1_col_1(self):
        toks = tokenize("x = 1")
        assert toks[0].line == 1
        assert toks[0].col  == 1

    def test_segundo_token_col_correcta(self):
        toks = [t for t in tokenize("x = 1") if t.type not in (TT.NEWLINE, TT.EOF)]
        # x (col 1) = (col 3) 1 (col 5)
        assert toks[0].col == 1
        assert toks[1].col == 3
        assert toks[2].col == 5

    def test_token_segunda_linea(self):
        toks = tokenize("x = 1\ny = 2\n")
        y_tok = next(t for t in toks if t.value == "y")
        assert y_tok.line == 2

    def test_comentario_ignorado(self):
        toks = [t for t in tokenize("x = 1  # comentario\n")
                if t.type not in (TT.NEWLINE, TT.EOF)]
        # Solo deben quedar: NAME, ASSIGN, INTEGER
        assert len(toks) == 3


# ════════════════════════════════════════════════════════════════════════════
#  Código real de los ejemplos del proyecto
# ════════════════════════════════════════════════════════════════════════════

class TestCodigoReal:

    def test_tokeniza_login_vulnerable(self):
        src = """
username = request.form.get("username")
query = "SELECT * FROM usuarios WHERE username='" + username + "'"
cursor.execute(query)
"""
        toks = tokenize(src)
        types_list = [t.type for t in toks]
        # Verificar presencia de elementos esperados
        assert TT.NAME    in types_list
        assert TT.STRING  in types_list
        assert TT.ASSIGN  in types_list
        assert TT.DOT     in types_list
        assert TT.PLUS    in types_list
        assert TT.EOF     in types_list
        # Sin errores
        assert TT.ERROR not in types_list

    def test_tokeniza_consulta_parametrizada(self):
        src = 'cursor.execute("SELECT * FROM t WHERE id=?", (user_id,))\n'
        toks = tokenize(src)
        assert TT.ERROR not in [t.type for t in toks]

    def test_sin_errores_lexicos_en_ejemplos(self):
        """Todos los archivos de ejemplo deben tokenizarse sin errores léxicos."""
        import pathlib
        examples_dir = pathlib.Path("examples")
        if not examples_dir.exists():
            pytest.skip("directorio examples/ no encontrado")
        for py_file in examples_dir.glob("*.py"):
            src = py_file.read_text()
            toks = tokenize(src)
            errors = [t for t in toks if t.type == TT.ERROR]
            assert not errors, f"Errores en {py_file.name}: {errors}"
