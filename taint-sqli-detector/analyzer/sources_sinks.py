"""
Catálogo de Sources, Sinks y Sanitizadores para SQL Injection.

- SOURCE : función o atributo que introduce datos no confiables al programa.
- SINK   : función donde datos contaminados pueden causar SQLi.
- SANITIZER: función que neutraliza el peligro de datos contaminados.
"""

from dataclasses import dataclass, field
from typing import Set, Tuple, Optional


@dataclass(frozen=True)
class SourceSpec:
    """Especificación de una fuente de contaminación."""
    module:    Optional[str]   # módulo (None = builtin)
    attr_path: str             # "input", "request.args.get", etc.
    arg_index: Optional[int]  = None  # qué argumento retorna dato sucio
    description: str          = ""

    @property
    def short_name(self) -> str:
        return self.attr_path.split(".")[-1]


@dataclass(frozen=True)
class SinkSpec:
    """Especificación de un sink peligroso."""
    module:      Optional[str]
    attr_path:   str
    tainted_args: Tuple[int, ...] = (0,)   # índices de args que deben ser limpios
    description: str = ""


@dataclass(frozen=True)
class SanitizerSpec:
    """Especificación de una función que limpia datos contaminados."""
    module:    Optional[str]
    attr_path: str
    description: str = ""


# ════════════════════════════════════════════════════════════════════════════
#  SOURCES  —  Entradas no confiables
# ════════════════════════════════════════════════════════════════════════════

SOURCES: list[SourceSpec] = [
    # Python builtins
    SourceSpec(None,    "input",                  description="Entrada estándar del usuario"),
    # Flask / Werkzeug
    SourceSpec("flask", "request.args.get",       description="Parámetro GET (Flask)"),
    SourceSpec("flask", "request.args.__getitem__",description="Parámetro GET indexado"),
    SourceSpec("flask", "request.form.get",       description="Campo de formulario POST (Flask)"),
    SourceSpec("flask", "request.form.__getitem__",description="Campo POST indexado"),
    SourceSpec("flask", "request.json",           description="Body JSON (Flask)"),
    SourceSpec("flask", "request.values.get",     description="Valores GET+POST (Flask)"),
    SourceSpec("flask", "request.cookies.get",    description="Cookie HTTP (Flask)"),
    SourceSpec("flask", "request.headers.get",    description="Cabecera HTTP (Flask)"),
    # Django
    SourceSpec("django","request.GET.get",        description="Parámetro GET (Django)"),
    SourceSpec("django","request.GET.__getitem__",description="Parámetro GET indexado"),
    SourceSpec("django","request.POST.get",       description="Campo POST (Django)"),
    SourceSpec("django","request.POST.__getitem__",description="Campo POST indexado"),
    SourceSpec("django","request.body",           description="Cuerpo HTTP crudo (Django)"),
    SourceSpec("django","request.META.get",       description="Metadatos HTTP (Django)"),
    # FastAPI
    SourceSpec("fastapi","Query",                 description="Parámetro de query (FastAPI)"),
    SourceSpec("fastapi","Body",                  description="Cuerpo request (FastAPI)"),
    # Standard library
    SourceSpec("sys",   "argv",                   description="Argumentos de línea de comandos"),
    SourceSpec("os",    "environ.get",            description="Variable de entorno"),
    SourceSpec("urllib","parse.parse_qs",         description="Query string parseada"),
]

# Nombres cortos para lookup rápido  (func_name tal como aparece en el IR)
SOURCE_NAMES: Set[str] = {
    "input",
    "request.args.get", "request.form.get", "request.values.get",
    "request.cookies.get", "request.headers.get", "request.json",
    "request.GET.get", "request.POST.get", "request.body",
    "request.META.get",
    "Query", "Body",
    "sys.argv", "os.environ.get", "urllib.parse.parse_qs",
    # Accesos directos a atributos
    "args", "form", "GET", "POST", "json", "body", "cookies",
}


# ════════════════════════════════════════════════════════════════════════════
#  SINKS  —  Operaciones peligrosas con SQL
# ════════════════════════════════════════════════════════════════════════════

SINKS: list[SinkSpec] = [
    # DB-API 2.0 (PEP 249): sqlite3, psycopg2, pymysql, cx_Oracle, etc.
    SinkSpec(None, "cursor.execute",       (0,), "Ejecución de SQL cruda"),
    SinkSpec(None, "cursor.executemany",   (0,), "Ejecución SQL múltiple"),
    SinkSpec(None, "connection.execute",   (0,), "Ejecución directa en conexión"),
    SinkSpec(None, "execute",              (0,), "Función execute genérica"),
    # SQLAlchemy Core / ORM
    SinkSpec(None, "session.execute",      (0,), "SQLAlchemy session.execute"),
    SinkSpec(None, "engine.execute",       (0,), "SQLAlchemy engine.execute"),
    SinkSpec(None, "db.execute",           (0,), "SQLAlchemy db.execute"),
    SinkSpec(None, "text",                 (0,), "SQLAlchemy text()"),
    # Django ORM raw
    SinkSpec(None, "objects.raw",          (0,), "Django ORM raw query"),
    SinkSpec(None, "connection.cursor.execute", (0,), "Django raw execute"),
    # Genéricas
    SinkSpec(None, "run_query",            (0,), "Query genérica"),
    SinkSpec(None, "query",                (0,), "Función query genérica"),
    SinkSpec(None, "db_query",             (0,), "Función db_query"),
]

SINK_NAMES: Set[str] = {s.attr_path.split(".")[-1] for s in SINKS} | {
    "execute", "executemany", "raw", "run_query", "query", "db_query", "text"
}

# Nombres completos para verificación más precisa
SINK_FULL_NAMES: Set[str] = {s.attr_path for s in SINKS}


# ════════════════════════════════════════════════════════════════════════════
#  SANITIZADORES  —  Funciones que neutralizan contaminación
# ════════════════════════════════════════════════════════════════════════════

SANITIZERS: list[SanitizerSpec] = [
    # Escape de caracteres especiales SQL
    SanitizerSpec(None, "escape_string",       "Escape de caracteres SQL"),
    SanitizerSpec(None, "quote",               "Quoteo de valor SQL"),
    SanitizerSpec(None, "mysql.escape_string", "Escape MySQL"),
    SanitizerSpec(None, "psycopg2.extensions.adapt", "Adaptador psycopg2"),
    # Validación y limpieza genérica
    SanitizerSpec(None, "int",                 "Conversión a entero (valida formato numérico)"),
    SanitizerSpec(None, "float",               "Conversión a float"),
    SanitizerSpec(None, "sanitize",            "Función sanitize genérica"),
    SanitizerSpec(None, "clean",               "Función clean genérica"),
    SanitizerSpec(None, "validate",            "Función validate genérica"),
    SanitizerSpec(None, "bleach.clean",        "Limpieza HTML/SQL con bleach"),
    # Consultas parametrizadas — el verdadero sanitizador es usar placeholders
    # Se detecta a nivel de CALL: si args[0] contiene '?' o '%s' y args[1] es tuple
    SanitizerSpec(None, "_parametrized_query", "Consulta con placeholders (segura)"),
]

SANITIZER_NAMES: Set[str] = {
    "escape_string", "quote", "adapt", "int", "float",
    "sanitize", "clean", "validate", "bleach.clean",
}
