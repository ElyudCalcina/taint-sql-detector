#!/usr/bin/env python3
"""
taint-sqli-detector — Detección Proactiva de SQLi mediante Taint Analysis
Universidad Nacional de San Agustín — Compiladores 2024

Pipeline de compilador implementado (6 fases propias + reporte):

  Fase 1 — Análisis Léxico      : analyzer/lexer.py
  Fase 2 — Análisis Sintáctico  : analyzer/parser.py
  Fase 3 — Análisis Semántico   : analyzer/semantic.py
  Fase 4 — Generación de IR/TAC : analyzer/ir_gen.py
  Fase 5 — Construcción del CFG : analyzer/cfg_builder.py
  Fase 6 — Taint Analysis (opt) : analyzer/taint_engine.py
  Reporte                        : analyzer/reporter.py

Uso:
    python3 main.py <archivo.py> [opciones]

Opciones:
    --tokens        Muestra tabla de tokens (Fase 1)
    --ast           Muestra el AST (Fase 2)
    --symbols       Muestra la tabla de símbolos (Fase 3)
    --ir            Muestra la Representación Intermedia (Fase 4)
    --cfg           Muestra el Grafo de Flujo de Control (Fase 5)
    --json          Salida en formato JSON
    --taint-params  Marca los parámetros de función como tainted
    --strict        Aborta si hay errores semánticos
"""

import sys
import argparse
from pathlib import Path

ANSI_BOLD  = "\033[1m"
ANSI_CYAN  = "\033[96m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW= "\033[93m"
ANSI_RED   = "\033[91m"
ANSI_RESET = "\033[0m"


def _phase(n: int, name: str) -> None:
    print(f"\n{ANSI_BOLD}{ANSI_CYAN}▶ Fase {n}: {name}{ANSI_RESET}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Detector estático de SQL Injection — pipeline de compilador"
    )
    ap.add_argument("file",           help="Archivo Python a analizar")
    ap.add_argument("--tokens",       action="store_true",
                    help="Mostrar tokens (Fase 1)")
    ap.add_argument("--ast",          action="store_true",
                    help="Mostrar AST (Fase 2)")
    ap.add_argument("--symbols",      action="store_true",
                    help="Mostrar tabla de símbolos (Fase 3)")
    ap.add_argument("--ir",           action="store_true",
                    help="Mostrar IR/TAC (Fase 4)")
    ap.add_argument("--cfg",          action="store_true",
                    help="Mostrar CFG (Fase 5)")
    ap.add_argument("--json",         action="store_true",
                    help="Salida en JSON")
    ap.add_argument("--taint-params", action="store_true",
                    help="Tratar parámetros de función como tainted")
    ap.add_argument("--strict",       action="store_true",
                    help="Abortar si hay errores semánticos")
    args = ap.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"Error: archivo '{args.file}' no encontrado.", file=sys.stderr)
        return 1

    source = path.read_text(encoding="utf-8")
    print(f"\n{ANSI_BOLD}{'='*62}{ANSI_RESET}")
    print(f"{ANSI_BOLD}  taint-sqli-detector  |  {path.name}{ANSI_RESET}")
    print(f"{ANSI_BOLD}{'='*62}{ANSI_RESET}")

    # ════════════════════════════════════════════════════════════════
    #  FASE 1 — Análisis Léxico
    # ════════════════════════════════════════════════════════════════
    _phase(1, "Análisis Léxico")
    from analyzer.lexer import Lexer, print_token_table, token_statistics

    lexer  = Lexer(source)
    tokens = lexer.tokenize()

    stats = token_statistics(tokens)
    print(f"  Tokens generados : {stats['total_tokens']}")
    print(f"  Identificadores  : {stats['identifiers']}")
    print(f"  Errores léxicos  : {stats['errors']}")

    if stats["errors"]:
        print(f"{ANSI_RED}  [!] Errores léxicos detectados — abortando.{ANSI_RESET}")
        return 1

    if args.tokens:
        print_token_table(tokens)

    # ════════════════════════════════════════════════════════════════
    #  FASE 2 — Análisis Sintáctico
    # ════════════════════════════════════════════════════════════════
    _phase(2, "Análisis Sintáctico")
    from analyzer.parser import Parser, ASTPrinter

    parser   = Parser(tokens)
    ast_tree = parser.parse()

    if parser.errors:
        print(f"{ANSI_YELLOW}  Errores sintácticos: {len(parser.errors)}{ANSI_RESET}")
        for e in parser.errors:
            print(f"    {e}")
    else:
        print(f"  {ANSI_GREEN}AST construido sin errores "
              f"({len(ast_tree.body)} sentencias top-level){ANSI_RESET}")

    if args.ast:
        print()
        ASTPrinter().print_tree(ast_tree)

    # ════════════════════════════════════════════════════════════════
    #  FASE 3 — Análisis Semántico
    # ════════════════════════════════════════════════════════════════
    _phase(3, "Análisis Semántico")
    from analyzer.semantic import SemanticAnalyzer

    sem       = SemanticAnalyzer()
    sym_table = sem.analyze(ast_tree)

    global_syms = sym_table.global_scope.all_symbols()
    tainted_vars = [s for s in global_syms.values() if s.is_tainted]

    print(f"  Símbolos globales  : {len(global_syms)}")
    print(f"  Variables tainted  : {len(tainted_vars)}")
    if sem.errors:
        print(f"  {ANSI_RED}Errores semánticos  : {len(sem.errors)}{ANSI_RESET}")
        for e in sem.errors:
            print(f"    {e}")
    if sem.warnings:
        print(f"  {ANSI_YELLOW}Advertencias        : {len(sem.warnings)}{ANSI_RESET}")
        for w in sem.warnings:
            print(f"    {w}")

    if args.symbols:
        sem.print_table()

    if args.strict and sem.errors:
        print(f"{ANSI_RED}  [!] Errores semánticos — abortando (--strict).{ANSI_RESET}")
        return 1

    # ════════════════════════════════════════════════════════════════
    #  FASE 4 — Generación de IR (Representación Intermedia / TAC)
    # ════════════════════════════════════════════════════════════════
    _phase(4, "Generación de IR / TAC")
    from analyzer.ir_gen import IRGenerator
    from analyzer.reporter import Reporter

    ir_gen = IRGenerator()
    instrs = ir_gen.generate(ast_tree)
    print(f"  Instrucciones TAC  : {len(instrs)}")

    if args.ir:
        Reporter.print_ir(instrs)

    # ════════════════════════════════════════════════════════════════
    #  FASE 5 — Construcción del CFG
    # ════════════════════════════════════════════════════════════════
    _phase(5, "Construcción del Grafo de Flujo de Control (CFG)")
    from analyzer.cfg_builder import CFGBuilder

    cfg = CFGBuilder().build(instrs, func_name=path.stem)
    print(f"  Bloques básicos    : {len(cfg.all_blocks())}")
    print(f"  Bloque entrada     : {cfg.entry.bid}")
    print(f"  Bloque salida      : {cfg.exit.bid}")

    if args.cfg:
        Reporter.print_cfg(cfg)

    # ════════════════════════════════════════════════════════════════
    #  FASE 6 — Taint Analysis (Fase de Optimización del Compilador)
    # ════════════════════════════════════════════════════════════════
    _phase(6, "Taint Analysis — Análisis de Flujo de Datos (Optimización)")
    from analyzer.taint_engine import TaintEngine

    engine = TaintEngine(cfg, func_params_tainted=args.taint_params)
    vulns  = engine.analyze()

    # ════════════════════════════════════════════════════════════════
    #  REPORTE
    # ════════════════════════════════════════════════════════════════
    reporter = Reporter(str(path), source)

    if args.json:
        print(reporter.to_json(vulns))
    else:
        reporter.print_report(vulns)

    return 1 if vulns else 0


if __name__ == "__main__":
    sys.exit(main())
