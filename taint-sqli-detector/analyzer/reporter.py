"""
Módulo de reporte de vulnerabilidades.
Genera salida en consola con colores ANSI y opcionalmente en JSON.
"""

import json
from typing import List
from .taint_engine import Vulnerability


ANSI_RESET  = "\033[0m"
ANSI_RED    = "\033[91m"
ANSI_YELLOW = "\033[93m"
ANSI_GREEN  = "\033[92m"
ANSI_CYAN   = "\033[96m"
ANSI_BOLD   = "\033[1m"


class Reporter:

    def __init__(self, source_path: str, source_code: str):
        self._path   = source_path
        self._lines  = source_code.splitlines()

    # ── consola ──────────────────────────────────────────────────────────────

    def print_report(self, vulns: List[Vulnerability]) -> None:
        print(f"\n{ANSI_BOLD}{'='*60}{ANSI_RESET}")
        print(f"{ANSI_BOLD}  TAINT-SQLI-DETECTOR — Reporte de Análisis{ANSI_RESET}")
        print(f"  Archivo: {ANSI_CYAN}{self._path}{ANSI_RESET}")
        print(f"{'='*60}{ANSI_RESET}\n")

        if not vulns:
            print(f"{ANSI_GREEN}[OK] No se detectaron vulnerabilidades de inyección SQL.{ANSI_RESET}\n")
            return

        print(f"{ANSI_RED}{ANSI_BOLD}[!] Se detectaron {len(vulns)} vulnerabilidad(es):{ANSI_RESET}\n")

        for i, v in enumerate(vulns, 1):
            sev_color = ANSI_RED if v.severity == "HIGH" else ANSI_YELLOW
            print(f"  {ANSI_BOLD}Vulnerabilidad #{i}{ANSI_RESET}")
            print(f"  Tipo     : {sev_color}{v.vuln_type} [{v.severity}]{ANSI_RESET}")
            print(f"  Línea    : {v.line_no}")
            print(f"  Sink     : {ANSI_RED}{v.sink_name}(){ANSI_RESET}")
            print(f"  Args tainted: {v.tainted_args}")
            print(f"  Bloque CFG  : {v.block_id}")

            # Mostrar línea de código relevante
            if 0 < v.line_no <= len(self._lines):
                code_line = self._lines[v.line_no - 1]
                print(f"\n  {ANSI_CYAN}Código fuente (línea {v.line_no}):{ANSI_RESET}")
                print(f"  {ANSI_YELLOW}>>> {code_line.strip()}{ANSI_RESET}")

            print(f"\n  Descripción: {v.description}")
            print(f"  CWE: CWE-89 (SQL Injection)")
            print(f"  {'─'*56}\n")

        print(f"{ANSI_BOLD}Resumen:{ANSI_RESET}")
        print(f"  Total vulnerabilidades: {len(vulns)}")
        print(f"  HIGH: {sum(1 for v in vulns if v.severity=='HIGH')}")
        print()

    # ── JSON ─────────────────────────────────────────────────────────────────

    def to_json(self, vulns: List[Vulnerability]) -> str:
        data = {
            "file": self._path,
            "total": len(vulns),
            "vulnerabilities": [
                {
                    "type":        v.vuln_type,
                    "severity":    v.severity,
                    "line":        v.line_no,
                    "sink":        v.sink_name,
                    "tainted_args":v.tainted_args,
                    "block":       v.block_id,
                    "description": v.description,
                    "cwe":         "CWE-89",
                }
                for v in vulns
            ],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    # ── IR legible ───────────────────────────────────────────────────────────

    @staticmethod
    def print_ir(instrs) -> None:
        print(f"\n{ANSI_BOLD}── Representación Intermedia (TAC) ──{ANSI_RESET}")
        for i, instr in enumerate(instrs):
            print(f"  {i:3d}: {instr}")
        print()

    @staticmethod
    def print_cfg(cfg) -> None:
        print(f"\n{ANSI_BOLD}── Grafo de Flujo de Control ──{ANSI_RESET}")
        for blk in cfg.all_blocks():
            succs = [s.bid for s in blk.successors]
            preds = [p.bid for p in blk.predecessors]
            print(f"\n  {ANSI_CYAN}[{blk.bid}]{ANSI_RESET}  pred={preds}  succ={succs}")
            for instr in blk.instructions:
                print(f"      {instr}")
        print()
