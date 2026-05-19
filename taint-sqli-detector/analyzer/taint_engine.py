"""
Motor de Análisis de Taint (Propagación de Manchas).

Implementa un análisis de flujo de datos hacia adelante (forward dataflow)
sobre el CFG. El conjunto de datos es el conjunto de variables contaminadas
(tainted) en cada punto del programa.

Lattice:
    ⊥  = {}   (ninguna variable contaminada — valor inicial)
    ⊤  = all_vars  (todas las variables contaminadas)

Operador de unión:  IN[B] = ⋃ OUT[P]  para todo predecesor P de B.
Función de transferencia:  OUT[B] = gen[B] ∪ (IN[B] − kill[B])
"""

from __future__ import annotations
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple

from .ir import BasicBlock, CFG, Instruction, OpType
from .sources_sinks import SOURCE_NAMES, SINK_NAMES, SANITIZER_NAMES


# ════════════════════════════════════════════════════════════════════════════
#  Vulnerabilidad encontrada
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class Vulnerability:
    vuln_type:    str
    sink_name:    str
    tainted_args: List[str]
    line_no:      int
    block_id:     str
    description:  str = ""
    severity:     str = "HIGH"


# ════════════════════════════════════════════════════════════════════════════
#  Motor principal
# ════════════════════════════════════════════════════════════════════════════

class TaintEngine:
    """
    Análisis de taint hacia adelante con algoritmo worklist.

    Pasos:
      1. Inicializar taint_in = {} para todos los bloques.
      2. Poner todos los bloques en la worklist.
      3. Para cada bloque B de la worklist:
           a. Computar IN[B] = ⋃ OUT[P]
           b. Aplicar transfer_block  →  nuevo OUT[B]
           c. Si OUT[B] cambió, agregar sucesores a la worklist.
      4. Repetir hasta que la worklist esté vacía (punto fijo).
      5. Durante la transferencia, reportar vulnerabilidades si un sink
         recibe un argumento contaminado.
    """

    def __init__(self, cfg: CFG, func_params_tainted: bool = False):
        self._cfg = cfg
        self._func_params_tainted = func_params_tainted
        self._vulnerabilities: List[Vulnerability] = []

    # ── API pública ──────────────────────────────────────────────────────────

    def analyze(self) -> List[Vulnerability]:
        """Ejecuta el análisis y retorna la lista de vulnerabilidades."""
        self._vulnerabilities = []
        self._run_worklist()
        return self._vulnerabilities

    # ── algoritmo worklist ───────────────────────────────────────────────────

    def _run_worklist(self) -> None:
        cfg = self._cfg

        # Inicialización: OUT[entry] puede tener parámetros contaminados
        for blk in cfg.all_blocks():
            blk.taint_in  = set()
            blk.taint_out = set()

        # Seed: parámetros de función como fuentes si se indica
        if self._func_params_tainted:
            for instr in cfg.entry.instructions:
                if instr.op == OpType.PARAM and instr.dest:
                    cfg.entry.taint_out.add(instr.dest)

        worklist: deque[BasicBlock] = deque(cfg.all_blocks())
        visited_with: Dict[str, Set[str]] = {
            blk.bid: set() for blk in cfg.all_blocks()
        }

        while worklist:
            blk = worklist.popleft()

            # IN[B] = ⋃ OUT[P]
            new_in: Set[str] = set()
            for pred in blk.predecessors:
                new_in |= pred.taint_out
            blk.taint_in = new_in

            # OUT[B] = transfer(IN[B], instrs[B])
            new_out = self._transfer_block(blk, new_in)

            if new_out != blk.taint_out:
                blk.taint_out = new_out
                for succ in blk.successors:
                    if succ not in worklist:
                        worklist.append(succ)

    # ── función de transferencia ─────────────────────────────────────────────

    def _transfer_block(
            self, blk: BasicBlock, taint_in: Set[str]) -> Set[str]:
        """
        Procesa las instrucciones del bloque de arriba a abajo,
        actualizando el conjunto de manchas y reportando vulnerabilidades.
        """
        tainted: Set[str] = set(taint_in)

        for instr in blk.instructions:
            tainted = self._transfer_instr(instr, tainted, blk.bid)

        return tainted

    def _transfer_instr(
            self, instr: Instruction,
            tainted: Set[str], block_id: str) -> Set[str]:

        tainted = set(tainted)  # copia para no mutar el estado anterior

        match instr.op:

            # ── PARAM: marcar parámetro de función como fuente ──────────────
            case OpType.PARAM:
                if self._func_params_tainted and instr.dest:
                    tainted.add(instr.dest)

            # ── CONST: constante nunca es tainted ───────────────────────────
            case OpType.CONST:
                if instr.dest:
                    tainted.discard(instr.dest)

            # ── ASSIGN: x = y  →  taint se propaga ──────────────────────────
            case OpType.ASSIGN:
                if instr.dest:
                    if instr.src1 and instr.src1 in tainted:
                        tainted.add(instr.dest)
                    else:
                        tainted.discard(instr.dest)

            # ── BINOP: x = a OP b  →  si alguno es tainted, resultado también ─
            case OpType.BINOP:
                if instr.dest:
                    if (instr.src1 in tainted) or (instr.src2 in tainted):
                        tainted.add(instr.dest)
                    else:
                        tainted.discard(instr.dest)

            # ── LOAD: x = obj.attr / obj[key] ────────────────────────────────
            # Propaga taint si el objeto origen es tainted O si el nombre
            # semántico completo del atributo es una fuente conocida.
            case OpType.LOAD:
                if instr.dest:
                    if instr.src1 in tainted:
                        tainted.add(instr.dest)
                    elif instr.func_name and self._is_source(instr.func_name):
                        # Acceso a atributo de source (ej. request.args)
                        tainted.add(instr.dest)
                    else:
                        tainted.discard(instr.dest)

            # ── CALL ─────────────────────────────────────────────────────────
            case OpType.CALL:
                tainted = self._handle_call(instr, tainted, block_id)

            # ── STORE / BRANCH / JUMP / RETURN: no modifican taint set ───────
            case _:
                pass

        return tainted

    # ── manejo especial de CALL ──────────────────────────────────────────────

    def _handle_call(
            self, instr: Instruction,
            tainted: Set[str], block_id: str) -> Set[str]:

        func  = instr.func_name or ""
        dest  = instr.dest
        args  = instr.args

        short = func.split(".")[-1]   # último segmento del nombre

        # ── 1. ¿Es una fuente (source)? ─────────────────────────────────────
        if self._is_source(func):
            if dest:
                tainted.add(dest)
            return tainted

        # ── 2. ¿Es un sanitizador? ──────────────────────────────────────────
        if self._is_sanitizer(func):
            if dest:
                tainted.discard(dest)
            return tainted

        # ── 3. ¿Es un sink? ─────────────────────────────────────────────────
        if self._is_sink(func):
            # Detecta si la llamada usa consulta parametrizada segura
            if not self._is_parametrized(instr, tainted):
                tainted_in_args = [a for a in args if a in tainted]
                if tainted_in_args:
                    self._report_vuln(instr, tainted_in_args, block_id)

            # Aunque sea sink, el resultado no hereda taint
            if dest:
                tainted.discard(dest)
            return tainted

        # ── 4. Función genérica: si algún arg está tainted, resultado también ─
        if dest:
            if any(a in tainted for a in args):
                tainted.add(dest)
            else:
                tainted.discard(dest)

        return tainted

    # ── detección de vulnerabilidad ──────────────────────────────────────────

    def _report_vuln(
            self, instr: Instruction,
            tainted_args: List[str], block_id: str) -> None:
        vuln = Vulnerability(
            vuln_type="SQL_INJECTION",
            sink_name=instr.func_name or "?",
            tainted_args=tainted_args,
            line_no=instr.line_no,
            block_id=block_id,
            description=(
                f"Argumento(s) contaminado(s) {tainted_args} "
                f"alcanza sink '{instr.func_name}' sin saneamiento. "
                f"Posible inyección SQL (CWE-89)."
            ),
            severity="HIGH"
        )
        # Evitar duplicados exactos
        if not any(
            v.line_no == vuln.line_no and v.sink_name == vuln.sink_name
            for v in self._vulnerabilities
        ):
            self._vulnerabilities.append(vuln)

    # ── predicados auxiliares ────────────────────────────────────────────────

    @staticmethod
    def _is_source(func: str) -> bool:
        short = func.split(".")[-1]
        return func in SOURCE_NAMES or short in SOURCE_NAMES

    @staticmethod
    def _is_sink(func: str) -> bool:
        short = func.split(".")[-1]
        return func in SINK_NAMES or short in SINK_NAMES

    @staticmethod
    def _is_sanitizer(func: str) -> bool:
        short = func.split(".")[-1]
        return func in SANITIZER_NAMES or short in SANITIZER_NAMES

    @staticmethod
    def _is_parametrized(instr: Instruction, tainted: Set[str]) -> bool:
        """
        Heurística: considera la llamada segura si el primer argumento
        es una constante (no tainted) y hay un segundo argumento (parámetros).
        Ej: cursor.execute("SELECT * FROM u WHERE id=%s", (user_id,))
        """
        args = instr.args
        if len(args) >= 2 and args[0] not in tainted:
            return True
        return False
