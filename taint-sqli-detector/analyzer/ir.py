"""
Representación Intermedia (IR) - Código de Tres Direcciones (TAC)
Modela las instrucciones del programa en una forma normalizada
sobre la que se ejecuta el análisis de taint.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional, Any, Set


class OpType(Enum):
    ASSIGN  = "assign"   # dest = src
    BINOP   = "binop"    # dest = src1 op src2
    UNOP    = "unop"     # dest = op src1
    CONST   = "const"    # dest = literal
    CALL    = "call"     # dest = func(args...)
    LOAD    = "load"     # dest = obj.attr  /  obj[key]
    STORE   = "store"    # obj.attr = src
    BRANCH  = "branch"   # if src1 goto true_label else false_label
    JUMP    = "jump"     # goto label
    LABEL   = "label"    # L:
    RETURN  = "return"   # return src1
    PARAM   = "param"    # función: parámetro formal (posible source)
    NOP     = "nop"


@dataclass
class Instruction:
    """Instrucción de código de tres direcciones."""
    op:          OpType
    dest:        Optional[str]       = None
    src1:        Optional[str]       = None
    src2:        Optional[str]       = None
    args:        List[str]           = field(default_factory=list)
    func_name:   Optional[str]       = None
    operator:    Optional[str]       = None
    label:       Optional[str]       = None
    true_label:  Optional[str]       = None
    false_label: Optional[str]       = None
    const_value: Any                 = None
    line_no:     int                 = 0

    # ── helpers para el análisis de flujo de datos ──────────────────────────

    def uses(self) -> List[str]:
        """Variables leídas por esta instrucción."""
        used: List[str] = []
        for v in (self.src1, self.src2):
            if v and not _is_literal(v):
                used.append(v)
        used.extend(a for a in self.args if a and not _is_literal(a))
        return used

    def defines(self) -> Optional[str]:
        """Variable escrita por esta instrucción (si existe)."""
        return self.dest

    # ── representación legible ───────────────────────────────────────────────

    def __repr__(self) -> str:
        d = self.dest or "_"
        match self.op:
            case OpType.ASSIGN:
                return f"{d} = {self.src1}"
            case OpType.BINOP:
                return f"{d} = {self.src1} {self.operator} {self.src2}"
            case OpType.UNOP:
                return f"{d} = {self.operator}{self.src1}"
            case OpType.CONST:
                return f"{d} = {repr(self.const_value)}"
            case OpType.CALL:
                args = ", ".join(self.args)
                prefix = f"{d} = " if self.dest else ""
                return f"{prefix}{self.func_name}({args})"
            case OpType.LOAD:
                return f"{d} = {self.src1}[{self.src2}]" if self.operator == "subscript" \
                       else f"{d} = {self.src1}.{self.src2}"
            case OpType.STORE:
                return f"{self.dest}.{self.src2} = {self.src1}"
            case OpType.BRANCH:
                return f"if {self.src1} goto {self.true_label} else {self.false_label}"
            case OpType.JUMP:
                return f"goto {self.label}"
            case OpType.LABEL:
                return f"{self.label}:"
            case OpType.RETURN:
                return f"return {self.src1 or ''}"
            case OpType.PARAM:
                return f"param {self.dest}"
            case _:
                return "nop"


def _is_literal(s: str) -> bool:
    """Detecta si el operando es una constante y no un nombre de variable."""
    try:
        float(s)
        return True
    except ValueError:
        pass
    if (s.startswith('"') and s.endswith('"')) or \
       (s.startswith("'") and s.endswith("'")):
        return True
    if s in ("True", "False", "None"):
        return True
    return False


# ════════════════════════════════════════════════════════════════════════════
#  Bloques Básicos y CFG
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class BasicBlock:
    """Bloque básico: secuencia maximal de instrucciones sin saltos intermedios."""
    bid:          str
    instructions: List[Instruction]      = field(default_factory=list)
    successors:   List["BasicBlock"]     = field(default_factory=list)
    predecessors: List["BasicBlock"]     = field(default_factory=list)

    # Conjuntos del análisis de flujo de datos
    taint_in:  Set[str] = field(default_factory=set)
    taint_out: Set[str] = field(default_factory=set)

    def add_instr(self, instr: Instruction) -> None:
        self.instructions.append(instr)

    def __hash__(self):
        return hash(self.bid)

    def __repr__(self):
        return f"BB({self.bid}, {len(self.instructions)} instrs)"


@dataclass
class CFG:
    """Grafo de Flujo de Control completo de una función."""
    func_name: str
    entry:     BasicBlock
    exit:      BasicBlock
    blocks:    List[BasicBlock] = field(default_factory=list)

    def add_block(self, block: BasicBlock) -> None:
        self.blocks.append(block)

    def add_edge(self, src: BasicBlock, dst: BasicBlock) -> None:
        if dst not in src.successors:
            src.successors.append(dst)
        if src not in dst.predecessors:
            dst.predecessors.append(src)

    def all_blocks(self) -> List[BasicBlock]:
        return self.blocks

    def __repr__(self):
        return (f"CFG({self.func_name}, "
                f"{len(self.blocks)} bloques, "
                f"entry={self.entry.bid})")
