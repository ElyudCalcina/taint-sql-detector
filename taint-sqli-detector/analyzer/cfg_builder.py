"""
Construcción del CFG a partir del AST de Python.
Pipeline:  código fuente → ast.parse() → IR (TAC) → BasicBlocks → CFG
"""

import ast
import textwrap
from typing import List, Dict, Optional, Tuple

from .ir import Instruction, OpType, BasicBlock, CFG


# ════════════════════════════════════════════════════════════════════════════
#  Generador de temporales
# ════════════════════════════════════════════════════════════════════════════

class _TempGen:
    def __init__(self):
        self._n = 0
        self._l = 0

    def temp(self) -> str:
        self._n += 1
        return f"t{self._n}"

    def label(self) -> str:
        self._l += 1
        return f"L{self._l}"


# ════════════════════════════════════════════════════════════════════════════
#  Traductor AST → IR (TAC)
# ════════════════════════════════════════════════════════════════════════════

class ASTToIR(ast.NodeVisitor):
    """
    Recorre el AST de Python y emite instrucciones de tres direcciones (TAC).
    Soporta: asignaciones, llamadas a funciones, acceso a atributos,
             condicionales if/else, bucles while/for, return.
    """

    def __init__(self):
        self._gen   = _TempGen()
        self._instrs: List[Instruction] = []
        # Mapea temp → nombre semántico completo (ej. t5 → "request.form")
        self._attr_names: Dict[str, str] = {}

    # ── API pública ──────────────────────────────────────────────────────────

    def translate(self, source: str) -> List[Instruction]:
        """Retorna la lista de instrucciones TAC para el código fuente dado."""
        tree = ast.parse(textwrap.dedent(source))
        self.visit(tree)
        return self._instrs

    # ── helpers internos ─────────────────────────────────────────────────────

    def _emit(self, instr: Instruction) -> None:
        self._instrs.append(instr)

    def _new_temp(self) -> str:
        return self._gen.temp()

    def _new_label(self) -> str:
        return self._gen.label()

    def _label_instr(self, name: str) -> Instruction:
        return Instruction(op=OpType.LABEL, label=name)

    # ── visitores de expresiones (retornan el nombre del temp que guarda el val) ──

    def visit_Constant(self, node: ast.Constant) -> str:
        t = self._new_temp()
        self._emit(Instruction(
            op=OpType.CONST, dest=t, const_value=node.value,
            line_no=node.lineno
        ))
        return t

    def visit_Name(self, node: ast.Name) -> str:
        return node.id   # retorna el nombre de la variable directamente

    def visit_BinOp(self, node: ast.BinOp) -> str:
        left  = self.visit(node.left)
        right = self.visit(node.right)
        t     = self._new_temp()
        op_sym = {
            ast.Add: "+", ast.Sub: "-", ast.Mult: "*",
            ast.Div: "/", ast.Mod: "%",
        }.get(type(node.op), "?")
        self._emit(Instruction(
            op=OpType.BINOP, dest=t, src1=left, src2=right,
            operator=op_sym, line_no=node.lineno
        ))
        return t

    def visit_JoinedStr(self, node: ast.JoinedStr) -> str:
        """f-string: se trata como concatenación de partes."""
        parts: List[str] = []
        for v in node.values:
            parts.append(self.visit(v))
        if not parts:
            return self.visit_Constant(ast.Constant(value=""))
        result = parts[0]
        for p in parts[1:]:
            t = self._new_temp()
            self._emit(Instruction(
                op=OpType.BINOP, dest=t, src1=result, src2=p,
                operator="+", line_no=node.lineno
            ))
            result = t
        return result

    def visit_FormattedValue(self, node: ast.FormattedValue) -> str:
        return self.visit(node.value)

    def visit_Attribute(self, node: ast.Attribute) -> str:
        obj = self.visit(node.value)
        # Resuelve nombre semántico completo: "request" → "request.form"
        obj_name  = self._attr_names.get(obj, obj)
        full_name = f"{obj_name}.{node.attr}"
        t = self._new_temp()
        self._emit(Instruction(
            op=OpType.LOAD, dest=t, src1=obj, src2=node.attr,
            func_name=full_name,      # guardado para detección de sources/sinks
            line_no=node.lineno
        ))
        self._attr_names[t] = full_name
        return t

    def visit_Subscript(self, node: ast.Subscript) -> str:
        obj   = self.visit(node.value)
        index = self.visit(node.slice) if isinstance(node.slice, ast.AST) \
                else str(node.slice)
        t = self._new_temp()
        self._emit(Instruction(
            op=OpType.LOAD, dest=t, src1=obj, src2=index,
            operator="subscript", line_no=node.lineno
        ))
        return t

    def visit_Call(self, node: ast.Call) -> str:
        # Determina el nombre de la función/método
        if isinstance(node.func, ast.Attribute):
            receiver      = self.visit(node.func.value)
            receiver_name = self._attr_names.get(receiver, receiver)
            func_name     = f"{receiver_name}.{node.func.attr}"
            attr_name     = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
            receiver  = None
            attr_name = node.func.id
        else:
            func_name = "unknown_func"
            receiver  = None
            attr_name = "unknown_func"

        # Evalúa los argumentos
        arg_temps: List[str] = []
        for a in node.args:
            arg_temps.append(self.visit(a))
        for kw in node.keywords:
            arg_temps.append(self.visit(kw.value))

        t = self._new_temp()
        self._emit(Instruction(
            op=OpType.CALL, dest=t, func_name=func_name,
            args=arg_temps, line_no=node.lineno
        ))
        return t

    def visit_IfExp(self, node: ast.IfExp) -> str:
        """Expresión ternaria: x if cond else y."""
        cond = self.visit(node.test)
        t_true  = self._new_label()
        t_false = self._new_label()
        t_end   = self._new_label()
        result  = self._new_temp()

        self._emit(Instruction(
            op=OpType.BRANCH, src1=cond,
            true_label=t_true, false_label=t_false,
            line_no=node.lineno
        ))
        self._emit(self._label_instr(t_true))
        val_true = self.visit(node.body)
        self._emit(Instruction(op=OpType.ASSIGN, dest=result, src1=val_true))
        self._emit(Instruction(op=OpType.JUMP, label=t_end))
        self._emit(self._label_instr(t_false))
        val_false = self.visit(node.orelse)
        self._emit(Instruction(op=OpType.ASSIGN, dest=result, src1=val_false))
        self._emit(self._label_instr(t_end))
        return result

    # ── visitores de sentencias ──────────────────────────────────────────────

    def visit_Module(self, node: ast.Module) -> None:
        for stmt in node.body:
            self.visit(stmt)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Emite PARAMs para los argumentos
        for arg in node.args.args:
            self._emit(Instruction(
                op=OpType.PARAM, dest=arg.arg, line_no=node.lineno
            ))
        for stmt in node.body:
            self.visit(stmt)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        val = self.visit(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._emit(Instruction(
                    op=OpType.ASSIGN, dest=target.id, src1=val,
                    line_no=node.lineno
                ))
            elif isinstance(target, ast.Attribute):
                obj = self.visit(target.value)
                self._emit(Instruction(
                    op=OpType.STORE, dest=obj, src2=target.attr, src1=val,
                    line_no=node.lineno
                ))

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        """x += y  →  x = x + y"""
        val = self.visit(node.value)
        if isinstance(node.target, ast.Name):
            name = node.target.id
            t = self._new_temp()
            op_sym = {
                ast.Add: "+", ast.Sub: "-", ast.Mult: "*",
            }.get(type(node.op), "?")
            self._emit(Instruction(
                op=OpType.BINOP, dest=t, src1=name, src2=val,
                operator=op_sym, line_no=node.lineno
            ))
            self._emit(Instruction(
                op=OpType.ASSIGN, dest=name, src1=t, line_no=node.lineno
            ))

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value and isinstance(node.target, ast.Name):
            val = self.visit(node.value)
            self._emit(Instruction(
                op=OpType.ASSIGN, dest=node.target.id, src1=val,
                line_no=node.lineno
            ))

    def visit_Expr(self, node: ast.Expr) -> None:
        """Expresión usada como sentencia (ej: llamada a función sin asignar)."""
        val = self.visit(node.value)
        # Si el resultado de un CALL se descarta, aun así debe estar en el IR

    def visit_Return(self, node: ast.Return) -> None:
        val = self.visit(node.value) if node.value else None
        self._emit(Instruction(
            op=OpType.RETURN, src1=val, line_no=node.lineno
        ))

    def visit_If(self, node: ast.If) -> None:
        cond    = self.visit(node.test)
        l_true  = self._new_label()
        l_false = self._new_label()
        l_end   = self._new_label()

        self._emit(Instruction(
            op=OpType.BRANCH, src1=cond,
            true_label=l_true, false_label=l_false,
            line_no=node.lineno
        ))
        self._emit(self._label_instr(l_true))
        for s in node.body:
            self.visit(s)
        self._emit(Instruction(op=OpType.JUMP, label=l_end))
        self._emit(self._label_instr(l_false))
        for s in node.orelse:
            self.visit(s)
        self._emit(self._label_instr(l_end))

    def visit_While(self, node: ast.While) -> None:
        l_cond = self._new_label()
        l_body = self._new_label()
        l_end  = self._new_label()

        self._emit(self._label_instr(l_cond))
        cond = self.visit(node.test)
        self._emit(Instruction(
            op=OpType.BRANCH, src1=cond,
            true_label=l_body, false_label=l_end,
            line_no=node.lineno
        ))
        self._emit(self._label_instr(l_body))
        for s in node.body:
            self.visit(s)
        self._emit(Instruction(op=OpType.JUMP, label=l_cond))
        self._emit(self._label_instr(l_end))

    def visit_For(self, node: ast.For) -> None:
        """for var in iterable  → while-loop simplificado."""
        iterable = self.visit(node.iter)
        l_cond   = self._new_label()
        l_body   = self._new_label()
        l_end    = self._new_label()

        # Obtenemos variable de iteración
        iter_var = node.target.id if isinstance(node.target, ast.Name) else self._new_temp()
        t_iter = self._new_temp()
        self._emit(Instruction(op=OpType.CALL, dest=t_iter, func_name="iter",
                               args=[iterable]))
        self._emit(self._label_instr(l_cond))
        t_next = self._new_temp()
        self._emit(Instruction(op=OpType.CALL, dest=t_next, func_name="next",
                               args=[t_iter]))
        self._emit(Instruction(op=OpType.ASSIGN, dest=iter_var, src1=t_next))
        self._emit(Instruction(op=OpType.BRANCH, src1=t_next,
                               true_label=l_body, false_label=l_end))
        self._emit(self._label_instr(l_body))
        for s in node.body:
            self.visit(s)
        self._emit(Instruction(op=OpType.JUMP, label=l_cond))
        self._emit(self._label_instr(l_end))

    def visit_Pass(self, node: ast.Pass) -> None:
        self._emit(Instruction(op=OpType.NOP, line_no=node.lineno))

    def generic_visit(self, node: ast.AST):
        """Visita hijos de nodos no manejados explícitamente."""
        for child in ast.iter_child_nodes(node):
            self.visit(child)


# ════════════════════════════════════════════════════════════════════════════
#  CFG Builder: IR → BasicBlocks → CFG
# ════════════════════════════════════════════════════════════════════════════

class CFGBuilder:
    """
    Construye el Grafo de Flujo de Control (CFG) a partir de
    la lista de instrucciones TAC generada por ASTToIR.
    """

    def build(self, instrs: List[Instruction], func_name: str = "main") -> CFG:
        blocks        = self._partition_into_blocks(instrs)
        label_to_block = {
            instr.label: blk
            for blk in blocks
            for instr in blk.instructions
            if instr.op == OpType.LABEL
        }
        self._connect_edges(blocks, label_to_block)

        entry = blocks[0] if blocks else BasicBlock("entry")
        exit_ = BasicBlock("exit")
        blocks.append(exit_)

        # Bloques que caen al exit: los que no tienen sucesor explícito
        for blk in blocks[:-1]:
            if not blk.successors and blk is not exit_:
                blk.successors.append(exit_)
                exit_.predecessors.append(blk)

        cfg = CFG(func_name=func_name, entry=entry, exit=exit_, blocks=blocks)
        return cfg

    # ── particionado en bloques básicos ──────────────────────────────────────

    def _partition_into_blocks(
            self, instrs: List[Instruction]) -> List[BasicBlock]:
        """
        Regla: un nuevo bloque comienza en:
          1. La primera instrucción.
          2. Cualquier LABEL.
          3. La instrucción que sigue a un BRANCH, JUMP o RETURN.
        """
        leaders: set[int] = {0}
        for i, instr in enumerate(instrs):
            if instr.op in (OpType.BRANCH, OpType.JUMP, OpType.RETURN):
                if i + 1 < len(instrs):
                    leaders.add(i + 1)
            if instr.op == OpType.LABEL:
                leaders.add(i)

        leaders_sorted = sorted(leaders)
        blocks: List[BasicBlock] = []
        for idx, start in enumerate(leaders_sorted):
            end = leaders_sorted[idx + 1] if idx + 1 < len(leaders_sorted) \
                  else len(instrs)
            blk = BasicBlock(bid=f"B{idx+1}",
                             instructions=instrs[start:end])
            blocks.append(blk)

        return blocks if blocks else [BasicBlock(bid="B1")]

    # ── conexión de aristas ───────────────────────────────────────────────────

    def _connect_edges(
            self,
            blocks: List[BasicBlock],
            label_to_block: Dict[str, BasicBlock]) -> None:

        for i, blk in enumerate(blocks):
            if not blk.instructions:
                continue
            last = blk.instructions[-1]
            next_blk = blocks[i + 1] if i + 1 < len(blocks) else None

            if last.op == OpType.JUMP:
                target = label_to_block.get(last.label)
                if target:
                    self._add_edge(blk, target)

            elif last.op == OpType.BRANCH:
                for lbl in (last.true_label, last.false_label):
                    target = label_to_block.get(lbl)
                    if target:
                        self._add_edge(blk, target)

            elif last.op == OpType.RETURN:
                pass  # sin sucesor dentro del CFG

            else:
                if next_blk:
                    self._add_edge(blk, next_blk)

    @staticmethod
    def _add_edge(src: BasicBlock, dst: BasicBlock) -> None:
        if dst not in src.successors:
            src.successors.append(dst)
        if src not in dst.predecessors:
            dst.predecessors.append(src)


# ════════════════════════════════════════════════════════════════════════════
#  Función de conveniencia
# ════════════════════════════════════════════════════════════════════════════

def build_cfg_from_source(source: str, func_name: str = "programa") -> Tuple[List[Instruction], CFG]:
    """
    Pipeline completo: código fuente Python → CFG.
    Retorna (instrucciones_TAC, cfg).
    """
    translator = ASTToIR()
    instrs     = translator.translate(source)
    cfg        = CFGBuilder().build(instrs, func_name=func_name)
    return instrs, cfg
