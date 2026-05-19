│   ├── ir.py                # Representación Intermedia (IR/TAC)
│   ├── cfg_builder.py       # AST → IR → CFG
│   ├── taint_engine.py      # Motor de Taint Analysis
│   ├── sources_sinks.py     # Catálogo de sources/sinks/sanitizadores
│   └── reporter.py          # Módulo de reporte
├── examples/
│   ├── vulnerable_login.py  # Caso vulnerable: login gubernamental
│   ├── vulnerable_search.py # Caso vulnerable: flujo complejo
│   └── safe_login.py        # Caso seguro: consultas parametrizadas
├── tests/
│   └── test_taint.py        # Suite de pruebas (pytest)
└── docs/
    └── technical_doc.md     # Este documento
```

---

## 3. Módulo `ir.py` — Representación Intermedia

### 3.1 Tipos de Instrucción (`OpType`)

| Tipo       | Semántica TAC                    | Ejemplo                          |
|------------|----------------------------------|----------------------------------|
| `ASSIGN`   | `dest = src`                     | `username = t7`                  |
| `BINOP`    | `dest = src1 op src2`            | `t19 = t17 + password`           |
| `CONST`    | `dest = literal`                 | `t13 = "SELECT * FROM ..."`      |
| `CALL`     | `dest = func(args...)`           | `t7 = request.form.get(t6)`      |
| `LOAD`     | `dest = obj.attr` o `obj[key]`   | `t5 = request.form`              |
| `STORE`    | `obj.attr = src`                 | `app.config = t2`                |
| `BRANCH`   | `if src1 goto L1 else L2`        | `if row goto L1 else L2`         |
| `JUMP`     | `goto label`                     | `goto L3`                        |
| `LABEL`    | `L:`                             | `L1:`                            |
| `RETURN`   | `return src`                     | `return t22`                     |
| `PARAM`    | parámetro formal de función      | `param dni`                      |
| `NOP`      | sin operación                    | `nop`                            |

### 3.2 Clase `Instruction`

```python
@dataclass
class Instruction:
    op:          OpType           # tipo de operación
    dest:        Optional[str]    # variable destino
    src1:        Optional[str]    # primer operando
    src2:        Optional[str]    # segundo operando / nombre de atributo
    args:        List[str]        # argumentos de llamada
    func_name:   Optional[str]    # nombre semántico completo (ej. "request.form.get")
    operator:    Optional[str]    # operador binario (+, -, *, /, %)
    label:       Optional[str]    # etiqueta de salto
    line_no:     int              # línea en el código fuente
```

**Métodos auxiliares:**
- `uses() → List[str]`: variables leídas por la instrucción (para análisis de vivacidad)
- `defines() → Optional[str]`: variable escrita (destino)

### 3.3 Clases `BasicBlock` y `CFG`

```
BasicBlock
├── bid: str                    # identificador único (B1, B2, ...)
├── instructions: List[Instruction]
├── successors: List[BasicBlock]  # aristas de salida en el CFG
├── predecessors: List[BasicBlock] # aristas de entrada
├── taint_in: Set[str]           # manchas al inicio del bloque
└── taint_out: Set[str]          # manchas al final del bloque

CFG
├── func_name: str
├── entry: BasicBlock
├── exit: BasicBlock
└── blocks: List[BasicBlock]
```

---

## 4. Módulo `cfg_builder.py` — Construcción del CFG

### 4.1 Clase `ASTToIR` — Traductor AST → TAC

Visita el AST de Python con el patrón *Visitor* y emite instrucciones TAC.

**Característica clave:** rastreo de nombres semánticos de atributos.

```python
self._attr_names: Dict[str, str] = {}
```

Cuando se visita `request.form`, el temporal resultado (e.g. `t5`) se registra como:
```
_attr_names["t5"] = "request.form"
```

Así, cuando se visita `request.form.get("username")`, el `func_name` generado es `"request.form.get"` (no `"t5.get"`), permitiendo la detección correcta de fuentes.

**Nodos AST manejados:**

| Nodo AST         | IR generado                                    |
|------------------|------------------------------------------------|
| `ast.Constant`   | `CONST`                                        |
| `ast.Name`       | retorna el nombre directamente                 |
| `ast.BinOp`      | `BINOP`                                        |
| `ast.JoinedStr`  | serie de `BINOP` con `+`                       |
| `ast.Attribute`  | `LOAD` + registro en `_attr_names`             |
| `ast.Subscript`  | `LOAD` con `operator="subscript"`              |
| `ast.Call`       | `CALL` con `func_name` semántico               |
| `ast.Assign`     | `ASSIGN`                                       |
| `ast.AugAssign`  | `BINOP` + `ASSIGN`                             |
| `ast.If`         | `BRANCH` + `LABEL` + `JUMP`                    |
| `ast.While`      | `LABEL` + `BRANCH` + `JUMP` (back-edge)        |
| `ast.For`        | llamadas a `iter()`/`next()` + `WHILE`         |
| `ast.Return`     | `RETURN`                                       |

### 4.2 Clase `CFGBuilder` — IR → Bloques Básicos → CFG

**Algoritmo de particionado (identificación de líderes):**

Un líder de bloque básico es:
1. La primera instrucción del programa.
2. Cualquier instrucción `LABEL`.
3. La instrucción inmediatamente siguiente a `BRANCH`, `JUMP` o `RETURN`.

```python
def _partition_into_blocks(self, instrs):
    leaders = {0}
    for i, instr in enumerate(instrs):
        if instr.op in (BRANCH, JUMP, RETURN):
            leaders.add(i + 1)
        if instr.op == LABEL:
            leaders.add(i)
    ...
```

**Conexión de aristas:**
- `JUMP L` → arista al bloque cuyas instrucciones comienzan en `L`
- `BRANCH ... L2 L2` → dos aristas: a `L1` y a `L2`
- `RETURN` → sin sucesor (cae al nodo exit)
- Cualquier otro final → arista al bloque siguiente (fall-through)

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        176,2         14%
