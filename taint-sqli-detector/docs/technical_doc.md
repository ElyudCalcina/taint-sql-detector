# Documentación Técnica — taint-sqli-detector

## Sistema de Detección Proactiva de Inyección SQL mediante Análisis de Taint  
**Curso de Compiladores — UNSA 2024**  
**Autores:** Job L. Quispe · Elyud E. Chayña

---

## 1. Visión General

`taint-sqli-detector` es una herramienta de análisis estático que detecta vulnerabilidades de **inyección SQL (CWE-89)** integrándose en la fase de optimización del compilador. El análisis se realiza sobre la **Representación Intermedia (IR)** del programa antes de generar el ejecutable final, implementando la filosofía *Shift Left Security*.

### Pipeline de Análisis

```
Código Fuente Python
        │
        ▼  Fase 1: Análisis léxico + sintáctico
   ast.parse()  (módulo estándar de Python)
        │
        ▼  Fase 2: Generación de IR
   ASTToIR  →  Lista de instrucciones TAC
        │
        ▼  Fase 3: Construcción del CFG
   CFGBuilder  →  BasicBlocks + aristas
        │
        ▼  Fase 4: Taint Analysis (optimización del compilador)
   TaintEngine  →  Propagación de manchas (worklist)
        │
        ▼  Fase 5: Reporte
   Reporter  →  Consola / JSON
```

---

## 2. Estructura del Proyecto

```
taint-sqli-detector/
├── main.py                  # Punto de entrada CLI
├── analyzer/
│   ├── __init__.py
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
- `BRANCH ... L1 L2` → dos aristas: a `L1` y a `L2`
- `RETURN` → sin sucesor (cae al nodo exit)
- Cualquier otro final → arista al bloque siguiente (fall-through)

---

## 5. Módulo `taint_engine.py` — Análisis de Taint

### 5.1 Marco Teórico: Análisis de Flujo de Datos

El análisis de taint es un **análisis de flujo de datos hacia adelante** sobre el CFG.

**Dominio:** conjuntos de variables contaminadas (tainted).  
**Dirección:** forward (de predecesores a sucesores).  
**Función de combinación:** unión (∪) — análisis *may* (puede contaminar).

```
Ecuaciones de flujo de datos:
    IN[B]  = ⋃  OUT[P]    para todo predecesor P de B
    OUT[B] = transfer(IN[B], instrucciones de B)
```

**Función de transferencia por instrucción:**

| Instrucción             | Efecto sobre taint                              |
|-------------------------|-------------------------------------------------|
| `CONST`                 | `kill(dest)` — constante nunca es tainted       |
| `ASSIGN dest = src`     | `gen(dest)` si src ∈ tainted; else `kill(dest)` |
| `BINOP dest = a op b`   | `gen(dest)` si a ∈ tainted ∨ b ∈ tainted        |
| `LOAD dest = obj.attr`  | `gen(dest)` si obj ∈ tainted ∨ attr es source   |
| `CALL` (source)         | `gen(dest)` — resultado siempre contaminado     |
| `CALL` (sanitizer)      | `kill(dest)` — resultado limpio                 |
| `CALL` (sink)           | reportar vulnerabilidad si argumento ∈ tainted  |
| `CALL` (general)        | `gen(dest)` si algún arg ∈ tainted              |
| `PARAM`                 | `gen(dest)` si `--taint-params` activado        |

### 5.2 Algoritmo Worklist

```python
def _run_worklist(self):
    # 1. Inicializar: todos los conjuntos vacíos
    for blk in cfg.all_blocks():
        blk.taint_in = set()
        blk.taint_out = set()

    # 2. Poner todos los bloques en la worklist
    worklist = deque(cfg.all_blocks())

    # 3. Iterar hasta punto fijo
    while worklist:
        blk = worklist.popleft()

        # IN[B] = ⋃ OUT[P]
        new_in = set().union(*(p.taint_out for p in blk.predecessors))
        blk.taint_in = new_in

        # OUT[B] = transfer(IN[B])
        new_out = transfer_block(blk, new_in)

        # Si OUT cambió → re-encolar sucesores
        if new_out != blk.taint_out:
            blk.taint_out = new_out
            worklist.extend(blk.successors)
```

**Complejidad:**  
- Espacio: O(|B| × |V|) donde |B| = bloques, |V| = variables  
- Tiempo: O(|B|² × |V|) en el peor caso (convergencia en pocos ciclos para análisis de taint típicos)

### 5.3 Detección de Sources

**Sources** reconocidas (función `_is_source`):

```python
SOURCE_NAMES = {
    "input",
    "request.args.get", "request.form.get", "request.values.get",
    "request.cookies.get", "request.headers.get",
    "request.GET.get", "request.POST.get",
    "args", "form", "GET", "POST", "json", "body", "cookies",
    "sys.argv", "os.environ.get", ...
}
```

La detección verifica tanto el nombre completo como el segmento final:
```python
func in SOURCE_NAMES  OR  func.split(".")[-1] in SOURCE_NAMES
```

### 5.4 Detección de Sinks

**Sinks** reconocidos: `execute`, `executemany`, `raw`, `query`, `db_query`, `text`, ...

**Detección de consultas parametrizadas** (heurística de seguridad):
```python
def _is_parametrized(instr, tainted):
    # Seguro si: args[0] es constante (query template) y hay args[1] (parámetros)
    return len(instr.args) >= 2 and instr.args[0] not in tainted
```

### 5.5 Sanitizadores

Funciones que eliminan la contaminación de sus argumentos:
- `int()`, `float()` — validación numérica
- `escape_string()`, `quote()` — escape de caracteres SQL
- `sanitize()`, `clean()`, `validate()` — limpiezas genéricas

---

## 6. Módulo `sources_sinks.py` — Catálogo

Define las especificaciones de seguridad del análisis:

```python
@dataclass(frozen=True)
class SourceSpec:
    module:      Optional[str]   # módulo de origen
    attr_path:   str             # "request.form.get"
    description: str

@dataclass(frozen=True)
class SinkSpec:
    module:       Optional[str]
    attr_path:    str
    tainted_args: Tuple[int, ...]  # índices de args peligrosos
    description:  str

@dataclass(frozen=True)
class SanitizerSpec:
    module:    Optional[str]
    attr_path: str
    description: str
```

---

## 7. Módulo `reporter.py` — Reporte de Vulnerabilidades

### 7.1 Salida en Consola

Genera un reporte coloreado (ANSI) con:
- Tipo y severidad (HIGH / MEDIUM)
- Número de línea exacto
- Nombre del sink comprometido
- Variables contaminadas involucradas
- Bloque básico del CFG donde se detectó
- Extracto del código fuente
- CWE aplicable

### 7.2 Salida JSON (flag `--json`)

```json
{
  "file": "vulnerable_login.py",
  "total": 2,
  "vulnerabilities": [
    {
      "type": "SQL_INJECTION",
      "severity": "HIGH",
      "line": 32,
      "sink": "cursor.execute",
      "tainted_args": ["query"],
      "block": "B2",
      "description": "...",
      "cwe": "CWE-89"
    }
  ]
}
```

---

## 8. Uso de la Herramienta

### 8.1 Línea de comandos

```bash
# Análisis básico
python3 main.py <archivo.py>

# Mostrar IR (Representación Intermedia)
python3 main.py <archivo.py> --ir

# Mostrar CFG
python3 main.py <archivo.py> --cfg

# Salida JSON (para integración CI/CD)
python3 main.py <archivo.py> --json

# Tratar parámetros de función como tainted
python3 main.py <archivo.py> --taint-params

# Combinaciones
python3 main.py <archivo.py> --ir --cfg
```

### 8.2 Código de salida

| Código | Significado                                   |
|--------|-----------------------------------------------|
| `0`    | Sin vulnerabilidades — build continúa         |
| `1`    | Vulnerabilidades detectadas — build abortado  |

### 8.3 Integración en pipeline CI/CD

```yaml
# .github/workflows/security.yml
- name: Taint Analysis — SQLi Detection
  run: |
    python3 taint-sqli-detector/main.py src/app.py --json
  # El step falla automáticamente si hay vulnerabilidades (exit code 1)
```

---

## 9. Casos de Prueba

### 9.1 Casos positivos (vulnerabilidades detectadas)

| Test                              | Descripción                                       | Resultado |
|-----------------------------------|---------------------------------------------------|-----------|
| `test_direct_input_to_execute`    | `input()` concatenado en `execute()`              | DETECTADO |
| `test_fstring_in_execute`         | F-string con `request.args.get` en `execute()`   | DETECTADO |
| `test_taint_through_multiple_assignments` | Cadena de 4 asignaciones desde source  | DETECTADO |
| `test_taint_via_function_param`   | Parámetro de función → sink (modo `--taint-params`) | DETECTADO |
| `test_taint_in_conditional_branch`| Taint en rama `if` llega al sink                 | DETECTADO |

### 9.2 Casos negativos (sin falsos positivos)

| Test                            | Descripción                            | Resultado      |
|---------------------------------|----------------------------------------|----------------|
| `test_parametrized_query`       | Consulta con placeholder `?`           | NO REPORTADO ✓ |
| `test_int_sanitizer`            | `int()` elimina la contaminación       | NO REPORTADO ✓ |
| `test_constant_query_no_taint`  | Consulta solo con constantes           | NO REPORTADO ✓ |
| `test_unrelated_function_calls` | `len()`, `str()`, `print()` genéricos  | NO REPORTADO ✓ |

---

## 10. Limitaciones y Trabajo Futuro

| Limitación                         | Impacto                                | Mitigación propuesta              |
|------------------------------------|----------------------------------------|-----------------------------------|
| Análisis intra-procedural          | No rastrea taint entre funciones       | Extender a análisis inter-proc.  |
| Heurística de parametrización      | Puede haber falsos negativos en casos borde | Análisis de tipos de args    |
| Solo Python                        | No aplica a Java, PHP, C#             | IR agnóstico de lenguaje          |
| Alias no totalmente rastreados     | Variables que son alias de fuentes     | Análisis de puntos (points-to)   |
| Sin análisis de sanitizadores custom | Sanitizadores no catalogados se ignoran | Configuración de whitelist      |

---

## 11. Ejecución de Tests

```bash
cd taint-sqli-detector
python3 -m pytest tests/ -v

# Resultado esperado:
# 11 passed in 0.04s
```
