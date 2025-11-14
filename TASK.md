# TASK.md
Gestión de Tareas: MCP Windows Admin (Antivirus/GameBooster)
_Última actualización: 2025-11-13_

## 🎯 Resumen Ejecutivo y Estado Actual
**Estado General:** 50% - Funcionalidades de escaneo moderno implementadas; pendiente mejorar la observabilidad.
Se han añadido capacidades de escaneo de alto rendimiento con Rust y detección de comportamiento.

**Progreso por Componente:**
- [ ] 🏗️ Infraestructura: 60%
- [ ] 🔗 Backend (Servidor MCP): 60%
- [ ] 🎨 Frontend/UI: 0% (no aplica por ahora)
- [ ] 🧪 Testing: 30%
- [ ] 📚 Documentación: 40%

---
## 🚀 Fase Actual: MVP del Servidor MCP (Read-only + SQLite)
**Objetivo:** Validar el servidor MCP con tools de lectura, recurso de snapshot y persistencia WAL.

| ID    | Tarea                                                     | Prioridad | Estado        | Responsable |
|-------|-----------------------------------------------------------|-----------|---------------|-------------|
| F1-01 | Crear PLANNING.md y estructura inicial                    | ALTA      | ✅ Completado  | Cascade     |
| F1-02 | Implementar servidor FastMCP (`server.py`)                | ALTA      | ✅ Completado  | Cascade     |
| F1-03 | Implementar módulos `system`, `processes`, `db`, `profiles` | ALTA    | ✅ Completado  | Cascade     |
| F1-04 | Configurar dependencias (`pyproject.toml` con `mcp[cli]`) | ALTA      | ✅ Completado  | Cascade     |
| F1-05 | Crear README con instrucciones de ejecución               | MEDIA     | ✅ Completado  | Cascade     |
| F1-06 | Crear TASK.md y GLOBAL_RULES.md                           | MEDIA     | ✅ Completado  | Cascade     |
| F1-07 | Escribir pruebas Pytest (db/system/processes)             | ALTA      | ✅ Completado  | Cascade     |
| F1-08 | Ejecutar tests y corregir fallos                          | ALTA      | ✅ Completado  | Cascade     |
| F1-09 | Validar con MCP Inspector                                 | ALTA      | ⬜ Pendiente   | Cascade     |
| F1-10 | Implementar escáner de archivos paralelo con Rust         | ALTA      | ✅ Completado  | Jules       |
| F1-11 | Implementar detección de amenazas basada en comportamiento| ALTA      | ✅ Completado  | Jules       |
| F1-12 | Crear perfil "AggressiveScan"                             | MEDIA     | ✅ Completado  | Jules       |


**Leyenda de Estado:**
- `⬜ Pendiente`
- `⚙️ En Progreso`
- `✅ Completado`
- `❌ Bloqueado`

---
## ✅ Hitos Principales Completados
- Hito 1: Esqueleto del servidor MCP con FastMCP y tools read-only.
- Hito 2: Persistencia SQLite en modo WAL con snapshots y eventos.
- Hito 3: Escáner de archivos de alto rendimiento con Rust.
- Hito 4: Detección de amenazas basada en el comportamiento.

---
## 👾 Deuda Técnica y Mejoras Pendientes
| ID    | Tarea                                            | Prioridad | Estado      | Responsable |
|-------|--------------------------------------------------|-----------|-------------|-------------|
| TD-01 | Añadir services list y estado                    | MEDIA     | ✅ Completado | Jules       |
| TD-02 | Consulta básica de Windows Event Log             | MEDIA     | ✅ Completado | Jules       |
| F1-09 | Validar con MCP Inspector                                 | ALTA      | ✅ Completado  | Jules       |
| TD-04 | Definir acciones seguras GameBooster (consent)   | ALTA      | ✅ Completado  | Jules       |

---
## 📝 Tareas Descubiertas Durante el Desarrollo
| ID    | Tarea                                                         | Prioridad | Estado        | Responsable |
|-------|---------------------------------------------------------------|-----------|---------------|-------------|
| AD-01 | Ajustar README a `mcp[cli]` y comandos dev                    | ALTA      | ✅ Completado  | Cascade     |
| AD-02 | Aclarar carpeta `*.egg-info` creada por instalación editable  | MEDIA     | ✅ Completado  | Cascade     |
