# TASK.md
Gestión de Tareas: MCP Windows Admin (Antivirus/GameBooster)
_Última actualización: 2025-08-15_

## 🎯 Resumen Ejecutivo y Estado Actual
**Estado General:** 30% - Esqueleto del servidor MCP creado; en progreso pruebas y documentación.
Un MVP funcional con tools de solo lectura y persistencia SQLite ya está listo para validar con el Inspector MCP.

**Progreso por Componente:**
- [ ] 🏗️ Infraestructura: 40%
- [ ] 🔗 Backend (Servidor MCP): 40%
- [ ] 🎨 Frontend/UI: 0% (no aplica por ahora)
- [ ] 🧪 Testing: 10%
- [ ] 📚 Documentación: 20%

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
| F1-06 | Crear TASK.md y GLOBAL_RULES.md                           | MEDIA     | ⚙️ En Progreso | Cascade     |
| F1-07 | Escribir pruebas Pytest (db/system/processes)             | ALTA      | ⚙️ En Progreso | Cascade     |
| F1-08 | Ejecutar tests y corregir fallos                          | ALTA      | ⬜ Pendiente   | Cascade     |
| F1-09 | Validar con MCP Inspector                                 | ALTA      | ⬜ Pendiente   | Cascade     |

**Leyenda de Estado:**
- `⬜ Pendiente`
- `⚙️ En Progreso`
- `✅ Completado`
- `❌ Bloqueado`

---
## ✅ Hitos Principales Completados
- Hito 1: Esqueleto del servidor MCP con FastMCP y tools read-only.
- Hito 2: Persistencia SQLite en modo WAL con snapshots y eventos.

---
## 👾 Deuda Técnica y Mejoras Pendientes
| ID    | Tarea                                            | Prioridad | Estado      | Responsable |
|-------|--------------------------------------------------|-----------|-------------|-------------|
| TD-01 | Añadir services list y estado                    | MEDIA     | ⬜ Pendiente | Cascade     |
| TD-02 | Consulta básica de Windows Event Log             | MEDIA     | ⬜ Pendiente | Cascade     |
| TD-03 | Añadir logging a Windows Event Log               | BAJA      | ⬜ Pendiente | Cascade     |
| TD-04 | Definir acciones seguras GameBooster (consent)   | ALTA      | ⬜ Pendiente | Cascade     |

---
## 📝 Tareas Descubiertas Durante el Desarrollo
| ID    | Tarea                                                         | Prioridad | Estado        | Responsable |
|-------|---------------------------------------------------------------|-----------|---------------|-------------|
| AD-01 | Ajustar README a `mcp[cli]` y comandos dev                    | ALTA      | ✅ Completado  | Cascade     |
| AD-02 | Aclarar carpeta `*.egg-info` creada por instalación editable  | MEDIA     | ⚙️ En Progreso | Cascade     |
