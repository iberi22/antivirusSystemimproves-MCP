# POML Conventions for MCP Windows Admin (This Repo)

Source of truth upstream: https://github.com/microsoft/poml
This project adopts a minimal, stable subset tailored for agent workflows (Cascade, Gemini CLI) operating our MCP Windows Admin server.

We rely on the following POML elements:

- `poml`
- `task` (with `className="instruction"`) – high-level intent for the agent
- `output-format` (with `className="instruction"`) – structured expected outputs
- `cp` blocks (with captions):
  - `cp` caption="Style" captionSerialized="style"
  - `cp` caption="Include" captionSerialized="include"
  - `cp` caption="Constraints" captionSerialized="constraints"

Lists are represented with `<list>` and `<item>`. Content is plain text unless a code block is needed.

## Design goals
- Predictable prompts and outputs for cross-agent interoperability (Gemini CLI, Cascade/Windsurf).
- Stable schema to keep prompts backward compatible over time.
- Guardrails emphasize clarity, citation of tools/commands, and safety (no destructive actions by default).

## Project-wide norms
- Default language: Spanish.
- Diagnostic actions are non-destructive. Active defenses (kill/quarantine/firewall) require explicit user approval and separate workflows.
- Reference concrete tool names from our server (e.g., `processes_list`, `connections_list_enriched`, `av_scan_path`).
- Prefer reproducible CLI invocations (Inspector CLI) or SDK (official python-sdk) and persist artifacts to `artifacts/`.

## Example skeleton used here
```xml
<poml>
  <task className="instruction">Realiza diagnóstico Windows con MCP y prepara reporte HTML</task>
  <output-format className="instruction">
    <list>
      <item>Plan (pasos claros)</item>
      <item>Comandos MCP/CLI exactos</item>
      <item>Artefactos generados (JSON, HTML)</item>
      <item>Hallazgos y riesgos</item>
      <item>Acciones sugeridas y próximas tareas</item>
    </list>
  </output-format>
  <cp className="instruction" caption="Style" captionSerialized="style">
    <list>
      <item>Claro, breve, con secciones y listas</item>
      <item>Cita nombres de tools y rutas</item>
      <item>Evita jergas innecesarias</item>
    </list>
  </cp>
  <cp className="instruction" caption="Include" captionSerialized="include">
    <list>
      <item>Comandos Inspector CLI o SDK</item>
      <item>Políticas de seguridad (no destructivo por defecto)</item>
      <item>Parámetros y límites (limit, fast, include_cpu, etc.)</item>
    </list>
  </cp>
  <cp className="instruction" caption="Constraints" captionSerialized="constraints">
    <list>
      <item>Sin alucinaciones; si falta data, di "no disponible"</item>
      <item>Respeta rutas y permisos; no eleves privilegios</item>
      <item>No ejecutes acciones destructivas sin aprobación explícita</item>
    </list>
  </cp>
</poml>
```
