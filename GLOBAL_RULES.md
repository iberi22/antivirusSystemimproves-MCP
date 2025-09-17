# GLOBAL_RULES.md — Reglas Globales para IA IDEs

## 🔄 Conciencia del Proyecto
- Lee `PLANNING.md` al inicio de cada sesión para entender arquitectura, objetivos y restricciones.
- Revisa `TASK.md` antes de empezar una tarea. Si no está listada, añádela con fecha y breve descripción.
- Respeta la estructura de módulos y convenciones definidas en `PLANNING.md`.

## 🧱 Estructura y Modularidad
- Evita archivos > 500 líneas. Divide en módulos por responsabilidad.
- Importaciones claras y consistentes (preferir relativas dentro del paquete).

## 🧪 Testing y Confiabilidad
- Crea pruebas con `pytest` para cada nueva función/módulo.
- Tras refactors, actualiza pruebas afectadas.
- Las pruebas viven en `tests/` espejando la estructura del paquete, e incluyen:
  - 1 caso esperado (happy path)
  - 1 caso borde
  - 1 caso de fallo

## ✅ Finalización de Tareas
- Marca tareas como completadas en `TASK.md` al terminar.
- Añade subtareas o TODOs encontrados en “Tareas Descubiertas Durante el Desarrollo”.

## 📎 Estilo y Convenciones
- Lenguaje: Python. PEP8 + type hints. Formato con `black` (o equivalente).
- Usa `pydantic` para validación donde aplique.
- Docstrings estilo Google.

## 📚 Documentación
- Actualiza `README.md` cuando cambie el setup o se agreguen features.
- Comenta el porqué detrás de decisiones no obvias.

## 🧠 Reglas de Comportamiento de IA
- No asumas contexto faltante; pregunta si es necesario.
- No alucines librerías/funciones. Solo paquetes verificados.
- Confirma rutas y nombres de módulos antes de referenciarlos.
- No borres código existente salvo instrucción explícita o tarea en `TASK.md`.
