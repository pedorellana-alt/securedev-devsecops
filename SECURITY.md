# Política de gestión de dependencias y parcheo - SecureDev

## 1. Reglas de gestión de dependencias
- Todas las dependencias se declaran en `Pipfile` y se fijan en `Pipfile.lock` (versiones exactas + hashes).
- `requirements.txt` se genera automáticamente desde el lock en cada build (`pipenv requirements`), nunca a mano.
- Solo se usan paquetes desde el índice oficial PyPI (`verify_ssl = true`).
- La imagen base del contenedor usa una versión fija (`python:3.12-slim`) y se revisa semanalmente.

## 2. Detección de vulnerabilidades
| Control | Herramienta | Cuándo |
|---|---|---|
| CVE en dependencias | `pip-audit` (etapa *Dependency Management*) | Cada build |
| Dependencias desactualizadas | `pip list --outdated` | Cada build |
| Código inseguro (SAST) | `bandit` | Cada build |
| Pruebas dinámicas (DAST) | OWASP ZAP | Cada build, sobre la app desplegada |
| Actualizaciones automáticas | GitHub Dependabot (`.github/dependabot.yml`) | Semanal |

## 3. Plazos de parcheo según riesgo
| Severidad (CVSS) | Plazo máximo para parchear |
|---|---|
| Crítica (9.0–10) | 24–72 horas |
| Alta (7.0–8.9) | 7 días |
| Media (4.0–6.9) | 30 días |
| Baja (< 4.0) | Próximo ciclo de mantenimiento |

## 4. Procedimiento de parcheo
1. El pipeline o Dependabot detecta la vulnerabilidad (build en estado **UNSTABLE**).
2. Se revisa el reporte (`reports/pip-audit.md`) y se identifica la versión corregida (*Fix Versions*).
3. Se actualiza la versión en `Pipfile` y se ejecuta `pipenv lock`.
4. Se ejecutan las pruebas (`pytest`) para verificar que nada se rompió.
5. Se hace commit con mensaje `fix(deps): actualiza <paquete> a <versión> (CVE-XXXX-XXXX)`.
6. El pipeline vuelve a correr; el build debe quedar sin hallazgos en pip-audit.
7. El reporte de trazabilidad del build (`reports/trazabilidad.md`) queda como evidencia para auditoría.
