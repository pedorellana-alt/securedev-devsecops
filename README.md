# SecureDev App

Aplicación Flask usada en el pipeline DevSecOps (Jenkins + Docker) de la evaluación OCY1102 EV3.

## Endpoints
| Ruta | Descripción |
|---|---|
| `/` | Página de inicio |
| `/hello?name=...` | Saluda al usuario |
| `/metrics` | Métricas para Prometheus |

## Pipeline (Jenkinsfile)
Checkout → Dependency Management (pipenv + pip-audit) → Build → Test (pytest) → Analyze (Bandit)
→ Generate Documentation (Doxygen) → Deploy (Docker) → Security Test (OWASP ZAP) → Trazabilidad.

Todos los reportes quedan como artefactos del build en Jenkins (carpeta `reports/` y `docs/html/`).

## Política de seguridad
Ver [SECURITY.md](SECURITY.md).
