## @file app.py
#  @brief Aplicación Flask de SecureDev - VERSIÓN VULNERABLE (fase 1).
#  @details Basada en el "Código No Seguro" de la guía 3.2.2. Solo se agregó
#  instrumentación para monitoreo (métricas Prometheus) y una página de inicio
#  con un enlace, SIN corregir las vulnerabilidades originales:
#   - XSS reflejado en /hello (el parámetro "name" se devuelve sin escapar).
#   - Modo debug de Flask activado (expone el depurador interactivo de Werkzeug).
#   - Dependencias desactualizadas con CVE conocidos (ver Pipfile).

import re
import time
from urllib.parse import unquote_plus

from flask import Flask, request, g
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Métricas de monitorización (Prometheus / Grafana)
# ---------------------------------------------------------------------------

## Total de peticiones HTTP por método, endpoint y código de respuesta.
REQUESTS = Counter("app_http_requests", "Total de peticiones HTTP",
                   ["method", "endpoint", "status"])

## Peticiones que contienen patrones de ataque conocidos, por tipo.
SUSPICIOUS = Counter("app_suspicious_requests",
                     "Peticiones con patrones de ataque", ["tipo"])

## Latencia de respuesta por endpoint.
LATENCY = Histogram("app_request_latency_seconds",
                    "Latencia de respuesta en segundos", ["endpoint"])

## Patrones simples para detectar intentos de ataque en la URL.
PATRONES_ATAQUE = {
    "xss": re.compile(r"(<\s*script|onerror\s*=|onload\s*=|javascript:|<\s*img|<\s*svg|alert\s*\()", re.I),
    "sqli": re.compile(r"('\s*(or|and)\s)|(union\s+select)|(--)|(;\s*drop\s)", re.I),
    "path_traversal": re.compile(r"(\.\./)|(\.\.\\)", re.I),
}


## Devuelve la lista de tipos de ataque detectados en un texto.
#  @param texto Ruta y query string de la petición (decodificada).
#  @return Lista de tipos detectados (xss, sqli, path_traversal).
def detectar_ataque(texto):
    return [tipo for tipo, patron in PATRONES_ATAQUE.items() if patron.search(texto)]


## Registra el inicio de la petición y detecta patrones de ataque.
@app.before_request
def antes_de_peticion():
    g.inicio = time.perf_counter()
    texto = unquote_plus(request.full_path)
    for tipo in detectar_ataque(texto):
        SUSPICIOUS.labels(tipo=tipo).inc()
        app.logger.warning("Posible ataque %s desde %s: %s", tipo, request.remote_addr, texto)


## Registra la métrica de la petición ya respondida.
@app.after_request
def despues_de_peticion(resp):
    endpoint = request.url_rule.rule if request.url_rule else "no_encontrado"
    if endpoint != "/metrics":
        REQUESTS.labels(request.method, endpoint, str(resp.status_code)).inc()
        LATENCY.labels(endpoint).observe(time.perf_counter() - g.get("inicio", time.perf_counter()))
    return resp


# ---------------------------------------------------------------------------
# Rutas
# ---------------------------------------------------------------------------

## Página de inicio con enlace a /hello (permite que OWASP ZAP la descubra).
@app.route("/")
def index():
    return '<h1>SecureDev</h1><p><a href="/hello?name=Invitado">Saludar</a></p>'


## Saluda al usuario. VULNERABLE: XSS reflejado (no escapa "name").
@app.route('/hello')
def hello():
    name = request.args.get('name')
    return f"Hello, {name}!"


## Expone las métricas para Prometheus.
@app.route("/metrics")
def metrics():
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}


if __name__ == '__main__':
    # VULNERABLE: debug=True expone el depurador de Werkzeug.
    app.run(host="0.0.0.0", port=5000, debug=True)
