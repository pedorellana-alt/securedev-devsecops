## @file app.py
#  @brief Aplicación Flask de SecureDev - VERSIÓN CORREGIDA (fase 2).
#  @details Correcciones aplicadas sobre el código vulnerable:
#   - XSS reflejado: validación de entrada (lista blanca) + escape de salida.
#   - Debug desactivado: se controla por variable de entorno y en producción
#     se usa gunicorn (servidor WSGI de producción), no el servidor de desarrollo.
#   - Cabeceras de seguridad HTTP (CSP, X-Frame-Options, nosniff, etc.).
#   - Dependencias actualizadas a versiones sin CVE conocidos (ver Pipfile).
#   - El contenedor corre con un usuario sin privilegios (ver Dockerfile).

import os
import re
import time
from urllib.parse import unquote_plus

from flask import Flask, request, g
from markupsafe import escape
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


## Lista blanca para el parámetro "name": solo letras y espacios, 1 a 50 caracteres.
NOMBRE_VALIDO = re.compile(r"^[A-Za-zÁÉÍÓÚáéíóúÑñÜü ]{1,50}$")


## Agrega cabeceras de seguridad HTTP a todas las respuestas (mitiga alertas de OWASP ZAP).
@app.after_request
def cabeceras_seguridad(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    return resp


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


## Saluda al usuario. CORREGIDO: valida la entrada y escapa la salida.
#  @return 200 con el saludo, o 400 si "name" no cumple la lista blanca.
@app.route("/hello")
def hello():
    name = request.args.get("name", "Invitado").strip()
    if not NOMBRE_VALIDO.fullmatch(name):
        app.logger.warning("Entrada rechazada en /hello desde %s", request.remote_addr)
        return "Parametro 'name' invalido", 400
    return f"Hello, {escape(name)}!"


## Expone las métricas para Prometheus.
@app.route("/metrics")
def metrics():
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}


if __name__ == "__main__":
    # CORREGIDO: debug apagado por defecto y escucha solo en localhost.
    # En el contenedor la app se sirve con gunicorn (ver Dockerfile).
    app.run(host=os.getenv("APP_HOST", "127.0.0.1"),
            port=int(os.getenv("APP_PORT", "5000")),
            debug=os.getenv("FLASK_DEBUG") == "1")
