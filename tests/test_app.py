## @file test_app.py
#  @brief Pruebas unitarias y de seguridad de la aplicación SecureDev.
#  @details En la fase 1 (código vulnerable) las pruebas de seguridad FALLAN a
#  propósito: así el pipeline evidencia las vulnerabilidades. En la fase 2
#  (código corregido) todas deben pasar.

import pytest

from app import app

XSS = "<script>alert(1)</script>"


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


## La página de inicio responde 200.
def test_index_ok(client):
    assert client.get("/").status_code == 200


## Un nombre normal se saluda correctamente.
def test_hello_nombre_normal(client):
    r = client.get("/hello?name=Bastian")
    assert r.status_code == 200
    assert "Bastian" in r.get_data(as_text=True)


## SEGURIDAD: un payload XSS no debe devolverse sin escapar.
def test_hello_no_refleja_xss(client):
    r = client.get("/hello", query_string={"name": XSS})
    assert "<script>" not in r.get_data(as_text=True)


## SEGURIDAD: la respuesta debe incluir cabeceras de seguridad.
def test_cabeceras_de_seguridad(client):
    r = client.get("/")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert "Content-Security-Policy" in r.headers
    assert r.headers.get("X-Frame-Options") == "DENY"


## El endpoint de métricas para Prometheus está disponible.
def test_metrics_disponible(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "app_http_requests_total" in r.get_data(as_text=True)
