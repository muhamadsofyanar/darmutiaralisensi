import json
import sqlite3

from lisensi import activate


def response(start_response, status, data):
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    start_response(status, [
        ("Content-Type", "application/json"), ("Content-Length", str(len(payload))),
        ("Cache-Control", "no-store"),
    ])
    return [payload]


def application(environ, start_response):
    path = environ["PATH_INFO"]
    method = environ["REQUEST_METHOD"]
    if path == "/health" and method == "GET":
        return response(start_response, "200 OK", {"status": "ok"})
    if path != "/v1/activate":
        return response(start_response, "404 Not Found", {"error": "not_found"})
    if method != "POST":
        return response(start_response, "405 Method Not Allowed", {"error": "method_not_allowed"})
    if environ.get("CONTENT_TYPE", "").split(";")[0].strip().lower() != "application/json":
        return response(start_response, "415 Unsupported Media Type", {"error": "use_application_json"})
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
        if not 1 <= length <= 4096:
            raise ValueError("Invalid body length.")
        data = json.loads(environ["wsgi.input"].read(length))
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object.")
        result = activate(data.get("license_key"), data.get("domain"))
    except (ValueError, RecursionError):
        return response(start_response, "400 Bad Request", {"error": "invalid_request"})
    except (sqlite3.Error, RuntimeError):
        return response(start_response, "503 Service Unavailable", {"error": "issuer_unavailable"})
    if result is None:
        return response(start_response, "403 Forbidden", {"error": "license_denied"})
    return response(start_response, "200 OK", result)
