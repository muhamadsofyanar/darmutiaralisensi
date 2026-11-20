import base64
from datetime import datetime, timezone
from html import escape
import hashlib
import hmac
import os
from urllib.parse import parse_qs

from activation import Activation, IssuerUnavailable, LicenseDenied


STYLE = """*{box-sizing:border-box}body{margin:0;background:#f4f2e9;color:#17352d;font:1rem/1.55 system-ui}
main{max-width:680px;margin:8vh auto;padding:1rem}section{padding:clamp(1rem,5vw,2rem);background:#fffdf6;
border:1px solid #d9e0d6;border-radius:18px}header{padding-bottom:1rem}strong{color:#1b593d}
h1{line-height:1.2;margin:.3rem 0}label{display:block;margin-top:1rem;font-weight:600}
input,button{font:inherit;width:100%;padding:.75rem;border-radius:8px}input{border:1px solid #7b8e82;margin:.3rem 0 1rem}
button{background:#174d38;color:white;border:0;cursor:pointer}[role=alert]{color:#8c3827}"""


def create_app(config, opener=None):
    username = config.get("ADMIN_USER", "admin")
    password = config["ADMIN_PASSWORD"]
    if len(password) < 16:
        raise ValueError("ADMIN_PASSWORD harus memiliki setidaknya 16 karakter.")
    credentials = f"{username}:{password}".encode()
    csrf = hmac.new(credentials, b"darmutiara:license-activation-form:v1", hashlib.sha256).hexdigest()
    activation = Activation(config.get("LICENSE_STATE", "/data/activation.sqlite3"),
                            config["APP_DOMAIN"], config["ISSUER_URL"], config["ISSUER_PUBLIC_KEY"], opener)

    def app(environ, start):
        def send(status, body, headers=()):
            body = body.encode("utf-8")
            start(status, [
                ("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
                ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"),
                *headers,
            ])
            return [body]

        path = environ["PATH_INFO"]
        method = environ["REQUEST_METHOD"]
        if path == "/health" and method == "GET":
            return send("200 OK", "ok")
        auth = environ.get("HTTP_AUTHORIZATION", "")
        try:
            scheme, data = auth.split(" ", 1)
            authorized = scheme.lower() == "basic" and hmac.compare_digest(
                base64.b64decode(data, validate=True), credentials
            )
        except ValueError:
            authorized = False
        if not authorized:
            return send("401 Unauthorized", "Masuk sebagai pengurus.",
                        [("WWW-Authenticate", 'Basic realm="Darmutiara", charset="UTF-8"')])
        if path not in ("/", "/aktivasi"):
            return send("404 Not Found", "Halaman tidak ditemukan.")
        error = ""
        if path == "/aktivasi" and method == "POST":
            try:
                length = int(environ.get("CONTENT_LENGTH") or "0")
                content_type = environ.get("CONTENT_TYPE", "").split(";")[0].strip().lower()
                if not 1 <= length <= 2048 or content_type != "application/x-www-form-urlencoded":
                    return send("400 Bad Request", "Form tidak valid.")
                data = parse_qs(environ["wsgi.input"].read(length).decode("utf-8"), max_num_fields=4)
                if not hmac.compare_digest(data.get("csrf", [""])[0].encode(), csrf.encode()):
                    return send("403 Forbidden", "Muat ulang halaman aktivasi.")
                activation.activate(data.get("license_key", [""])[0].strip())
                return send("303 See Other", "", [("Location", "/")])
            except ValueError:
                return send("400 Bad Request", "Form tidak valid.")
            except LicenseDenied:
                error = "Lisensi ditolak. Periksa kunci, domain, dan masa berlakunya."
            except IssuerUnavailable:
                error = "Server lisensi belum bisa diverifikasi. Coba lagi nanti."
        elif method != "GET":
            return send("405 Method Not Allowed", "Metode tidak tersedia.")

        state, claims = activation.status()
        labels = {
            "active": "Aktif", "denied": "Lisensi ditolak oleh penerbit",
            "expired": "Bukti aktivasi kedaluwarsa", "unactivated": "Belum diaktifkan",
        }
        detail = ""
        if claims:
            expires = datetime.fromtimestamp(claims["exp"], timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
            detail = f"<p>Bukti aktivasi berlaku sampai {escape(expires)}.</p>"
        alert = f'<p role="alert">{escape(error)}</p>' if error else ""
        return send("200 OK", f"""<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aktivasi Darmutiara</title><style>{STYLE}</style></head>
<body><main><header><strong>Darmutiara</strong><h1>Aktivasi lisensi</h1>
<p>Domain instalasi <b>{escape(activation.domain)}</b></p></header>
<section><p>Status <strong>{labels[state]}</strong></p>{detail}{alert}
<form method="post" action="/aktivasi">
<input type="hidden" name="csrf" value="{csrf}">
<label for="key">Kunci lisensi Darmutiara</label>
<input id="key" name="license_key" type="password" maxlength="47" autocomplete="off" required>
<button type="submit">Aktifkan</button></form></section></main></body></html>""")
    return app


def from_env():
    os.umask(0o077)
    return create_app(os.environ)
