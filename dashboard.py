import base64
from datetime import datetime, timedelta, timezone
from html import escape
import hashlib
import hmac
from http import HTTPStatus
import os
import sqlite3
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode
import uuid

from lisensi import database, issue, issue_until, manage, normalize_domain, update_license


WIB = timezone(timedelta(hours=7), "WIB")
STATUSES = {"": "Semua status", "active": "Aktif", "soon": "Segera habis",
            "expired": "Kedaluwarsa", "revoked": "Dicabut"}
PAGE_SIZE = 30
STYLE = """
:root{font:16px system-ui,sans-serif;color:#15332b;background:#f4f5ee;color-scheme:light}
*{box-sizing:border-box}body{margin:0}a{color:#17614d}a:hover{text-decoration:none}
header{background:#123b31;color:#fff;padding:1.1rem max(1.2rem,calc((100% - 70rem)/2))}
header a{color:inherit;text-decoration:none;font-weight:700}main{max-width:72rem;margin:auto;padding:2rem 1rem 4rem}
h1{font-size:clamp(1.7rem,4vw,2.45rem);letter-spacing:-.04em;margin:0 0 .4rem}
h2{font-size:1.12rem;margin:0 0 .85rem}p{line-height:1.55;margin:.45rem 0 .9rem}
small,.muted{color:#50665b}.top,.filters,.buttons,.pagination{display:flex;gap:.7rem;flex-wrap:wrap;align-items:end}
.top{justify-content:space-between;align-items:center;margin-bottom:1.4rem}.panel{background:#fff;border:1px solid #dce4da;padding:1.2rem;border-radius:1rem;margin-top:1rem}
.editor{max-width:42rem}.table{overflow:auto}table{width:100%;border-collapse:collapse;text-align:left}
th,td{padding:.8rem;white-space:nowrap;border-bottom:1px solid #e3e9e0}th{font-size:.84rem;color:#496055}
label{display:grid;gap:.35rem;font-weight:600}input,select,button,.button{font:inherit;border-radius:.5rem;padding:.64rem .75rem}
input,select{border:1px solid #9bad9e;background:#fff;color:inherit;max-width:100%;min-width:0}
.filters form,.editor form{display:grid;gap:.85rem}.filters label:first-child{flex:1;min-width:14rem}
button,.button{display:inline-block;border:1px solid #15634e;background:#15634e;color:white;text-decoration:none;font-weight:650;cursor:pointer}
.secondary{background:#fff;color:#155b49}.danger{background:#9a382c;border-color:#9a382c}
.badge{display:inline-block;padding:.24rem .55rem;border-radius:.5rem;background:#e5f3e6;font-size:.85rem}
.soon{background:#fff0c7}.expired,.revoked,.error{background:#f9e5dc;color:#74291f}
.notice{padding:.7rem;border-radius:.5rem}.key{display:grid;gap:.5rem}.key input{font:1rem monospace;width:100%}
.pagination{justify-content:space-between;padding-top:1rem}input[type=checkbox]{width:1rem}
:focus-visible{outline:3px solid #ca8d25;outline-offset:2px}@media(max-width:36rem){main{padding-top:1.35rem}}
"""
SCRIPT = """
for(const button of document.querySelectorAll('[data-copy]')){
  button.addEventListener('click', async ()=>{
    const field=document.getElementById(button.dataset.copy);
    try{await navigator.clipboard.writeText(field.value);button.textContent='Tersalin'}
    catch{field.focus();field.select()}
  })
}
"""


def page(start, title, body, status=200):
    # Static dashboard CSS and clipboard script, scoped to this response.
    nonce = base64.b64encode(os.urandom(18)).decode()
    raw = f"""<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)} · Lisensi Darmutiara</title><style nonce="{nonce}">{STYLE}</style></head>
<body><header><a href="/admin/">Darmutiara / Lisensi</a></header><main>{body}</main>
<script nonce="{nonce}">{SCRIPT}</script></body></html>""".encode()
    start(f"{status} {HTTPStatus(status).phrase}", [
        ("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(raw))),
        ("Cache-Control", "no-store"), ("Referrer-Policy", "no-referrer"),
        ("X-Content-Type-Options", "nosniff"),
        ("Content-Security-Policy", f"default-src 'none'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"),
    ])
    return [raw]


def display_time(value):
    return datetime.fromtimestamp(value, WIB).strftime("%d/%m/%Y %H:%M WIB")


def status_of(row, now):
    if row["revoked_at"] is not None:
        return "revoked"
    if row["expires_at"] <= now:
        return "expired"
    return "soon" if row["expires_at"] <= now + 30 * 86400 else "active"


def status_badge(row, now):
    status = status_of(row, now)
    return f'<span class="badge {status}">{STATUSES[status]}</span>'


def dashboard(start, params, notice=""):
    query = params.get("q", [""])[0].strip()[:160]
    status = params.get("status", [""])[0]
    if status not in STATUSES:
        status = ""
    try:
        number = max(1, min(100000, int(params.get("page", ["1"])[0])))
    except ValueError:
        number = 1
    now = int(time.time())
    rows = []
    with database() as db:
        for row in db.execute("SELECT id, domain, customer, expires_at, revoked_at FROM licenses ORDER BY expires_at, id"):
            if query.casefold() not in (row["domain"] + " " + row["customer"]).casefold():
                continue
            if status and status != status_of(row, now):
                continue
            rows.append(row)
    pages = max(1, (len(rows) + PAGE_SIZE - 1) // PAGE_SIZE)
    number = min(number, pages)
    options = "".join(f'<option value="{key}"{" selected" if status == key else ""}>{label}</option>'
                      for key, label in STATUSES.items())
    table = "".join(
        f'<tr><td><a href="/admin/license?id={escape(row["id"])}">{escape(row["domain"])}</a></td>'
        f'<td>{escape(row["customer"])}</td><td>{status_badge(row, now)}</td>'
        f'<td>{display_time(row["expires_at"])}</td></tr>'
        for row in rows[(number - 1) * PAGE_SIZE:number * PAGE_SIZE]
    )
    def nav(target, label):
        href = escape(urlencode({"q": query, "status": status, "page": target}))
        return f'<a href="/admin/?{href}">{label}</a>'
    return page(start, "Dashboard", f"""
<div class="top"><div><h1>Kelola lisensi</h1><p class="muted">Atur akses instalasi berdasarkan domain.</p></div>
<div class="buttons"><a class="button secondary" href="/admin/public-key">Kunci publik</a>
<a class="button" href="/admin/new">Buat lisensi</a></div></div>{notice}
<section class="panel"><form class="filters" method="get" action="/admin/">
<label>Cari domain atau pelanggan<input name="q" value="{escape(query)}" maxlength="160" type="search"></label>
<label>Status<select name="status">{options}</select></label><button class="secondary">Tampilkan</button></form>
<p class="muted">{len(rows)} lisensi · Segera habis dalam 30 hari</p>
<div class="table"><table><thead><tr><th>Domain</th><th>Pelanggan</th><th>Status</th><th>Berakhir</th></tr></thead>
<tbody>{table or '<tr><td colspan="4">Tidak ada lisensi yang cocok.</td></tr>'}</tbody></table></div>
<div class="pagination">{nav(number - 1, 'Sebelumnya') if number > 1 else '<span></span>'}
<span>Halaman {number} / {pages}</span>{nav(number + 1, 'Berikutnya') if number < pages else '<span></span>'}</div></section>""")


def secret_field(key, label):
    return (f'<div class="key"><label>{label}<input id="copy-key" readonly value="{escape(key)}"></label>'
            '<div><button type="button" class="secondary" data-copy="copy-key">Salin</button></div></div>')


def editor(start, csrf, row=None, form=None, error=""):
    form = form or {}
    editing = row is not None
    title = "Detail lisensi" if editing else "Buat lisensi"
    domain = escape(form.get("domain", row["domain"] if editing else ""))
    customer = escape(form.get("customer", row["customer"] if editing else ""))
    expiry = escape(form.get("expiry", ""))
    id_field = f'<input type="hidden" name="id" value="{escape(row["id"])}">' if editing else ""
    csrf_field = f'<input type="hidden" name="csrf" value="{csrf}">'
    if editing:
        duration = f'<p>Berakhir <strong>{display_time(row["expires_at"])}</strong> · {status_badge(row, int(time.time()))}</p>'
        duration += f'<label>Tanggal berakhir baru (WIB)<input name="expiry" type="datetime-local" value="{expiry}"></label><small>Kosongkan untuk mempertahankan tanggal saat ini.</small>'
    else:
        duration = f"""<label>Masa berlaku<select name="days"><option value="30">30 hari</option>
<option value="90">90 hari</option><option value="365">1 tahun</option></select></label>
<label>Tanggal khusus (WIB)<input name="expiry" type="datetime-local" value="{expiry}"></label>
<small>Jika diisi, tanggal khusus dipakai.</small>"""
    error_html = f'<p class="notice error" role="alert">{escape(error)}</p>' if error else ""
    back = '<p><a href="/admin/">← Semua lisensi</a></p>'
    if editing and row["revoked_at"] is not None:
        return page(start, title, f'{back}<h1>{title}</h1><div class="panel"><h2>{domain}</h2><p>{customer}</p><p>Dicabut pada {display_time(row["revoked_at"])}.</p></div>')
    revoke = f"""<section class="panel"><h2>Cabut lisensi</h2>
<p>Bukti yang sudah diterbitkan bisa tetap berlaku sampai diperiksa ulang atau kedaluwarsa.</p>
<form method="post" action="/admin/revoke">{csrf_field}{id_field}
<div><input id="revoke" type="checkbox" name="confirm" value="yes" required>
<label for="revoke">Saya ingin mencabut lisensi untuk {escape(row["domain"])}</label></div>
<div><button class="danger">Cabut lisensi</button></div></form></section>""" if editing else ""
    confirmation = """<div><input id="move" type="checkbox" name="confirm_move" value="yes">
<label for="move">Konfirmasi jika domain berubah</label>
<small>Instalasi lama akan ditolak pada pemeriksaan berikutnya.</small></div>""" if editing else ""
    action = "license" if editing else "new"
    return page(start, title, f"""{back}<h1>{title}</h1><div class="editor">{error_html}
<section class="panel"><form method="post" action="/admin/{action}">{csrf_field}{id_field}
<label>Domain<input name="domain" required maxlength="253" placeholder="kajian.contoh.id" value="{domain}"></label>
<label>Pelanggan<input name="customer" required maxlength="160" value="{customer}"></label>
{duration}{confirmation}<div><button>{"Simpan perubahan" if editing else "Terbitkan lisensi"}</button></div></form></section>
{revoke}</div>""", 400 if error else 200)


def get_license(license_id):
    if not license_id or str(uuid.UUID(license_id)) != license_id:
        raise ValueError("ID lisensi tidak valid.")
    with database() as db:
        return db.execute("SELECT id, domain, customer, expires_at, revoked_at FROM licenses WHERE id = ?",
                          (license_id,)).fetchone()


def expiry_value(raw):
    try:
        return int(datetime.strptime(raw, "%Y-%m-%dT%H:%M").replace(tzinfo=WIB).timestamp())
    except (ValueError, OverflowError) as error:
        raise ValueError("Pilih tanggal dan jam dalam WIB.") from error


def admin(environ, start):
    password = os.environ.get("ISSUER_ADMIN_PASSWORD", "")
    user = os.environ.get("ISSUER_ADMIN_USER", "admin")
    if len(password) < 16 or not user:
        return page(start, "Dashboard belum disiapkan",
                    "<h1>Dashboard belum disiapkan</h1><p>Isi ISSUER_ADMIN_PASSWORD di konfigurasi penerbit.</p>", 503)
    expected = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    auth = environ.get("HTTP_AUTHORIZATION", "")
    if not hmac.compare_digest(auth.encode(), expected.encode()):
        start("401 Unauthorized", [("WWW-Authenticate", 'Basic realm="Darmutiara Lisensi", charset="UTF-8"'),
                                    ("Cache-Control", "no-store"), ("Content-Length", "0")])
        return [b""]
    csrf = hmac.new(password.encode(), b"darmutiara-issuer-admin-csrf-v1", hashlib.sha256).hexdigest()
    path = environ["PATH_INFO"].rstrip("/")
    method = environ["REQUEST_METHOD"]
    if method not in ("GET", "POST"):
        return page(start, "Metode gagal", "<h1>Metode tidak tersedia</h1>", 405)
    form = {}
    row = None
    try:
        if method == "GET":
            params = parse_qs(environ.get("QUERY_STRING", "")[:4096], max_num_fields=12)
            if path == "/admin":
                return dashboard(start, params)
            if path == "/admin/new":
                return editor(start, csrf)
            if path == "/admin/public-key":
                key = manage(SimpleNamespace(command="public-key"))["public_key"]
                return page(start, "Kunci publik", '<p><a href="/admin/">← Semua lisensi</a></p>'
                            '<h1>Kunci publik penerbit</h1><section class="panel editor"><p>Salin nilai ini ke pengaturan klien Darmutiara.</p>'
                            + secret_field(key, "Kunci publik Ed25519") + "</section>")
            if path == "/admin/license":
                row = get_license(params.get("id", [""])[0])
                if row is not None:
                    return editor(start, csrf, row)
        elif path in ("/admin/new", "/admin/license", "/admin/revoke"):
            length = int(environ.get("CONTENT_LENGTH") or 0)
            if not 1 <= length <= 4096 or environ.get("CONTENT_TYPE", "").split(";")[0] != "application/x-www-form-urlencoded":
                raise ValueError("Formulir tidak valid.")
            raw = environ["wsgi.input"].read(length).decode("utf-8")
            form = {key: values[0] for key, values in parse_qs(raw, max_num_fields=12).items()}
            if not hmac.compare_digest(form.get("csrf", "").encode(), csrf.encode()):
                return page(start, "Sesi formulir tidak valid", "<h1>Muat ulang halaman dan coba lagi.</h1>", 403)
            if path == "/admin/new":
                domain, customer = form.get("domain", ""), form.get("customer", "")
                date = form.get("expiry")
                result = issue_until(domain, customer, expiry_value(date)) if date else issue(domain, customer, int(form.get("days", "0")))
                return page(start, "Lisensi diterbitkan",
                            f'<h1>Lisensi diterbitkan</h1><div class="panel editor"><h2>{escape(result["domain"])}</h2>'
                            f'<p>Berakhir {display_time(datetime.fromisoformat(result["expires_at"]).timestamp())}.</p>'
                            '<p>Simpan kunci sekarang. Setelah halaman ini ditutup, kunci tidak dapat ditampilkan kembali.</p>'
                            + secret_field(result["license_key"], "Kunci lisensi DRM")
                            + '<p><a href="/admin/">Kembali ke daftar lisensi</a></p></div>', 201)
            row = get_license(form.get("id", ""))
            if row is not None:
                if path == "/admin/revoke":
                    if form.get("confirm") != "yes":
                        raise ValueError("Konfirmasikan pencabutan.")
                    manage(SimpleNamespace(command="revoke", id=row["id"]))
                else:
                    domain = normalize_domain(form.get("domain", ""))
                    if domain != row["domain"] and form.get("confirm_move") != "yes":
                        raise ValueError(f"Konfirmasikan perpindahan dari {row['domain']} ke {domain}.")
                    expiry = expiry_value(form["expiry"]) if form.get("expiry") else None
                    update_license(row["id"], domain, form.get("customer", ""), expiry, row["domain"])
                start("303 See Other", [("Location", "/admin/license?" + urlencode({"id": row["id"]})),
                                         ("Cache-Control", "no-store"), ("Content-Length", "0")])
                return [b""]
    except ValueError as error:
        if method == "POST":
            message = str(error) if type(error) is ValueError else "Periksa isian formulir."
            return editor(start, csrf, row, form, message)
        return page(start, "Permintaan tidak valid", "<h1>Alamat halaman tidak valid.</h1>", 400)
    except (sqlite3.Error, RuntimeError):
        return page(start, "Tidak tersedia", "<h1>Dashboard sementara tidak tersedia.</h1>", 503)
    return page(start, "Tidak ditemukan", '<h1>Halaman tidak ditemukan</h1><a href="/admin/">Semua lisensi</a>', 404)
