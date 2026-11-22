import base64
import csv
import io
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

from lisensi import access_license_key, database, issue, issue_until, manage, normalize_domain, update_license


WIB = timezone(timedelta(hours=7), "WIB")
STATUSES = {"": "Semua status", "active": "Aktif", "soon": "Segera habis",
            "expired": "Kedaluwarsa", "revoked": "Dicabut"}
PAGE_SIZE = 30
ENVIRONMENTS = {"": "Belum ditetapkan", "production": "Produksi", "test": "Uji"}
FEEDBACK = {"license": "Perubahan lisensi tersimpan.", "renew": "Masa berlaku diperpanjang.",
            "revoke": "Lisensi dicabut.", "profile": "Profil instalasi tersimpan."}
STYLE = """
:root{font:16px system-ui,sans-serif;color:#15332b;background:#f4f5ee;color-scheme:light}
*{box-sizing:border-box}body{margin:0}a{color:#17614d}a:hover{text-decoration:none}
header{background:#123b31;color:#fff;padding:1.1rem max(1.2rem,calc((100% - 70rem)/2))}
header{display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap}header nav{display:flex;gap:1.25rem}
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
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,10rem),1fr));gap:.8rem}
.metric{background:white;border:1px solid #dce4da;border-radius:.85rem;display:grid;gap:.4rem;padding:1rem;text-decoration:none}
.metric:hover,.metric.selected{border-color:#17614d;background:#edf5ef}.metric strong{font-size:1.9rem}
.panel .top h2{margin:0}.details{display:grid;grid-template-columns:minmax(8rem,1fr) 2fr;gap:.6rem;margin:0}
.details dd{margin:0;overflow-wrap:anywhere}.history{padding-left:1.25rem}.history li{margin-bottom:.7rem}
.detail-layout{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
@media(max-width:53rem){.detail-layout{grid-template-columns:1fr;gap:0}.editor{max-width:none}}
body{background:#f3f6f1}header{align-items:center;padding-inline:max(1rem,calc((100% - 76rem)/2))}
header nav{flex-wrap:wrap;gap:.65rem 1.2rem}header nav a{font-weight:550;color:#e4efe8}
main{max-width:78rem}.brand{display:flex;align-items:center;gap:.65rem}.brand span{background:#dfeecb;color:#173c31;padding:.34rem .62rem;border-radius:.45rem}
.hero{background:#193e33;color:white;border-radius:1rem;padding:clamp(1.2rem,4vw,2.2rem);margin-bottom:1rem}
.hero .muted{color:#dcece3}.hero .button{background:#e0efcf;color:#183328;border-color:#e0efcf}
.hero p{margin-bottom:0}.hero h1{overflow-wrap:anywhere}.metric{box-shadow:0 2px 4px #16382b08}
.metric.selected{box-shadow:inset 0 0 0 1px #17614d}.notice.success{background:#e4f2e2;color:#235032}
td{vertical-align:top}td small{display:block;margin-top:.25rem}.date{display:block}.checkbox{display:flex;align-items:flex-start;gap:.5rem}
.checkbox input{flex:none;margin:.25rem 0}.detail-layout{grid-template-columns:minmax(0,1.05fr) minmax(0,1fr)}
details.panel summary{cursor:pointer;font-weight:700}details.panel[open] summary{margin-bottom:.85rem}
.notes{white-space:pre-wrap}textarea{font:inherit;border:1px solid #9bad9e;border-radius:.5rem;padding:.65rem;min-height:6rem;resize:vertical;width:100%}
.skip{position:absolute;left:.5rem;top:.5rem;transform:translateY(-200%);background:white;padding:.5rem;z-index:5}.skip:focus{transform:none}
@media(max-width:53rem){.detail-layout{grid-template-columns:minmax(0,1fr)}}
@media(max-width:40rem){.filters>label{width:100%;min-width:0!important}.responsive thead{position:absolute;clip-path:inset(50%);width:1px;height:1px;overflow:hidden}.responsive,.responsive tbody,.responsive tr,.responsive td{display:block}.responsive tr{padding:.5rem 0;border-bottom:1px solid #dce4da}.responsive td{display:grid;grid-template-columns:minmax(6rem,.8fr) minmax(0,1.2fr);gap:.5rem;white-space:normal;border:0;padding:.35rem .2rem;overflow-wrap:anywhere}.responsive td[data-label]::before{content:attr(data-label);color:#50665b;font-size:.875rem}.responsive td small{grid-column:2}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}}
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
<body><a class="skip" href="#content">Lewati ke konten</a>
<header><a class="brand" href="/admin/"><span aria-hidden="true">D</span>Darmutiara Lisensi</a>
<nav aria-label="Administrasi"><a href="/admin/">Lisensi</a><a href="/admin/customers">Pelanggan</a>
<a href="/admin/installations">Instalasi</a><a href="/admin/public-key">Kunci publik</a></nav></header>
<main id="content">{body}</main>
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


def license_filters(params, now):
    query = params.get("q", [""])[0].strip()[:160]
    status = params.get("status", [""])[0]
    sort = params.get("sort", [""])[0]
    if status not in STATUSES:
        status = ""
    if sort not in SORTS:
        sort = "expiry"
    conditions = {
        "": ("1", ()),
        "active": ("revoked_at IS NULL AND expires_at > ?", (now + 30 * 86400,)),
        "soon": ("revoked_at IS NULL AND expires_at > ? AND expires_at <= ?", (now, now + 30 * 86400)),
        "expired": ("revoked_at IS NULL AND expires_at <= ?", (now,)),
        "revoked": ("revoked_at IS NOT NULL", ()),
    }
    condition, args = conditions[status]
    # instr treats percent and underscore in search text literally.
    condition += " AND instr(casefold(domain || ' ' || customer), ?) > 0"
    args = (*args, query.casefold())
    for field in ("customer", "domain"):
        exact = params.get(field, [""])[0][:253]
        if exact:
            condition += f" AND {field} = ?"
            args += (exact,)
    return query, status, sort, condition, args


SORTS = {
    "expiry": ("Berakhir terdekat", "expires_at, id"),
    "latest": ("Berakhir terjauh", "expires_at DESC, id"),
    "domain": ("Domain A–Z", "domain, expires_at, id"),
    "verified": ("Verifikasi terbaru", "last_verified_at DESC, id"),
}
LICENSE_ROWS = """
SELECT id, domain, customer, expires_at, revoked_at, last_verified_at, successful_checks,
       environment, notes, updated_at
FROM licenses LEFT JOIN license_activity ON license_activity.license_id = licenses.id
LEFT JOIN license_profiles ON license_profiles.license_id = licenses.id
"""


def dashboard(start, params):
    now = int(time.time())
    query, status, sort, condition, args = license_filters(params, now)
    try:
        number = max(1, int(params.get("page", ["1"])[0]))
    except ValueError:
        number = 1
    with database() as db:
        db.create_function("casefold", 1, str.casefold)
        db.execute("BEGIN")
        metrics = db.execute("""
            SELECT COUNT(*) AS total,
                COUNT(CASE WHEN revoked_at IS NULL AND expires_at > :soon THEN 1 END) AS active,
                COUNT(CASE WHEN revoked_at IS NULL AND expires_at > :now
                           AND expires_at <= :soon THEN 1 END) AS soon,
                COUNT(CASE WHEN revoked_at IS NULL AND expires_at <= :now THEN 1 END) AS expired,
                COUNT(revoked_at) AS revoked
            FROM licenses
        """, {"now": now, "soon": now + 30 * 86400}).fetchone()
        count = db.execute(f"SELECT COUNT(*) FROM licenses WHERE {condition}", args).fetchone()[0]
        pages = max(1, (count + PAGE_SIZE - 1) // PAGE_SIZE)
        number = min(number, pages)
        rows = db.execute(
            f"{LICENSE_ROWS} WHERE {condition} ORDER BY {SORTS[sort][1]} LIMIT ? OFFSET ?",
            (*args, PAGE_SIZE, (number - 1) * PAGE_SIZE),
        ).fetchall()
    options = "".join(f'<option value="{key}"{" selected" if status == key else ""}>{label}</option>'
                      for key, label in STATUSES.items())
    sorts = "".join(f'<option value="{key}"{" selected" if sort == key else ""}>{label}</option>'
                    for key, (label, _) in SORTS.items())

    scope = {field: params[field][0][:253] for field in ("customer", "domain") if params.get(field)}
    scope_fields = "".join(f'<input type="hidden" name="{field}" value="{escape(value)}">' for field, value in scope.items())
    scope_caption = " · ".join(escape(value) for value in scope.values())
    scope_line = f'<p>Daftar untuk <strong>{scope_caption}</strong> · <a href="/admin/">Hapus filter</a></p>' if scope else ""

    def link(path, **overrides):
        values = {"q": query, "status": status, "sort": sort} | scope
        return path + "?" + escape(urlencode(values | overrides))

    cards = "".join(
        f'<a class="metric {"selected" if status == key else ""}" href="/admin/?{escape(urlencode({"status": key, "sort": sort}))}">'
        f'<span>{label}</span><strong>{metrics[key or "total"]}</strong></a>'
        for key, label in (("", "Total lisensi"), ("active", "Aktif >30 hari"), *list(STATUSES.items())[2:])
    )
    table = "".join(
        f'<tr><td data-label="Instalasi"><a href="/admin/license?id={escape(row["id"])}">{escape(row["domain"])}</a>'
        f'<small>{ENVIRONMENTS[row["environment"] or ""]} · {escape(row["id"][:8])}</small></td>'
        f'<td data-label="Pelanggan">{escape(row["customer"])}</td>'
        f'<td data-label="Status">{status_badge(row, now)}</td>'
        f'<td data-label="Berakhir">{display_time(row["expires_at"])}</td>'
        f'<td data-label="Verifikasi">{optional_time(row["last_verified_at"])}</td></tr>'
        for row in rows
    )
    previous = f'<a href="{link("/admin/", page=number - 1)}">Sebelumnya</a>' if number > 1 else '<span></span>'
    following = f'<a href="{link("/admin/", page=number + 1)}">Berikutnya</a>' if number < pages else '<span></span>'
    return page(start, "Dasbor", f"""
<div class="top hero"><div><h1>Dasbor lisensi</h1><p class="muted">Pantau akses instalasi dan masa berlaku lisensi.</p></div>
<div class="buttons"><a class="button" href="/admin/new">Buat lisensi</a></div></div>
<div class="metrics">{cards}</div>
<section class="panel"><div class="top"><h2>Daftar lisensi</h2>
<a class="button secondary" href="{link('/admin/export.csv')}">Ekspor CSV</a></div>
<form class="filters" method="get" action="/admin/">{scope_fields}
<label>Domain atau pelanggan<input name="q" value="{escape(query)}" maxlength="160" type="search"></label>
<label>Status<select name="status">{options}</select></label>
<label>Urutkan<select name="sort">{sorts}</select></label><button class="secondary">Terapkan</button></form>
{scope_line}<p class="muted">{count} lisensi · Segera habis dalam 30 hari</p>
<div class="table"><table class="responsive"><thead><tr><th>Domain</th><th>Pelanggan</th><th>Status</th><th>Berakhir</th>
<th>Verifikasi terakhir</th></tr></thead>
<tbody>{table or '<tr><td colspan="5">Tidak ada lisensi yang cocok.</td></tr>'}</tbody></table></div>
<div class="pagination">{previous}<span>Halaman {number} / {pages}</span>{following}</div></section>""")


def directory(start, field, params):
    label = "Pelanggan" if field == "customer" else "Instalasi"
    path = "/admin/customers" if field == "customer" else "/admin/installations"
    query = params.get("q", [""])[0].strip()[:160]
    try:
        number = max(1, int(params.get("page", ["1"])[0]))
    except ValueError:
        number = 1
    with database() as db:
        db.create_function("casefold", 1, str.casefold)
        grouped = f"FROM licenses WHERE instr(casefold({field}), ?) > 0 GROUP BY {field}"
        args = (query.casefold(),)
        db.execute("BEGIN")
        count = db.execute(f"SELECT COUNT(*) FROM (SELECT 1 {grouped})", args).fetchone()[0]
        pages = max(1, (count + PAGE_SIZE - 1) // PAGE_SIZE)
        number = min(number, pages)
        rows = db.execute(f"""
            SELECT {field} AS name, COUNT(*) AS total,
                   COUNT(CASE WHEN revoked_at IS NULL AND expires_at > ? THEN 1 END) AS valid
            {grouped} ORDER BY casefold({field}), {field} LIMIT ? OFFSET ?
        """, (int(time.time()), *args, PAGE_SIZE, (number - 1) * PAGE_SIZE)).fetchall()
    table = "".join(f'<tr><td data-label="{label}"><a href="/admin/?{escape(urlencode({field: row["name"]}))}">'
                    f'{escape(row["name"])}</a></td><td data-label="Total">{row["total"]}</td>'
                    f'<td data-label="Berlaku">{row["valid"]}</td></tr>' for row in rows)
    def nav(target, text):
        return f'<a href="{path}?{escape(urlencode({"q": query, "page": target}))}">{text}</a>'
    return page(start, label, f"""
<div class="hero"><h1>{label}</h1><p class="muted">Buka {label.lower()} untuk melihat lisensinya.</p></div>
<section class="panel"><form class="filters" method="get" action="{path}">
<label>Cari {label.lower()}<input name="q" type="search" maxlength="160" value="{escape(query)}"></label>
<button class="secondary">Cari</button></form><p>{count} hasil</p>
<div class="table"><table class="responsive"><thead><tr><th>{label}</th><th>Total lisensi</th><th>Masih berlaku</th></tr></thead>
<tbody>{table or '<tr><td colspan="3">Tidak ada hasil.</td></tr>'}</tbody></table></div>
<div class="pagination">{nav(number - 1, "Sebelumnya") if number > 1 else "<span></span>"}
<span>Halaman {number} / {pages}</span>{nav(number + 1, "Berikutnya") if number < pages else "<span></span>"}</div></section>""")


def optional_time(value):
    return display_time(value) if value is not None else "Belum tercatat"


def export_csv(start, params):
    now = int(time.time())
    _, _, sort, condition, args = license_filters(params, now)
    def spreadsheet_cell(value):
        # Prevent spreadsheet formula interpretation for user-entered fields.
        return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")) else value
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(("ID", "Domain", "Pelanggan", "Status", "Berakhir", "Dicabut", "Verifikasi terakhir", "Verifikasi berhasil", "Lingkungan"))
    with database() as db:
        db.create_function("casefold", 1, str.casefold)
        for row in db.execute(f"{LICENSE_ROWS} WHERE {condition} ORDER BY {SORTS[sort][1]}", args):
            writer.writerow((row["id"], row["domain"], spreadsheet_cell(row["customer"]),
                             STATUSES[status_of(row, now)], display_time(row["expires_at"]),
                             optional_time(row["revoked_at"]), optional_time(row["last_verified_at"]),
                             row["successful_checks"] or 0, ENVIRONMENTS[row["environment"] or ""]))
    raw = output.getvalue().encode("utf-8-sig")
    start("200 OK", [("Content-Type", "text/csv; charset=utf-8"),
                     ("Content-Disposition", 'attachment; filename="darmutiara-lisensi.csv"'),
                     ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
                     ("Content-Length", str(len(raw)))])
    return [raw]


def license_summary(row):
    with database() as db:
        history = db.execute("""
            SELECT * FROM license_history WHERE license_id = ? ORDER BY event_id DESC LIMIT 50
        """, (row["id"],)).fetchall()
    events = []
    for event in history:
        changes = []
        if event["event"] == "updated":
            for field, label, render in (
                ("domain", "Domain", escape), ("customer", "Pelanggan", escape),
                ("expiry", "Masa berlaku", display_time),
            ):
                previous = event["previous_" + field]
                current = event[field]
                if previous != current:
                    changes.append(f"{label} {render(previous)} → {render(current)}")
        label = {"issued": "Lisensi diterbitkan", "updated": "Lisensi diubah", "revoked": "Lisensi dicabut"}[event["event"]]
        details = f'<br><small>{"<br>".join(changes)}</small>' if changes else ""
        events.append(f'<li><strong>{label}</strong><br><small>{display_time(event["occurred_at"])}</small>{details}</li>')
    history_html = f'<ol class="history">{"".join(events)}</ol>' if events else '<p>Belum ada perubahan yang tercatat.</p>'
    return f"""
<section class="panel"><h2>Informasi lisensi</h2>
<dl class="details"><dt>ID lisensi</dt><dd><code>{escape(row["id"])}</code></dd>
<dt>Domain</dt><dd>{escape(row["domain"])}</dd><dt>Pelanggan</dt><dd><a href="/admin/?{escape(urlencode({"customer": row["customer"]}))}">{escape(row["customer"])}</a></dd>
<dt>Lingkungan</dt><dd>{ENVIRONMENTS[row["environment"] or ""]}</dd>
<dt>Status</dt><dd>{status_badge(row, int(time.time()))}</dd>
<dt>Berakhir</dt><dd>{display_time(row["expires_at"])}</dd>
<dt>Verifikasi terakhir</dt><dd>{optional_time(row["last_verified_at"])}</dd>
<dt>Verifikasi berhasil</dt><dd>{row["successful_checks"] or 0}</dd>
<dt>Catatan internal</dt><dd class="notes">{escape(row["notes"] or "Belum ada catatan")}</dd>
<dt>Profil diperbarui</dt><dd>{optional_time(row["updated_at"])}</dd></dl></section>
<section class="panel"><h2>Riwayat perubahan</h2><p class="muted">Hingga 50 perubahan terbaru.</p>{history_html}</section>"""


def secret_field(key, label):
    return (f'<div class="key"><label>{label}<input id="copy-key" readonly value="{escape(key)}"></label>'
            '<div><button type="button" class="secondary" data-copy="copy-key">Salin</button></div></div>')


def key_controls(row, csrf_field, id_field, action):
    with database() as db:
        events = db.execute("""
            SELECT occurred_at, actor, action FROM license_key_events
            WHERE license_id = ? ORDER BY event_id DESC LIMIT 20
        """, (row["id"],)).fetchall()
    titles = {"reveal": "Kunci dibuka", "rotate": "Kunci diganti"}
    items = "".join(f'<li>{titles[event["action"]]} · {escape(event["actor"])}'
                    f'<br><small>{display_time(event["occurred_at"])}</small></li>' for event in events)
    audit = f'<ol class="history">{items}</ol>' if items else '<p>Belum ada aktivitas kunci.</p>'
    controls = ""
    if row["revoked_at"] is None:
        if os.environ.get("ISSUER_KEY_VAULT_SECRET"):
            reveal = f"""<form method="post" action="/admin/reveal">{csrf_field}{id_field}
<div><button class="secondary">Buka kunci</button></div></form>""" if row["key_saved"] else (
                "<p>Kunci lama belum tersimpan. Gunakan Ganti kunci untuk menerbitkan penggantinya.</p>"
            )
            controls = f"""{reveal}<details class="panel"{" open" if action == "rotate" else ""}><summary>Ganti kunci</summary>
<p>Kunci lama akan ditolak pada verifikasi berikutnya. Pasang kunci baru di Kajian.
Bukti yang sudah diterbitkan bisa tetap berlaku hingga kedaluwarsa.</p>
<form method="post" action="/admin/rotate">{csrf_field}{id_field}
<input type="hidden" name="version" value="{row["key_version"]}">
<label class="checkbox"><input type="checkbox" name="confirm" value="yes" required>Saya siap memasang kunci pengganti.</label>
<div><button class="danger">Terbitkan kunci pengganti</button></div></form></details>"""
        else:
            controls = "<p>Aktifkan penyimpanan terenkripsi melalui konfigurasi penerbit untuk membuka dan mengganti kunci.</p>"
    return f'<section class="panel"><h2>Kunci lisensi</h2>{controls}<h3>Aktivitas kunci</h3>{audit}</section>'


def editor(start, csrf, row=None, form=None, error="", action="", feedback=""):
    form = form or {}
    editing = row is not None
    title = "Detail lisensi" if editing else "Buat lisensi"
    domain = escape(form.get("domain", row["domain"] if editing else ""))
    customer = escape(form.get("customer", row["customer"] if editing else ""))
    expiry = escape(form.get("expiry", ""))
    id_field = f'<input type="hidden" name="id" value="{escape(row["id"])}">' if editing else ""
    csrf_field = f'<input type="hidden" name="csrf" value="{csrf}">'
    if editing:
        duration = f'<label>Tanggal berakhir baru (WIB)<input name="expiry" type="datetime-local" value="{expiry}"></label><small>Kosongkan untuk mempertahankan tanggal saat ini.</small>'
    else:
        duration = f"""<label>Masa berlaku<select name="days"><option value="30">30 hari</option>
<option value="90">90 hari</option><option value="365">1 tahun</option></select></label>
<label>Tanggal khusus (WIB)<input name="expiry" type="datetime-local" value="{expiry}"></label>
<small>Jika diisi, tanggal khusus dipakai.</small>"""
    error_html = f'<p class="notice error" role="alert">{escape(error)}</p>' if error else ""
    back = '<p><a href="/admin/">← Semua lisensi</a></p>'
    summary = license_summary(row) if editing else ""
    keys = key_controls(row, csrf_field, id_field, action) if editing else ""
    confirmation_feedback = f'<p class="notice success" role="status">{escape(feedback)}</p>' if feedback else ""
    hero = f'<div class="hero"><h1>{escape(row["domain"]) if editing else title}</h1>'
    if editing:
        hero += f'<p class="muted">{escape(row["customer"])} · {display_time(row["expires_at"])} · {status_badge(row, int(time.time()))}</p>'
    hero += "</div>"
    if editing and row["revoked_at"] is not None:
        return page(start, title, f'{back}{hero}{confirmation_feedback}{error_html}<p>Dicabut pada {display_time(row["revoked_at"])}.</p>{summary}{keys}', 400 if error else 200)
    revoke = f"""<details class="panel"{" open" if action == "revoke" else ""}><summary>Cabut lisensi</summary>
<p>Bukti yang sudah diterbitkan bisa tetap berlaku sampai diperiksa ulang atau kedaluwarsa.</p>
<form method="post" action="/admin/revoke">{csrf_field}{id_field}
<label class="checkbox"><input type="checkbox" name="confirm" value="yes" required>
Saya ingin mencabut lisensi untuk {escape(row["domain"])}</label>
<div><button class="danger">Cabut lisensi</button></div></form></details>""" if editing else ""
    confirmation = """<div><label class="checkbox"><input type="checkbox" name="confirm_move" value="yes">Konfirmasi jika domain berubah</label>
<small>Instalasi lama akan ditolak pada pemeriksaan berikutnya.</small></div>""" if editing else ""
    renewal = f"""<details class="panel"{" open" if action == "renew" else ""}><summary>Perpanjang lisensi</summary>
<p>Tambahkan hari dari tanggal berakhir atau dari hari ini jika lisensi sudah kedaluwarsa.</p>
<form method="post" action="/admin/renew">{csrf_field}{id_field}
<label>Tambahan masa berlaku (hari)<input name="days" type="number" min="1" max="3650" value="{escape(form.get("days", "30")) if action == "renew" else "30"}" required></label>
<div><button>Perpanjang</button></div></form></details>""" if editing else ""
    form_action = "license" if editing else "new"
    fields = f"""<form method="post" action="/admin/{form_action}">{csrf_field}{id_field}
<label>Domain<input name="domain" required maxlength="253" placeholder="kajian.contoh.id" value="{domain}"></label>
<label>Pelanggan<input name="customer" required maxlength="160" value="{customer}"></label>
{duration}{confirmation}<div><button>{"Simpan perubahan" if editing else "Terbitkan lisensi"}</button></div></form>"""
    if not editing:
        return page(start, title, f'{back}{hero}<div class="editor">{error_html}<section class="panel">{fields}</section></div>',
                    400 if error else 200)
    profile_environment = form.get("environment", row["environment"] or "")
    profile_notes = escape(form.get("notes", row["notes"] or ""))
    options = "".join(f'<option value="{key}"{" selected" if key == profile_environment else ""}>{label}</option>'
                      for key, label in ENVIRONMENTS.items())
    profile = f"""<details class="panel"{" open" if action == "profile" else ""}><summary>Edit profil instalasi</summary>
<form method="post" action="/admin/profile">{csrf_field}{id_field}
<label>Lingkungan<select name="environment">{options}</select></label>
<label>Catatan internal<textarea name="notes" maxlength="500">{profile_notes}</textarea></label>
<small>Gunakan untuk konteks instalasi. Simpan kredensial secara terpisah.</small>
<div><button>Simpan profil</button></div></form></details>"""
    return page(start, title, f"""{back}{hero}{confirmation_feedback}{error_html}
<div class="detail-layout"><div>{summary}</div><div class="editor">
{renewal}
<details class="panel"{" open" if action == "license" else ""}><summary>Edit lisensi</summary>{fields}</details>
{profile}{keys}{revoke}</div></div>""", 400 if error else 200)


def save_profile(license_id, environment, notes):
    if environment not in ENVIRONMENTS or len(notes) > 500:
        raise ValueError("Pilih lingkungan yang valid dan batasi catatan hingga 500 karakter.")
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        if not db.execute("SELECT 1 FROM licenses WHERE id = ? AND revoked_at IS NULL", (license_id,)).fetchone():
            raise ValueError("Profil hanya dapat diubah untuk lisensi yang belum dicabut.")
        db.execute("""
            INSERT INTO license_profiles (license_id, environment, notes, updated_at)
            VALUES (?, ?, ?, ?) ON CONFLICT (license_id) DO UPDATE SET
                environment = excluded.environment, notes = excluded.notes, updated_at = excluded.updated_at
        """, (license_id, environment, notes.strip(), int(time.time())))


def get_license(license_id):
    if not license_id or str(uuid.UUID(license_id)) != license_id:
        raise ValueError("ID lisensi tidak valid.")
    with database() as db:
        return db.execute(LICENSE_ROWS.replace("SELECT id,", """SELECT id,
            lower(substr(hex(key_digest), 1, 16)) AS key_version,
            EXISTS(SELECT 1 FROM license_secrets WHERE license_id = licenses.id) AS key_saved,""", 1)
                          + " WHERE id = ?",
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
            if path == "/admin/customers":
                return directory(start, "customer", params)
            if path == "/admin/installations":
                return directory(start, "domain", params)
            if path == "/admin/export.csv":
                return export_csv(start, params)
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
                    return editor(start, csrf, row, feedback=FEEDBACK.get(params.get("saved", [""])[0], ""))
        elif path in ("/admin/new", "/admin/license", "/admin/revoke", "/admin/renew", "/admin/profile", "/admin/reveal", "/admin/rotate"):
            length = int(environ.get("CONTENT_LENGTH") or 0)
            if not 1 <= length <= 8192 or environ.get("CONTENT_TYPE", "").split(";")[0] != "application/x-www-form-urlencoded":
                raise ValueError("Formulir tidak valid.")
            raw = environ["wsgi.input"].read(length).decode("utf-8")
            form = {key: values[0] for key, values in parse_qs(raw, max_num_fields=12, keep_blank_values=True).items()}
            if not hmac.compare_digest(form.get("csrf", "").encode(), csrf.encode()):
                return page(start, "Sesi formulir tidak valid", "<h1>Muat ulang halaman dan coba lagi.</h1>", 403)
            if path == "/admin/new":
                domain, customer = form.get("domain", ""), form.get("customer", "")
                date = form.get("expiry")
                result = issue_until(domain, customer, expiry_value(date)) if date else issue(domain, customer, int(form.get("days", "0")))
                return page(start, "Lisensi diterbitkan",
                            f'<h1>Lisensi diterbitkan</h1><div class="panel editor"><h2>{escape(result["domain"])}</h2>'
                            f'<p>Berakhir {display_time(datetime.fromisoformat(result["expires_at"]).timestamp())}.</p>'
                            + ('<p>Admin dapat membukanya kembali dari detail lisensi.</p>' if result["key_saved"] else
                             '<p>Simpan kunci sekarang. Kunci ini belum disimpan secara terenkripsi.</p>')
                            + secret_field(result["license_key"], "Kunci lisensi DRM")
                            + '<p><a href="/admin/">Kembali ke daftar lisensi</a></p></div>', 201)
            row = get_license(form.get("id", ""))
            if row is not None:
                if path in ("/admin/reveal", "/admin/rotate"):
                    action = path.rsplit("/", 1)[-1]
                    if action == "rotate" and form.get("confirm") != "yes":
                        raise ValueError("Konfirmasikan penggantian kunci.")
                    key = access_license_key(row["id"], user, action, form.get("version", ""))
                    heading = "Kunci pengganti diterbitkan" if action == "rotate" else "Kunci lisensi DRM"
                    detail_url = "/admin/license?" + escape(urlencode({"id": row["id"]}))
                    return page(start, heading, f'<h1>{heading}</h1><section class="panel editor">'
                                f'<p>{escape(row["domain"])}</p>' + secret_field(key, "Kunci lisensi DRM")
                                + f'<p><a href="{detail_url}">Tutup dan kembali ke detail</a></p></section>')
                if path == "/admin/revoke":
                    if form.get("confirm") != "yes":
                        raise ValueError("Konfirmasikan pencabutan.")
                    manage(SimpleNamespace(command="revoke", id=row["id"]))
                elif path == "/admin/profile":
                    save_profile(row["id"], form.get("environment", ""), form.get("notes", ""))
                elif path == "/admin/renew":
                    manage(SimpleNamespace(command="renew", id=row["id"], days=int(form.get("days", "0"))))
                else:
                    domain = normalize_domain(form.get("domain", ""))
                    if domain != row["domain"] and form.get("confirm_move") != "yes":
                        raise ValueError(f"Konfirmasikan perpindahan dari {row['domain']} ke {domain}.")
                    expiry = expiry_value(form["expiry"]) if form.get("expiry") else None
                    update_license(row["id"], domain, form.get("customer", ""), expiry, row["domain"])
                start("303 See Other", [("Location", "/admin/license?" + urlencode({"id": row["id"], "saved": path.rsplit("/", 1)[-1]})),
                                         ("Cache-Control", "no-store"), ("Content-Length", "0")])
                return [b""]
    except ValueError as error:
        if method == "POST":
            message = str(error) if type(error) is ValueError else "Periksa isian formulir."
            return editor(start, csrf, row, form, message, path.rsplit("/", 1)[-1])
        return page(start, "Permintaan tidak valid", "<h1>Alamat halaman tidak valid.</h1>", 400)
    except (sqlite3.Error, RuntimeError):
        return page(start, "Tidak tersedia", "<h1>Dashboard sementara tidak tersedia.</h1>", 503)
    return page(start, "Tidak ditemukan", '<h1>Halaman tidak ditemukan</h1><a href="/admin/">Semua lisensi</a>', 404)
