import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import sys
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


ISSUER = "darmutiara-license-v1"
TOKEN_LIFETIME = 24 * 60 * 60
DATABASE = Path(os.environ.get("LICENSE_DB", "/data/licenses.sqlite3"))
LICENSE_PATTERN = re.compile(r"DRM-[A-Za-z0-9_-]{43}", re.ASCII)
DOMAIN_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)

SCHEMA = """
CREATE TABLE IF NOT EXISTS issuer (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    signing_key BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS licenses (
    id TEXT PRIMARY KEY,
    key_digest BLOB NOT NULL UNIQUE,
    domain TEXT NOT NULL,
    customer TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
"""


def normalize_domain(raw):
    domain = raw.strip().rstrip(".").encode("idna").decode("ascii").lower()
    parts = domain.split(".")
    if len(domain) > 253 or len(parts) < 2 or not all(DOMAIN_PATTERN.fullmatch(p) for p in parts):
        raise ValueError("Gunakan nama domain tanpa skema, port, atau jalur.")
    if not any(letter.isalpha() for letter in parts[-1]):
        raise ValueError("Gunakan nama domain, bukan alamat IP.")
    return domain


@contextmanager
def database():
    db = sqlite3.connect(DATABASE, timeout=5)
    db.row_factory = sqlite3.Row
    try:
        with db:
            yield db
    finally:
        db.close()


def initialize():
    DATABASE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.umask(0o077)
    with database() as db:
        db.executescript(SCHEMA)
        if not db.execute("SELECT 1 FROM issuer WHERE id = 1").fetchone():
            key = Ed25519PrivateKey.generate().private_bytes_raw()
            db.execute("INSERT OR IGNORE INTO issuer (id, signing_key) VALUES (1, ?)", (key,))
    DATABASE.chmod(0o600)


def signing_key(db):
    row = db.execute("SELECT signing_key FROM issuer WHERE id = 1").fetchone()
    if row is None:
        raise RuntimeError("Penerbit belum diinisialisasi.")
    return Ed25519PrivateKey.from_private_bytes(row["signing_key"])


def digest(key):
    return hashlib.sha256(key.encode("ascii")).digest()


def encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode(encoded):
    return base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)


def issue(domain, customer, days):
    domain = normalize_domain(domain)
    customer = customer.strip()
    if not customer or len(customer) > 160:
        raise ValueError("Isi nama pelanggan dengan maksimal 160 karakter.")
    if not 1 <= days <= 3650:
        raise ValueError("Masa berlaku harus 1–3650 hari.")
    key = "DRM-" + secrets.token_urlsafe(32)
    license_id = str(uuid.uuid4())
    expiry = int(time.time()) + days * 86400
    with database() as db:
        db.execute(
            "INSERT INTO licenses (id, key_digest, domain, customer, expires_at) VALUES (?, ?, ?, ?, ?)",
            (license_id, digest(key), domain, customer, expiry),
        )
    return {"id": license_id, "domain": domain, "expires_at": utc_time(expiry), "license_key": key}


def activate(key, domain, now=None):
    if not isinstance(domain, str) or not isinstance(key, str) or not LICENSE_PATTERN.fullmatch(key):
        raise ValueError("Masukkan license_key dan domain yang valid.")
    domain = normalize_domain(domain)
    now = int(time.time()) if now is None else now
    with database() as db:
        license_row = db.execute(
            "SELECT id, domain, expires_at, revoked_at FROM licenses WHERE key_digest = ? AND domain = ?",
            (digest(key), domain),
        ).fetchone()
        if license_row is None or license_row["revoked_at"] is not None or license_row["expires_at"] <= now:
            return None
        claims = {
            "iss": ISSUER,
            "license_id": license_row["id"],
            "domain": domain,
            "iat": now,
            "exp": min(now + TOKEN_LIFETIME, license_row["expires_at"]),
        }
        payload = encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
        signature = signing_key(db).sign(payload.encode("ascii"))
        return {"token": payload + "." + encode(signature), "expires_at": utc_time(claims["exp"])}


def verify(token, public_key, domain, now=None):
    payload, signature = token.split(".")
    key = Ed25519PublicKey.from_public_bytes(decode(public_key))
    key.verify(decode(signature), payload.encode("ascii"))
    claims = json.loads(decode(payload))
    now = int(time.time()) if now is None else now
    if (claims["iss"] != ISSUER or claims["domain"] != normalize_domain(domain)
        or not claims["iat"] <= now < claims["exp"] or claims["exp"] - claims["iat"] > TOKEN_LIFETIME):
        raise ValueError("Bukti aktivasi tidak berlaku untuk instalasi ini.")
    return claims


def utc_time(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def manage(args):
    now = int(time.time())
    if args.command == "init":
        initialize()
        return None
    if args.command == "issue":
        return issue(args.domain, args.customer, args.days)
    with database() as db:
        if args.command == "public-key":
            return {"public_key": encode(signing_key(db).public_key().public_bytes_raw())}
        if args.command == "list":
            rows = db.execute("SELECT id, domain, customer, expires_at, revoked_at FROM licenses ORDER BY domain, id")
            return [
                {"id": row["id"], "domain": row["domain"], "customer": row["customer"],
                 "expires_at": utc_time(row["expires_at"]),
                 "status": "dicabut" if row["revoked_at"] is not None
                 else "kedaluwarsa" if row["expires_at"] <= now else "aktif"}
                for row in rows
            ]
        if args.command == "revoke":
            result = db.execute(
                "UPDATE licenses SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?",
                (now, args.id),
            )
        else:
            if not 1 <= args.days <= 3650:
                raise ValueError("Masa perpanjangan harus 1–3650 hari.")
            result = db.execute(
                "UPDATE licenses SET expires_at = MAX(expires_at, ?) + ? WHERE id = ? AND revoked_at IS NULL",
                (now, args.days * 86400, args.id),
            )
        if result.rowcount != 1:
            raise ValueError("Lisensi tidak ditemukan atau sudah dicabut.")
        return {"id": args.id, "operation": args.command}


def main():
    parser = argparse.ArgumentParser(description="Administrasi lisensi Darmutiara.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "public-key", "list"):
        sub.add_parser(name)
    create = sub.add_parser("issue")
    create.add_argument("--domain", required=True)
    create.add_argument("--customer", required=True)
    create.add_argument("--days", type=int, required=True)
    revoke = sub.add_parser("revoke")
    revoke.add_argument("id")
    renew = sub.add_parser("renew")
    renew.add_argument("id")
    renew.add_argument("--days", type=int, required=True)
    try:
        result = manage(parser.parse_args())
    except (ValueError, sqlite3.Error, OSError, RuntimeError) as error:
        print(f"Gagal: {error}", file=sys.stderr)
        return 1
    if result is not None:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
