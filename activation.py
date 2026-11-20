import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ISSUER = "darmutiara-license-v1"
TOKEN_LIFETIME = 86400
CHECK_INTERVAL = 3600
KEY_PATTERN = re.compile(r"DRM-[A-Za-z0-9_-]{43}", re.ASCII)


class LicenseDenied(Exception):
    pass


class IssuerUnavailable(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def decode(value):
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


class Activation:
    def __init__(self, database, domain, issuer_url, public_key, opener=None):
        self.path = Path(database)
        self.domain = domain.strip().rstrip(".").encode("idna").decode("ascii").lower()
        if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", self.domain):
            raise ValueError("APP_DOMAIN harus berupa nama domain.")
        url = urlsplit(issuer_url)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
            raise ValueError("ISSUER_URL harus berupa origin HTTPS.")
        self.endpoint = issuer_url.rstrip("/") + "/v1/activate"
        self.verify_key = Ed25519PublicKey.from_public_bytes(decode(public_key))
        self.opener = opener or build_opener(NoRedirect()).open
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.database() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS activation (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    license_key TEXT NOT NULL,
                    token TEXT,
                    next_check INTEGER NOT NULL,
                    denied INTEGER NOT NULL DEFAULT 0
                )
            """)
        self.path.chmod(0o600)

    @contextmanager
    def database(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def claims(self, token, now=None):
        if not token or not isinstance(token, str) or len(token) > 4096:
            return None
        try:
            body, signature = token.split(".")
            self.verify_key.verify(decode(signature), body.encode("ascii"))
            claims = json.loads(decode(body))
            now = int(time.time()) if now is None else now
            if (claims["iss"] == ISSUER
                and claims["domain"] == self.domain
                and type(claims["iat"]) is int and type(claims["exp"]) is int
                and claims["iat"] <= now < claims["exp"]
                and claims["exp"] - claims["iat"] <= TOKEN_LIFETIME):
                return claims
        except (InvalidSignature, ValueError, KeyError, TypeError):
            pass
        return None

    def request_token(self, key):
        request = Request(self.endpoint, data=json.dumps({
            "license_key": key, "domain": self.domain,
        }).encode(), headers={"Content-Type": "application/json"}, method="POST")
        try:
            with self.opener(request, timeout=5) as response:
                raw = response.read(4097)
            if len(raw) > 4096:
                raise IssuerUnavailable()
            token = json.loads(raw)["token"]
        except HTTPError as error:
            code = error.code
            error.close()
            if code == 403:
                raise LicenseDenied() from None
            raise IssuerUnavailable() from None
        except (URLError, OSError, KeyError, ValueError, TypeError):
            raise IssuerUnavailable() from None
        if not self.claims(token):
            raise IssuerUnavailable()
        return token

    def activate(self, key):
        if not KEY_PATTERN.fullmatch(key):
            raise LicenseDenied()
        token = self.request_token(key)
        with self.database() as db:
            db.execute("""
                INSERT INTO activation VALUES (1, ?, ?, ?, 0)
                ON CONFLICT (id) DO UPDATE SET
                    license_key = excluded.license_key, token = excluded.token,
                    next_check = excluded.next_check, denied = 0
            """, (key, token, int(time.time()) + CHECK_INTERVAL))

    def status(self):
        now = int(time.time())
        with self.database() as db:
            row = db.execute("SELECT * FROM activation WHERE id = 1").fetchone()
            if row is None:
                return "unactivated", None
            reserved = db.execute("""
                UPDATE activation SET next_check = ? WHERE id = 1 AND next_check <= ? AND license_key = ?
            """, (now + CHECK_INTERVAL, now, row["license_key"])).rowcount == 1

        if reserved:
            try:
                token = self.request_token(row["license_key"])
            except IssuerUnavailable:
                pass
            except LicenseDenied:
                self._refresh(row["license_key"], now + CHECK_INTERVAL, None, True)
            else:
                self._refresh(row["license_key"], now + CHECK_INTERVAL, token, False)
        with self.database() as db:
            row = db.execute("SELECT token, denied FROM activation WHERE id = 1").fetchone()
        if row["denied"]:
            return "denied", None
        claims = self.claims(row["token"])
        return ("active", claims) if claims else ("expired", None)

    def _refresh(self, key, reserved_until, token, denied):
        with self.database() as db:
            db.execute("""
                UPDATE activation SET token = ?, denied = ?
                WHERE id = 1 AND license_key = ? AND next_check = ?
            """, (token, int(denied), key, reserved_until))
