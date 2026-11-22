import base64
from io import BytesIO
import os
from pathlib import Path
import re
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit
from wsgiref.util import setup_testing_defaults

import api
import lisensi


class DashboardTest(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(TemporaryDirectory())
        path = Path(directory) / "legacy.sqlite3"
        self.enterContext(patch.object(lisensi, "DATABASE", path))
        self.enterContext(patch.dict(os.environ, {"ISSUER_ADMIN_USER": "admin",
                                                "ISSUER_ADMIN_PASSWORD": "test-issuer-password"}))
        with sqlite3.connect(path) as connection:
            connection.executescript(lisensi.SCHEMA.split("CREATE INDEX")[0])
        signing_key = lisensi.Ed25519PrivateKey.generate()
        self.public_key = lisensi.encode(signing_key.public_key().public_bytes_raw())
        with lisensi.database() as db:
            db.execute("INSERT INTO issuer VALUES (1, ?)", (signing_key.private_bytes_raw(),))
            db.execute("INSERT INTO licenses VALUES (?, ?, ?, ?, ?, NULL)",
                       ("4c4f0d26-fb79-422d-992c-4bc227cd0e14", lisensi.digest("DRM-" + "a" * 43),
                        "legacy.example", "Pelanggan Lama", 4102444800))
        lisensi.initialize()

    def request(self, url, form=None, authorize=True):
        target = urlsplit(url)
        environ = {}
        setup_testing_defaults(environ)
        environ.update(PATH_INFO=target.path, QUERY_STRING=target.query)
        if authorize:
            environ["HTTP_AUTHORIZATION"] = "Basic " + base64.b64encode(b"admin:test-issuer-password").decode()
        if form is not None:
            raw = urlencode(form).encode()
            environ.update(REQUEST_METHOD="POST", CONTENT_TYPE="application/x-www-form-urlencoded",
                           CONTENT_LENGTH=str(len(raw)))
            environ["wsgi.input"] = BytesIO(raw)
        headers = {}
        body = b"".join(api.application(environ, lambda status, _: headers.update(status=status)))
        return int(headers["status"].split()[0]), body.decode("utf-8-sig")

    def test_migration_preserves_signing_key_and_old_license(self):
        result = lisensi.activate("DRM-" + "a" * 43, "legacy.example")
        self.assertIsNotNone(result)
        lisensi.verify(result["token"], self.public_key, "legacy.example")
        _, body = self.request("/admin/?q=legacy")
        self.assertIn("legacy.example", body)
        self.assertIn("Verifikasi terakhir", body)

    def test_history_renewal_revocation_and_export(self):
        self.assertEqual(self.request("/admin/export.csv", authorize=False)[0], 401)
        record = lisensi.issue("uji.example", "=1+1", 5)
        url = "/admin/license?" + urlencode({"id": record["id"]})
        csrf = re.search(r'name="csrf" value="([^"]+)"', self.request(url)[1])[1]
        form = {"id": record["id"], "csrf": csrf, "days": "60"}
        self.assertEqual(self.request("/admin/renew", form | {"csrf": "bad"})[0], 403)
        self.assertEqual(self.request("/admin/renew", form)[0], 303)
        detail = self.request(url)[1]
        self.assertIn("Lisensi diterbitkan", detail)
        self.assertIn("Lisensi diubah", detail)
        self.assertEqual(self.request("/admin/revoke", form | {"confirm": "yes"})[0], 303)
        self.assertIn("Lisensi dicabut", self.request(url)[1])
        _, export = self.request("/admin/export.csv?status=revoked&sort=domain")
        self.assertIn("uji.example,'=1+1,Dicabut", export)
        self.assertNotIn("legacy.example", export)
        self.assertNotIn(record["license_key"], export)

    def test_root_redirects_to_protected_dashboard(self):
        environ = {}
        setup_testing_defaults(environ)
        environ["PATH_INFO"] = "/"
        headers = {}
        list(api.application(environ, lambda status, fields: headers.update(fields, status=status)))
        self.assertEqual(headers["status"], "302 Found")
        self.assertEqual(headers["Location"], "/admin/")
        self.assertEqual(self.request(headers["Location"], authorize=False)[0], 401)

    def test_profile_and_exact_directory_filters(self):
        record = lisensi.issue("uji.example", "Pelanggan Lama", 30)
        lisensi.issue("uji.example", "Pelanggan Lama Dua", 60)
        url = "/admin/license?" + urlencode({"id": record["id"]})
        csrf = re.search(r'name="csrf" value="([^"]+)"', self.request(url)[1])[1]
        form = {"id": record["id"], "csrf": csrf, "environment": "test", "notes": "<catatan>"}
        self.assertEqual(self.request("/admin/profile", form | {"csrf": "bad"})[0], 403)
        self.assertEqual(self.request("/admin/profile", form | {"environment": "invalid"})[0], 400)
        self.assertEqual(self.request("/admin/profile", form)[0], 303)
        detail = self.request(url + "&saved=profile")[1]
        self.assertIn("Profil instalasi tersimpan.", detail)
        self.assertIn("&lt;catatan&gt;", detail)
        self.assertNotIn("<catatan>", detail)
        self.assertIn("Pelanggan Lama Dua", self.request("/admin/customers")[1])
        self.assertIn("uji.example", self.request("/admin/installations")[1])
        scope = urlencode({"customer": "Pelanggan Lama", "domain": "uji.example"})
        self.assertNotIn("Pelanggan Lama Dua", self.request("/admin/?" + scope)[1])
        export = self.request("/admin/export.csv?" + scope)[1]
        self.assertIn(",Uji", export)
        self.assertNotIn("Pelanggan Lama Dua", export)
        self.assertNotIn("catatan", export)
        self.assertEqual(self.request("/admin/profile", form | {"notes": ""})[0], 303)
        self.assertIn("Belum ada catatan", self.request(url)[1])

    def test_vault_reveal_and_rotate(self):
        from cryptography.fernet import Fernet
        self.enterContext(patch.dict(os.environ, {"ISSUER_KEY_VAULT_SECRET": Fernet.generate_key().decode()}))
        record = lisensi.issue("vault.example", "Pelanggan", 30)
        key = record["license_key"]
        url = "/admin/license?" + urlencode({"id": record["id"]})
        detail = self.request(url)[1]
        self.assertNotIn(key, detail)
        self.assertNotIn(key, self.request("/admin/export.csv")[1])
        self.assertIn("Buka kunci", detail)
        csrf = re.search(r'name="csrf" value="([^"]+)"', detail)[1]
        version = re.search(r'name="version" value="([^"]+)"', detail)[1]
        data = {"id": record["id"], "csrf": csrf, "version": version}
        self.assertEqual(self.request("/admin/reveal", data, authorize=False)[0], 401)
        self.assertEqual(self.request("/admin/reveal", data | {"csrf": "bad"})[0], 403)
        self.assertIn(key, self.request("/admin/reveal", data)[1])
        self.assertEqual(self.request("/admin/rotate", data)[0], 400)
        status, body = self.request("/admin/rotate", data | {"confirm": "yes"})
        self.assertEqual(status, 200)
        replacement = re.search(r'DRM-[A-Za-z0-9_-]{43}', body)[0]
        self.assertNotEqual(key, replacement)
        self.assertIsNone(lisensi.activate(key, "vault.example"))
        self.assertIsNotNone(lisensi.activate(replacement, "vault.example"))
        self.assertEqual(self.request("/admin/rotate", data | {"confirm": "yes"})[0], 400)
        self.assertIn(replacement, self.request("/admin/reveal", data)[1])
        detail = self.request(url)[1]
        self.assertIn("Kunci dibuka", detail)
        self.assertIn("Kunci diganti", detail)
        self.assertNotIn(replacement, detail)
        with lisensi.database() as db:
            row = db.execute("SELECT ciphertext FROM license_secrets WHERE license_id = ?", (record["id"],)).fetchone()
            self.assertNotIn(replacement.encode(), row["ciphertext"])
        legacy = "4c4f0d26-fb79-422d-992c-4bc227cd0e14"
        detail = self.request("/admin/license?id=" + legacy)[1]
        self.assertIn("Kunci lama belum tersimpan", detail)
        self.assertEqual(self.request("/admin/reveal", data | {"id": legacy})[0], 400)
        wrong = {"ISSUER_KEY_VAULT_SECRET": Fernet.generate_key().decode()}
        with patch.dict(os.environ, wrong):
            self.assertEqual(self.request("/admin/reveal", data)[0], 400)
            self.assertIsNotNone(lisensi.activate(replacement, "vault.example"))
        revoked = data | {"confirm": "yes"}
        self.assertEqual(self.request("/admin/revoke", revoked)[0], 303)
        self.assertEqual(self.request("/admin/reveal", data)[0], 400)
