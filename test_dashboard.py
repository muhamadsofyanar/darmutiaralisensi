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
