from argparse import Namespace
import base64
from pathlib import Path
import re
import sys
import tempfile
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from wsgiref.simple_server import WSGIRequestHandler, make_server

from app import create_app


class Handler(WSGIRequestHandler):
    def log_message(self, *_):
        pass


class Integration(unittest.TestCase):
    def setUp(self):
        import api
        import lisensi
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.lisensi = lisensi
        self.old_db = lisensi.DATABASE
        lisensi.DATABASE = root / "issuer.sqlite3"
        lisensi.initialize()
        self.license = lisensi.issue("darmutiara.com", "Darmutiara", 30)
        self.server = self.serve(api.application)

        def route_issuer(request, timeout):
            return urlopen(Request(self.server + "/v1/activate", data=request.data,
                                   headers={"Content-Type": "application/json"}), timeout=timeout)

        self.path = root / "client.sqlite3"
        self.client = self.serve(create_app({
            "ADMIN_PASSWORD": "only-for-testing-123",
            "APP_DOMAIN": "darmutiara.com",
            "ISSUER_URL": "https://licenses.example",
            "ISSUER_PUBLIC_KEY": lisensi.manage(Namespace(command="public-key"))["public_key"],
            "LICENSE_STATE": str(self.path),
        }, route_issuer))
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(setattr, lisensi, "DATABASE", self.old_db)

    def serve(self, application):
        server = make_server("127.0.0.1", 0, application, handler_class=Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}"

    def read(self, path="/", data=None, authorize=True):
        headers = {}
        if authorize:
            headers["Authorization"] = "Basic " + base64.b64encode(b"admin:only-for-testing-123").decode()
        if data is not None:
            data = urlencode(data).encode()
        with urlopen(Request(self.client + path, headers=headers, data=data), timeout=3) as result:
            return result.read().decode()

    def test_login_and_csrf(self):
        with self.assertRaises(HTTPError) as error:
            self.read(authorize=False)
        self.assertEqual(error.exception.code, 401)
        with self.assertRaises(HTTPError) as error:
            self.read("/aktivasi", {"license_key": self.license["license_key"], "csrf": "invalid"})
        self.assertEqual(error.exception.code, 403)
        self.assertIn("Belum diaktifkan", self.read())

    def test_activation_other_domain_and_revocation(self):
        csrf = re.search(r'name="csrf" value="([^"]+)"', self.read())[1]
        wrong = self.lisensi.issue("lain.example", "Organisasi lain", 5)
        denied = self.read("/aktivasi", {"license_key": wrong["license_key"], "csrf": csrf})
        self.assertIn("Lisensi ditolak.", denied)
        activated = self.read("/aktivasi", {"license_key": self.license["license_key"], "csrf": csrf})
        self.assertIn("Status <strong>Aktif</strong>", activated)
        self.assertNotIn(self.license["license_key"], activated)
        self.lisensi.manage(Namespace(command="revoke", id=self.license["id"]))
        import sqlite3
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE activation SET next_check = 0")
        self.assertIn("Lisensi ditolak oleh penerbit", self.read())


if __name__ == "__main__":
    unittest.main()
