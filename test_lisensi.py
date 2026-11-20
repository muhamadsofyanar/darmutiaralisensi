from argparse import Namespace
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import sqlite3
import tempfile
from threading import Thread
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from wsgiref.simple_server import make_server, WSGIRequestHandler

from cryptography.exceptions import InvalidSignature

from api import application
import lisensi


class QuietHandler(WSGIRequestHandler):
    def log_message(self, *_):
        pass


class LicensingTest(unittest.TestCase):
    def setUp(self):
        self.original_db = lisensi.DATABASE
        self.temp = tempfile.TemporaryDirectory()
        lisensi.DATABASE = Path(self.temp.name) / "licenses.sqlite3"
        lisensi.initialize()
        self.public_key = lisensi.manage(Namespace(command="public-key"))["public_key"]
        self.license = lisensi.issue("darmutiara.com", "Darul Mutaqin Sejahtera", 7)

    def tearDown(self):
        lisensi.DATABASE = self.original_db
        self.temp.cleanup()

    def test_signed_token_and_domain(self):
        now = int(time.time())
        token = lisensi.activate(self.license["license_key"], "DARMUTIARA.COM.", now)["token"]
        claims = lisensi.verify(token, self.public_key, "darmutiara.com", now)
        self.assertEqual(claims["license_id"], self.license["id"])
        self.assertEqual(claims["exp"], now + 86400)
        with self.assertRaises(ValueError):
            lisensi.verify(token, self.public_key, "lain.example", now)
        with self.assertRaises(ValueError):
            lisensi.verify(token, self.public_key, "darmutiara.com", claims["exp"])
        payload, signature = token.split(".")
        changed = ("A" if signature[0] != "A" else "B") + signature[1:]
        with self.assertRaises(InvalidSignature):
            lisensi.verify(payload + "." + changed, self.public_key, "darmutiara.com", now)

    def test_renew_expiry_and_revocation(self):
        license_id = self.license["id"]
        with lisensi.database() as db:
            db.execute("UPDATE licenses SET expires_at = ? WHERE id = ?", (int(time.time()) - 5, license_id))
        self.assertIsNone(lisensi.activate(self.license["license_key"], "darmutiara.com"))
        lisensi.manage(Namespace(command="renew", id=license_id, days=10))
        self.assertIsNotNone(lisensi.activate(self.license["license_key"], "darmutiara.com"))
        lisensi.manage(Namespace(command="revoke", id=license_id))
        self.assertIsNone(lisensi.activate(self.license["license_key"], "darmutiara.com"))
        with self.assertRaises(ValueError):
            lisensi.manage(Namespace(command="renew", id=license_id, days=10))

    def test_storage_and_restart(self):
        raw = lisensi.DATABASE.read_bytes()
        self.assertNotIn(self.license["license_key"].encode(), raw)
        lisensi.initialize()
        self.assertEqual(lisensi.manage(Namespace(command="public-key"))["public_key"], self.public_key)

    def test_http_activation(self):
        with make_server("127.0.0.1", 0, application, handler_class=QuietHandler) as server:
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{server.server_port}/v1/activate"
                headers = {"Content-Type": "application/json"}
                data = lambda domain: json.dumps({
                    "license_key": self.license["license_key"], "domain": domain,
                }).encode("utf-8")
                with urlopen(Request(url, data=data("darmutiara.com"), headers=headers), timeout=3) as result:
                    self.assertEqual(result.status, 200)
                    lisensi.verify(json.load(result)["token"], self.public_key, "darmutiara.com")
                for body, status in [(data("lain.example"), 403), (b"{}", 400), (b" " * 4097, 400)]:
                    with self.assertRaises(HTTPError) as error:
                        urlopen(Request(url, data=body, headers=headers), timeout=3)
                    with error.exception as response:
                        self.assertEqual(response.code, status)
            finally:
                server.shutdown()
                thread.join()


if __name__ == "__main__":
    unittest.main()
