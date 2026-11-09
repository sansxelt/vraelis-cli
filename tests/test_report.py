"""Reporting privacy boundary and failure isolation."""
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vraelis import report, cli


class Reporting(unittest.TestCase):
    def test_projection_omits_private_fields(self):
        original = {"verdict": "CHANGED", "root": "/private", "reason": "secret", "changes": [
            {"file": "weights/model.bin", "change": "changed", "locked_sha256": "secret"}]}
        self.assertEqual(report.payload(original, "model"), {"name": "model", "result": {
            "verdict": "CHANGED", "changes": [{"file": "weights/model.bin", "change": "changed"}]}})

    def test_rejects_paths_and_agent_changes(self):
        for path in ("/etc/passwd", "../x", "a/../x", "C:/x", "a\\b", "a\nb", "a//b", "."):
            with self.subTest(path=path), self.assertRaises(ValueError):
                report.payload({"verdict": "CHANGED", "changes": [{"file": path, "change": "added"}]}, "m")
        with self.assertRaises(ValueError):
            report.payload({"verdict": "CHANGED", "changes": [{"kind": "changed", "where": "x"}]}, "m")

    def test_consistency(self):
        for verdict, changes in (("CHANGED", []), ("UNCHANGED", [{"file":"x","change":"added"}]), ("bad", [])):
            with self.assertRaises(ValueError):
                report.payload({"verdict":verdict,"changes":changes}, "m")
        self.assertEqual(report.payload({"verdict":"CANT_VERIFY","changes":[],"reason":"secret"}, "m")["result"], {"verdict":"CANT_VERIFY","changes":[]})

    def test_no_redirect(self):
        self.assertIsNone(report.NoRedirect().redirect_request(None, None, 302, "", {}, "https://elsewhere"))

    def test_transport_bounds_and_validation(self):
        for raw in (b'{}', b'not json', b'{"ok":true,"compared":true}', b'x' * (report.MAX_RESPONSE + 1)):
            response = MagicMock()
            response.status = 200
            response.read.return_value = raw
            response.__enter__.return_value = response
            with patch.object(report.urllib.request, 'build_opener') as factory:
                factory.return_value.open.return_value = response
                with self.assertRaises(ValueError): report._send(b'{}', 'vrc_test')
                response.read.assert_called_once_with(report.MAX_RESPONSE + 1)

    def test_failures_preserve_secret(self):
        token = "vrc_" + "s" * 32
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "result.json")
            with open(path, "w") as f: json.dump({"verdict":"UNCHANGED","changes":[]}, f)
            for failure in (OSError(token), ValueError(token), TimeoutError(token)):
                out, err = io.StringIO(), io.StringIO()
                with patch.dict(os.environ, {"VRAELIS_REPORT_TOKEN": token}), patch.object(report, 'send', side_effect=failure), redirect_stdout(out), redirect_stderr(err):
                    self.assertEqual(cli.run(['report','--file',path,'--name','model']), 2)
                self.assertNotIn(token, out.getvalue() + err.getvalue())
            with patch.dict(os.environ, {"VRAELIS_REPORT_TOKEN": token}), patch.object(report, 'send') as send, redirect_stdout(io.StringIO()):
                self.assertEqual(cli.run(['report','--file',path,'--name','model']), 0)
                self.assertEqual(json.loads(send.call_args.args[0]), {"name":"model","result":{"verdict":"UNCHANGED","changes":[]}})

    def test_http_failures_are_single_attempt(self):
        for status in (301, 302, 307, 308, 401, 429, 500, 503):
            with self.subTest(status=status), patch.object(report.urllib.request, 'build_opener') as factory:
                factory.return_value.open.side_effect = urllib.error.HTTPError(report.ENDPOINT, status, "private", {}, None)
                with self.assertRaises(ValueError): report.send(b'{}', 'vrc_secret')
                factory.return_value.open.assert_called_once()

    def test_missing_token_and_invalid_input_never_send(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(report, 'send') as send, redirect_stderr(io.StringIO()):
            self.assertEqual(report.main(['--file','absent','--name','model']), 2)
            send.assert_not_called()

    def test_deadline(self):
        with patch.object(report.threading, 'Thread'), patch.object(report.queue.Queue, 'get', side_effect=report.queue.Empty):
            with self.assertRaises(ValueError): report.send(b'{}', 'token')


if __name__ == '__main__': unittest.main()
