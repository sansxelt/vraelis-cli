"""Bulk verification preserves local evidence and fails CI on any incomplete check."""
import io
import json
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vraelis import cli, report
from vraelis.models import core, batch


class BatchVerification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.folders = []
        for name in ('model one', 'model two'):
            folder = self.root / name
            folder.mkdir()
            (folder / 'weights.bin').write_bytes(b'baseline')
            core.write_lock(str(folder), core.lock(str(folder)))
            self.folders.append(str(folder))

    def run_cli(self, *args):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.run(['models', 'verify-many', *args, '--json'])
        return code, json.loads(out.getvalue())

    def test_unchanged_and_read_only(self):
        before = {p:(p.read_bytes(),p.stat().st_mtime_ns) for p in self.root.rglob('*') if p.is_file()}
        code, doc = self.run_cli(*self.folders)
        self.assertEqual(code, 0)
        self.assertEqual(doc['summary'], {'total':2,'UNCHANGED':2,'CHANGED':0,'CANT_VERIFY':0})
        self.assertEqual([x['folder'] for x in doc['results']], self.folders)
        after = {p:(p.read_bytes(),p.stat().st_mtime_ns) for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before, after)

    def test_mixed_changes_and_missing_folder(self):
        (Path(self.folders[1]) / 'weights.bin').write_bytes(b'changed')
        code, doc = self.run_cli(*self.folders)
        self.assertEqual(code, 1)
        self.assertEqual(doc['summary']['CHANGED'], 1)
        code, doc = self.run_cli(*self.folders, str(self.root/'absent'))
        self.assertEqual(code, 2)
        self.assertEqual(doc['summary'], {'total':3,'UNCHANGED':1,'CHANGED':1,'CANT_VERIFY':1})
        self.assertEqual(doc['results'][1]['result']['changes'][0]['file'], 'weights.bin')

    def test_internal_failure_does_not_skip_remaining_folder(self):
        unchanged = core.verify(self.folders[1])
        with patch.object(core,'verify',side_effect=[RuntimeError('private secret'),unchanged]):
            doc = batch.verify_many(self.folders)
        self.assertEqual(doc['verdict'], 'CANT_VERIFY')
        self.assertEqual(doc['summary']['UNCHANGED'], 1)
        self.assertNotIn('private secret', json.dumps(doc))

    def test_keyboard_interrupt_is_not_swallowed(self):
        with patch.object(core,'verify',side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            batch.verify_many(self.folders)

    def test_batch_cannot_be_mistaken_for_single_report(self):
        with self.assertRaises(ValueError):
            report.payload(batch.verify_many(self.folders), 'model')

    def test_terminal_output_escapes_untrusted_text(self):
        doc = batch.verify_many(self.folders)
        doc['results'][0]['folder'] = 'folder\x1b[2J'
        out = io.StringIO()
        with redirect_stdout(out): batch.display(doc)
        self.assertNotIn('\x1b', out.getvalue())
        self.assertIn('\\u001b', out.getvalue())

    def test_rejects_empty_and_oversized_batches(self):
        for folders in ([], ['x']*257):
            with patch.object(core, 'verify') as verify, self.assertRaises(ValueError):
                batch.verify_many(folders)
            verify.assert_not_called()


if __name__ == '__main__': unittest.main()
