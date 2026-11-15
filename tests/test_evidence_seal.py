import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


CLI = Path(__file__).resolve().parents[1] / "evidence_seal.py"


class EvidenceSealTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.evidence = self.base / "evidence"
        self.evidence.mkdir()
        self.manifest = self.base / "manifest.json"

    def run_cli(self, command, evidence=None, manifest=None, *, expected=0):
        result = subprocess.run(
            [sys.executable, CLI, command, evidence or self.evidence, manifest or self.manifest],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def test_snapshot_is_portable_and_deterministic(self):
        (self.evidence / "nested").mkdir()
        content = b"case data\x00" * 120_000
        (self.evidence / "nested" / "log file.txt").write_bytes(content)
        (self.evidence / "empty").touch()
        self.run_cli("snapshot")
        manifest = json.loads(self.manifest.read_bytes())
        self.assertEqual(manifest["files"][1], {
            "path": "nested/log file.txt",
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        })
        copied = self.base / "working-copy"
        shutil.copytree(self.evidence, copied)
        self.assertIn("Verified 2 file(s).", self.run_cli("verify", copied).stdout)
        second_manifest = self.base / "second.json"
        self.run_cli("snapshot", copied, second_manifest)
        self.assertEqual(self.manifest.read_bytes(), second_manifest.read_bytes())

    def test_verify_reports_all_mismatches_and_detects_same_size_edit(self):
        (self.evidence / "changed").write_bytes(b"before")
        (self.evidence / "removed").touch()
        self.run_cli("snapshot")
        (self.evidence / "changed").write_bytes(b"edited")
        (self.evidence / "removed").unlink()
        (self.evidence / "added\nfile").touch()
        result = self.run_cli("verify", expected=1)
        self.assertEqual(result.stdout.splitlines(), [
            'ADDED "added\\nfile"',
            'MISSING "removed"',
            'CHANGED "changed"',
            "Mismatch: 1 added, 1 missing, 1 changed.",
        ])

    def test_snapshot_protects_existing_manifest_and_evidence_tree(self):
        self.manifest.write_bytes(b"original")
        self.run_cli("snapshot", expected=2)
        self.assertEqual(self.manifest.read_bytes(), b"original")
        inside = self.evidence / "manifest.json"
        self.run_cli("snapshot", manifest=inside, expected=2)
        self.assertFalse(inside.exists())

    def test_symlinks_and_fifos_fail_without_writing_a_manifest(self):
        self.manifest.write_bytes(b"outside evidence")
        for target in (self.manifest, self.base, self.base / "missing"):
            with self.subTest(target=target):
                symlink = self.evidence / "symlink"
                symlink.symlink_to(target)
                result = self.run_cli("snapshot", manifest=self.base / "new.json", expected=2)
                self.assertIn("symlink", result.stderr)
                self.assertFalse((self.base / "new.json").exists())
                symlink.unlink()
        self.manifest.unlink()
        os.mkfifo(self.evidence / "fifo")
        self.run_cli("snapshot", expected=2)
        self.assertFalse(self.manifest.exists())

    def test_invalid_manifest_entries_fail_verification(self):
        entry = {"path": "file", "size": 0, "sha256": "0" * 64}
        for files in ([entry, entry], [{**entry, "path": "../file"}], [{**entry, "size": True}]):
            with self.subTest(files=files):
                self.manifest.write_text(
                    json.dumps({"format": "evidence-seal-sha256-v1", "files": files}),
                    encoding="utf-8",
                )
                self.run_cli("verify", expected=2)

    def test_verify_rejects_a_manifest_fifo_without_blocking(self):
        os.mkfifo(self.manifest)
        result = self.run_cli("verify", expected=2)
        self.assertIn("the manifest must be a regular file", result.stderr)
