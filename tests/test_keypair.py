import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import start


class EnsureKeypairTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.private_key = Path(self.tempdir.name) / "cscs-key"
        self.public_key = self.private_key.with_suffix(".pub")

    def test_generates_keypair_when_both_files_are_missing(self):
        def fake_run(cmd, **_kwargs):
            if cmd[1] == "-t":
                self.private_key.write_text("private")
                self.public_key.write_text("ssh-ed25519 AAAA generated\n")
                return subprocess.CompletedProcess(cmd, 0)
            return subprocess.CompletedProcess(
                cmd, 0, stdout="ssh-ed25519 AAAA generated\n"
            )

        with patch("start.subprocess.run", side_effect=fake_run) as run:
            public_key = start.ensure_keypair(self.private_key)

        self.assertEqual(public_key, "ssh-ed25519 AAAA generated\n")
        self.assertEqual(run.call_args_list[0].args[0][1], "-t")

    def test_derives_missing_public_key_from_existing_private_key(self):
        self.private_key.write_text("private")

        with patch(
            "start.subprocess.run",
            return_value=subprocess.CompletedProcess(
                ["ssh-keygen"], 0, stdout="ssh-ed25519 AAAA derived\n"
            ),
        ):
            public_key = start.ensure_keypair(self.private_key)

        self.assertEqual(public_key, "ssh-ed25519 AAAA derived\n")
        self.assertEqual(self.public_key.read_text(), "ssh-ed25519 AAAA derived\n")

    def test_rejects_mismatched_public_key(self):
        self.private_key.write_text("private")
        self.public_key.write_text("ssh-ed25519 AAAA stale\n")

        with patch(
            "start.subprocess.run",
            return_value=subprocess.CompletedProcess(
                ["ssh-keygen"], 0, stdout="ssh-ed25519 BBBB derived\n"
            ),
        ):
            with self.assertRaises(start.PublicKeyMismatchError):
                start.ensure_keypair(self.private_key)

    def test_rejects_public_key_without_private_key(self):
        self.public_key.write_text("ssh-ed25519 AAAA stale\n")

        with patch("start.subprocess.run") as run:
            with self.assertRaises(start.MissingPrivateKeyError):
                start.ensure_keypair(self.private_key)

        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
