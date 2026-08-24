import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "fairystack-setup.py"
PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICekrrR1aZN4Zq8P26X6d6CloRqFgG5S4LnLVPbSX4lr"
FINGERPRINT = "SHA256:FJlAi3c2knEL+N+Lvdw3ucsAur4T5WaniH875k68bME"


class FairyStackConnectTest(unittest.TestCase):
    def test_connector_stays_small_enough_to_review(self):
        self.assertLessEqual(len(SCRIPT.read_text().splitlines()), 120)
        self.assertNotIn("def fail(", SCRIPT.read_text())
        self.assertIn("\n        \"  ConnectTimeout 10\",\n", SCRIPT.read_text())

    def test_connector_starts_with_a_call_tree(self):
        source = SCRIPT.read_text()
        self.assertLess(source.index("# Call tree"), source.index("import argparse"))
        for operation in ("setup(connection_file)", "read_connection_details(connection_file)", "verify_server_identity(value)"):
            self.assertIn(operation, source)
        self.assertNotIn("open_tunnel", source)
        self.assertIn('private setup link downloads it temporarily to /tmp', source)
        self.assertIn('saves only the SSH config and pinned server key', source)
        self.assertNotIn('~/.ssh/fairystack/connection.json', source)
        self.assertIn('reads this public key and prints its SHA-256 identity code', source)
        self.assertIn('The address says where the server is; its public SSH key says which server it is.', source)

    def connection_details(self, root, fingerprint=FINGERPRINT):
        key = root / "customer-key"
        key.write_text("not a real private key")
        value = {
            "name": "acme", "host": "203.0.113.10", "ssh_user": "tunnel_acme",
            "identity_file": str(key), "host_key": PUBLIC_KEY,
            "host_key_fingerprint": fingerprint, "local_port": 19150,
        }
        path = root / "connection.json"
        path.write_text(json.dumps(value))
        return path, key

    def run_setup(self, home, connection_details, check=True):
        env = {**os.environ, "HOME": str(home)}
        return subprocess.run(
            ["python3", str(SCRIPT), str(connection_details)], env=env,
            capture_output=True, text=True, timeout=5, check=check,
        )

    def test_setup_preserves_ssh_config_and_installs_verified_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ssh = root / ".ssh"
            ssh.mkdir()
            (ssh / "config").write_text("Host existing\n  HostName example.test\n")
            connection_details, key = self.connection_details(root)
            first = self.run_setup(root, connection_details)
            self.run_setup(root, connection_details)
            main = (ssh / "config").read_text()
            profile = (ssh / "fairystack" / "config").read_text()
            self.assertIn("Host existing", main)
            self.assertEqual(main.count("Include ~/.ssh/fairystack/config"), 1)
            self.assertTrue(main.startswith("Include ~/.ssh/fairystack/config\n"))
            self.assertIn("Host fairystack-acme-tunnel", profile)
            self.assertNotIn("Host fairystack-acme\n", profile)
            self.assertEqual(profile.count("Host "), 1)
            self.assertIn("LocalForward 19150 127.0.0.1:9150", profile)
            self.assertIn("SessionType none", profile)
            self.assertIn("StrictHostKeyChecking yes", profile)
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            self.assertFalse((ssh / "fairystack" / "connection.json").exists())
            self.assertIn("ssh fairystack-acme-tunnel", first.stdout)

    def test_fingerprint_mismatch_fails_without_installing_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            connection_details, _ = self.connection_details(root, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            result = self.run_setup(root, connection_details, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("fingerprint mismatch", result.stderr)
            self.assertFalse((root / ".ssh" / "fairystack" / "config").exists())

    def test_ssh_config_injection_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            connection_details, _ = self.connection_details(root)
            value = json.loads(connection_details.read_text())
            value["host"] = "example.test\n  ProxyCommand danger"
            connection_details.write_text(json.dumps(value))
            result = self.run_setup(root, connection_details, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid host", result.stderr)
            self.assertFalse((root / ".ssh" / "fairystack" / "config").exists())


if __name__ == "__main__":
    unittest.main()
