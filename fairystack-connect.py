#!/usr/bin/env python3
"""Install and run a verified, loopback-only FairyStack SSH tunnel."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path


# Enrollment values are interpolated into SSH configuration, so accept only
# simple names rather than trying to escape arbitrary user-supplied text.
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
SAFE_HOST = re.compile(r"^[A-Za-z0-9.-]+$")
FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]+={0,2}$")

# Keep everything FairyStack adds in its own directory. The one-line Include
# below lets the user's existing ~/.ssh/config remain otherwise untouched.
SSH_DIR = Path.home() / ".ssh"
INSTALL_DIR = SSH_DIR / "fairystack"
CONFIG_PATH = INSTALL_DIR / "config"
KNOWN_HOSTS_PATH = INSTALL_DIR / "known_hosts"
MAIN_CONFIG_PATH = SSH_DIR / "config"
INCLUDE_LINE = "Include ~/.ssh/fairystack/config"


def fail(message: str) -> None:
    raise SystemExit(f"FairyStack connection setup failed: {message}")


def load_enrollment(path: Path) -> dict:
    """Load and strictly validate the non-secret connection description."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read enrollment file: {exc}")
    required = {"name", "host", "ssh_user", "identity_file", "host_key", "host_key_fingerprint"}
    missing = sorted(required - value.keys())
    if missing:
        fail("enrollment file is missing: " + ", ".join(missing))
    if not SAFE_NAME.fullmatch(str(value["name"])):
        fail("name contains unsupported characters")
    if not SAFE_HOST.fullmatch(str(value["host"])):
        fail("host is not a hostname or IPv4 address")
    if not SAFE_NAME.fullmatch(str(value["ssh_user"])):
        fail("ssh_user contains unsupported characters")
    if value.get("jump_host") and not SAFE_NAME.fullmatch(str(value["jump_host"])):
        fail("jump_host contains unsupported characters")
    fingerprint = str(value["host_key_fingerprint"])
    if not FINGERPRINT.fullmatch(fingerprint):
        fail("host_key_fingerprint is invalid")
    port = int(value.get("local_port", 19150))
    if not 1024 <= port <= 65535:
        fail("local_port must be between 1024 and 65535")
    value["local_port"] = port
    return value


def atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    """Replace a file completely so an interruption cannot leave half a config."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def verify_host_key(host_key: str, expected: str) -> str:
    """Prove the supplied server key matches the separately issued fingerprint."""
    fields = host_key.strip().split()
    if len(fields) < 2 or fields[0] not in {"ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"}:
        fail("host_key is not a supported SSH public key")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
        handle.write(f"host {fields[0]} {fields[1]}\n")
        handle.flush()
        try:
            result = subprocess.run(
                ["ssh-keygen", "-lf", handle.name, "-E", "sha256"], check=True,
                capture_output=True, text=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.SubprocessError) as exc:
            fail(f"could not verify SSH host key: {exc}")
    actual = next((part for part in result.stdout.split() if part.startswith("SHA256:")), "")
    if actual != expected:
        fail(f"host-key fingerprint mismatch: expected {expected}, received {actual or 'none'}")
    return f"{fields[0]} {fields[1]}"


def ensure_main_include() -> None:
    SSH_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    current = MAIN_CONFIG_PATH.read_text(encoding="utf-8") if MAIN_CONFIG_PATH.exists() else ""
    # Include must be in the global section. Appending it after a Host block makes
    # OpenSSH treat it as conditional and the generated aliases disappear.
    preserved = [line for line in current.splitlines() if line.strip() != INCLUDE_LINE]
    body = "\n".join(preserved).lstrip("\n")
    atomic_write(MAIN_CONFIG_PATH, INCLUDE_LINE + "\n" + body + ("\n" if body else ""))


def setup(enrollment_path: Path) -> None:
    """Install the verified host identity and two isolated SSH aliases."""
    value = load_enrollment(enrollment_path)

    # The private key is delivered separately from this public repository. SSH
    # refuses keys with loose permissions, so normalize it before first use.
    identity = Path(os.path.expanduser(str(value["identity_file"]))).resolve()
    if not identity.is_file():
        fail(f"SSH private key does not exist: {identity}")
    identity.chmod(0o600)
    public_key = verify_host_key(str(value["host_key"]), str(value["host_key_fingerprint"]))
    host = str(value["host"])
    alias = "fairystack-" + str(value["name"])
    host_key_name = f"[{host}]:22" if ":" in host else host

    # Use a dedicated known-hosts file. This pins the issued server key without
    # changing or relying on the user's general SSH trust database.
    atomic_write(KNOWN_HOSTS_PATH, f"{host_key_name} {public_key}\n")

    # The base alias is useful for diagnostics. Every network operation has a
    # connection deadline and strict key checking; no interactive trust prompt
    # can silently accept a different machine.
    lines = [
        f"Host {alias}", f"  HostName {host}", f"  User {value['ssh_user']}",
        f"  IdentityFile {identity}", "  IdentitiesOnly yes", "  StrictHostKeyChecking yes",
        f"  UserKnownHostsFile {KNOWN_HOSTS_PATH}", "  ExitOnForwardFailure yes",
        "  ConnectTimeout 10", "  ServerAliveInterval 30", "  ServerAliveCountMax 3",
    ]
    if value.get("jump_host"):
        lines.append(f"  ProxyJump {value['jump_host']}")

    # The tunnel alias does not open a remote shell. It exposes FairyStack only
    # on this computer's loopback address and fails if forwarding cannot start.
    lines.extend([
        "", f"Host {alias}-tunnel", f"  HostName {host}", f"  User {value['ssh_user']}",
        f"  IdentityFile {identity}", "  IdentitiesOnly yes", "  StrictHostKeyChecking yes",
        f"  UserKnownHostsFile {KNOWN_HOSTS_PATH}", "  ExitOnForwardFailure yes",
        "  ConnectTimeout 10", "  ServerAliveInterval 30", "  ServerAliveCountMax 3",
        f"  LocalForward {value['local_port']} 127.0.0.1:9150", "  SessionType none",
    ])
    if value.get("jump_host"):
        lines.append(f"  ProxyJump {value['jump_host']}")
    atomic_write(CONFIG_PATH, "\n".join(lines) + "\n")

    # Save the validated values so future `open` calls do not need to download
    # the enrollment again. This file contains routing details, not credentials.
    atomic_write(INSTALL_DIR / "enrollment.json", json.dumps(value, indent=2, sort_keys=True) + "\n")
    ensure_main_include()
    print(f"Configured {alias}. Run: {Path(__file__).name} open {value['name']}")


def port_available(port: int) -> bool:
    """Check whether the requested local tunnel address can be claimed."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def open_tunnel(name: str) -> None:
    """Start SSH, verify FairyStack becomes reachable, and supervise the tunnel."""
    enrollment_path = INSTALL_DIR / "enrollment.json"
    value = load_enrollment(enrollment_path)
    if value["name"] != name:
        fail(f"installed enrollment is for {value['name']}, not {name}")
    port = value["local_port"]
    if not port_available(port):
        fail(f"localhost:{port} is already in use; close the existing tunnel and retry")
    alias = "fairystack-" + name + "-tunnel"
    # SSH reads every security and forwarding option from the generated alias.
    # Keep stderr so a failed connection can be reported in plain language.
    process = subprocess.Popen(["ssh", alias], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)

    def stop(_signum=None, _frame=None):
        if process.poll() is None:
            process.terminate()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    # Do not declare success merely because the SSH process is alive. Probe the
    # service through the new local tunnel, with both per-request and overall
    # deadlines, before telling the user where to open the interface.
    deadline = time.monotonic() + 15
    url = f"http://127.0.0.1:{port}/api/version"
    while time.monotonic() < deadline and process.poll() is None:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    print(f"FairyStack is ready: http://localhost:{port}/dashboard", flush=True)
                    process.wait()
                    return
        except OSError:
            time.sleep(0.25)
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
        fail("tunnel opened but FairyStack did not become ready within 15 seconds")
    error = (process.stderr.read() if process.stderr else "").strip()
    fail(error or f"ssh exited with status {process.returncode}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup_parser = commands.add_parser("setup", help="install a customer enrollment file")
    setup_parser.add_argument("enrollment", type=Path)
    open_parser = commands.add_parser("open", help="open and monitor the private tunnel")
    open_parser.add_argument("name")
    args = parser.parse_args()
    if args.command == "setup":
        setup(args.enrollment)
    else:
        open_tunnel(args.name)


if __name__ == "__main__":
    main()
