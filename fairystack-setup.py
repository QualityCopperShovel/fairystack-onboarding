#!/usr/bin/env python3
"""Set up a private FairyStack SSH tunnel."""

# Call tree
# ├─ setup(connection_file)
# │  ├─ read_connection_details(connection_file)
# │  ├─ verify_server_identity(value)
# │  └─ write(...) → known_hosts, tunnel config, ~/.ssh/config

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

# Allow only single-line SSH-safe values so connection data cannot add configuration directives.
SAFE = re.compile(r"^[A-Za-z0-9_.-]+$")
HOST = re.compile(r"^[A-Za-z0-9.-]+$")
SSH = Path.home() / ".ssh"
DIR = SSH / "fairystack"
INCLUDE = "Include ~/.ssh/fairystack/config"

# FairyStack creates this file; your private setup link downloads it temporarily to /tmp.
# setup checks it once, then saves only the SSH config and pinned server key.
def read_connection_details(connection_file):
    try:
        value = json.loads(connection_file.read_text())
        required = {"name", "host", "ssh_user", "identity_file", "host_key", "host_key_fingerprint"}
        missing = required - value.keys()
        if missing:
            raise SystemExit("FairyStack setup failed: missing " + ", ".join(sorted(missing)))
        if not SAFE.fullmatch(str(value["name"])) or not SAFE.fullmatch(str(value["ssh_user"])):
            raise SystemExit("FairyStack setup failed: invalid name or SSH user")
        if not HOST.fullmatch(str(value["host"])):
            raise SystemExit("FairyStack setup failed: invalid host")
        if value.get("jump_host") and not SAFE.fullmatch(str(value["jump_host"])):
            raise SystemExit("FairyStack setup failed: invalid jump host")
        value["local_port"] = int(value.get("local_port", 19150))
        if not 1024 <= value["local_port"] <= 65535:
            raise SystemExit("FairyStack setup failed: invalid local port")
        return value
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise SystemExit(f"FairyStack setup failed: invalid connection details: {error}")

def write(path, text):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as handle:
        handle.write(text)
        temporary = handle.name
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)

def verify_server_identity(value):
    fields = str(value["host_key"]).split()
    if len(fields) < 2 or fields[0] not in {"ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"}:
        raise SystemExit("FairyStack setup failed: invalid SSH host key")
    with tempfile.NamedTemporaryFile("w") as key_file:
        key_file.write(f"host {fields[0]} {fields[1]}\n")
        key_file.flush()
        try:
            # Despite its name, ssh-keygen -l only reads this public key and prints its SHA-256 identity code.
            # It creates nothing and makes no network connection.
            result = subprocess.run(
                ["ssh-keygen", "-lf", key_file.name, "-E", "sha256"],
                check=True, capture_output=True, text=True, timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise SystemExit(f"FairyStack setup failed: cannot verify SSH host key: {error}")
    fingerprint = next((word for word in result.stdout.split() if word.startswith("SHA256:")), "")
    if fingerprint != value["host_key_fingerprint"]:
        raise SystemExit("FairyStack setup failed: SSH host-key fingerprint mismatch")
    return " ".join(fields[:2])


def setup(connection_file):
    value = read_connection_details(connection_file)
    identity = Path(os.path.expanduser(value["identity_file"])).resolve()
    if not identity.is_file():
        raise SystemExit(f"FairyStack setup failed: private key not found: {identity}")
    identity.chmod(0o600)
    write(DIR / "known_hosts", f'{value["host"]} {verify_server_identity(value)}\n')

    # This profile can only forward the FairyStack port; it does not open a shell.
    lines = [
        f'Host fairystack-{value["name"]}-tunnel',
        f'  HostName {value["host"]}',
        f'  User {value["ssh_user"]}',
        f"  IdentityFile {identity}",
        "  IdentitiesOnly yes",
        "  StrictHostKeyChecking yes",
        f"  UserKnownHostsFile {DIR / 'known_hosts'}",
        "  ExitOnForwardFailure yes",
        "  ConnectTimeout 10",
        "  ServerAliveInterval 30",
        "  ServerAliveCountMax 3",
        f'  LocalForward {value["local_port"]} 127.0.0.1:9150',
        "  SessionType none",
    ]
    if value.get("jump_host"):
        lines.append(f'  ProxyJump {value["jump_host"]}')
    write(DIR / "config", "\n".join(lines) + "\n")
    current = (SSH / "config").read_text() if (SSH / "config").exists() else ""
    body = "\n".join(line for line in current.splitlines() if line.strip() != INCLUDE).lstrip("\n")
    write(SSH / "config", INCLUDE + "\n" + body + ("\n" if body else ""))
    print(f'Configured FairyStack. Open it with: ssh fairystack-{value["name"]}-tunnel')


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("connection_file", type=Path)
args = parser.parse_args()
setup(args.connection_file)
