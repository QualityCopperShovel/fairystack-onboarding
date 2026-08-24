# FairyStack onboarding

This public repository contains the small client used to connect a computer to
a private FairyStack installation. You can inspect the complete client before
running it.

## Files

- [`fairystack-setup.py`](fairystack-setup.py) is the canonical setup script.
  It verifies the issued server identity, writes an isolated SSH profile, opens
  the local connection, and reports failures with bounded timeouts.
- [`fairystack-workspace.example.json`](fairystack-workspace.example.json)
  documents the connection details with nonfunctional example routing data.
  Real connection details are issued privately and are not stored here.

The repository contains no private keys, passwords, web credentials, API
tokens, prompts, application data, or FairyStack server source code.

## Inspect and test

```bash
python3 -m unittest discover -s tests
python3 fairystack-setup.py --help
```

The live onboarding guide links directly to the connector's canonical raw file
in this repository. User-specific connection details remain private.

## Security

The connector requires strict host-key verification and accepts only a bounded
set of connection fields. Do not put private keys or passwords in a connection
file or commit real customer connection files to this repository.
