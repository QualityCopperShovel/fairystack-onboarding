# FairyStack onboarding

This public repository contains the small client used to connect a computer to
a private FairyStack installation. You can inspect the complete client before
running it.

## Files

- [`fairystack-connect.py`](fairystack-connect.py) is the canonical connector.
  It verifies the issued server identity, writes an isolated SSH profile, opens
  the local connection, and reports failures with bounded timeouts.
- [`fairystack-enrollment.example.json`](fairystack-enrollment.example.json)
  documents the enrollment shape with nonfunctional example routing data. A
  real enrollment is issued separately for each user and is not stored here.

The repository contains no private keys, passwords, web credentials, API
tokens, prompts, application data, or FairyStack server source code.

## Inspect and test

```bash
python3 -m unittest discover -s tests
python3 fairystack-connect.py --help
```

The live onboarding guide links directly to the connector's canonical raw file
in this repository. User-specific enrollment details remain on the onboarding
service.

## Security

The connector requires strict host-key verification and accepts only a bounded
set of enrollment fields. Do not put private keys or passwords in an enrollment
file or commit real customer enrollment files to this repository.
