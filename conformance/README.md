# Dart / Rust provider compatibility

This suite calls the actual Filen and Internxt package APIs. Python `hashlib`
and `cryptography` generate independent reference data; neither production
implementation supplies the oracle. All keys, passwords and bytes are synthetic.
No account or live provider endpoint is required.

Run with Python 3.12+, Dart 3.13.7 and stable Rust:

```sh
python -m pip install cryptography==50.0.0
python -m unittest discover -s conformance -p 'test_*.py' -v
python conformance/run.py --pointycastle '^4.0.0'
# Release/default-promotion gate: also fail on reviewed compatibility gaps.
python conformance/run.py --pointycastle '^4.0.0' --strict
```

CI runs the SDK lockfile combination (PointyCastle 3.9.1 / dart_pg 2.0.0) and
the app combination (PointyCastle 4.0.0 / dart_pg 2.1.0). A fresh SDK dependency
resolution with PointyCastle 3.x and dart_pg 2.1.0 fails compilation because of
missing cipher classes; use `--dart-pg 2.0.0` when testing the older combination.
Both software Filen AES-GCM backends are checked.
The Linux run also requires the selected native backend to load OpenSSL; a
silent software fallback fails. The Dart probe is compiled to a CLI executable
before running. Reports include both compiled probes for repeatable fixture
checks (`--prebuilt /path/to/extracted/results`), with the tested source versions
and lockfiles supplied by the workflow commit/artifact.
The harness accepts `--dart-filen`, `--dart-internxt`, `--rust-filen` and
`--rust-internxt` source directories to qualify vendored app variants without
changing their production dependencies. It restores the Rust probe manifest
after running.

The initial corpus covers login derivation, metadata, authenticated chunk
encryption, password hashes, OpenSSL CBC envelopes, bucket/file key derivation
and CTR ranges. It includes Unicode, NUL/control characters, zero bytes,
15/16/17-byte boundaries, 64 KiB boundaries, data over 1 MiB, counter wrap,
4 GiB offsets, wrong keys, truncation, invalid encodings and tampering.
Encryption exports are decrypted by every other engine/backend. Results are
compared with the independent oracle, so identical mistakes in both engines
still fail. Missing cases, unexpected exports, rejected positive cases and
Rust panics fail.
Valid AES-128/192 ciphertext and short/long encryption keys must be rejected by
the AES-256 APIs. Incremental CTR output must match a single continuous stream
across multiple blocks and a partial final block.

Loopback HTTP fixtures exercise real listing and mutation APIs with independent
encrypted metadata. They cover empty/Unicode directories, 49/50/51/100/101-item
pagination, cache reuse, 401/403/404, malformed JSON, missing or invalid response
collections, unreadable metadata, one transient 503 and create/rename/move/trash
success and denial. The server verifies bearer authentication, pagination
offsets, sort parameters, methods and mutation bodies. Denied mutations must
make exactly one mutation request. Dart's parent-cache metadata reads are
verified separately from the mutation, rather than requiring identical internal
request counts. No production HTTP endpoint is used by these tests.

`results/report.md` and `results/report.json` distinguish unexpected failures
from exact, reviewed compatibility differences. Reviewed differences are
regression baselines, never evidence that the implementations are equivalent.
Any difference blocks `--strict` and the reported `promotion_ready` flag.
Removing or changing a difference requires updating its precise expected
result, with a protocol compatibility review for existing encrypted data.

Known diagnostic cases include the Dart empty-CBC limitation, missing CBC
envelope validation, legacy Latin-1 versus UTF-8 secret encoding, and negative
CTR offsets. Do not change stored credential encoding merely to make parity
green. The Rust malformed-Unicode metadata rejection has a package unit test.

This suite does not yet certify full login/key exchange, live provider behavior,
all transfer orchestration, platform FFI packaging, GUI settings or performance.
It does not change engine defaults or introduce automatic operation replay.
Keep Dart as the Flutter provider default until required compatibility and app
surface gates are met. Existing package tests remain necessary.
