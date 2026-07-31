# crisp-internxt

## Unofficial Internxt Drive client

This is an independent, unofficial implementation. It is not affiliated with,
endorsed by, or supported by Internxt.

Purpose-built Rust client and CLI for Internxt Cloud Drive. It is the native
Internxt transport layer used by CrispSorter, but can also be built and used
as an independent library or command-line tool.

> Unofficial software. This project is not affiliated with or endorsed by
> Internxt.

## Why this crate exists

This crate is deliberately focused on the file-system-facing Drive workflow:

- remote path resolution (`/a/b/file.txt` → Drive UUIDs);
- login, session refresh, and explicit session serialization;
- Internxt-compatible end-to-end encryption and decryption;
- bounded-memory streaming uploads and ranged downloads;
- automatic single-part versus multipart uploads;
- serial multipart uploads by default for gateway reliability;
- opt-in concurrent multipart workers for controlled testing;
- persisted resumable upload state, including file key/index, upload UUID,
  upload ID, part URLs, ETags, and completed-part state;
- recursive upload/download with filters, conflict policies, timestamp
  preservation, and skip-unchanged support;
- search, copy, update, move, rename, trash, restore, purge, and empty-trash
  operations.

It is intentionally independent of the general-purpose `internxt-core-rust`
reference implementation. That project is useful as a protocol and crypto
oracle; this crate owns path semantics, transfer policy, resume behavior, and
the CLI needed by CrispSorter.

## Install

Install the CLI from crates.io:

```sh
cargo install crisp-internxt
```

Or add the library to an application:

```toml
[dependencies]
crisp-internxt = "0.1"
```

The package exposes the `crisp_internxt` library and the
`crisp-internxt` binary.

## CLI quick start

The CLI reads passwords from stdin and stores credentials only in the session
file path explicitly supplied by the caller. Session files contain bearer
tokens and the account mnemonic; protect them with filesystem permissions and
delete them after testing.

```sh
printf '%s\n' "$INTERNXT_PASSWORD" \
  | crisp-internxt login user@example.com --session /tmp/internxt-session.json

crisp-internxt list /tmp/internxt-session.json .
crisp-internxt refresh /tmp/internxt-session.json
crisp-internxt read /tmp/internxt-session.json /remote/file.bin ./file.bin
crisp-internxt write /tmp/internxt-session.json ./file.bin /remote/file.bin
```

For a live account, use a throwaway test folder and clean it afterward. The
CLI does not print passwords or session contents.

### Upload diagnostics

Verbose mode prints path resolution, transfer stages, multipart configuration,
and timing context without printing credentials:

```sh
crisp-internxt write \
  /tmp/internxt-session.json \
  ./large-file.tar.gz \
  /uploads/large-file.tar.gz \
  --verbose
```

Files below 100 MiB use one encrypted network upload. Files at or above
100 MiB use 30 MiB multipart parts. Multipart workers default to `1`, which
keeps the gateway-safe serial behavior. Experimental concurrency can be
selected explicitly:

```sh
crisp-internxt write \
  /tmp/internxt-session.json ./large-file.tar.gz /uploads/large-file.tar.gz \
  --multipart-workers 3 \
  --verbose
```

## Resumable uploads

For an interrupted multipart upload, provide a state-file path:

```sh
crisp-internxt write \
  /tmp/internxt-session.json \
  ./large-file.tar.gz \
  /uploads/large-file.tar.gz \
  --resume-state ./large-file.tar.gz.internxt-resume.json \
  --verbose
```

The state file is written atomically and binds the upload to the original
file identity and encryption material. It records the generated file index,
upload UUID, network upload ID, part URLs, part count, part size, and completed
ETags. A resumed run therefore continues the same encrypted upload instead of
re-encrypting chunks with a new key. Remove the state file only after the
remote file has been verified or when abandoning that upload.

## Recursive transfers

```sh
crisp-internxt write-tree \
  /tmp/internxt-session.json ./local-folder /remote-folder \
  --on-conflict skip \
  --include '*.pdf' \
  --exclude 'tmp/**' \
  --preserve-timestamps \
  --skip-unchanged

crisp-internxt read-tree \
  /tmp/internxt-session.json /remote-folder ./restored \
  --on-conflict overwrite \
  --preserve-timestamps
```

Use `write-tree --dry-run` to inspect a local tree without contacting Drive.
Conflict policies are `fail`, `skip`, and `overwrite`.

## Library example

```rust,no_run
use crisp_internxt::{InternxtNativeClient, InternxtSession};

fn example(session: &InternxtSession) -> anyhow::Result<()> {
    let client = InternxtNativeClient::new(
        &session.drive_api_url,
        &session.new_token,
    )?;

    let remote = client.resolve_path(session, "/documents/report.pdf".as_ref())?;
    let output = std::path::Path::new("report.pdf");
    client.download_file_to_path(session, &remote.uuid, output)?;
    Ok(())
}
```

The public API also includes `crypt_at` for aligned random-access CTR
processing, `download_file_to_path_ranged`, `TransferOptions`, progress
callbacks, and explicit `UploadResumeState` load/save/clear methods.

## Crypto compatibility

The implementation follows the formats used by Internxt clients:

- BIP-39 mnemonic seed derivation;
- SHA-512 bucket/file-key derivation;
- AES-256-CTR file encryption;
- AES-CBC `Salted__` envelopes for login password transport;
- PBKDF2-HMAC-SHA1 password hashing;
- bridge password derivation and shard metadata handling.

Crypto and transfer behavior are covered by deterministic unit tests and local
HTTP harnesses. The ignored live tests exercise authentication, path
resolution, refresh, small-file round trips, multipart transfers, recursive
transfers, search, copy, update, move, rename, trash, restore, and purge.

## Testing

Run the offline suite:

```sh
cargo test --all-targets
cargo test --all-targets --release
cargo run -- crypto-vector
```

The live tests are ignored by default because they mutate a real account and
transfer real data. Supply `INTERNXT_LOGIN` and `INTERNXT_PW`, then run them
explicitly:

```sh
INTERNXT_LOGIN=user@example.com INTERNXT_PW='...' \
  cargo test --test live -- --ignored --nocapture
```

Use a dedicated test account or test folder. Live tests attempt cleanup, but
remote cleanup should always be checked manually after network failures.

Package exactly what will be published:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo package --allow-dirty
```

## API and compatibility notes

The crate targets the gateway behavior used by Internxt Drive and may need
adjustments if Internxt changes undocumented endpoints or response shapes.
The `0.x` API is not yet stable. The default serial multipart mode is
intentional: it is the most reliable path against gateways that accept all
part PUTs but delay or intermittently reject the finalization request.

## License

Licensed under the Mozilla Public License, version 2.0. See [LICENSE](LICENSE).
