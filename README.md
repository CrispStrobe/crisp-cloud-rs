# crisp-cloud-rs

## Unofficial encrypted cloud-drive clients

This is an independent, unofficial Rust project. It is not affiliated with,
endorsed by, or supported by Internxt or Filen.

`crisp-cloud-rs` bundles two independently usable protocol clients:

- [`crisp-internxt`](crates/crisp-internxt/) — path-aware Internxt Drive
  client, streaming and multipart transfers, durable resumable uploads, and
  the `crisp-internxt` CLI.
- [`crisp-filen`](crates/crisp-filen/) — Filen v1/v2/v3 crypto and API client,
  configurable chunk/file workers, resumable transfers, recursive operations,
  and the `crisp-filen` CLI.

The root `crisp-cloud-rs` crate re-exports both backends for applications that
want one dependency:

```toml
[dependencies]
crisp-cloud-rs = "0.1"
```

```rust,no_run
use crisp_cloud_rs::{filen, internxt};

fn type_names() {
    let _: Option<filen::FilenSession> = None;
    let _: Option<internxt::InternxtSession> = None;
}
```

## Execution model

The 0.x API is explicitly blocking-only. Both provider clients use blocking
HTTP and do not create a Tokio runtime. Async applications should run calls
at their own blocking boundary, such as `tokio::task::spawn_blocking`; the
crate does not promise async portability or mix blocking calls into an async
runtime implicitly.

## Install either CLI

```sh
cargo install crisp-internxt
cargo install crisp-filen
```

Both CLIs are unofficial diagnostic tools. They read passwords from stdin or
explicit credential arguments as documented by their sub-crate README files;
session files contain sensitive bearer credentials and must be protected.

## Internxt highlights

The Internxt client provides login and refresh, remote path resolution,
encryption-compatible file transfers, ranged downloads, serial multipart by
default, opt-in concurrent multipart workers, recursive transfers, search,
copy/update/move/rename, trash recovery, and persisted resume state containing
the original file key/index, upload UUID, upload ID, URLs, and completed ETags.

## Filen highlights

The Filen client provides v1/v2/v3 metadata crypto, 2FA-aware login,
keychain-friendly sessions, listing caches, path resolution, wildcard search,
recursive transfers, configurable chunk/file workers, durable resumable
uploads and downloads, progress callbacks, timestamps, replacement, copy,
trash, and restore.

## Testing

Run all hermetic tests from the workspace:

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo package -p crisp-cloud-rs --allow-dirty
cargo package -p crisp-internxt --allow-dirty
cargo package -p crisp-filen --allow-dirty
```

Authenticated tests are ignored by default because they create remote data.
See each backend README for the required environment variables and cleanup
behavior. Use a dedicated test account or test folder.

## Status

The public API is `0.x` and may change between releases. The clients target
the currently observed gateway behavior and include local HTTP harnesses plus
crypto vectors, but cloud-provider endpoints are not stable public standards.

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
