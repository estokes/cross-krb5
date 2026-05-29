# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`cross-krb5` is a small, safe, cross-platform Kerberos 5 (GSSAPI/SSPI) library.
It exposes a single uniform API that compiles against the OS-native security
layer — GSSAPI (via `libgssapi`) on Unix, SSPI (via the `windows` crate) on
Windows — so that services interoperate transparently across platforms.

## Build / check / run

```sh
cargo build                      # build for the host platform
cargo build --no-default-features # build with the `iov` feature OFF (emulated iov)
cargo check
cargo clippy
cargo doc --open

# The auth example performs a real client<->server Kerberos handshake in two
# threads. It needs a live KDC, a valid TGT (run `kinit` first), and an SPN
# that resolves in your realm:
cargo run --example auth -- service/host@REALM

# Unix-only: round-trips a libgssapi Cred into a cross-krb5 Cred and back.
cargo run --example cred
```

There are **no unit/integration tests** — authentication can't be exercised
without a live KDC, so verification is manual via the `auth` example against a
real realm.

### Build prerequisites (Unix)

- The `libgssapi` dependency is a **local path override**:
  `path = "../libgssapi/libgssapi"` in `Cargo.toml`. A sibling checkout of the
  `libgssapi` repo must exist next to this one (it does in this environment).
  The `version = "0.9.0"` is the crates.io fallback, but the path wins when
  present.
- A system GSSAPI/krb5 implementation (MIT krb5 or Heimdal) must be installed;
  `libgssapi` links against it.

## Architecture

### Facade + per-platform impl (the core pattern)

`src/lib.rs` is a thin, platform-agnostic facade. It defines the public traits
(`K5Ctx`, `K5ServerCtx`, `K5Cred`) and public newtype wrappers (`Cred`,
`ClientCtx`, `ServerCtx`, `PendingClientCtx`, `PendingServerCtx`, the `Step`
enum, and the `InitiateFlags` / `AcceptFlags` bitflags). Each wrapper holds one
field — the platform impl, aliased via `#[cfg]`:

- `#[cfg(unix)]`   → `src/unix.rs`    (GSSAPI through `libgssapi`)
- `#[cfg(windows)]` → `src/windows.rs` (SSPI through the `windows` crate)

`lib.rs` imports the chosen module's types under `*Impl` names and forwards
every method to them.

**The contract that makes this work: both platform modules must expose
identically-named types with identical method signatures.** `lib.rs` is
compiled against whichever module matches the target, so it only sees one set.
If you change a method's signature in `unix.rs`, you must mirror it in
`windows.rs` (and vice versa) or the *other* platform's build breaks — and CI
on the platform you didn't touch is the only thing that catches it.

### Typestate handshake (invalid states unrepresentable)

Context setup is a typestate machine, so you cannot call `wrap`/`unwrap` on a
context that isn't fully established:

1. `ClientCtx::new(...)` / `ServerCtx::new(...)` → a `Pending*Ctx` plus the
   first token to send to the peer. (`*_with_cred` variants take an explicit
   `Cred` instead of acquiring the process default.)
2. Feed peer tokens to `pending.step(token)`, which returns `Step::Continue`
   (more tokens to exchange) or `Step::Finished` (the established `ClientCtx`/
   `ServerCtx`, plus an *optional* final token).
3. Only the established context implements `K5Ctx` (wrap/unwrap/ttl). The
   server context also implements `K5ServerCtx::client()` to read the peer's
   principal name.

The handshake may exchange **more than two tokens** (notably to surface error
messages), so always loop on `step` until `Finished` rather than assuming a
fixed round count — see `examples/auth.rs`.

### Two wrap paths: contiguous vs. IOV

- `wrap` / `unwrap` — contiguous buffers, copying.
- `wrap_iov` / `unwrap_iov` — in-place, allocation-free using `bytes::BytesMut`
  chains. `wrap_iov` returns a non-contiguous `Buf` (use `writev` /
  tokio `write_buf` / `Buf::chunks_vectored` to send it).

The **`iov` feature is on by default**. With it off, the IOV calls are emulated
on top of `wrap`/`unwrap` (correct, but no speed gain — typically 2–3× slower).
`iov` is **not available on macOS**; enabling it there fails to compile.

The associated buffer types differ per platform (don't assume they match):
Unix `Buffer = libgssapi::util::Buf` and a 4-segment IOV chain
(header/data/padding/trailer); Windows `Buffer = BytesMut` and a 3-segment IOV
chain (header/data/padding — no trailer).

### Platform-specific behavior to keep in mind

- **`NEGOTIATE_TOKEN` flags are Windows-only.** They switch SSPI to the
  "Negotiate" package instead of "Kerberos" for peers that send SPNEGO tokens.
  On Unix the flag is accepted but ignored; the Unix path always uses the raw
  Kerberos 5 mechanism (`GSS_MECH_KRB5`) with mutual-auth + confidentiality.
- **Credential injection** crosses the FFI boundary via `From`/`Into` on
  `Cred`: `libgssapi::credential::Cred` on Unix, `SecHandle` on Windows.
- The Windows context structs manage raw SSPI handles, so they carry explicit
  `Drop` and hand-written `Debug` impls; the Unix side leans on `libgssapi`'s
  own RAII.

## Style

`rustfmt.toml` sets `max_width = 90` (block indent, 4 spaces, merged imports).
Match the existing formatting by hand — per the global instructions, do **not**
run `cargo fmt`, as it would produce a large unrelated diff.
