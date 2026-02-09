## Project overview

hostexec is a host command execution daemon and client for containers. It lets
a process inside a container request command execution on the host, subject to
interactive user approval via a tmux popup. Communication uses a Unix
SOCK_SEQPACKET socket with SCM_RIGHTS fd passing.

## Architecture

- `src/main.rs` -- CLI parsing (clap) and dispatch
- `src/protocol.rs` -- wire protocol types (Request, Response, MAX_MSG)
- `src/client.rs` -- `run` subcommand: connects to daemon, sends request with fds
- `src/serve.rs` -- `serve` subcommand (daemon) and `prompt` subcommand (tmux popup UI)

## Build and test

```
cargo build
cargo clippy
cargo test
```

No CI pipeline exists. Default `rustfmt` and `clippy` settings are used (no
`rustfmt.toml` or `clippy.toml`). The Rust edition is 2024.

Always run `cargo clippy` before considering a change complete.

### Manual integration test

```bash
# Terminal 1
SOCK_FILE=$(mktemp)
cargo run -- serve --write-socket-path-to "$SOCK_FILE" --dangerously-approve-all

# Terminal 2
HOSTEXEC_SOCKET=$(cat "$SOCK_FILE") cargo run -- run echo hello
```

## Conventions

### Platform

Linux-only. The codebase uses Unix SEQPACKET sockets, SCM_RIGHTS fd passing,
`/proc/self/exe`, and `termios`. No `#[cfg]` portability gates exist.

### Error handling

Use `anyhow::Result` as the return type for all fallible functions. No custom
error types or `thiserror`.

- **Add context to every fallible operation** using `.context("lowercase
  description of what failed")` or `.with_context(|| format!(...))`. Context
  strings should be lowercase and describe what was being attempted, e.g.
  `"cannot bind socket"`, not `"BindError"`.

- **Use `bail!()` for early-return validation errors:**
  ```rust
  bail!("expected 3 fds, got {}", fds.len());
  ```

- **Never use `unwrap()` or `expect()`** except for true logic invariants.
  Prefer `unwrap_or()`, `unwrap_or_else()`, or `unwrap_or_default()` for
  fallback values.

- **Use `let _ =` to explicitly discard errors** when failure is acceptable
  (e.g. sending a response on a connection that is about to close):
  ```rust
  let _ = send_response(conn_fd, &Response::Error { message });
  ```

### Logging

Use `tracing::{info, error}` for all logging. Never use `eprintln!` except in
`client.rs` for user-facing messages (e.g. "request denied").

Use structured fields with the `%` display hint for types that implement
`Display` but not the default tracing format:
```rust
info!(path = %sock_path.display(), "listening");
info!(cmd = cmd_str, cwd = req.cwd, "request");
```

### Imports

Organize imports in three groups separated by blank lines:

1. `std::` imports
2. External crate imports (alphabetical by crate name)
3. `crate::` imports

```rust
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{bail, Context};
use nix::sys::socket::{self, AddressFamily, SockFlag, SockType, UnixAddr};

use crate::protocol::{Request, Response, MAX_MSG};
```

When importing a module and items from it, use `self`:
`use nix::sys::socket::{self, AddressFamily, ...};`

### Naming

Public subcommand entry points use the `cmd_` prefix: `cmd_run`, `cmd_serve`,
`cmd_prompt`. Private helpers use descriptive verb-noun names: `send_request`,
`recv_response`, `handle_connection`.

### Function ordering

Public functions come first, ordered by data-flow lifecycle (constructor/setup,
core operations, cleanup). Private functions follow in **depth-first call
order** from their first public caller. Shared utility functions go last.
