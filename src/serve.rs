// Daemon side: listens for command execution requests and runs them after
// user approval. Also contains the `prompt` subcommand (the interactive UI
// shown inside the tmux popup).

use std::collections::HashSet;
use std::io::{BufRead, IoSlice, IoSliceMut, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{ExitCode, Stdio};

use anyhow::{Context, bail};
use nix::libc;
use nix::sys::socket::{
    self, AddressFamily, Backlog, ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr,
    UnixCredentials, sockopt::PeerCredentials,
};
use nix::sys::termios;
use nix::unistd::{Uid, User};
use tracing::{error, info};

use crate::protocol::{MAX_MSG, Request, Response};

/// Prompt subcommand exit codes.
const PROMPT_ALLOW: u8 = 0;
const PROMPT_DENY: u8 = 1;
const PROMPT_ALWAYS: u8 = 2;

pub fn cmd_serve(write_socket_path_to: Option<&Path>, approve_all: bool) -> anyhow::Result<()> {
    let sock_dir = create_socket_dir()?;
    let sock_path = sock_dir.path().join("socket");

    let sock = socket::socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .context("cannot create socket")?;

    let addr =
        UnixAddr::new(sock_path.as_os_str().as_encoded_bytes()).context("invalid socket path")?;
    socket::bind(sock.as_raw_fd(), &addr).context("cannot bind socket")?;
    socket::listen(&sock, Backlog::new(1).context("invalid backlog value")?)
        .context("cannot listen on socket")?;

    if let Some(path) = write_socket_path_to {
        std::fs::write(path, format!("{}\n", sock_path.display()))
            .with_context(|| format!("cannot write socket path to {}", path.display()))?;
    }

    info!(path = %sock_path.display(), "listening");

    let mut allowlist: HashSet<Vec<String>> = HashSet::new();
    let mut window_base_name: Option<String> = None;

    loop {
        let conn_fd = match socket::accept(sock.as_raw_fd()) {
            // SAFETY: fd was just returned by accept() and is not owned elsewhere.
            Ok(fd) => unsafe { OwnedFd::from_raw_fd(fd) },
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e).context("accept"),
        };

        let peer_cred =
            socket::getsockopt(&conn_fd, PeerCredentials).context("cannot get peer credentials")?;

        if let Err(e) = handle_connection(
            conn_fd.as_raw_fd(),
            peer_cred,
            &mut allowlist,
            approve_all,
            &mut window_base_name,
        ) {
            error!("error handling connection: {e:#}");
        }
        // conn_fd dropped here, closing the connection
    }
}

fn create_socket_dir() -> anyhow::Result<tempfile::TempDir> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").context("XDG_RUNTIME_DIR not set")?;
    tempfile::Builder::new()
        .prefix("hostexec.")
        .tempdir_in(runtime_dir)
        .context("cannot create socket directory")
}

/// Handle a single client connection.
fn handle_connection(
    conn_fd: RawFd,
    peer_cred: UnixCredentials,
    allowlist: &mut HashSet<Vec<String>>,
    approve_all: bool,
    window_base_name: &mut Option<String>,
) -> anyhow::Result<()> {
    let (req, mut client_fds) = recv_request(conn_fd)?;

    let result = match req {
        Request::Run { cmd, cwd } => {
            if client_fds.len() != 3 {
                bail!("expected 3 fds for run request, got {}", client_fds.len());
            }
            handle_run(
                conn_fd,
                &cmd,
                &cwd,
                &peer_cred,
                allowlist,
                approve_all,
                &mut client_fds,
            )
        }
        Request::Notify { hook } => handle_notify(conn_fd, &hook, window_base_name),
    };

    // Ensure client fds are always closed, even on early return.
    close_fds(&mut client_fds);
    result
}

fn recv_request(conn_fd: RawFd) -> anyhow::Result<(Request, Vec<OwnedFd>)> {
    let mut buf = vec![0u8; MAX_MSG];
    let mut cmsg_buf = nix::cmsg_space!([RawFd; 3]);

    let (nbytes, fds) = {
        let mut iov = [IoSliceMut::new(&mut buf)];
        let msg =
            socket::recvmsg::<UnixAddr>(conn_fd, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())
                .context("recvmsg")?;

        let mut fds = Vec::new();
        for cmsg in msg.cmsgs()? {
            if let ControlMessageOwned::ScmRights(received) = cmsg {
                fds.extend(
                    received
                        .into_iter()
                        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }),
                );
            }
        }

        (msg.bytes, fds)
    };

    if nbytes == 0 {
        bail!("empty message from client");
    }

    let req: Request = serde_json::from_slice(&buf[..nbytes]).context("invalid request JSON")?;
    Ok((req, fds))
}

fn handle_run(
    conn_fd: RawFd,
    cmd: &[String],
    cwd: &Path,
    peer_cred: &UnixCredentials,
    allowlist: &mut HashSet<Vec<String>>,
    approve_all: bool,
    client_fds: &mut Vec<OwnedFd>,
) -> anyhow::Result<()> {
    if cmd.is_empty() {
        send_response(
            conn_fd,
            &Response::Error {
                message: "empty command".into(),
            },
        )?;
        return Ok(());
    }

    let cmd_str = format_cmd(cmd);
    info!(cmd = cmd_str, cwd = %cwd.display(), pid = peer_cred.pid(), uid = peer_cred.uid(), "request");

    // Check allowlist (match on exact command + args).
    if !approve_all && !allowlist.contains(cmd) {
        match prompt_user(&cmd_str, cwd, peer_cred)? {
            PromptResult::Always => {
                allowlist.insert(cmd.to_vec());
                info!(cmd = cmd_str, "always allowed");
            }
            PromptResult::Allow => {
                info!(cmd = cmd_str, "allowed");
            }
            PromptResult::Deny => {
                info!(cmd = cmd_str, "denied");
                send_response(conn_fd, &Response::Denied)?;
                return Ok(());
            }
        }
    }

    run_command(conn_fd, cmd, cwd, client_fds);
    Ok(())
}

enum PromptResult {
    Allow,
    Always,
    Deny,
}

fn prompt_user(
    cmd_str: &str,
    cwd: &Path,
    peer_cred: &UnixCredentials,
) -> anyhow::Result<PromptResult> {
    // Pass data via environment variables (tmux -e) so that no user-controlled
    // content appears in the shell command that tmux passes to sh -c.
    let exe = std::fs::read_link("/proc/self/exe").context("cannot read /proc/self/exe")?;
    let prompt_cmd = shlex::try_join([exe.to_string_lossy().as_ref(), "prompt"].iter().copied())
        .context("failed to quote prompt command")?;

    let exec_uid = nix::unistd::geteuid();

    let status = std::process::Command::new("tmux")
        .args([
            "display-popup",
            "-w",
            "80%",
            "-h",
            "50%",
            "-e",
            &format!("XOC_PROMPT_CMD={cmd_str}"),
            "-e",
            &format!("XOC_PROMPT_CWD={}", cwd.display()),
            "-e",
            &format!("XOC_PROMPT_PID={}", peer_cred.pid()),
            "-e",
            &format!("XOC_PROMPT_PEER_UID={}", peer_cred.uid()),
            "-e",
            &format!("XOC_PROMPT_EXEC_UID={exec_uid}"),
            "-E",
            &prompt_cmd,
        ])
        .status()
        .context("failed to run tmux display-popup")?;

    match status.code() {
        Some(code) if code == PROMPT_ALLOW as i32 => Ok(PromptResult::Allow),
        Some(code) if code == PROMPT_ALWAYS as i32 => Ok(PromptResult::Always),
        _ => Ok(PromptResult::Deny),
    }
}

fn run_command(conn_fd: RawFd, cmd: &[String], cwd: &Path, client_fds: &mut Vec<OwnedFd>) {
    // Consume ownership of the fds so the child process inherits them.
    let stdin_fd = client_fds.remove(0);
    let stdout_fd = client_fds.remove(0);
    let stderr_fd = client_fds.remove(0);

    let mut command = std::process::Command::new(&cmd[0]);
    command
        .args(&cmd[1..])
        .current_dir(cwd)
        .stdin(Stdio::from(stdin_fd))
        .stdout(Stdio::from(stdout_fd))
        .stderr(Stdio::from(stderr_fd));

    // SAFETY: prctl(PR_SET_PDEATHSIG) is async-signal-safe and the only
    // operation in this pre_exec hook.
    unsafe {
        command.pre_exec(|| {
            let ret = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = command.spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            let code = if e.kind() == std::io::ErrorKind::NotFound {
                let _ = send_response(
                    conn_fd,
                    &Response::Error {
                        message: format!("command not found: {}", cmd[0]),
                    },
                );
                127
            } else {
                let _ = send_response(
                    conn_fd,
                    &Response::Error {
                        message: e.to_string(),
                    },
                );
                1
            };
            let _ = send_response(conn_fd, &Response::Exit { code });
            return;
        }
    };

    // TODO: we don't monitor the client connection while waiting, so if the
    // client is killed (e.g. the agent times out), the child keeps running and
    // the server blocks here, preventing any further requests. We should poll
    // both the connection (for hangup) and the child (for exit) concurrently,
    // and kill the child if the client disconnects. Which means going async.
    let status = child.wait();

    let code = match status {
        Ok(s) => {
            use std::os::unix::process::ExitStatusExt;
            s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(1))
        }
        Err(_) => 1,
    };

    let _ = send_response(conn_fd, &Response::Exit { code });
}

fn handle_notify(
    conn_fd: RawFd,
    hook: &str,
    window_base_name: &mut Option<String>,
) -> anyhow::Result<()> {
    info!(hook, "notify");
    match hook {
        "session-start" => {
            snapshot_tmux_window_name(window_base_name);
            set_tmux_window_name(window_base_name, None);
        }
        "busy" => set_tmux_window_name(window_base_name, Some("⏳")),
        "idle" => {
            let _ = std::io::stdout().write_all(b"\x07");
            let _ = std::io::stdout().flush();
            set_tmux_window_name(window_base_name, Some("✋"));
        }
        "session-exit" => {
            tmux_rename_window(window_base_name.as_deref());
            *window_base_name = None;
        }
        _ => info!(hook, "unknown hook, ignoring"),
    }
    send_response(conn_fd, &Response::Exit { code: 0 })?;
    Ok(())
}

/// Capture the current tmux window name as the base name for later changes.
fn snapshot_tmux_window_name(base: &mut Option<String>) {
    let pane = match std::env::var("TMUX_PANE") {
        Ok(p) => p,
        Err(_) => return,
    };
    let output = std::process::Command::new("tmux")
        .args(["display-message", "-t", &pane, "-p", "#{window_name}"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    if let Ok(o) = output
        && o.status.success()
    {
        *base = Some(String::from_utf8_lossy(&o.stdout).trim().to_string());
    }
}

/// Set the tmux window name to `🤖 <base> [suffix]`.
/// No-op if no base name has been captured (i.e. no prior `session-start`).
fn set_tmux_window_name(base: &Option<String>, suffix: Option<&str>) {
    let Some(base) = base else { return };
    let name = match suffix {
        Some(s) => format!("🤖 {base} {s}"),
        None => format!("🤖 {base}"),
    };
    tmux_rename_window(Some(&name));
}

/// Rename the tmux window containing this daemon's pane.
/// No-op if `$TMUX_PANE` is unset or `name` is None.
fn tmux_rename_window(name: Option<&str>) {
    let (Some(name), Ok(pane)) = (name, std::env::var("TMUX_PANE")) else {
        return;
    };
    let _ = std::process::Command::new("tmux")
        .args(["rename-window", "-t", &pane, name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub fn cmd_prompt() -> anyhow::Result<ExitCode> {
    let cmd_str = std::env::var("XOC_PROMPT_CMD").context("XOC_PROMPT_CMD not set")?;
    let cwd = std::env::var("XOC_PROMPT_CWD").context("XOC_PROMPT_CWD not set")?;
    let pid = std::env::var("XOC_PROMPT_PID").context("XOC_PROMPT_PID not set")?;
    let peer_uid: u32 = std::env::var("XOC_PROMPT_PEER_UID")
        .context("XOC_PROMPT_PEER_UID not set")?
        .parse()
        .context("invalid XOC_PROMPT_PEER_UID")?;
    let exec_uid: u32 = std::env::var("XOC_PROMPT_EXEC_UID")
        .context("XOC_PROMPT_EXEC_UID not set")?
        .parse()
        .context("invalid XOC_PROMPT_EXEC_UID")?;

    let caller = format_uid(peer_uid);
    let run_as = format_uid(exec_uid);

    let display = format!(
        "\n\
         \x20 Host command execution request\n\
         \x20 ─────────────────────────────────\n\
         \n\
         \x20    cmd: {cmd_str}\n\
         \x20    cwd: {cwd}\n\
         \x20    pid: {pid}\n\
         \x20 caller: {caller}\n\
         \x20 run as: {run_as}\n"
    );

    // Use `less` for scrollable display. It handles wrapping and scrolling
    // correctly regardless of terminal dimensions. The -F flag makes it exit
    // immediately if the content fits on one screen, -R passes through ANSI
    // codes, and -X keeps content visible after exit.
    loop {
        show_with_pager(&display);

        println!();
        println!("  [Y] Allow once  [A] Always allow  [N] Deny  [R] Review");
        println!();
        std::io::stdout().flush()?;

        match read_keypress() {
            b'r' | b'R' => continue,
            b'y' | b'Y' | b'\r' | b'\n' => return Ok(ExitCode::from(PROMPT_ALLOW)),
            b'a' | b'A' => return Ok(ExitCode::from(PROMPT_ALWAYS)),
            _ => return Ok(ExitCode::from(PROMPT_DENY)),
        }
    }
}

fn show_with_pager(text: &str) {
    let child = std::process::Command::new("less")
        .args(["-FRX"])
        .stdin(Stdio::piped())
        .spawn();

    match child {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
                // Drop stdin to signal EOF to less.
            }
            let _ = child.wait();
        }
        Err(_) => {
            // less not available; print directly.
            let _ = std::io::stdout().write_all(text.as_bytes());
            let _ = std::io::stdout().flush();
        }
    }
}

fn format_uid(uid: u32) -> String {
    match User::from_uid(Uid::from_raw(uid)) {
        Ok(Some(user)) => format!("{uid} ({name})", name = user.name),
        _ => uid.to_string(),
    }
}

fn read_keypress() -> u8 {
    let stdin = std::io::stdin();

    let orig = match termios::tcgetattr(&stdin) {
        Ok(t) => t,
        Err(_) => {
            // Not a tty (e.g. piped input); fall back to reading a line.
            let mut line = String::new();
            let _ = stdin.lock().read_line(&mut line);
            return line.trim().as_bytes().first().copied().unwrap_or(b'n');
        }
    };

    let mut raw = orig.clone();
    termios::cfmakeraw(&mut raw);
    let _ = termios::tcsetattr(&stdin, termios::SetArg::TCSANOW, &raw);

    let mut buf = [0u8; 1];
    let result = std::io::stdin().lock().read_exact(&mut buf);

    // Always restore terminal settings.
    let _ = termios::tcsetattr(&stdin, termios::SetArg::TCSADRAIN, &orig);

    match result {
        Ok(()) => buf[0],
        Err(_) => b'n',
    }
}

fn send_response(fd: RawFd, resp: &Response) -> anyhow::Result<()> {
    let payload = serde_json::to_vec(resp)?;
    let iov = [IoSlice::new(&payload)];
    socket::sendmsg::<UnixAddr>(fd, &iov, &[], MsgFlags::empty(), None)?;
    Ok(())
}

fn close_fds(fds: &mut Vec<OwnedFd>) {
    // OwnedFd::drop closes the fd automatically.
    fds.clear();
}

fn format_cmd(cmd: &[String]) -> String {
    shlex::try_join(cmd.iter().map(|s| s.as_str())).unwrap_or_else(|_| cmd.join(" "))
}
