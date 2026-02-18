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
};
use nix::sys::termios;
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

    loop {
        let conn_fd = match socket::accept(sock.as_raw_fd()) {
            // SAFETY: fd was just returned by accept() and is not owned elsewhere.
            Ok(fd) => unsafe { OwnedFd::from_raw_fd(fd) },
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e).context("accept"),
        };

        if let Err(e) = handle_connection(conn_fd.as_raw_fd(), &mut allowlist, approve_all) {
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
    allowlist: &mut HashSet<Vec<String>>,
    approve_all: bool,
) -> anyhow::Result<()> {
    let (req, mut client_fds) = recv_request(conn_fd)?;

    let result = match req {
        Request::Run { cmd, cwd } => {
            if client_fds.len() != 3 {
                bail!("expected 3 fds for run request, got {}", client_fds.len());
            }
            handle_run(conn_fd, &cmd, &cwd, allowlist, approve_all, &mut client_fds)
        }
        Request::Notify => handle_notify(conn_fd),
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
    info!(cmd = cmd_str, cwd = %cwd.display(), "request");

    // Check allowlist (match on exact command + args).
    if !approve_all && !allowlist.contains(cmd) {
        match prompt_user(&cmd_str, cwd)? {
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

fn prompt_user(cmd_str: &str, cwd: &Path) -> anyhow::Result<PromptResult> {
    // Pass data via environment variables (tmux -e) so that no user-controlled
    // content appears in the shell command that tmux passes to sh -c.
    let exe = std::fs::read_link("/proc/self/exe").context("cannot read /proc/self/exe")?;
    let prompt_cmd = shlex::try_join([exe.to_string_lossy().as_ref(), "prompt"].iter().copied())
        .context("failed to quote prompt command")?;

    let status = std::process::Command::new("tmux")
        .args([
            "display-popup",
            "-w",
            "80%",
            "-h",
            "12",
            "-e",
            &format!("XOC_PROMPT_CMD={cmd_str}"),
            "-e",
            &format!("XOC_PROMPT_CWD={}", cwd.display()),
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

fn handle_notify(conn_fd: RawFd) -> anyhow::Result<()> {
    info!("notify");
    std::io::stdout()
        .write_all(b"\x07")
        .context("cannot write bell to stdout")?;
    std::io::stdout().flush().context("cannot flush stdout")?;
    send_response(conn_fd, &Response::Exit { code: 0 })?;
    Ok(())
}

pub fn cmd_prompt() -> anyhow::Result<ExitCode> {
    let cmd_str = std::env::var("XOC_PROMPT_CMD").context("XOC_PROMPT_CMD not set")?;
    let cwd = std::env::var("XOC_PROMPT_CWD").context("XOC_PROMPT_CWD not set")?;

    println!();
    println!("  Host command execution request");
    println!("  ─────────────────────────────────");
    println!();
    println!("  cwd: {cwd}");
    println!("  cmd: {cmd_str}");
    println!();
    println!("  [Y] Allow once  [A] Always allow  [N] Deny");
    println!();
    std::io::stdout().flush()?;

    let key = read_keypress();
    match key {
        b'y' | b'Y' | b'\r' | b'\n' => Ok(ExitCode::from(PROMPT_ALLOW)),
        b'a' | b'A' => Ok(ExitCode::from(PROMPT_ALWAYS)),
        _ => Ok(ExitCode::from(PROMPT_DENY)),
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
