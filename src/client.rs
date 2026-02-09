// Client side: connects to the daemon and requests host command execution.

use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use nix::libc;
use nix::sys::socket::{
    self, AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, UnixAddr,
};

use crate::protocol::{MAX_MSG, Request, Response};

pub fn cmd_run(sock_path: &Path, cmd: &[String]) -> anyhow::Result<ExitCode> {
    if !sock_path.exists() {
        bail!("socket not found: {}", sock_path.display());
    }

    let cwd = std::env::current_dir().context("cannot determine current directory")?;

    let req = Request {
        cmd: cmd.to_vec(),
        cwd,
    };

    let conn = socket::socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .context("cannot create socket")?;

    let addr =
        UnixAddr::new(sock_path.as_os_str().as_encoded_bytes()).context("invalid socket path")?;
    socket::connect(conn.as_raw_fd(), &addr).context("cannot connect to hostexec daemon")?;

    send_request(conn.as_raw_fd(), &req)?;
    let code = recv_response_loop(conn.as_raw_fd())?;
    Ok(ExitCode::from(code))
}

fn send_request(fd: RawFd, req: &Request) -> anyhow::Result<()> {
    let payload = serde_json::to_vec(req)?;
    let iov = [IoSlice::new(&payload)];
    let fds = [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    socket::sendmsg::<UnixAddr>(fd, &iov, &cmsg, MsgFlags::empty(), None)?;
    Ok(())
}

fn recv_response_loop(fd: RawFd) -> anyhow::Result<u8> {
    loop {
        let resp = match recv_response(fd) {
            Ok(resp) => resp,
            Err(_) => return Ok(1),
        };
        match resp {
            Response::Denied => {
                eprintln!("hostexec: request denied by user");
                return Ok(1);
            }
            Response::Error { message } => {
                eprintln!("hostexec: {message}");
                // keep waiting for the exit message
            }
            Response::Exit { code } => {
                return Ok(u8::try_from(code).unwrap_or(1));
            }
        }
    }
}

fn recv_response(fd: RawFd) -> anyhow::Result<Response> {
    let mut buf = vec![0u8; MAX_MSG];
    let nbytes = {
        let mut iov = [IoSliceMut::new(&mut buf)];
        let msg = socket::recvmsg::<UnixAddr>(fd, &mut iov, None, MsgFlags::empty())
            .context("recvmsg")?;
        msg.bytes
    };
    if nbytes == 0 {
        bail!("connection closed");
    }
    let resp: Response = serde_json::from_slice(&buf[..nbytes])?;
    Ok(resp)
}
