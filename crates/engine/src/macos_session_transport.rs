//! Transfer only the root operation flock, never arbitrary file capabilities.
#[cfg(any(target_os = "macos", test))]
use super::Owner;
use super::{Request, MAX_FRAME, TIMEOUT};
use serde::Serialize;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::Instant;

// XNU bsd/kern/uipc_usrreq.c: UIPC_MAX_CMSG_FD is 512 and statically
// covers MCLBYTES / sizeof(int). sockargs bounds a control mbuf by MCLBYTES;
// unp_internalize accepts exactly one SCM_RIGHTS header per control mbuf.
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_usrreq.c
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_syscalls.c
const MAX_ANCILLARY_RIGHTS: usize = 512;
const CONTROL_WORDS: usize = (std::mem::size_of::<libc::cmsghdr>() + std::mem::size_of::<usize>()
    - 1)
    / std::mem::size_of::<usize>()
    + (MAX_ANCILLARY_RIGHTS * std::mem::size_of::<RawFd>() + std::mem::size_of::<usize>() - 1)
        / std::mem::size_of::<usize>();

pub(super) fn send(
    stream: &mut UnixStream,
    request: &Request,
    fd: Option<RawFd>,
) -> Result<(), String> {
    let Some(fd) = fd else {
        return super::write_frame(stream, request);
    };
    let bytes = encode(request)?;
    let deadline = Instant::now() + TIMEOUT;
    let mut header = (bytes.len() as u32).to_be_bytes();
    let mut vector = libc::iovec {
        iov_base: header.as_mut_ptr().cast(),
        iov_len: header.len(),
    };
    let mut control = [0usize; 4];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as _) } as _;
    unsafe {
        let entry = libc::CMSG_FIRSTHDR(&message);
        if entry.is_null() {
            return Err("Cannot encode operation lock transfer".into());
        }
        (*entry).cmsg_level = libc::SOL_SOCKET;
        (*entry).cmsg_type = libc::SCM_RIGHTS;
        (*entry).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as _) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(entry).cast::<RawFd>(), fd);
    }
    #[cfg(target_os = "macos")]
    {
        let enabled: libc::c_int = 1;
        if unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&enabled) as _,
            )
        } != 0
        {
            return Err("Cannot protect operation transfer from SIGPIPE".into());
        }
    }
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_NOSIGNAL;
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    let count = loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("Operation transfer timed out")?;
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|_| "Cannot configure operation transfer")?;
        let count = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, flags) };
        if count >= 0 {
            break count as usize;
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err("The operation lock could not be transferred".into());
        }
    };
    if count == 0 {
        return Err("The operation transfer connection closed".into());
    }
    super::write_all_until(stream, &header[count..], deadline)?;
    super::write_all_until(stream, &bytes, deadline)
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(value).map_err(|_| "Cannot encode runtime request")?;
    if bytes.len() > MAX_FRAME {
        return Err("Runtime request is too large".into());
    }
    Ok(bytes)
}

fn readable(stream: &UnixStream, deadline: Instant) -> std::io::Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "Runtime request timed out")
            })?;
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe {
            libc::poll(
                &mut descriptor,
                1,
                remaining.as_millis().clamp(1, i32::MAX as u128) as i32,
            )
        };
        if result > 0 {
            return Ok(());
        }
        if result == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Runtime request timed out",
            ));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn receive_chunk(
    stream: &UnixStream,
    bytes: &mut [u8],
    accept_right: bool,
) -> std::io::Result<(usize, Option<File>)> {
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut control = [0usize; CONTROL_WORDS];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen =
        unsafe { libc::CMSG_SPACE((MAX_ANCILLARY_RIGHTS * std::mem::size_of::<RawFd>()) as _) }
            as _;
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = libc::MSG_DONTWAIT;
    let count = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, flags) };
    if count < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut transferred = None;
    let mut invalid = message.msg_flags & libc::MSG_CTRUNC != 0;
    let control_end = message.msg_control as usize + message.msg_controllen as usize;
    unsafe {
        let mut entry = libc::CMSG_FIRSTHDR(&message);
        while !entry.is_null() {
            let minimum = libc::CMSG_LEN(0) as usize;
            let available = control_end.saturating_sub(entry as usize);
            let length = (*entry).cmsg_len as usize;
            if length < minimum {
                invalid = true;
                break;
            }
            let copied = length.min(available);
            invalid |= length > available;
            if (*entry).cmsg_level != libc::SOL_SOCKET || (*entry).cmsg_type != libc::SCM_RIGHTS {
                invalid = true;
            } else {
                let data_len = copied.saturating_sub(minimum);
                let rights = data_len / std::mem::size_of::<RawFd>();
                invalid |= !accept_right || !data_len.is_multiple_of(std::mem::size_of::<RawFd>());
                for index in 0..rights {
                    let fd =
                        std::ptr::read_unaligned(libc::CMSG_DATA(entry).cast::<RawFd>().add(index));
                    if fd < 0 {
                        invalid = true;
                        continue;
                    }
                    let file = File::from_raw_fd(fd);
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    invalid |=
                        flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) != 0;
                    if transferred.is_some() {
                        invalid = true;
                    } else {
                        transferred = Some(file);
                    }
                }
            }
            if length > available {
                break;
            }
            entry = libc::CMSG_NXTHDR(&message, entry);
        }
    }
    // All externalized descriptors are now CLOEXEC and either owned here or
    // already closed. Only now reject policy violations, even with zero data.
    if invalid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "A runtime request must transfer exactly one operation lock or none",
        ));
    }
    Ok((count as usize, transferred))
}

#[cfg(any(target_os = "macos", test))]
fn receive_header(
    stream: &UnixStream,
    header: &mut [u8; 4],
) -> Result<(usize, Option<File>), String> {
    let (count, file) = receive_chunk(stream, header, true)
        .map_err(|error| format!("The runtime control frame could not be received: {error}"))?;
    if count == 0 {
        return Err("The runtime request connection closed".into());
    }
    Ok((count, file))
}

pub(super) fn read_plain_until<G>(
    stream: &UnixStream,
    bytes: &mut [u8],
    deadline: Instant,
    owner: Option<&Mutex<G>>,
) -> Result<usize, String> {
    readable(stream, deadline)
        .map_err(|error| format!("The runtime connection did not answer: {error}"))?;
    let _spawn_barrier = owner
        .map(|owner| owner.lock())
        .transpose()
        .map_err(|_| "Connection owner is unavailable")?;
    receive_chunk(stream, bytes, false)
        .map(|(count, _)| count)
        .map_err(|error| format!("The runtime connection could not be read: {error}"))
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn lease_open(stream: &UnixStream, owner: &Mutex<Owner>) -> Result<bool, String> {
    match readable(
        stream,
        Instant::now() + std::time::Duration::from_millis(250),
    ) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => return Ok(true),
        Err(_) => return Err("The foreground control socket failed".into()),
    }
    let _spawn_barrier = owner
        .lock()
        .map_err(|_| "Connection owner is unavailable")?;
    receive_chunk(stream, &mut [0u8], false)
        .map(|_| false)
        .map_err(|_| "Unexpected foreground control data".into())
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn receive(
    stream: &mut UnixStream,
    owner: &Mutex<Owner>,
) -> Result<(Request, Option<File>), String> {
    let deadline = Instant::now() + TIMEOUT;
    readable(stream, deadline)
        .map_err(|error| format!("The runtime request did not arrive: {error}"))?;
    let mut header = [0; 4];
    // Darwin has no MSG_CMSG_CLOEXEC. No backend may fork between recvmsg and
    // fcntl; every service-side process spawn is serialized by this mutex.
    let (count, transferred) = {
        let _spawn_barrier = owner
            .lock()
            .map_err(|_| "Connection owner is unavailable")?;
        if Instant::now() >= deadline {
            return Err("Runtime request timed out".into());
        }
        receive_header(stream, &mut header)?
    };
    super::read_exact_until_owner(stream, &mut header[count..], deadline, Some(owner))?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err("Invalid runtime request size".into());
    }
    let mut bytes = vec![0; size];
    super::read_exact_until_owner(stream, &mut bytes, deadline, Some(owner))?;
    Ok((super::decode(&bytes)?, transferred))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos_transaction;

    fn send_rights(stream: &UnixStream, fd: RawFd, rights: usize, data_len: usize) {
        let bytes =
            unsafe { libc::CMSG_SPACE((rights * std::mem::size_of::<RawFd>()) as _) } as usize;
        let mut control =
            vec![0usize; (bytes + std::mem::size_of::<usize>() - 1) / std::mem::size_of::<usize>()];
        let mut data = [1u8];
        let mut vector = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data_len,
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = bytes as _;
        unsafe {
            let entry = libc::CMSG_FIRSTHDR(&message);
            (*entry).cmsg_level = libc::SOL_SOCKET;
            (*entry).cmsg_type = libc::SCM_RIGHTS;
            (*entry).cmsg_len = libc::CMSG_LEN((rights * std::mem::size_of::<RawFd>()) as _) as _;
            for index in 0..rights {
                std::ptr::write_unaligned(libc::CMSG_DATA(entry).cast::<RawFd>().add(index), fd);
            }
            assert_eq!(
                libc::sendmsg(stream.as_raw_fd(), &message, 0),
                data_len as isize
            );
        }
    }

    #[test]
    fn oversized_rights_close_every_duplicate_before_rejection() {
        for accept_right in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let (sender, receiver) = UnixStream::pair().unwrap();
            macos_transaction::with_root_lock(root.path(), || {
                send_rights(
                    &sender,
                    macos_transaction::operation_fd(root.path())?.unwrap(),
                    64,
                    1,
                );
                Ok(())
            })
            .unwrap();
            assert!(macos_transaction::try_root_lock(root.path())
                .unwrap()
                .is_none());
            assert!(receive_chunk(&receiver, &mut [0u8], accept_right).is_err());
            assert!(macos_transaction::try_root_lock(root.path())
                .unwrap()
                .is_some());
        }
    }

    #[test]
    fn plain_handshake_body_and_control_reads_reject_and_release_rights() {
        for rights in [1, 6, 64] {
            let root = tempfile::tempdir().unwrap();
            let (sender, receiver) = UnixStream::pair().unwrap();
            macos_transaction::with_root_lock(root.path(), || {
                send_rights(
                    &sender,
                    macos_transaction::operation_fd(root.path())?.unwrap(),
                    rights,
                    1,
                );
                Ok(())
            })
            .unwrap();
            assert!(
                read_plain_until::<()>(&receiver, &mut [0u8], Instant::now() + TIMEOUT, None)
                    .is_err()
            );
            assert!(macos_transaction::try_root_lock(root.path())
                .unwrap()
                .is_some());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn zero_data_rights_are_released_before_closed_header_error() {
        let root = tempfile::tempdir().unwrap();
        let (sender, receiver) = UnixStream::pair().unwrap();
        macos_transaction::with_root_lock(root.path(), || {
            send_rights(
                &sender,
                macos_transaction::operation_fd(root.path())?.unwrap(),
                1,
                0,
            );
            Ok(())
        })
        .unwrap();
        sender.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(receive_header(&receiver, &mut [0u8; 4]).is_err());
        assert!(macos_transaction::try_root_lock(root.path())
            .unwrap()
            .is_some());
    }
}
