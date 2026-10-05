// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Filesystem checks for Unix sockets owned by this gateway.

use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

/// Check for a Unix socket, rejecting other file types and symlinks.
///
/// This confirms that an endpoint was bound, not that it can serve requests.
///
/// # Errors
///
/// Returns an error for unexpected file types or failed metadata lookups.
pub fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a Unix socket",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Remove an old socket before spawning any children.
///
/// Init must exclusively own this endpoint during startup; unlinking a live socket
/// would prevent new clients from reaching its owner. An absent socket is harmless.
///
/// # Errors
///
/// Returns an error if the path is not a socket or cannot be inspected or removed.
pub fn remove_stale(path: &Path) -> io::Result<()> {
    if !exists(path)? {
        return Ok(());
    }
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::{UnixDatagram, UnixListener};

    #[test]
    fn cleanup_handles_both_socket_types_and_missing_paths() {
        let root = std::env::temp_dir().join(format!("init-sockets-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let datagram = root.join("dataplane.sock");
        let stream = root.join("agent.sock");
        drop(UnixDatagram::bind(&datagram).unwrap());
        drop(UnixListener::bind(&stream).unwrap());

        for path in [&datagram, &stream, &root.join("absent.sock")] {
            remove_stale(path).unwrap();
            assert!(!exists(path).unwrap());
            remove_stale(path).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unexpected_files_and_symlinks_are_preserved_and_rejected() {
        let root = std::env::temp_dir().join(format!("init-socket-types-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("file.sock"), "keep me").unwrap();
        fs::create_dir(root.join("dir.sock")).unwrap();
        let _socket = UnixListener::bind(root.join("real.sock")).unwrap();
        symlink(root.join("real.sock"), root.join("link.sock")).unwrap();
        symlink(root.join("absent"), root.join("dangling.sock")).unwrap();

        for name in ["file.sock", "dir.sock", "link.sock", "dangling.sock"] {
            let path = root.join(name);
            assert_eq!(
                exists(&path).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                remove_stale(&path).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert!(fs::symlink_metadata(path).is_ok());
        }
        assert!(exists(&root.join("real.sock")).unwrap());
        assert_eq!(
            fs::read_to_string(root.join("file.sock")).unwrap(),
            "keep me"
        );

        // An invalid parent must not be mistaken for an absent socket.
        let invalid = root.join("file.sock/child.sock");
        assert_eq!(
            remove_stale(&invalid).unwrap_err().raw_os_error(),
            Some(nix::libc::ENOTDIR)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
