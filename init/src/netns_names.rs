// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Operator-visible names for namespaces owned by init's descriptors.

use hardware::netns::NetworkNamespace;
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::Path;

const DIRECTORY: &str = "/run/netns";
const ALIAS: &str = "/var/run/netns";

/// Publish names without retaining the namespaces through bind mounts.
/// Keep the returned control namespace and the supplied descriptors until gateway shutdown.
///
/// # Errors
/// Returns an error if a namespace descriptor, private directory, or name cannot be created.
pub fn publish(
    datapath: Option<&NetworkNamespace>,
    host: Option<&NetworkNamespace>,
) -> io::Result<NetworkNamespace> {
    let control = NetworkNamespace::open("/proc/thread-self/ns/net").map_err(io::Error::other)?;
    unshare(CloneFlags::CLONE_NEWNS)?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )?;
    private_directory(Path::new(DIRECTORY), Path::new(ALIAS))?;

    for (name, namespace) in [
        ("control", Some(&control)),
        ("datapath", datapath),
        ("host", host),
    ] {
        if let Some(namespace) = namespace {
            let source = format!(
                "/proc/{}/fd/{}",
                std::process::id(),
                namespace.as_raw().as_raw_fd()
            );
            symlink(source, Path::new(DIRECTORY).join(name))?;
            tracing::info!("network namespace available as `ip netns exec {name}`");
        }
    }
    Ok(control)
}

/// Overlay inherited entries without changing them; the mount tree must already be private.
fn private_directory(directory: &Path, alias: &Path) -> io::Result<()> {
    fs::create_dir_all(directory)?;
    mount(
        Some("tmpfs"),
        directory,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("mode=0755,size=64k"),
    )?;

    // Usually /var/run already points to /run. Otherwise share the symlink files at both paths.
    fs::create_dir_all(alias)?;
    let original = fs::metadata(directory)?;
    let alternate = fs::metadata(alias)?;
    if (original.dev(), original.ino()) != (alternate.dev(), alternate.ino()) {
        mount(
            Some(directory),
            alias,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use caps::Capability;
    use fixin::wrap;
    use std::process::Command;
    use test_utils::with_caps;

    // A separate process must resolve the owner's PID, not its own /proc/self.
    #[test]
    fn namespace_reader() {
        let Ok(path) = std::env::var("INIT_TEST_NAMESPACE") else {
            return;
        };
        let expected = std::env::var("INIT_TEST_NAMESPACE_INODE")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let namespace = NetworkNamespace::open(path).unwrap();
        namespace.enter().unwrap();
        assert_eq!(
            fs::metadata("/proc/thread-self/ns/net").unwrap().ino(),
            expected
        );
    }

    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_SYS_ADMIN]))]
    fn names_are_private_and_do_not_retain_namespaces() {
        std::thread::spawn(|| {
            // Give the test its own inherited directory, including a name it must preserve.
            unshare(CloneFlags::CLONE_NEWNS).unwrap();
            mount(
                None::<&str>,
                "/",
                None::<&str>,
                MsFlags::MS_REC | MsFlags::MS_PRIVATE,
                None::<&str>,
            )
            .unwrap();
            mount(
                Some("tmpfs"),
                "/run",
                Some("tmpfs"),
                MsFlags::empty(),
                None::<&str>,
            )
            .unwrap();
            fs::create_dir_all(DIRECTORY).unwrap();
            fs::write(Path::new(DIRECTORY).join("control"), "preserve this entry").unwrap();
            let inherited = fs::File::open(DIRECTORY).unwrap();

            let datapath = NetworkNamespace::create().unwrap();
            let host = NetworkNamespace::open("/proc/thread-self/ns/net").unwrap();
            let control = publish(Some(&datapath), Some(&host)).unwrap();
            for (name, namespace) in [
                ("control", &control),
                ("datapath", &datapath),
                ("host", &host),
            ] {
                let source = format!(
                    "/proc/{}/fd/{}",
                    std::process::id(),
                    namespace.as_raw().as_raw_fd()
                );
                let expected = fs::metadata(&source).unwrap();
                for directory in [DIRECTORY, ALIAS] {
                    let path = Path::new(directory).join(name);
                    assert_eq!(fs::read_link(&path).unwrap(), Path::new(&source));
                    let actual = fs::metadata(&path).unwrap();
                    assert_eq!(
                        (actual.dev(), actual.ino()),
                        (expected.dev(), expected.ino())
                    );
                }
            }
            assert_eq!(
                fs::read_to_string(format!("/proc/self/fd/{}/control", inherited.as_raw_fd()))
                    .unwrap(),
                "preserve this entry"
            );

            let datapath_path = Path::new(ALIAS).join("datapath");
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "netns_names::test::namespace_reader",
                    "--nocapture",
                ])
                .env("INIT_TEST_NAMESPACE", &datapath_path)
                .env(
                    "INIT_TEST_NAMESPACE_INODE",
                    fs::metadata(&datapath_path).unwrap().ino().to_string(),
                )
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );

            // Keep the directory mounted after closing its only datapath namespace descriptor.
            drop(datapath);
            assert!(fs::symlink_metadata(&datapath_path).unwrap().is_symlink());
            assert_eq!(
                fs::File::open(&datapath_path).unwrap_err().kind(),
                io::ErrorKind::NotFound
            );
            assert!(NetworkNamespace::open(Path::new(DIRECTORY).join("control")).is_ok());

            // Cover images where /var/run is a separate directory rather than a symlink.
            let directory = Path::new("/run/names");
            let alias = Path::new("/run/alias");
            fs::create_dir_all(alias).unwrap();
            fs::write(alias.join("sentinel"), "untouched").unwrap();
            let inherited_alias = fs::File::open(alias).unwrap();
            private_directory(directory, alias).unwrap();
            symlink("/proc/1/ns/net", directory.join("example")).unwrap();
            assert_eq!(
                fs::read_link(alias.join("example")).unwrap(),
                Path::new("/proc/1/ns/net")
            );
            assert_eq!(
                fs::read_to_string(format!(
                    "/proc/self/fd/{}/sentinel",
                    inherited_alias.as_raw_fd()
                ))
                .unwrap(),
                "untouched"
            );
        })
        .join()
        .unwrap();
    }
}
