// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Starting FRR, and the agent that carries configuration into it.
//!
//! FRR used to be a container of its own, started by `/libexec/frr/docker-start`: a shell script
//! which swept stale nexthops, launched `watchfrr` with whatever `/etc/frr/daemons` enabled,
//! launched `frr-agent` beside it, and then `wait -n`'d for either to die. This module is what
//! replaces it, and it is smaller than the script for two reasons that are worth stating.
//!
//! # What the nexthop sweep was for, and why it is gone
//!
//! The script began by deleting every nexthop `zebra` had installed:
//!
//! ```sh
//! ip -j -d nexthop show | jq --raw-output '.[] | select(.protocol=="zebra").id' |
//!   while read -r id; do ip nexthop del id "${id}"; done
//! ```
//!
//! That is cleanup after a *previous* container. A restarted zebra meets the nexthop ids its
//! predecessor installed, will not reuse them, and cannot delete them either, because it has no
//! record of having created them. In a network namespace that outlives the process, somebody has to
//! sweep, and there is nowhere to do it from but the entrypoint.
//!
//! The namespace is now created per start and held by `dataplane-init` alone, so it dies when this
//! process does and the next start begins in an empty one. There is nothing to sweep. Note that
//! this is a property of the *namespace*, not of the supervision: the sweep never covered a daemon
//! restarted underneath a surviving namespace, which is a case
//! [`crate::supervisor`] removes separately by refusing to restart anything in place.
//!
//! # Why `watchfrr`, and not the daemons directly
//!
//! Supervising `zebra`, `bgpd` and the rest individually is tempting -- it would put every process
//! under one policy, and shared fate is the policy this supervisor exists to enforce. It was tried,
//! on hardware, and FRR did not come up faithfully: zebra never applied the `ip address` the
//! dataplane had generated for the tap, although `frr-agent` reported the reload applied. Enough of
//! FRR's startup lives in `watchfrr.sh` and `frrcommon.sh` -- per-daemon options, config file
//! creation, the `vtysh -b` pass that applies the running configuration once the daemons are up --
//! that launching the binaries by hand produces a subtly different FRR.
//!
//! So `watchfrr` stays, and the difference from the old arrangement is the layer above it: when
//! `watchfrr` exits, everything else comes down with it rather than the container lingering.
//!
//! `watchfrr` starts its daemons with `-d`, so they daemonize out of its process group and are
//! reparented onto this process. They are reaped here as orphans, and the broadcast at the end of
//! [`crate::supervisor::Supervisor::shut_down`] is what stops them -- signalling `watchfrr`'s group
//! alone would not reach them.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::{debug, info, warn};

use crate::supervisor::Process;

/// Where FRR installs its daemons, `watchfrr` among them.
///
/// This is FRR's own `--libexecdir`, so it is also where `watchfrr` looks for the daemons it is
/// asked to watch; naming a daemon whose binary is not here would have it fail one restart
/// interval at a time instead of at startup.
const DAEMON_DIR: &str = "/libexec/frr";

/// FRR's configuration directory, its `--sysconfdir`.
const CONFIG_DIR: &str = "/etc/frr";

/// FRR's state directory, its `--localstatedir`, and `watchfrr`'s default `--statedir`.
///
/// Each daemon opens `<state>/<daemon>.vty` here once it is serving, which is how `watchfrr`
/// decides a daemon is up and how [`readiness`] decides FRR is.
const STATE_DIR: &str = "/run/frr";

/// The agent that applies dataplane-generated configuration to FRR.
const AGENT_BINARY: &str = "/bin/frr-agent";

/// Daemons FRR runs whether or not `/etc/frr/daemons` mentions them.
///
/// The same three `frrcommon.sh` forces on: `zebra` is FRR, and `mgmtd` and `staticd` are how
/// configuration reaches it in FRR 10.
const ALWAYS_ENABLED: &[&str] = &["mgmtd", "zebra", "staticd"];

/// Every daemon `/etc/frr/daemons` may enable, in the order `frrcommon.sh` lists them.
///
/// The order is kept because it is the order daemons are named to `watchfrr`, and reproducing the
/// script's behaviour exactly is cheaper than establishing that the order does not matter.
/// Anything not on this list is not a daemon, so a `key=value` line naming something else is a
/// setting -- `vtysh_enable`, `zebra_options` -- and is skipped rather than misread as a daemon
/// nobody can start.
const KNOWN_DAEMONS: &[&str] = &[
    "mgmtd", "zebra", "bfdd", "bgpd", "ripd", "ripngd", "ospfd", "ospf6d", "isisd", "babeld",
    "pimd", "pim6d", "ldpd", "nhrpd", "eigrpd", "sharpd", "pbrd", "staticd", "fabricd", "vrrpd",
    "pathd",
];

/// Anything that can go wrong working out how to start FRR.
#[derive(Debug, thiserror::Error)]
pub enum FrrError {
    /// `/etc/frr/daemons` could not be read.
    #[error("could not read {path}: {source}")]
    UnreadableDaemons {
        /// The file that could not be read.
        path: PathBuf,
        /// Why it could not be read.
        #[source]
        source: std::io::Error,
    },

    /// A daemon FRR cannot run without is not installed.
    #[error("{daemon} is enabled but {path} is not an executable, so FRR cannot start")]
    MissingDaemon {
        /// The daemon that is missing.
        daemon: &'static str,
        /// Where it was looked for.
        path: PathBuf,
    },
}

/// Which daemons to ask `watchfrr` to run.
///
/// Read from `/etc/frr/daemons` rather than decided here, so that the file an operator would edit
/// is still the file that decides. The rules are `frrcommon.sh`'s: a `<daemon>=<value>` line
/// enables that daemon unless the value is empty, `no`, or `0`; [`ALWAYS_ENABLED`] is on
/// regardless; and everything else in the file is a setting rather than a daemon.
///
/// A daemon whose binary is absent is dropped with a warning rather than named to `watchfrr`, which
/// would otherwise keep trying to start it forever. One that is [`ALWAYS_ENABLED`] is an error
/// instead: FRR without `zebra` is not a degraded FRR, it is a broken install, and saying so here
/// is better than a restart loop.
///
/// # Errors
///
/// Returns [`FrrError::UnreadableDaemons`] if the file cannot be read and
/// [`FrrError::MissingDaemon`] if a daemon FRR cannot run without is not installed.
pub fn enabled_daemons(config_dir: &Path, daemon_dir: &Path) -> Result<Vec<String>, FrrError> {
    let path = config_dir.join("daemons");
    let contents = fs::read_to_string(&path).map_err(|source| FrrError::UnreadableDaemons {
        path: path.clone(),
        source,
    })?;

    let mut enabled: Vec<&'static str> = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        // `KNOWN_DAEMONS` is what makes this a daemon line rather than a settings line, and taking
        // the name from that list is also what keeps these `&'static str` for the error type.
        let Some(daemon) = KNOWN_DAEMONS.iter().find(|d| **d == key.trim()) else {
            continue;
        };
        // Shell assignment, so the value may be quoted; `bgpd="yes"` and `bgpd=yes` are the same
        // statement to the script this replaces.
        let value = value.trim().trim_matches(['"', '\'']).trim();
        if value.is_empty() || value == "no" || value == "0" {
            debug!("{daemon} is disabled in {}", path.display());
            continue;
        }
        enabled.push(daemon);
    }

    // Ordered by `KNOWN_DAEMONS` rather than by where they appeared in the file, and deduplicated
    // on the way: a file that names a daemon twice, or names one that is always on, should not
    // produce it twice on `watchfrr`'s command line.
    let wanted: Vec<&'static str> = KNOWN_DAEMONS
        .iter()
        .copied()
        .filter(|d| ALWAYS_ENABLED.contains(d) || enabled.contains(d))
        .collect();

    let mut runnable = Vec::with_capacity(wanted.len());
    for daemon in wanted {
        let binary = daemon_dir.join(daemon);
        if is_executable(&binary) {
            runnable.push(daemon.to_string());
        } else if ALWAYS_ENABLED.contains(&daemon) {
            return Err(FrrError::MissingDaemon {
                daemon,
                path: binary,
            });
        } else {
            warn!(
                "{daemon} is enabled in {} but {} is not installed; not starting it",
                path.display(),
                binary.display()
            );
        }
    }

    info!("FRR daemons to run: {}", runnable.join(" "));
    Ok(runnable)
}

/// Whether `path` is a file this process could execute.
///
/// Only the bits are checked, not the caller's identity: this runs as root in a container, and the
/// question being asked is "is the daemon installed", not "may this user run it".
fn is_executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// What has to exist before FRR can be said to be running.
///
/// Zebra's `vty` socket, which is the same evidence `watchfrr` itself uses: a daemon that has
/// opened it is serving, and one that has not is still starting up. It matters because `frr-agent`
/// applies configuration through `vtysh`, and a `vtysh` that runs before zebra is listening fails
/// rather than waits.
fn readiness(state_dir: &Path) -> PathBuf {
    state_dir.join("zebra.vty")
}

/// Run FRR.
///
/// `watchfrr` is left in the foreground: it is this process's child and its exit is what tells the
/// supervisor FRR has gone. Passing `-d` would daemonize it and it would be reaped as an orphan
/// with nothing waiting on it.
#[must_use]
pub fn watchfrr(daemons: &[String]) -> Process {
    let mut command = Command::new(PathBuf::from(DAEMON_DIR).join("watchfrr"));
    command.args(daemons);
    Process::new("frr", command).ready_when_path_exists(readiness(Path::new(STATE_DIR)))
}

/// Run the agent that carries configuration from the dataplane into FRR.
///
/// Ready when it is listening, which is the only thing the dataplane needs of it. The dataplane
/// reconnects on its own, so this ordering is a courtesy rather than a requirement -- but a gateway
/// that reports itself started before the agent is listening is a gateway that will log a
/// connection failure first and work second.
#[must_use]
pub fn agent(socket: &str) -> Process {
    let mut command = Command::new(AGENT_BINARY);
    command.arg("--sock-path").arg(socket);
    Process::new("frr-agent", command).ready_when_path_exists(socket)
}

/// Where the daemon list is read from, and where the daemons are looked for.
///
/// Separate from [`enabled_daemons`] so the tests can point it somewhere else.
#[must_use]
pub fn install() -> (PathBuf, PathBuf) {
    (PathBuf::from(CONFIG_DIR), PathBuf::from(DAEMON_DIR))
}

#[cfg(test)]
mod test {
    use super::*;

    /// A daemons file and a matching `libexec` directory, in a directory that cleans itself up.
    struct Install {
        root: PathBuf,
    }

    impl Install {
        fn new(name: &str, daemons: &str, installed: &[&str]) -> Self {
            let root = std::env::temp_dir().join(format!("frr-test-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("etc")).expect("temp dir");
            fs::create_dir_all(root.join("libexec")).expect("temp dir");
            fs::write(root.join("etc/daemons"), daemons).expect("daemons file");
            for daemon in installed {
                let path = root.join("libexec").join(daemon);
                fs::write(&path, "#!/bin/sh\n").expect("daemon binary");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                    .expect("daemon binary");
            }
            Install { root }
        }

        fn enabled(&self) -> Result<Vec<String>, FrrError> {
            enabled_daemons(&self.root.join("etc"), &self.root.join("libexec"))
        }
    }

    impl Drop for Install {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// Everything installed, so the answer is only about the file.
    const ALL: &[&str] = &["mgmtd", "zebra", "staticd", "bgpd", "bfdd", "ospfd"];

    #[test]
    fn the_daemons_the_gateway_ships_are_the_ones_that_run() {
        let install = Install::new(
            "gateway",
            "bgpd=yes\nospfd=no\nbfdd=yes\nvtysh_enable=yes\n",
            ALL,
        );
        assert_eq!(
            install.enabled().expect("a readable daemons file"),
            ["mgmtd", "zebra", "bfdd", "bgpd", "staticd"],
            "the enabled set should be the file's, in frrcommon.sh's order"
        );
    }

    #[test]
    fn zebra_mgmtd_and_staticd_run_even_when_the_file_does_not_mention_them() {
        let install = Install::new("implicit", "bgpd=no\n", ALL);
        assert_eq!(
            install.enabled().expect("a readable daemons file"),
            ["mgmtd", "zebra", "staticd"],
            "FRR is not FRR without these three"
        );
    }

    #[test]
    fn a_disabled_daemon_stays_off_however_it_is_spelled() {
        for value in ["no", "0", "", "\"no\""] {
            let install = Install::new("off", &format!("bgpd={value}\n"), ALL);
            let enabled = install.enabled().expect("a readable daemons file");
            assert!(
                !enabled.iter().any(|d| d == "bgpd"),
                "bgpd={value} should not start bgpd, got {enabled:?}"
            );
        }
    }

    #[test]
    fn a_quoted_yes_still_enables() {
        let install = Install::new("quoted", "bgpd=\"yes\"\n", ALL);
        assert!(
            install
                .enabled()
                .expect("a readable daemons file")
                .iter()
                .any(|d| d == "bgpd"),
            "shell quoting is not a different answer"
        );
    }

    /// The settings in this file outnumber the daemons, and several end in `_options`. Reading one
    /// as a daemon would name something to `watchfrr` that cannot be started.
    #[test]
    fn settings_are_not_mistaken_for_daemons() {
        let install = Install::new(
            "settings",
            "zebra_options=\" -A 127.0.0.1\"\nbgpd_options=\"-M bmp\"\nvtysh_enable=yes\n\
             frr_global_options=\"--limit-fds 100000\"\n",
            ALL,
        );
        assert_eq!(
            install.enabled().expect("a readable daemons file"),
            ["mgmtd", "zebra", "staticd"],
            "only the implicit three; nothing here enables a daemon"
        );
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let install = Install::new("comments", "# bgpd=yes\n\n   \nbfdd=yes\n", ALL);
        let enabled = install.enabled().expect("a readable daemons file");
        assert!(
            !enabled.iter().any(|d| d == "bgpd"),
            "that line is a comment"
        );
        assert!(enabled.iter().any(|d| d == "bfdd"), "but this one is not");
    }

    /// A daemon that is enabled but not installed would otherwise be named to `watchfrr`, which
    /// retries a failing start on an interval rather than reporting it.
    #[test]
    fn an_enabled_daemon_that_is_not_installed_is_dropped() {
        let install = Install::new("absent", "bgpd=yes\n", &["mgmtd", "zebra", "staticd"]);
        assert_eq!(
            install.enabled().expect("a readable daemons file"),
            ["mgmtd", "zebra", "staticd"],
            "bgpd is enabled but absent, so it should not be named"
        );
    }

    #[test]
    fn a_missing_zebra_is_an_error_rather_than_a_smaller_frr() {
        let install = Install::new("no-zebra", "bgpd=yes\n", &["mgmtd", "staticd", "bgpd"]);
        assert!(
            matches!(
                install.enabled(),
                Err(FrrError::MissingDaemon {
                    daemon: "zebra",
                    ..
                })
            ),
            "FRR without zebra is a broken install, not a degraded one"
        );
    }

    #[test]
    fn a_file_that_is_not_there_is_an_error() {
        let root = std::env::temp_dir().join(format!("frr-test-none-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        assert!(
            matches!(
                enabled_daemons(&root, &root),
                Err(FrrError::UnreadableDaemons { .. })
            ),
            "a missing daemons file is a broken install"
        );
    }

    /// A directory is not a daemon, however it is named.
    #[test]
    fn a_directory_named_like_a_daemon_is_not_executable() {
        let install = Install::new("dir", "bgpd=yes\n", &["mgmtd", "zebra", "staticd"]);
        fs::create_dir_all(install.root.join("libexec/bgpd")).expect("a directory");
        assert!(
            !install
                .enabled()
                .expect("a readable daemons file")
                .iter()
                .any(|d| d == "bgpd"),
            "a directory cannot be started"
        );
    }

    #[test]
    fn frr_is_ready_when_zebra_is_listening() {
        assert_eq!(
            readiness(Path::new("/run/frr")),
            PathBuf::from("/run/frr/zebra.vty"),
            "watchfrr uses the same evidence"
        );
    }

    #[test]
    fn the_agent_is_told_where_to_listen_and_waited_for_there() {
        let process = agent("/run/frr/frr-agent.sock");
        assert_eq!(process.name, "frr-agent");
        assert_eq!(
            process.command.get_args().collect::<Vec<_>>(),
            ["--sock-path", "/run/frr/frr-agent.sock"],
            "the socket the dataplane will connect to is the agent's to bind"
        );
        assert_eq!(
            process.ready,
            crate::supervisor::Ready::Path(PathBuf::from("/run/frr/frr-agent.sock")),
            "and the same path is the evidence it is listening"
        );
    }

    /// `watchfrr` must stay in the foreground, or the supervisor has nothing to wait on.
    #[test]
    fn watchfrr_is_not_daemonized() {
        let daemons = ["zebra".to_string(), "bgpd".to_string()];
        let process = watchfrr(&daemons);
        let args: Vec<_> = process.command.get_args().collect();
        assert_eq!(args, ["zebra", "bgpd"], "the daemons, and nothing else");
        assert!(
            !args.iter().any(|a| *a == "-d" || *a == "--daemon"),
            "a daemonized watchfrr would be reaped as an orphan with nobody waiting on it"
        );
    }
}
