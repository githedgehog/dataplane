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

/// The reloader `frr-agent` drives to turn a configuration into commands FRR accepts.
///
/// Passed explicitly because the agent's own default, `/hedgehog/frr-reload.py`, describes a
/// Debian FRR container and names nothing in this image. The `DaemonSet` this replaces passed this
/// same path, so getting it wrong does not fail at startup -- the agent starts, listens, and then
/// fails every reload it is asked for.
const RELOADER: &str = "/libexec/frr/frr-reload.py";

/// Where the reloader looks for `vtysh`, the agent's `--bindir`.
///
/// Its default is `/usr/local/bin`, which is empty here. Same failure mode as [`RELOADER`].
const VTYSH_DIR: &str = "/bin";

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

    /// The image has no `frr` user for the daemons to drop to.
    #[error("this image has no {user} user, so FRR has nothing to drop privileges to")]
    NoFrrUser {
        /// The user that was looked for.
        user: &'static str,
    },

    /// FRR's state directory could not be made ready for it.
    #[error("could not prepare {path} for FRR: {source}")]
    StateDir {
        /// The directory that could not be prepared.
        path: PathBuf,
        /// Why it could not be prepared.
        #[source]
        source: std::io::Error,
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

/// The user FRR's daemons drop to.
///
/// Compiled in as `--enable-user=frr` / `--enable-group=frr` (`nix/pkgs/frr/default.nix`), so it
/// is not a choice made here -- it is the name that has to resolve, out of the image's
/// `/etc/passwd`, for FRR to be able to open anything.
const FRR_USER: &str = "frr";

/// Make FRR's state directory writable by FRR.
///
/// Every path in the image is laid down read-only and owned by root -- `dataplane.tar` is tarred
/// with `--mode='ugo-sw'` -- and FRR starts as root only long enough to drop to [`FRR_USER`].
/// After that it has to create `<state>/<daemon>.vty`, which is both how `watchfrr` decides a
/// daemon is up and how [`readiness`] decides FRR is, and the plugin's socket in `<state>/hh`.
/// Left to the image, all of that fails and FRR looks like it hangs on startup.
///
/// This is init's to do rather than the image's because it is the one thing here that is true at
/// runtime and not at build time: the image cannot carry an ownership it has no `chown` to apply,
/// and a container runtime will not apply one either.
///
/// # Errors
///
/// Returns [`FrrError::NoFrrUser`] if the image has no `frr` user, and [`FrrError::StateDir`] if
/// the directory cannot be created or given to it.
pub fn prepare_state_dir(state_dir: &Path) -> Result<(), FrrError> {
    let user = nix::unistd::User::from_name(FRR_USER)
        .ok()
        .flatten()
        .ok_or(FrrError::NoFrrUser { user: FRR_USER })?;

    // `hh` as well as the directory itself: the plugin binds its end of the control-plane socket
    // there as `frr`, while the dataplane binds the other end as root. Creating only the parent
    // leaves the pair half-working in a way that looks like a dataplane problem.
    for path in [state_dir.to_path_buf(), state_dir.join("hh")] {
        fs::create_dir_all(&path).map_err(|source| FrrError::StateDir {
            path: path.clone(),
            source,
        })?;
        nix::unistd::chown(&path, Some(user.uid), Some(user.gid)).map_err(|errno| {
            FrrError::StateDir {
                path: path.clone(),
                source: std::io::Error::from(errno),
            }
        })?;
        // The image's mode has the write bit stripped, so the `chown` alone would hand FRR a
        // directory it still cannot write to.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).map_err(|source| {
            FrrError::StateDir {
                path: path.clone(),
                source,
            }
        })?;
    }

    sweep_stale_state(state_dir);

    debug!(
        "{} is {FRR_USER}'s, uid {} gid {}",
        state_dir.display(),
        user.uid,
        user.gid
    );
    Ok(())
}

/// Suffixes a previous FRR left behind in a state directory that outlives it.
///
/// The vty sockets are the ones that matter. `<state>/zebra.vty` is what [`readiness`] waits for,
/// so a stale one is worse than a missing one: FRR is declared up the instant it is started, the
/// agent is released to configure a zebra that is not listening yet, and the failure surfaces as a
/// configuration that did not apply rather than as a startup problem.
const STALE_SUFFIXES: &[&str] = &[".pid", ".vty", ".sock", ".api", ".started"];

/// Remove what a previous FRR left in the state directory.
///
/// The directory is a host path that outlives the pod, which is what makes this necessary; the
/// `init-frr` container this replaces swept the same set. Only the top level, and only these
/// suffixes -- `hh/` below it is the dataplane's, and it binds its control-plane socket there
/// moments after this runs.
///
/// Failures are logged rather than returned. A file that cannot be removed is a reason to look,
/// not a reason to refuse to start -- FRR will say so itself, and more usefully, when it tries.
fn sweep_stale_state(state_dir: &Path) {
    let Ok(entries) = fs::read_dir(state_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !STALE_SUFFIXES.iter().any(|s| name.ends_with(s)) {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => info!("removed {}, left by a previous FRR", path.display()),
            Err(e) => warn!("could not remove {}: {e}", path.display()),
        }
    }
}

/// Where FRR keeps its state, for callers that have to prepare it.
#[must_use]
pub fn state_dir() -> PathBuf {
    PathBuf::from(STATE_DIR)
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
    command.arg("--reloader").arg(RELOADER);
    command.arg("--bindir").arg(VTYSH_DIR);
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
            [
                "--sock-path",
                "/run/frr/frr-agent.sock",
                "--reloader",
                RELOADER,
                "--bindir",
                VTYSH_DIR,
            ],
            "the socket the dataplane will connect to is the agent's to bind, and the reloader \
             and vtysh directory are passed because the agent's own defaults describe a Debian \
             container: getting them wrong fails every reload rather than the startup"
        );
        assert_eq!(
            process.ready,
            crate::supervisor::Ready::Path(PathBuf::from("/run/frr/frr-agent.sock")),
            "and the same path is the evidence it is listening"
        );
    }

    /// The sweep exists for `zebra.vty`; `hh/` exists for a socket the dataplane already bound.
    #[test]
    fn a_stale_vty_goes_and_the_dataplanes_socket_stays() {
        let root = std::env::temp_dir().join(format!("frr-sweep-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("hh")).expect("temp dir");
        for name in [
            "zebra.vty",
            "bgpd.pid",
            "frr-agent.sock",
            "watchfrr.started",
        ] {
            fs::write(root.join(name), "").expect("stale file");
        }
        fs::write(root.join("hh/dataplane.sock"), "").expect("live socket");
        // Not one of ours, and not a suffix we sweep: a sweep that took this would be a sweep
        // nobody could keep anything beside.
        fs::write(root.join("frr.log"), "").expect("bystander");

        sweep_stale_state(&root);

        for name in [
            "zebra.vty",
            "bgpd.pid",
            "frr-agent.sock",
            "watchfrr.started",
        ] {
            assert!(
                !root.join(name).exists(),
                "{name} would have made FRR look up before it was"
            );
        }
        assert!(
            root.join("hh/dataplane.sock").exists(),
            "`hh/` is the dataplane's; it binds its control-plane socket there moments after this"
        );
        assert!(root.join("frr.log").exists(), "not ours to remove");

        let _ = fs::remove_dir_all(&root);
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
