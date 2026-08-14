// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Removes test containers that `n-vm` left behind.
//!
//! The host tier cleans up after itself on every route it can reach: the
//! normal path, a panic, an early return, and -- since the signal handler in
//! `container.rs` -- `SIGTERM` and `SIGINT`.  `SIGKILL` is the one it cannot,
//! because nothing can catch it.  A test runner that escalates to `SIGKILL`,
//! an OOM kill, or a hard reboot therefore still strands a container.
//!
//! Stranded is worse than untidy.  The container is owned by the daemon
//! rather than by the process that asked for it, so it keeps running with
//! nothing left to collect its result -- for a fuzz target, for the whole
//! remaining time budget.  `auto_remove` is deliberately `false`, so even the
//! exited ones persist as records.
//!
//! Selection is by [`LABEL_OWNER`] alone, which is what makes removing in
//! bulk safe to offer: it cannot match a container this crate did not create.
//!
//! # Usage
//!
//! ```shell
//! n-vm-reap              # list orphans and ask before removing
//! n-vm-reap --force      # remove without asking
//! n-vm-reap --list       # list only, never remove
//! n-vm-reap --all        # include containers whose creator is still alive
//! ```

use std::collections::HashMap;
use std::io::Write;
use std::process::ExitCode;

use bollard::query_parameters::{
    ListContainersOptionsBuilder, RemoveContainerOptionsBuilder,
};
use n_vm_protocol::{LABEL_HOST_PID, LABEL_OWNER, LABEL_OWNER_VALUE, LABEL_TEST};

/// What the caller asked for.
struct Args {
    /// Remove without asking for confirmation.
    force: bool,
    /// List and exit, removing nothing.
    list_only: bool,
    /// Include containers whose creating process is still running.
    all: bool,
}

impl Args {
    /// Parses argv.
    ///
    /// Hand-rolled rather than pulled from `clap`: four flags do not justify
    /// adding a dependency to a crate that is otherwise test infrastructure.
    fn parse() -> Result<Self, String> {
        let mut args = Self {
            force: false,
            list_only: false,
            all: false,
        };

        for arg in std::env::args().skip(1) {
            match arg.as_str() {
                "--force" | "-f" => args.force = true,
                "--list" | "-l" => args.list_only = true,
                "--all" | "-a" => args.all = true,
                "--help" | "-h" => {
                    println!("{USAGE}");
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument `{other}`\n\n{USAGE}")),
            }
        }

        if args.force && args.list_only {
            return Err("--force and --list contradict each other".to_owned());
        }

        Ok(args)
    }
}

const USAGE: &str = "\
n-vm-reap -- remove test containers n-vm left behind

USAGE:
    n-vm-reap [FLAGS]

FLAGS:
    -f, --force    Remove without asking for confirmation
    -l, --list     List what would be removed, then exit
    -a, --all      Include containers whose creating process is still
                   running.  Off by default: such a container usually
                   belongs to a live test run, and removing it would
                   break that run rather than tidy up after one.
    -h, --help     Print this message";

/// A container this crate created, as the daemon reports it.
struct Orphan {
    id: String,
    /// Docker's human-readable status, e.g. `Exited (101) 2 minutes ago`.
    status: String,
    /// Test the container was launched for, from [`LABEL_TEST`].
    test: String,
    /// PID recorded at creation, if it parsed.
    host_pid: Option<u32>,
    /// Whether the container is still running.
    running: bool,
}

impl Orphan {
    /// Whether the process that created this container is still around.
    ///
    /// A hint, not proof: PIDs are reused, so a live PID here may be some
    /// unrelated process. That asymmetry is deliberate -- guessing "alive"
    /// leaves a container behind for the next run to clean up, while
    /// guessing "dead" removes one out from under a test that is still
    /// using it. Only the first is recoverable, so an unparseable or
    /// missing PID counts as alive and is left alone.
    fn creator_alive(&self) -> bool {
        let Some(pid) = self.host_pid else {
            return true;
        };
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }
}

fn main() -> ExitCode {
    let args = match Args::parse() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("error: could not start a tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(run(&args))
}

async fn run(args: &Args) -> ExitCode {
    let client = match bollard::Docker::connect_with_unix_defaults() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("error: could not reach the Docker daemon: {e}");
            return ExitCode::FAILURE;
        }
    };

    let found = match list_owned(&client).await {
        Ok(found) => found,
        Err(e) => {
            eprintln!("error: could not list containers: {e}");
            return ExitCode::FAILURE;
        }
    };

    if found.is_empty() {
        println!("no n-vm containers found");
        return ExitCode::SUCCESS;
    }

    // Partition rather than filter, so the skipped ones can be reported.
    // Silently ignoring them would read as "there were none", which is the
    // one message that would send someone looking in the wrong place.
    let (live, orphaned): (Vec<_>, Vec<_>) =
        found.into_iter().partition(|c| c.creator_alive());

    let targets = if args.all {
        orphaned.into_iter().chain(live).collect::<Vec<_>>()
    } else {
        if !live.is_empty() {
            println!(
                "skipping {} container(s) whose creating process is still alive \
                 (pass --all to include them):",
                live.len(),
            );
            for c in &live {
                println!("  {}", describe(c));
            }
            println!();
        }
        orphaned
    };

    if targets.is_empty() {
        println!("no orphaned n-vm containers to remove");
        return ExitCode::SUCCESS;
    }

    println!("{} n-vm container(s):", targets.len());
    for c in &targets {
        println!("  {}", describe(c));
    }

    if args.list_only {
        return ExitCode::SUCCESS;
    }

    if !args.force && !confirm(targets.len()) {
        println!("aborted; nothing removed");
        return ExitCode::SUCCESS;
    }

    let mut failed = 0usize;
    for c in &targets {
        // Forced, because a container that is still running would otherwise
        // fail removal with a 409 and leave exactly the mess being cleaned.
        let options = RemoveContainerOptionsBuilder::default().force(true).build();
        match client.remove_container(&c.id, Some(options)).await {
            Ok(()) => println!("removed {}", short(&c.id)),
            Err(e) => {
                failed += 1;
                eprintln!("error: failed to remove {}: {e}", short(&c.id));
            }
        }
    }

    if failed > 0 {
        eprintln!("{failed} container(s) could not be removed");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

/// Lists every container carrying [`LABEL_OWNER`], running or not.
async fn list_owned(client: &bollard::Docker) -> Result<Vec<Orphan>, bollard::errors::Error> {
    let mut filters = HashMap::new();
    filters.insert(
        "label".to_owned(),
        vec![format!("{LABEL_OWNER}={LABEL_OWNER_VALUE}")],
    );

    let options = ListContainersOptionsBuilder::default()
        // Exited containers are the common case, and they are invisible
        // without this.
        .all(true)
        .filters(&filters)
        .build();

    let containers = client.list_containers(Some(options)).await?;

    Ok(containers
        .into_iter()
        .map(|c| {
            let labels = c.labels.unwrap_or_default();
            Orphan {
                id: c.id.unwrap_or_default(),
                status: c.status.unwrap_or_else(|| "unknown".to_owned()),
                test: labels
                    .get(LABEL_TEST)
                    .cloned()
                    .unwrap_or_else(|| "<unknown test>".to_owned()),
                host_pid: labels.get(LABEL_HOST_PID).and_then(|p| p.parse().ok()),
                // Paused and restarting count as live: all three still hold
                // the VM and its resources, which is what the label is for.
                running: c.state.is_some_and(|s| {
                    use bollard::models::ContainerSummaryStateEnum as State;
                    matches!(s, State::RUNNING | State::RESTARTING | State::PAUSED)
                }),
            }
        })
        .collect())
}

/// One line describing a container, for the listing.
fn describe(c: &Orphan) -> String {
    let pid = c
        .host_pid
        .map_or_else(|| "pid unknown".to_owned(), |p| format!("pid {p}"));
    let running = if c.running { ", RUNNING" } else { "" };
    format!("{}  {}  [{}, {}{}]", short(&c.id), c.test, c.status, pid, running)
}

/// Docker's conventional short form of a container ID.
fn short(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
}

/// Asks before removing.
///
/// A non-tty answers "no": this is meant to be run from CI as well, and a
/// prompt nobody can answer must not be read as consent.  CI should pass
/// `--force`.
fn confirm(count: usize) -> bool {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() {
        eprintln!("not a terminal; refusing to remove without --force");
        return false;
    }

    print!("remove {count} container(s)? [y/N] ");
    if std::io::stdout().flush().is_err() {
        return false;
    }

    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }

    matches!(answer.trim(), "y" | "Y" | "yes" | "Yes")
}
