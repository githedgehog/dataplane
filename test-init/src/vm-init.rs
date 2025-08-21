use nix::errno::Errno;
use nix::mount::{MntFlags, MsFlags, mount};
use nix::sys::reboot::{RebootMode, reboot};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{Pid, sync};
use std::cell::{RefCell, RefMut};
use std::convert::Infallible;
use std::io::Write;
use std::process::{self, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Duration, sleep};
use tokio_vsock::VMADDR_CID_HOST;
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::fmt::MakeWriter;

mod utils;

#[derive(Debug)]
#[non_exhaustive]
struct InitSystem {}

impl InitSystem {
    fn mount_essential_filesystems() -> Result<(), std::io::Error> {
        // Mount /proc with security options
        debug!("mounting /proc");
        fn fail_on_mount(mount: &'static str, e: Errno) -> ! {
            match e {
                Errno::UnknownErrno => {
                    fatal!("unknown error while mounting {mount}");
                }
                Errno::EPERM => {
                    fatal!("permission denied while mounting {mount}");
                }
                other => {
                    fatal!("failed to mount {mount}: {other}");
                }
            }
        }
        if let Err(e) = mount(
            Some("proc"),
            "/proc",
            Some("proc"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            None::<&str>,
        ) {
            fail_on_mount("/proc", e)
        };

        // Mount /sys with security options
        debug!("mounting /sys");
        if let Err(e) = mount(
            Some("sysfs"),
            "/sys",
            Some("sysfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            None::<&str>,
        ) {
            fail_on_mount("/sys", e)
        }

        // no need to mount /dev because CONFIG_DEVTMPFS_MOUNT is enabled in the kernel.  /dev is auto mounted
        // // Mount /dev with appropriate options
        // debug!("mounting /dev");
        // if let Err(e) = mount(
        //     Some("devtmpfs"),
        //     "/dev",
        //     Some("devtmpfs"),
        //     MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        //     Some("mode=0755,size=10M"),
        // ) {
        //     fail_on_mount("/dev", e)
        // };

        // Mount /tmp as tmpfs
        debug!("mounting /tmp");
        if let Err(e) = mount(
            Some("tmpfs"),
            "/tmp",
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            Some("mode=1777,size=5%"),
        ) {
            fail_on_mount("/tmp", e)
        };

        // Mount /run as tmpfs
        debug!("mounting /run");
        if let Err(e) = mount(
            Some("tmpfs"),
            "/run",
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            Some("mode=0755,size=5%"),
        ) {
            fail_on_mount("/run", e)
        }

        // Mount /sys/fs/group with security options
        debug!("mounting /sys/fs/cgroup");
        if let Err(e) = mount(
            Some("cgroup2"),
            "/sys/fs/cgroup",
            Some("cgroup2"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            Some("nsdelegate,memory_recursiveprot"),
        ) {
            fail_on_mount("/sys/fs/cgroup", e)
        }

        // // Mount /project as virtiofs
        // debug!("mounting /project");
        // if let Err(e) = mount(
        //     Some("/dev/project"),
        //     "/project",
        //     Some("virtiofs"),
        //     MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_RDONLY,
        //     None::<&str>,
        // ) {
        //     fail_on_mount("/project", e)
        // }

        debug!("all essential filesystems mounted successfully");
        Ok(())
    }

    async fn spawn_main_process() -> (tokio::fs::File, Child) {
        debug!("spawning main process");

        let mut args = std::env::args();
        if args.len() == 0 {
            fatal!("no arguments provided to init process: no main process specified");
        }

        if args.len() < 2 {
            fatal!("no main process specified to init process");
        }

        let mut console = tokio::fs::OpenOptions::new()
            .read(false)
            .append(true)
            .create_new(false)
            .open("/dev/hvc0")
            .await
            .unwrap();
        console.set_max_buf_size(8_192);

        args.next().unwrap(); // skip self

        let child = Command::new(args.next().unwrap())
            .args(args)
            .kill_on_drop(true)
            .stdin(Stdio::inherit())
            .stderr(console.try_clone().await.unwrap().into_std().await)
            .stdout(console.try_clone().await.unwrap().into_std().await)
            // .current_dir("/project")
            .env("IN_VM", "YES")
            .env("PATH", "/bin")
            .spawn()
            .unwrap();

        if let Some(pid) = child.id() {
            debug!("main process spawned with PID: {pid}");
        } else {
            fatal!("unable to determine main processs id");
        }
        (console, child)
    }

    /// Reaps all orphaned child processes.
    #[tracing::instrument(level = "debug")]
    fn reap() -> bool {
        let mut success = true;
        const ANY_CHILD: Pid = Pid::from_raw(-1);

        loop {
            match waitpid(ANY_CHILD, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(pid, status)) => {
                    if status != 0 {
                        warn!("orphaned process {pid} exited with status {status}");
                    }
                }
                Ok(WaitStatus::Signaled(pid, signal, _)) => {
                    warn!("orphaned process {pid} killed by signal {signal}");
                }
                Ok(WaitStatus::StillAlive) => {
                    break;
                }
                Ok(status) => {
                    debug!("unexpected waitpid status in init: {status:?}");
                    success = false;
                    continue;
                }
                Err(e) => {
                    warn!("unexpected errno from waitpid in init: {e}");
                }
            }
        }
        success
    }

    /// Send signal to all processes except init (PID 1)
    /// Using PID -1 means "all processes that the calling process has permission to send signals to"
    #[tracing::instrument(level = "info")]
    fn send_signal_to_all_processes(signal: Signal) -> Option<()> {
        match kill(Pid::from_raw(-1), signal) {
            Ok(()) => {
                trace!("successfully sent {signal:?} to all processes");
                Some(())
            }
            Err(Errno::ESRCH) => {
                // No processes found - this can happen if we're the only process left
                trace!("no processes found to send {signal:?} to");
                None
            }
            Err(Errno::EPERM) => {
                // Permission denied for some processes - this is fatal to an init system
                fatal!("permission denied when sending signal to all processes: signal {signal:?}");
            }
            Err(e) => {
                fatal!("failed to send signal to all processes: {e}");
            }
        }
    }

    #[tracing::instrument(level = "info")]
    async fn terminate_remaining_processes() -> bool {
        const MAX_SIGTERM_ATTEMPTS: u8 = 50;
        if list_child_processes().await.is_empty() {
            trace!("no child processes remaining");
            return true;
        }
        if !Self::reap() {
            warn!("test seems to be leaking processes");
        }
        // Send SIGTERM to all processes
        let mut sigs: u8 = 0;
        warn!("sending SIGTERM to all remaining processes");
        while sigs <= MAX_SIGTERM_ATTEMPTS
            && let Some(()) = InitSystem::send_signal_to_all_processes(Signal::SIGTERM)
        {
            sigs += 1;
            sleep(Duration::from_millis(10)).await;
            if !Self::reap() {
                error!("test is leaking processes");
            }
            if list_child_processes().await.is_empty() {
                debug!("no child processes remaining");
                return false;
            }
        }
        error!("maximum SIGTERM attempts reached: test did not shut down correctly");
        return false;
    }

    #[tracing::instrument(level = "info")]
    fn unmount_filesystems() {
        debug!("unmounting filesystems");
        // Unmount in reverse order of mounting
        const MOUNTS_TO_UNMOUNT: [&str; 5] = [
            // "/project",
            "/run",
            "/tmp",
            "/sys/fs/cgroup",
            // "/dev",
            "/sys",
            "/proc",
        ];

        for mount_point in MOUNTS_TO_UNMOUNT {
            debug!("unmounting {mount_point}");
            sync();
            loop {
                match nix::mount::umount2(mount_point, MntFlags::MNT_DETACH) {
                    Ok(()) => {
                        debug!("successfully unmounted {mount_point}");
                        sync();
                        break;
                    }
                    Err(Errno::EBUSY) => {
                        warn!("{mount_point} can not be un-mounted yet: busy");
                        sync();
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(Errno::EINVAL) => {
                        warn!("{mount_point} not mounted or invalid");
                        break;
                    }
                    Err(e) => {
                        fatal!("failed to unmount {mount_point}: {e}");
                    }
                }
            }
        }
        debug!("filesystem unmounting completed");
    }

    #[tracing::instrument(level = "info")]
    async fn shutdown_system(success: bool) -> Infallible {
        info!("beginning system shutdown");

        // Terminate all processes using nix signal functions
        let success = Self::terminate_remaining_processes().await && success;

        // Final sync and power off
        match tokio::task::spawn_blocking(move || {
            debug!("syncing filesystems");
            sync();
            Self::unmount_filesystems();
            debug!("final sync");
            sync();
            if success {
                info!("powering off");
                match reboot(RebootMode::RB_POWER_OFF) {
                    Ok(_) => unreachable!(),
                    Err(e) => {
                        fatal!("failed to power off: {e}");
                    }
                }
            } else {
                fatal!("test failed");
            }
        })
        .await
        {
            Ok(_) => {
                // normaly I would use unreachable!() here, but in this case
                // it is better to use fatal!() to help ensure that stdio is flushed.
                fatal!("unreachable code?");
            }
            Err(err) => {
                fatal!("failed to shutdown system: {err}");
            }
        }
    }

    #[tracing::instrument(level = "info")]
    async fn run() -> Infallible {
        info!("starting init system");

        debug!("registering signal handlers");

        // signals to handle in init system
        let mut sigterm = signal(SignalKind::terminate()).unwrap();

        // benign signals to forward to main process
        // NOTE: we intentionally do not handle SIGCHLD yet.
        // If the test is leaking processes that is a failure criteria we will catch after the main process exits.
        let mut sighup = signal(SignalKind::hangup()).unwrap();
        let mut siguser1 = signal(SignalKind::user_defined1()).unwrap();
        let mut siguser2 = signal(SignalKind::user_defined2()).unwrap();
        let mut sigwindow = signal(SignalKind::window_change()).unwrap();

        // signals which represent failure if received, but which should still be forwarded to main process
        let mut sigint = signal(SignalKind::interrupt()).unwrap();
        let mut sigalarm = signal(SignalKind::alarm()).unwrap();
        let mut sigpipe = signal(SignalKind::pipe()).unwrap();
        let mut sigquit = signal(SignalKind::quit()).unwrap();

        debug!("signal handlers registered");

        // Mount essential filesystems
        tokio::task::spawn_blocking(|| Self::mount_essential_filesystems())
            .await
            .unwrap()
            .unwrap();

        // Spawn the main process
        let (mut console, mut child) = InitSystem::spawn_main_process().await;

        let pid = Pid::from_raw(child.id().unwrap() as i32);

        let mut success = true;

        // Main event loop
        loop {
            // any non-terminating exit of this loop should cause us to reap orphaned child processes
            tokio::select! {
                // Main process completion
                result = child.wait() => {
                    match result {
                        Ok(status) => {
                            if status.success() {
                                debug!("main process exited successfully with status {status}");
                            } else {
                                error!("main process exited with failure status {status}");
                                success = false;
                            }
                        },
                        Err(e) => {
                            error!("main process error: {e}");
                            success = false;
                        }
                    }
                    match console.flush().await {
                        Ok(_) => {},
                        Err(e) => {
                            error!("failed to flush console: {e}");
                            success = false;
                        },
                    }
                    break;
                }
                _ = sigterm.recv() => {
                    debug!("received SIGTERM");
                    success = false;
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGTERM).unwrap();
                }
                _ = sigint.recv() => {
                    warn!("forwarding SIGINT");
                    success = false;
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGINT).unwrap();
                }
                _ = sigalarm.recv() => {
                    warn!("forwarding ALARM");
                    success = false;
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGUSR2).unwrap();
                }
                _ = sigpipe.recv() => {
                    warn!("forwarding PIPE");
                    success = false;
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGPIPE).unwrap();
                }
                _ = sigquit.recv() => {
                    warn!("forwarding QUIT");
                    success = false;
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGQUIT).unwrap();
                }
                _ = sighup.recv() => {
                    debug!("forwarding SIGHUP");
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGHUP).unwrap();
                }
                _ = siguser1.recv() => {
                    debug!("forwarding SIGUSR1");
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGUSR1).unwrap();
                }
                _ = siguser2.recv() => {
                    debug!("forwarding SIGUSR2");
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGUSR2).unwrap();
                }
                _ = sigwindow.recv() => {
                    trace!("forwarding WINDOW");
                    nix::sys::signal::kill(pid, nix::sys::signal::SIGWINCH).unwrap();
                }
            }
        }
        InitSystem::shutdown_system(success).await
    }
}

pub struct VsockWriter(RefCell<vsock::VsockStream>);

pub struct VsockWriterGuard<'a>(RefMut<'a, vsock::VsockStream>);

impl std::io::Write for VsockWriterGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl<'a> MakeWriter<'a> for VsockWriter {
    type Writer = VsockWriterGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        VsockWriterGuard(self.0.borrow_mut())
    }
}

unsafe impl Send for VsockWriter {}
unsafe impl Sync for VsockWriter {}

fn main() -> Infallible {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .thread_name_fn(|| {
            static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
            let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
            format!("init-{}", id)
        })
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        eprintln!("init system runtime started: connecting to tracing vsock");
        let tracing_addr = vsock::VsockAddr::new(VMADDR_CID_HOST, 123456);
        let tracing_vsock = VsockWriter(RefCell::new(
            vsock::VsockStream::connect(&tracing_addr).unwrap(),
        ));
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_thread_ids(false)
            .with_thread_names(true)
            .with_line_number(true)
            .with_target(false)
            .with_writer(tracing_vsock)
            .with_file(true)
            .init();

        let _init_span = tracing::span!(tracing::Level::INFO, "init");
        let _guard = _init_span.enter();
        const INIT_PID: u32 = 1;
        if process::id() != INIT_PID {
            fatal!("this program must be run as PID {INIT_PID} (init process)");
        }
        InitSystem::run().await
    })
}

async fn list_child_processes() -> Vec<u32> {
    let mut child_pids = tokio::fs::read_dir("/proc").await.unwrap();
    let mut children = vec![];
    while let Ok(Some(process)) = child_pids.next_entry().await {
        let Ok(pid) = process.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let stat = tokio::fs::read_to_string(format!("/proc/{}/stat", pid)).await;
        let Ok(stat) = stat else {
            continue;
        };
        let Some(ppid) = stat.split_whitespace().nth(3) else {
            continue;
        };
        let Ok(ppid) = ppid.parse::<u32>() else {
            continue;
        };
        if ppid == 1 {
            children.push(pid);
        }
    }
    return children;
}
