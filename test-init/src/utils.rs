// NOTE: do not call `panic!` anywhere in this file.  Instead, use the `fatal!` macro.
// It is important that we flush stdout and stderr before exiting, and panic!
// may not do that correctly in the case of an init system.
#[macro_export]
macro_rules! fatal {
    ($msg:expr) => {
        // quick best effort flush of stdout and stderr before logging fatal error
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        // now we lock stdout and stderr to prevent the console from getting mangled when we abort
        let mut stdout_lock = std::io::stdout().lock();
        let mut stderr_lock = std::io::stderr().lock();
        let _ = stdout_lock.flush();
        let _ = stderr_lock.flush();
        error!($msg);
        error!("NOTE: test or test fixture failed! Expect a general protection fault and a kernel panic.");
        error!("see other logs for cause of failure.  The general protection fault is expected.");
        let _ = stdout_lock.flush();
        let _ = stderr_lock.flush();
        nix::unistd::close(0).unwrap();
        nix::unistd::close(1).unwrap();
        nix::unistd::close(2).unwrap();
        // Note: I use abort here so that the panic handlers can't interfere with the shutdown process.
        //
        // If we use panic! then the last few lines of the error message can get mangled because
        // tokio can forward the panic through task join handles and additional output may occur there.
        // That shouldn't be possible because we have closed stdout, stderr, and stdin.
        // But even then, the best case is that we fail for spurious reasons by attempting to write to closed
        // fds.
        //
        // Even worse, if additional files are somehow opened, they may get fd 0, 1, or 2 and then we have no idea
        // what will happen when messages are printed.  Best to just be heavy handed and abort.
        std::process::abort();
    };
}