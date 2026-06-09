// The `fatal!` macro must be used instead of `panic!` throughout this crate.
// `panic!` does not reliably flush stdout/stderr in an init system context,
// and tokio's panic-forwarding can mangle the final error output.
macro_rules! fatal {
    ($($arg:tt)*) => {
        {
            use ::std::io::Write as _;
            // quick best effort flush of stdout and stderr before logging fatal error
            let _ = ::std::io::stdout().flush();
            let _ = ::std::io::stderr().flush();
            // now we lock stdout and stderr to prevent the console from getting mangled when we abort
            let mut stdout_lock = ::std::io::stdout().lock();
            let mut stderr_lock = ::std::io::stderr().lock();
            let _ = stdout_lock.flush();
            let _ = stderr_lock.flush();
            ::tracing::error!($($arg)*);
            ::tracing::error!("NOTE: test or test fixture failed! Expect a general protection fault and a kernel panic.");
            ::tracing::error!("see other logs for cause of failure.  The general protection fault is expected.");
            let _ = stdout_lock.flush();
            let _ = stderr_lock.flush();
            let _ = ::nix::unistd::close(0);
            let _ = ::nix::unistd::close(1);
            let _ = ::nix::unistd::close(2);
            // Abort rather than panic to prevent tokio's panic-forwarding
            // from writing to fds 0/1/2 after they have been closed (or
            // worse, to unrelated file descriptors that reused those numbers).
            ::std::process::abort();
        }
    };
}
