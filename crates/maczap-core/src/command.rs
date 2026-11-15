//! Runs system tools the safe way (DESIGN §5.2): absolute path, argv (no shell),
//! timeout, captured output.

use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn success(&self) -> bool {
        self.status.success()
    }

    pub fn code(&self) -> Option<i32> {
        self.status.code()
    }
}

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs `program` (which must be an absolute path) with `args`. The child is killed
/// when it outlives `timeout`.
pub fn run<S: AsRef<std::ffi::OsStr>>(
    program: &Path,
    args: &[S],
    timeout: Duration,
) -> io::Result<Output> {
    if !program.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to run `{}`: not an absolute path",
                program.display()
            ),
        ));
    }
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("LC_ALL", "C")
        // Never let a Homebrew call update itself or phone home as a side effect.
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .env("HOMEBREW_NO_ANALYTICS", "1")
        .spawn()?;
    let mut stdout = child.stdout.take().expect("piped");
    let mut stderr = child.stderr.take().expect("piped");
    // Drain both pipes on threads so a chatty child never blocks on a full pipe.
    let out_reader = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = stdout.read_to_end(&mut s);
        s
    });
    let err_reader = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = stderr.read_to_end(&mut s);
        s
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("`{}` did not finish within {timeout:?}", program.display()),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = String::from_utf8_lossy(&out_reader.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&err_reader.join().unwrap_or_default()).into_owned();
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_relative_programs() {
        let err = run(Path::new("ls"), &["/"], DEFAULT_TIMEOUT).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn captures_output_and_status() {
        let out = run(Path::new("/bin/echo"), &["hello"], DEFAULT_TIMEOUT).unwrap();
        assert!(out.success());
        assert_eq!(out.stdout, "hello\n");
    }

    #[test]
    fn kills_a_child_that_outlives_the_timeout() {
        let started = Instant::now();
        let err = run(Path::new("/bin/sleep"), &["5"], Duration::from_millis(200)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
