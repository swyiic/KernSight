//! Device-loop probe: parent opens a file, child `clone`+exec inherits it,
//! child issues `close_range` on that descriptor, parent still reads.
//! Capture with `--files --files-fd --include-threads`.
//!
//! The workspace forbids `unsafe`, so this uses `Command` (kernel still emits
//! clone/fork) and `ksight_hwbp::close_range` rather than `fork(2)` in-process.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(spec) = args
        .iter()
        .find(|arg| arg.starts_with("--child-close-range=") || arg.starts_with("--child-close="))
    {
        let fd = spec
            .rsplit('=')
            .next()
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or(-1);
        if fd >= 0 {
            close_inherited(fd);
        }
        return;
    }
    device_main();
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn close_inherited(fd: i32) {
    if ksight_hwbp::close_range(fd, fd, 0).is_err() {
        let _ = nix::unistd::close(fd);
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn close_inherited(fd: i32) {
    let _ = nix::unistd::close(fd);
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn device_main() {
    use std::{
        fs::OpenOptions,
        io::{Read as _, Seek as _, SeekFrom, Write as _},
        os::fd::AsRawFd as _,
        process::Command,
    };

    let path = "/data/local/tmp/ksight-fd-probe.txt";
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(path)
        .expect("create probe file");
    file.write_all(b"probe\n").expect("write");
    file.sync_all().expect("sync");
    let fd = file.as_raw_fd();
    let exe = std::env::current_exe().expect("current exe");
    let status = Command::new(exe)
        .arg(format!("--child-close-range={fd}"))
        .status();
    match status {
        Ok(code) => {
            let _ = file.seek(SeekFrom::Start(0));
            let mut buf = [0_u8; 8];
            let read = file.read(&mut buf).unwrap_or(0);
            println!(
                "parent_fd={fd} child_status={} read={read} close_range=1",
                code.code().unwrap_or(-1)
            );
        }
        Err(error) => {
            eprintln!("spawn failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn device_main() {
    eprintln!("ksight-fd-probe runs on the Android device agent image");
    std::process::exit(1);
}
