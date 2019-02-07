use std::path::{Path, PathBuf};
use std::fs;
use std::io;
use std::process::{Command, Stdio};

// Find an executable produced by the Cargo build
fn find_exec(name: &str) -> PathBuf {

    // Find the path where Cargo has placed the executables by looking at this test process's
    // executable, which was also built by Cargo.
    let this_exec = std::env::current_exe().unwrap();
    let exec_dir = this_exec.parent().unwrap().parent().unwrap();

    exec_dir.join(name)
}

#[test]
fn test_epoll() {

    let signal_file = Path::new("/tmp/ptools-test-ready");
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }

    let mut example_proc = Command::new(find_exec("epoll_example"))
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .spawn()
        .unwrap();

    // Wait for example process to be ready
    while !signal_file.exists() {
       if let Some(status) = example_proc.try_wait().unwrap() {
           panic!("Child exited too soon with status {}", status)
       }
    }

    let pfiles_output = Command::new(find_exec("pfiles"))
        .arg(example_proc.id().to_string())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&pfiles_output.stderr);
    let stdout = String::from_utf8_lossy(&pfiles_output.stdout);
    assert_eq!(stderr, "");

    let pattern = "5: anon_inode(epoll)";
    if !stdout.contains(pattern) {
        panic!("String '{}' not found in command output:\n\n{}\n\n", pattern, stdout);
    }

    example_proc.kill().unwrap();
}
