//
//   Copyright 2018, 2019 Delphix
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//

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

// Run a ptool against a sample process and return the stdout of the ptool
pub fn run_ptool(tool: &str, test_proc: &str) -> String {

    let signal_file = Path::new("/tmp/ptools-test-ready");
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }

    let mut examined_proc = Command::new(find_exec(test_proc))
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .spawn()
        .unwrap();

    // Wait for process-to-be-examined to be ready
    while !signal_file.exists() {
        if let Some(status) = examined_proc.try_wait().unwrap() {
            panic!("Child exited too soon with status {}", status)
        }
    }

    let pfiles_output = Command::new(find_exec(tool))
        .arg(examined_proc.id().to_string())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&pfiles_output.stderr);
    let stdout = String::from_utf8_lossy(&pfiles_output.stdout);
    assert_eq!(stderr, "");

    examined_proc.kill().unwrap();

    stdout.into_owned()
}

