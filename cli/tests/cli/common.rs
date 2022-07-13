/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use std::io::Read;
use std::io::Write;

use memmem::{Searcher, TwoWaySearcher};

pub struct Setup {
    storage_file: tempfile::TempPath,
    secrets: Vec<Vec<u8>>,
}

impl Setup {
    pub fn new() -> Self {
        let setup = Self {
            storage_file: tempfile::NamedTempFile::new()
                .expect("Creating a temporary file should succeed")
                .into_temp_path(),
            secrets: Vec::new(),
        };
        std::fs::remove_file(&setup.storage_file).expect("Temporary file should be removed");
        setup
    }

    pub fn set_secrets(&mut self, secrets: &[&[u8]]) {
        for &secret in secrets.iter() {
            self.secrets.push(Vec::from(secret));
        }
    }

    pub fn set_file_data(&self, data: &str) {
        std::fs::write(&self.storage_file, data.as_bytes())
            .expect("Writing to temporary file should succeed");
    }

    pub fn run(&self, args: &[&str], master_password: Option<&str>) -> Session {
        let binary = env!("CARGO_BIN_EXE_pfp-cli");

        let process = subprocess::Exec::cmd(binary)
            .args(&[
                "--stdin-passwords".as_ref(),
                "-c".as_ref(),
                self.storage_file.as_os_str(),
            ])
            .args(if self.secrets.len() > 0 {
                &["--wait"]
            } else {
                &[]
            })
            .args(args)
            .stdin(subprocess::Redirection::Pipe)
            .stdout(subprocess::Redirection::Pipe)
            .stderr(subprocess::Redirection::Merge)
            .popen()
            .expect("Running binary should succeed");
        let mut session = Session::new(process, &self.secrets);

        if let Some(master_password) = master_password {
            session.expect_str("Your master password:");
            session.send_line(master_password);
        }

        session
    }

    pub fn initialize(&self, master_password: &str) {
        let mut session = self.run(&["set-master"], None);

        session.expect_str("New master password:");
        session.send_line(master_password);
        session.expect_str("Repeat master password:");
        session.send_line(master_password);
        session.expect_str("master password set");
    }
}

pub struct Session {
    process: subprocess::Popen,
    secrets: Vec<Vec<u8>>,
}

impl Session {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    fn new(process: subprocess::Popen, secrets: &Vec<Vec<u8>>) -> Self {
        Self {
            process,
            secrets: secrets.clone(),
        }
    }

    pub fn expect_str(&mut self, pattern: &str) {
        let start = std::time::Instant::now();
        let mut stdout = self
            .process
            .stdout
            .as_ref()
            .expect("Process should have stdout");
        let mut contents = Vec::new();
        let mut buffer = [0u8; 1];
        while !contents.ends_with(pattern.as_bytes()) {
            assert!(
                start.elapsed() < Self::TIMEOUT,
                "Timed out waiting for string '{}' in process output, instead received: '{}'",
                pattern,
                String::from_utf8(contents).unwrap()
            );
            let n = stdout.read(&mut buffer).expect(&format!(
                "Failed waiting for string {} in process output",
                pattern
            ));
            contents.extend_from_slice(&buffer[0..n]);
        }
    }

    pub fn send_line(&mut self, line: &str) {
        let mut stdin = self
            .process
            .stdin
            .as_ref()
            .expect("Process should have stdin");
        stdin.write_all(line.as_bytes()).expect(&format!(
            "Failed sending the string {} to process input",
            line
        ));
        stdin
            .write_all(b"\n")
            .expect("Failed sending terminating newline to process input");
    }

    pub fn read_to_empty_line(&mut self) -> String {
        let start = std::time::Instant::now();
        let mut stdout = self
            .process
            .stdout
            .as_ref()
            .expect("Process should have stdout");
        let mut contents = Vec::new();
        let mut buffer = [0u8; 1];
        while !contents.ends_with(b"\n\n") {
            assert!(
                start.elapsed() < Self::TIMEOUT,
                "Timed out waiting for empty line, instead received: '{}'",
                String::from_utf8(contents).unwrap()
            );
            let n = stdout
                .read(&mut buffer)
                .expect("Failed waiting for empty line in process output");
            contents.extend_from_slice(&buffer[0..n]);
        }
        String::from_utf8(contents)
            .expect("App output should be valid UTF-8")
            .replace('\r', "")
    }

    fn read_memory(
        mapping: &proc_maps::MapRange,
        handle: &read_process_memory::ProcessHandle,
    ) -> Vec<u8> {
        match read_process_memory::copy_address(mapping.start(), mapping.size(), handle) {
            Ok(data) => data,
            Err(error) => {
                eprintln!("Reading process memory failed: {}", error);
                Vec::new()
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn check_secrets(&mut self) {
        self.expect_str("Waiting...");

        let needles = self
            .secrets
            .iter()
            .map(|secret| TwoWaySearcher::new(secret))
            .collect::<Vec<TwoWaySearcher>>();

        let pid = self.process.pid().expect("Process should still be running")
            as read_process_memory::Pid;
        let handle: read_process_memory::ProcessHandle = pid.try_into().unwrap();

        let mut secret_found = false;
        'outer: for mapping in proc_maps::get_process_maps(pid).unwrap() {
            if mapping.is_exec() || !mapping.is_read() {
                continue;
            }
            if let Some(path) = mapping.filename() {
                // These special memory areas cannot always be read
                if path.as_os_str() == "[vvar]" || path.as_os_str() == "[vsyscall]" {
                    continue;
                }
            }
            let data = Self::read_memory(&mapping, &handle);
            for needle in &needles {
                if let Some(pos) = needle.search_in(&data) {
                    secret_found = true;
                    eprintln!(
                        "Secret found in process memory at address {:0>16X}",
                        mapping.start() + pos
                    );
                    dump_memory(&data, mapping.start(), pos);
                    break 'outer;
                }
            }
        }

        self.send_line("");
        if !std::thread::panicking() {
            assert!(!secret_found);
        }
    }

    #[cfg(target_os = "macos")]
    pub fn check_secrets(&mut self) {
        self.expect_str("Waiting...");
        self.send_line("");
    }

    pub fn kill(&mut self) {
        self.process.kill().expect("App should terminate");
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.secrets.len() > 0 {
            self.check_secrets();
        }
    }
}

fn dump_memory(memory: &[u8], offset: usize, pos: usize) {
    const CHUNK_SIZE: usize = 0x20;
    const PREFIX_CHUNKS: usize = 16;
    const POSTFIX_CHUNKS: usize = 16;

    let normalized_pos = pos & !(CHUNK_SIZE - 1);
    let start = std::cmp::max(normalized_pos - PREFIX_CHUNKS * CHUNK_SIZE, 0);
    let end = std::cmp::min(normalized_pos + POSTFIX_CHUNKS * CHUNK_SIZE, memory.len());
    let mut current_pos = start;
    for chunk in memory[start..end].chunks(CHUNK_SIZE) {
        eprint!("{:0>16X}  ", offset + current_pos);
        for byte in chunk {
            eprint!("{:0>2X} ", byte);
        }
        for _ in chunk.len()..CHUNK_SIZE {
            eprint!("   ");
        }
        eprint!(" ");
        for byte in chunk {
            if (0x20..0x7F).contains(byte) {
                eprint!("{}", *byte as char);
            } else {
                eprint!("·");
            }
        }
        eprintln!();
        current_pos += CHUNK_SIZE;
    }
    eprintln!();
}
