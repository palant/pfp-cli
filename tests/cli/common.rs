/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use std::io::Read;
use std::io::Write;

pub struct Setup
{
    storage_file: tempfile::TempPath,
}

impl Setup
{
    pub fn new() -> Self
    {
        let setup = Self {
            storage_file:
                tempfile::NamedTempFile::new()
                    .expect("Creating a temporary file should succeed")
                    .into_temp_path(),
        };
        std::fs::remove_file(&setup.storage_file).expect("Temporary file should be removed");
        setup
    }

    pub fn set_file_data(&self, data: &str)
    {
        std::fs::write(&self.storage_file, data.as_bytes()).expect("Writing to temporary file should succeed");
    }

    pub fn run(&self, args: &[&str], master_password: Option<&str>) -> Session
    {
        let binary = env!("CARGO_BIN_EXE_pfp-cli");

        let process =
            subprocess::Exec::cmd(binary)
                .args(&["--stdin-passwords".as_ref(), "-c".as_ref(), self.storage_file.as_os_str()])
                .args(args)
                .stdin(subprocess::Redirection::Pipe)
                .stdout(subprocess::Redirection::Pipe)
                .stderr(subprocess::Redirection::Merge)
                .popen()
                .expect("Running binary should succeed");
        let mut session = Session::new(process);

        if let Some(master_password) = master_password
        {
            session.expect_str("Your master password:");
            session.send_line(master_password);
        }

        session
    }

    pub fn initialize(&self, master_password: &str)
    {
        let mut session = self.run(&["set-master"], None);

        session.expect_str("New master password:");
        session.send_line(master_password);
        session.expect_str("Repeat master password:");
        session.send_line(master_password);
        session.expect_str("master password set");
    }
}

pub struct Session
{
    process: subprocess::Popen,
}

impl Session
{
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    fn new(process: subprocess::Popen) -> Self
    {
        Self { process }
    }

    pub fn expect_str(&mut self, pattern: &str)
    {
        let start = std::time::Instant::now();
        let mut stdout = self.process.stdout.as_ref().expect("Process should have stdout");
        let mut contents = Vec::new();
        let mut buffer = [0u8; 1];
        while !contents.ends_with(pattern.as_bytes())
        {
            assert!(start.elapsed() < Self::TIMEOUT, "Timed out waiting for string '{}' in process output, instead received: '{}'", pattern, String::from_utf8(contents).unwrap());
            let n = stdout.read(&mut buffer).expect(&format!("Failed waiting for string {} in process output", pattern));
            contents.extend_from_slice(&buffer[0 .. n]);
        }
    }

    pub fn send_line(&mut self, line: &str)
    {
        let mut stdin = self.process.stdin.as_ref().expect("Process should have stdin");
        stdin.write_all(line.as_bytes()).expect(&format!("Failed sending the string {} to process input", line));
        stdin.write_all(b"\n").expect("Failed sending terminating newline to process input");
    }

    pub fn read_to_eof(&mut self) -> String
    {
        let start = std::time::Instant::now();
        let mut stdout = self.process.stdout.as_ref().expect("Process should have stdout");
        let mut contents = Vec::new();
        let mut buffer = [0u8; 1000];
        loop
        {
            assert!(start.elapsed() < Self::TIMEOUT, "Timed out waiting for EOF");
            match stdout.read(&mut buffer)
            {
                Ok(n) => if n == 0
                {
                    break;
                }
                else
                {
                    contents.extend_from_slice(&buffer[0 .. n]);
                },
                Err(error) => if error.kind() == std::io::ErrorKind::UnexpectedEof
                {
                    break;
                }
                else if error.kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                else
                {
                    panic!("Unexpected error waiting for EOF: {}", error);
                },
            }
        }
        String::from_utf8(contents).expect("App output should be valid UTF-8").replace('\r', "")
    }

    pub fn kill(&mut self)
    {
        self.process.kill().expect("App should terminate");
    }
}
