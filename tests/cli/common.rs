/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

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

    pub fn run(&self, args: &[&str], master_password: Option<&str>) -> expectrl::session::Session
    {
        let binary = env!("CARGO_BIN_EXE_pfp-cli");
        let mut command = std::process::Command::new(binary);
        command.args(["-c", self.storage_file.to_str().expect("Temporary file path should be valid Unicode")]);
        command.args(args);

        let mut session = expectrl::session::Session::spawn(command).expect("Running binary should succeed");
        session.set_expect_timeout(Some(std::time::Duration::from_secs(10)));

        if let Some(master_password) = master_password
        {
            session.expect("Your master password:").expect("App should request master password");
            session.send_line(master_password).unwrap();
        }

        session
    }

    pub fn initialize(&self, master_password: &str)
    {
        let mut session = self.run(&["set-master"], None);

        session.expect("New master password:").expect("App should request master password");
        session.send_line(master_password).unwrap();
        session.expect("Repeat master password:").expect("App should request master password to be repeated");
        session.send_line(master_password).unwrap();
        session.expect("master password set").expect("App should accept master password");
    }
}

pub fn read_to_eof(session: &mut expectrl::session::Session) -> String
{
    let capture = session.expect(expectrl::Eof).expect("App should terminate");
    String::from_utf8_lossy(capture.as_bytes()).into_owned()
}
