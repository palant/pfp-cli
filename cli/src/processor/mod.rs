/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

mod add;
mod add_stored;
mod alias;
mod list;
mod notes;
mod remove;
mod set_primary;
mod shell;
mod show;
pub mod utils;

use crate::args::{Args, Commands};
use pfp::passwords::Passwords;
use pfp::storage_io;

pub fn process_command<IO: storage_io::StorageIO>(
    args: Args,
    storage_path: &std::path::PathBuf,
    passwords: &mut Passwords<IO>,
) -> Result<(), String> {
    match &args.command {
        Commands::SetPrimary { .. } => set_primary::processor(&args, storage_path, passwords),
        Commands::Add { .. } => add::processor(&args, passwords),
        Commands::AddStored { .. } => add_stored::processor(&args, passwords),
        Commands::Remove { .. } => remove::processor(&args, passwords),
        Commands::Show { .. } => show::processor(&args, passwords),
        Commands::Notes { .. } => notes::processor(&args, passwords),
        Commands::List { .. } => list::processor(&args, passwords),
        Commands::SetAlias { .. } => alias::processor_set(&args, passwords),
        Commands::RemoveAlias { .. } => alias::processor_remove(&args, passwords),
        Commands::Shell { .. } => shell::processor(&args, storage_path, passwords),
    }
}
