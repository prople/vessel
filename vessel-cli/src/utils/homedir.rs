use std::fs;
use std::path::Path;

use homedir::my_home;
use rst_common::with_logging::log::debug;

use crate::types::CliError;

pub fn setup_homedir(dir: &str) -> Result<String, CliError> {
    let current_homedir = my_home().map_err(|err| CliError::HomeDirError(err.to_string()))?;

    match current_homedir {
        Some(current_dir) => {
            let vessel_dir = format!("{}/{}", current_dir.display(), dir);
            let vessel_path = Path::new(vessel_dir.clone().as_str()).to_owned();

            if !vessel_path.exists() {
                debug!("vessel directory still not exists");
                let _ = fs::create_dir_all(vessel_path.clone())
                    .map_err(|err| CliError::HomeDirError(err.to_string()))?;
            }

            debug!("vessel home directory: {}", vessel_path.display());
            Ok(vessel_path.display().to_string())
        }
        None => Err(CliError::HomeDirError(
            "unknown home directory path".to_string(),
        )),
    }
}
