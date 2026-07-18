use std::{
    env, fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use ghostline_core::{USER_ID_SIZE, UserId};

const APP_DIRECTORY: &str = ".ghostline";
const USER_ID_FILE: &str = "user_id";
const FRIEND_IDS_FILE: &str = "friend_ids.toml";

pub fn get_path() -> Result<PathBuf> {
    let home = env::var_os("HOME").context("HOME is not set; cannot store the user ID")?;
    Ok(PathBuf::from(home).join(APP_DIRECTORY).join(USER_ID_FILE))
}

pub fn get_friend_store_path() -> Result<PathBuf> {
    let home = env::var_os("HOME").context("HOME is not set; cannot store friend IDs")?;
    Ok(PathBuf::from(home)
        .join(APP_DIRECTORY)
        .join(FRIEND_IDS_FILE))
}

pub fn load_or_create_user_id() -> Result<UserId> {
    load_or_create_user_id_at(&get_path()?)
}

fn load_or_create_user_id_at(path: &Path) -> Result<UserId> {
    match fs::read(path) {
        Ok(bytes) => {
            if bytes.len() != USER_ID_SIZE {
                bail!("stored user ID at {} has an invalid length", path.display());
            }
            let bytes: [u8; USER_ID_SIZE] = bytes.try_into().expect("length checked above");
            Ok(UserId::from_bytes(bytes))
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let user_id = UserId::new()?;
            let parent = path
                .parent()
                .context("user ID path has no parent directory")?;
            fs::create_dir_all(parent)?;
            fs::write(path, user_id.as_bytes())?;
            Ok(user_id)
        }
        Err(error) => Err(error).with_context(|| format!("could not read {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_id_is_persistent() {
        let directory = std::env::temp_dir().join(format!(
            "ghostline-user-id-test-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let path = directory.join(USER_ID_FILE);

        let created = load_or_create_user_id_at(&path).unwrap();
        let loaded = load_or_create_user_id_at(&path).unwrap();

        assert_eq!(created, loaded);
        fs::remove_dir_all(directory).unwrap();
    }
}
