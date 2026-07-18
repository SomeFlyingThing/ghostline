#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{fs, io::ErrorKind, path::Path};

use anyhow::{Context, Result};
use crypto_box::KEY_SIZE;
use ghostline_core::{RoomK, UserId};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    app_data_encryption::StorageCipher,
    encryption::{FriendK, Keys},
    storage::get_friend_store_path,
    user_driven_settings::{Friend, Settings},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredFriend {
    pub room_key: RoomK,
    pub settings: Settings<Friend>,
    #[serde(default)]
    pub messages_history: Option<Vec<String>>,
    #[serde(default)]
    private_key: Option<[u8; KEY_SIZE]>,
    #[serde(default)]
    friend_public_key: Option<[u8; KEY_SIZE]>,
}

impl StoredFriend {
    pub const fn room_key(&self) -> &RoomK {
        &self.room_key
    }

    pub const fn settings(&self) -> &Settings<Friend> {
        &self.settings
    }

    pub const fn user_id(&self) -> &UserId {
        &self.settings.user_id
    }

    pub fn into_parts(self) -> (RoomK, Settings<Friend>) {
        (self.room_key, self.settings)
    }

    pub fn chat_key_bytes(&self) -> Result<([u8; KEY_SIZE], [u8; KEY_SIZE])> {
        let private_key = self
            .private_key
            .as_ref()
            .context("this friend predates encrypted chat support; create a new invite")?;
        let friend_public_key = self
            .friend_public_key
            .as_ref()
            .context("this friend predates encrypted chat support; create a new invite")?;
        Ok((*private_key, *friend_public_key))
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct FriendsStore {
    #[serde(default)]
    pub friends: Vec<StoredFriend>,
    #[serde(skip)]
    cipher: Option<StorageCipher>,
}

impl FriendsStore {
    pub fn load(password: &[u8]) -> Result<Self> {
        Self::load_at(&get_friend_store_path()?, password)
    }

    fn load_at(path: &Path, password: &[u8]) -> Result<Self> {
        match fs::read(path) {
            Ok(data) if StorageCipher::is_encrypted(&data) => {
                let (cipher, plaintext) = StorageCipher::decrypt(&data, password)?;
                let mut store: Self = toml::from_slice(&plaintext)
                    .with_context(|| format!("could not parse {}", path.display()))?;
                store.cipher = Some(cipher);
                Ok(store)
            }
            Ok(mut plaintext) => {
                // Migrate the previous plaintext store immediately after loading it.
                let mut store: Self = toml::from_slice(&plaintext)
                    .with_context(|| format!("could not parse {}", path.display()))?;
                plaintext.zeroize();
                store.cipher = Some(StorageCipher::new(password)?);
                store.save_at(path)?;
                Ok(store)
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let store = Self {
                    friends: Vec::new(),
                    cipher: Some(StorageCipher::new(password)?),
                };
                store.save_at(path)?;
                Ok(store)
            }
            Err(error) => Err(error).with_context(|| format!("could not read {}", path.display())),
        }
    }

    pub fn save(&self) -> Result<()> {
        self.save_at(&get_friend_store_path()?)
    }

    fn save_at(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .context("friends store path has no parent directory")?;
        fs::create_dir_all(parent)?;

        let cipher = self
            .cipher
            .as_ref()
            .context("friend store has no encryption key")?;
        let plaintext = Zeroizing::new(toml::to_string_pretty(self)?);
        let encrypted = cipher.encrypt(plaintext.as_bytes())?;
        fs::write(path, encrypted)
            .with_context(|| format!("could not write {}", path.display()))?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("could not secure {}", path.display()))?;
        Ok(())
    }

    pub fn remember(
        &mut self,
        user_id: UserId,
        room_key: RoomK,
        settings: Settings<Friend>,
        keys: &Keys,
        friend_key: &FriendK,
    ) -> Result<()> {
        anyhow::ensure!(
            settings.user_id == user_id,
            "friend profile and handshake user IDs do not match"
        );
        let stored = StoredFriend {
            room_key,
            settings,
            messages_history: None,
            private_key: Some(*keys.private_bytes()),
            friend_public_key: Some(*friend_key.as_bytes()),
        };

        match self
            .friends
            .iter_mut()
            .find(|friend| friend.settings.user_id == user_id)
        {
            Some(existing) => *existing = stored,
            None => self.friends.push(stored),
        }

        self.save()
    }

    pub fn record_message(&mut self, user_id: &UserId, message: String) -> Result<()> {
        self.get_mut(user_id)
            .context("friend was removed while the chat was open")?
            .messages_history
            .get_or_insert_default()
            .push(message);
        self.save()
    }
    pub fn get(&self, user_id: &UserId) -> Option<&StoredFriend> {
        self.friends
            .iter()
            .find(|friend| &friend.settings.user_id == user_id)
    }

    pub fn get_mut(&mut self, user_id: &UserId) -> Option<&mut StoredFriend> {
        self.friends
            .iter_mut()
            .find(|friend| &friend.settings.user_id == user_id)
    }

    pub fn settings_for(&self, user_id: &UserId) -> Option<&Settings<Friend>> {
        self.get(user_id).map(StoredFriend::settings)
    }

    pub fn room_key_for(&self, user_id: &UserId) -> Option<&RoomK> {
        self.get(user_id).map(StoredFriend::room_key)
    }

    pub fn iter(&self) -> impl Iterator<Item = &StoredFriend> {
        self.friends.iter()
    }

    pub fn remove(&mut self, user_id: &UserId) -> Result<Option<StoredFriend>> {
        let removed = self
            .friends
            .iter()
            .position(|friend| &friend.settings.user_id == user_id)
            .map(|position| self.friends.remove(position));

        if removed.is_some() {
            self.save()?;
        }
        Ok(removed)
    }

    pub fn len(&self) -> usize {
        self.friends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.friends.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn friend_profile_and_room_key_are_persistent() {
        let directory = std::env::temp_dir().join(format!(
            "ghostline-friend-store-test-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let path = directory.join("friend_ids.toml");
        let user_id = UserId::new().unwrap();
        let room_key = RoomK::new().unwrap();
        let settings =
            Settings::<Friend>::from_parts(user_id.clone(), b"Alice", b"picture bytes", b"Hello");

        let mut store = FriendsStore {
            friends: Vec::new(),
            cipher: Some(StorageCipher::new(b"test password").unwrap()),
        };
        store.friends.push(StoredFriend {
            room_key: room_key.clone(),
            settings,
            messages_history: None,
            private_key: Some([1; KEY_SIZE]),
            friend_public_key: Some([2; KEY_SIZE]),
        });
        store.save_at(&path).unwrap();

        let loaded = FriendsStore::load_at(&path, b"test password").unwrap();
        let friend = loaded.get(&user_id).unwrap();
        assert_eq!(friend.room_key.bytes(), room_key.bytes());
        assert_eq!(friend.settings.name_to_string(), "Alice");
        assert_eq!(friend.settings.picture(), b"picture bytes");
        assert_eq!(friend.settings.bio(), b"Hello");
        let on_disk = fs::read(&path).unwrap();
        assert!(StorageCipher::is_encrypted(&on_disk));
        assert!(!on_disk.windows(5).any(|part| part == b"Alice"));

        fs::remove_dir_all(directory).unwrap();
    }
}
