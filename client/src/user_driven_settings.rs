use std::{env::home_dir, marker::PhantomData, path::PathBuf};

use ghostline_core::{Operation, UserId};
use serde::{self, Deserialize, Serialize};
use serde_big_array::BigArray;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::encryption::Encryption;

const APP_NAME: &str = "ghostmessager.toml";
const NAME_LEN: usize = 30;
const PIC_SIZE: usize = 120 * 64;
const BIO_LEN: usize = 250;

#[derive(Clone)]
pub struct Mine;
#[derive(Clone)]
pub struct Friend;

#[derive(Serialize, Deserialize, Hash, Clone)]
pub struct Settings<Person> {
    pub user_id: UserId,
    pub name: [u8; NAME_LEN],
    #[serde(with = "BigArray")]
    picture: [u8; PIC_SIZE],

    #[serde(with = "BigArray")]
    bio: [u8; BIO_LEN],
    #[serde(skip)]
    _person: PhantomData<Person>,
}
impl<T> Settings<T> {
    pub fn name_to_string(&self) -> String {
        let length = self
            .name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(NAME_LEN);
        let name = str::from_utf8(&self.name[..length]).expect("couldnt convert name to string");
        name.to_string()
    }

    pub fn picture(&self) -> &[u8] {
        unpadded(&self.picture)
    }

    pub fn bio(&self) -> &[u8] {
        unpadded(&self.bio)
    }
}

impl Settings<Mine> {
    pub fn new(user_id: UserId) -> Self {
        let raw = RealToml::new();

        let name = fixed::<NAME_LEN>(raw.name.as_bytes());
        let picture = fixed::<PIC_SIZE>(raw.picture.as_bytes());
        let bio = fixed::<BIO_LEN>(raw.bio.as_bytes());

        Self {
            user_id,
            name,
            picture,
            bio,
            _person: PhantomData,
        }
    }

    pub async fn share(
        &mut self,
        stream: &mut TcpStream,
        encryption: &mut Encryption,
    ) -> anyhow::Result<()> {
        let (name_nonce, name) = encryption.encrypt(&self.name)?;
        let (bio_nonce, bio) = encryption.encrypt(&self.bio)?;
        let (picture_nonce, picture) = encryption.encrypt(&self.picture)?;

        stream.write_all(&[Operation::ShowMyData as u8]).await?;
        self.user_id.write_to(stream).await?;
        stream.write_all(&name_nonce).await?;
        stream.write_all(&name).await?;
        stream.write_all(&bio_nonce).await?;
        stream.write_all(&bio).await?;
        stream.write_all(&picture_nonce).await?;
        stream.write_all(&picture).await?;

        Ok(())
    }
}
pub const ENC_ADDED: usize = 16;
pub const NONCE_SIZE: usize = 24;

impl Settings<Friend> {
    #[cfg(test)]
    pub(crate) fn from_parts(user_id: UserId, name: &[u8], picture: &[u8], bio: &[u8]) -> Self {
        Self {
            user_id,
            name: fixed(name),
            picture: fixed(picture),
            bio: fixed(bio),
            _person: PhantomData,
        }
    }

    pub async fn read_friend(
        stream: &mut TcpStream,
        encryption: &mut Encryption,
    ) -> anyhow::Result<Self> {
        let mut op = [0u8; 1];
        let mut name = [0u8; NAME_LEN + ENC_ADDED];
        let mut bio = [0u8; BIO_LEN + ENC_ADDED];
        let mut pic = [0u8; PIC_SIZE + ENC_ADDED];
        let mut name_nonce = [0u8; NONCE_SIZE];
        let mut bio_nonce = [0u8; NONCE_SIZE];
        let mut picture_nonce = [0u8; NONCE_SIZE];

        stream.read_exact(&mut op).await?;
        anyhow::ensure!(
            op[0] == Operation::ShowMyData as u8,
            "expected profile operation, received {}",
            op[0]
        );
        let user_id = UserId::read_from(stream).await?;
        stream.read_exact(&mut name_nonce).await?;
        stream.read_exact(&mut name).await?;
        stream.read_exact(&mut bio_nonce).await?;
        stream.read_exact(&mut bio).await?;
        stream.read_exact(&mut picture_nonce).await?;
        stream.read_exact(&mut pic).await?;

        let name: [u8; NAME_LEN] = encryption
            .decrypt(&name_nonce, &name)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("decrypted name has an invalid length"))?;
        let bio: [u8; BIO_LEN] = encryption
            .decrypt(&bio_nonce, &bio)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("decrypted bio has an invalid length"))?;
        let pic: [u8; PIC_SIZE] = encryption
            .decrypt(&picture_nonce, &pic)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("decrypted picture has an invalid length"))?;

        Ok(Self {
            user_id,
            name,
            bio,
            picture: pic,
            _person: PhantomData,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct RealToml {
    name: String,
    picture: String, //pic is a path to pic
    bio: String,
}
impl RealToml {
    fn new() -> Self {
        let text = std::fs::read_to_string(build_path())
            .expect("couldnt read the toml config check the format");
        toml::from_str(&text).expect("couldnt read the toml config check the format")
    }
}

fn build_path() -> PathBuf {
    let home = home_dir().expect("couldnt read home dir");
    home.join(APP_NAME)
}
fn fixed<const N: usize>(bytes: &[u8]) -> [u8; N] {
    assert!(bytes.len() <= N);

    let mut out = [0u8; N];
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

fn unpadded(bytes: &[u8]) -> &[u8] {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    &bytes[..length]
}
