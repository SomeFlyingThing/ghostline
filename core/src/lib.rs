pub const SERVE_IP: &str = "127.0.0.1:1278";

//never change the numbers
#[repr(u8)]
pub enum Operation {
    WaitingForJoin = 1,
    Accept = 2,
    HandShake = 3,
    ShowMyData = 4,
    Message = 5,
    Talk = 6,
}

//room keys
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

pub const ROOMK_SIZE: usize = 16;
pub const USER_ID_SIZE: usize = 16;
pub const MESSAGE_PUBLIC_KEY_SIZE: usize = 32;
pub const MESSAGE_NONCE_SIZE: usize = 24;
pub const MESSAGE_TAG_SIZE: usize = 16;
pub const MAX_MESSAGE_SIZE: u64 = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct UserId([u8; USER_ID_SIZE]);

impl UserId {
    pub fn new() -> Result<Self> {
        let mut id = [0u8; USER_ID_SIZE];
        getrandom::fill(&mut id)?;
        Ok(Self(id))
    }

    pub const fn from_bytes(bytes: [u8; USER_ID_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; USER_ID_SIZE] {
        &self.0
    }

    pub async fn read_from(stream: &mut (impl AsyncRead + Unpin)) -> Result<Self> {
        let mut bytes = [0u8; USER_ID_SIZE];
        stream.read_exact(&mut bytes).await?;
        Ok(Self(bytes))
    }

    pub async fn write_to(&self, stream: &mut (impl AsyncWrite + Unpin)) -> Result<()> {
        stream.write_all(self.as_bytes()).await?;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct RoomK([u8; ROOMK_SIZE]);
impl RoomK {
    pub fn new() -> Result<Self> {
        let mut key = [0u8; ROOMK_SIZE];

        getrandom::fill(&mut key)?;
        Ok(RoomK(key))
    }
    pub const fn bytes(&self) -> &[u8] {
        &self.0
    }
    pub async fn notify_server_of_room(
        &self,
        stream: &mut TcpStream,
        user_id: &UserId,
    ) -> Result<()> {
        stream.write_all(&[Operation::WaitingForJoin as u8]).await?;
        user_id.write_to(stream).await?;
        stream.write_all(self.bytes()).await?;

        Ok(())
    }
    pub const fn from(key: &[u8; ROOMK_SIZE]) -> Self {
        RoomK(*key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_user_ids_are_not_reused() {
        let first = UserId::new().unwrap();
        let second = UserId::new().unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn generated_room_key_contains_random_bytes() {
        let key = RoomK::new().unwrap();
        assert_ne!(key.bytes(), &[0; ROOMK_SIZE]);
    }
}
