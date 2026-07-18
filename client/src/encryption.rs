use crypto_box::{
    ChaChaBox, PublicKey, SecretKey,
    aead::{AeadCore, AeadMut, Nonce, OsRng},
};
use ghostline_core::{Operation, UserId};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use zeroize::Zeroize;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 24;

pub struct Keys {
    public: [u8; 32],
    private: [u8; 32],
}

impl Keys {
    pub fn new() -> Self {
        let secret = SecretKey::generate(&mut OsRng);
        let publiv = secret.public_key();
        let publiv = publiv.as_bytes();
        let secret = secret.to_bytes();
        Self {
            public: *publiv,
            private: secret,
        }
    }
    pub async fn share(&self, stream: &mut TcpStream, user_id: &UserId) -> anyhow::Result<()> {
        stream.write_all(&[Operation::HandShake as u8]).await?;
        user_id.write_to(stream).await?;
        stream.write_all(&self.public).await?;
        Ok(())
    }
    pub const fn private_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.private
    }

    pub const fn public_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.public
    }
}

pub struct FriendK {
    user_id: UserId,
    key: [u8; KEY_SIZE],
}
impl FriendK {
    pub async fn read(stream: &mut TcpStream) -> anyhow::Result<Self> {
        let mut key = [0u8; KEY_SIZE];

        let mut op = [0u8; 1];
        stream.read_exact(&mut op).await?;
        anyhow::ensure!(
            op[0] == Operation::HandShake as u8,
            "expected handshake operation, received {}",
            op[0]
        );
        let user_id = UserId::read_from(stream).await?;
        stream.read_exact(&mut key).await?;

        Ok(FriendK { user_id, key })
    }
    pub const fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

pub struct Encryption {
    cipher: ChaChaBox,
}

impl Encryption {
    pub fn derive_real(private: &Keys, friend: &FriendK) -> Self {
        Self::from_key_bytes(private.private_bytes(), friend.as_bytes())
    }

    pub fn from_key_bytes(
        private_key: &[u8; KEY_SIZE],
        friend_public_key: &[u8; KEY_SIZE],
    ) -> Self {
        let cipher = ChaChaBox::new(
            &PublicKey::from_bytes(*friend_public_key),
            &SecretKey::from_bytes(*private_key),
        );
        Self { cipher }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> anyhow::Result<([u8; NONCE_SIZE], Vec<u8>)> {
        let nonce = ChaChaBox::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| anyhow::anyhow!("could not encrypt message"))?;
        Ok((nonce.into(), ciphertext))
    }
    pub fn decrypt(&mut self, nonce: &[u8; NONCE_SIZE], data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = Nonce::<ChaChaBox>::from_slice(nonce);

        self.cipher
            .decrypt(nonce, data)
            .map_err(|_| anyhow::anyhow!("could not decrypt message"))
    }
}
