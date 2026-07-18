use anyhow::{Result, bail};
use argon2::Argon2;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"GHSTLN01";
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 24;
const KEY_SIZE: usize = 32;
const HEADER_SIZE: usize = MAGIC.len() + SALT_SIZE + NONCE_SIZE;

pub struct StorageCipher {
    key: Zeroizing<[u8; KEY_SIZE]>,
    salt: [u8; SALT_SIZE],
}

impl StorageCipher {
    pub fn new(password: &[u8]) -> Result<Self> {
        let mut salt = [0; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        Self::derive(password, salt)
    }

    pub fn decrypt(data: &[u8], password: &[u8]) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        if !Self::is_encrypted(data) {
            bail!("friend store is not in the encrypted Ghostline format");
        }
        if data.len() <= HEADER_SIZE {
            bail!("encrypted friend store is truncated");
        }

        let salt: [u8; SALT_SIZE] = data[MAGIC.len()..MAGIC.len() + SALT_SIZE]
            .try_into()
            .expect("salt range has a fixed length");
        let cipher = Self::derive(password, salt)?;
        let nonce = XNonce::from_slice(&data[MAGIC.len() + SALT_SIZE..HEADER_SIZE]);
        let plaintext = XChaCha20Poly1305::new_from_slice(cipher.key.as_ref())
            .expect("derived key has the required length")
            .decrypt(
                nonce,
                Payload {
                    msg: &data[HEADER_SIZE..],
                    aad: &data[..HEADER_SIZE],
                },
            )
            .map_err(|_| anyhow::anyhow!("incorrect storage password or corrupted friend store"))?;

        Ok((cipher, Zeroizing::new(plaintext)))
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut output = Vec::with_capacity(HEADER_SIZE + plaintext.len() + 16);
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&self.salt);
        output.extend_from_slice(&nonce);

        let ciphertext = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .expect("derived key has the required length")
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &output,
                },
            )
            .map_err(|_| anyhow::anyhow!("could not encrypt friend store"))?;
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    pub fn is_encrypted(data: &[u8]) -> bool {
        data.starts_with(MAGIC)
    }

    fn derive(password: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        if password.is_empty() {
            bail!("storage password cannot be empty");
        }

        let mut key = Zeroizing::new([0; KEY_SIZE]);
        Argon2::default()
            .hash_password_into(password, &salt, key.as_mut())
            .map_err(|error| anyhow::anyhow!("could not derive storage key: {error}"))?;
        Ok(Self { key, salt })
    }
}

pub fn storage_password_from_env() -> Result<Option<Zeroizing<String>>> {
    if let Ok(password) = std::env::var("GHOSTLINE_STORAGE_PASSWORD") {
        let password = Zeroizing::new(password);
        if password.is_empty() {
            bail!("GHOSTLINE_STORAGE_PASSWORD cannot be empty");
        }
        return Ok(Some(password));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_data_round_trips() {
        let cipher = StorageCipher::new(b"correct horse battery staple").unwrap();
        let encrypted = cipher.encrypt(b"room key and profile").unwrap();
        assert!(!encrypted.windows(8).any(|part| part == b"room key"));

        let (_, decrypted) =
            StorageCipher::decrypt(&encrypted, b"correct horse battery staple").unwrap();
        assert_eq!(decrypted.as_slice(), b"room key and profile");
    }

    #[test]
    fn wrong_password_is_rejected() {
        let cipher = StorageCipher::new(b"right password").unwrap();
        let encrypted = cipher.encrypt(b"secret").unwrap();

        assert!(StorageCipher::decrypt(&encrypted, b"wrong password").is_err());
    }
}
