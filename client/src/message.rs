use anyhow::{Context, bail};
use crypto_box::KEY_SIZE;
use ghostline_core::{
    MAX_MESSAGE_SIZE, MESSAGE_NONCE_SIZE, MESSAGE_PUBLIC_KEY_SIZE, MESSAGE_TAG_SIZE, Operation,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::encryption::{Encryption, Keys};

pub async fn send(
    contents: &str,
    stream: &mut (impl AsyncWrite + Unpin),
    recipient_public_key: &[u8; KEY_SIZE],
) -> anyhow::Result<()> {
    let plaintext = contents.as_bytes();
    if plaintext.len() as u64 > MAX_MESSAGE_SIZE {
        bail!("message is larger than the {MAX_MESSAGE_SIZE}-byte limit");
    }

    let ephemeral_keys = Keys::new();
    let mut encryption =
        Encryption::from_key_bytes(ephemeral_keys.private_bytes(), recipient_public_key);
    let (nonce, ciphertext) = encryption.encrypt(plaintext)?;

    stream.write_u8(Operation::Message as u8).await?;
    stream.write_all(ephemeral_keys.public_bytes()).await?;
    stream.write_all(&nonce).await?;
    stream.write_u64(ciphertext.len() as u64).await?;
    stream.write_all(&ciphertext).await?;
    Ok(())
}

pub async fn read(
    stream: &mut (impl AsyncRead + Unpin),
    recipient_private_key: &[u8; KEY_SIZE],
) -> anyhow::Result<String> {
    let operation = stream.read_u8().await?;
    anyhow::ensure!(
        operation == Operation::Message as u8,
        "expected message operation, received {operation}"
    );

    let mut ephemeral_public_key = [0; MESSAGE_PUBLIC_KEY_SIZE];
    stream.read_exact(&mut ephemeral_public_key).await?;
    let mut nonce = [0; MESSAGE_NONCE_SIZE];
    stream.read_exact(&mut nonce).await?;
    let ciphertext_size = stream.read_u64().await?;
    if ciphertext_size > MAX_MESSAGE_SIZE + MESSAGE_TAG_SIZE as u64 {
        bail!("encrypted message is larger than the allowed limit");
    }

    let mut ciphertext = vec![0; ciphertext_size as usize];
    stream.read_exact(&mut ciphertext).await?;
    let mut encryption = Encryption::from_key_bytes(recipient_private_key, &ephemeral_public_key);
    let plaintext = encryption.decrypt(&nonce, &ciphertext)?;
    String::from_utf8(plaintext).context("message is not valid UTF-8")
}

#[cfg(test)]
mod tests {
    use crypto_box::{SecretKey, aead::OsRng};

    use super::*;

    #[tokio::test]
    async fn encrypted_message_frame_round_trips() {
        let bob_secret = SecretKey::generate(&mut OsRng);
        let (mut sender, mut receiver) = tokio::io::duplex(1024);

        send(
            "hello over the relay",
            &mut sender,
            bob_secret.public_key().as_bytes(),
        )
        .await
        .unwrap();
        let received = read(&mut receiver, &bob_secret.to_bytes()).await.unwrap();

        assert_eq!(received, "hello over the relay");
    }

    #[tokio::test]
    async fn every_message_uses_a_new_ephemeral_key() {
        let recipient_secret = SecretKey::generate(&mut OsRng);
        let recipient_public = recipient_secret.public_key();

        let first = sent_ephemeral_public_key(recipient_public.as_bytes()).await;
        let second = sent_ephemeral_public_key(recipient_public.as_bytes()).await;

        assert_ne!(first, second);
    }

    async fn sent_ephemeral_public_key(
        recipient_public_key: &[u8; KEY_SIZE],
    ) -> [u8; MESSAGE_PUBLIC_KEY_SIZE] {
        let (mut sender, mut receiver) = tokio::io::duplex(1024);
        send("message", &mut sender, recipient_public_key)
            .await
            .unwrap();

        assert_eq!(receiver.read_u8().await.unwrap(), Operation::Message as u8);
        let mut ephemeral_public_key = [0; MESSAGE_PUBLIC_KEY_SIZE];
        receiver
            .read_exact(&mut ephemeral_public_key)
            .await
            .unwrap();
        ephemeral_public_key
    }
}
