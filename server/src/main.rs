use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, bail};
use ghostline_core::{
    MAX_MESSAGE_SIZE, MESSAGE_NONCE_SIZE, MESSAGE_PUBLIC_KEY_SIZE, MESSAGE_TAG_SIZE, Operation,
    ROOMK_SIZE, RoomK, SERVE_IP, UserId,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc},
};

type Rooms = Arc<Mutex<HashMap<RoomK, Room>>>;

struct Room {
    creator_id: UserId,
    creator_stream: Option<TcpStream>,
    creator_chat: Option<mpsc::UnboundedSender<Vec<u8>>>,
    joiner_id: Option<UserId>,
    joiner_chat: Option<mpsc::UnboundedSender<Vec<u8>>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let rooms = Rooms::default();
    let listener = TcpListener::bind(SERVE_IP).await?;

    loop {
        let (stream, address) = listener.accept().await?;
        let rooms = Arc::clone(&rooms);
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, rooms).await {
                eprintln!("connection from {address} failed: {error:#}");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, rooms: Rooms) -> anyhow::Result<()> {
    let operation = stream.read_u8().await?;

    match operation {
        operation if operation == Operation::WaitingForJoin as u8 => {
            let creator_id = UserId::read_from(&mut stream).await?;
            let room_key = read_room_key(&mut stream).await?;
            rooms.lock().await.insert(
                room_key,
                Room {
                    creator_id,
                    creator_stream: Some(stream),
                    creator_chat: None,
                    joiner_id: None,
                    joiner_chat: None,
                },
            );
        }
        operation if operation == Operation::Accept as u8 => {
            pair_room(stream, rooms).await?;
        }
        operation if operation == Operation::Talk as u8 => {
            register_chat(stream, rooms).await?;
        }
        operation => bail!("unknown operation {operation}"),
    }

    Ok(())
}

async fn pair_room(mut joiner_stream: TcpStream, rooms: Rooms) -> anyhow::Result<()> {
    let joiner_id = UserId::read_from(&mut joiner_stream).await?;
    let room_key = read_room_key(&mut joiner_stream).await?;

    let (creator_id, mut creator_stream) = {
        let mut rooms = rooms.lock().await;
        let room = rooms
            .get_mut(&room_key)
            .context("invite references an unknown room")?;
        anyhow::ensure!(
            room.joiner_id.is_none(),
            "room already has two participants"
        );
        let creator_stream = room
            .creator_stream
            .take()
            .context("room creator is no longer waiting")?;
        room.joiner_id = Some(joiner_id.clone());
        (room.creator_id.clone(), creator_stream)
    };

    notify_invite_accepted(&mut creator_stream, &joiner_id).await?;
    notify_invite_accepted(&mut joiner_stream, &creator_id).await?;

    tokio::spawn(async move {
        if let Err(error) =
            tokio::io::copy_bidirectional(&mut creator_stream, &mut joiner_stream).await
        {
            eprintln!("room handshake relay failed: {error}");
        }
    });
    Ok(())
}

async fn register_chat(
    mut stream: impl AsyncRead + tokio::io::AsyncWrite + Unpin,
    rooms: Rooms,
) -> anyhow::Result<()> {
    let user_id = UserId::read_from(&mut stream).await?;
    let room_key = read_room_key(&mut stream).await?;
    let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel();

    {
        let mut rooms = rooms.lock().await;
        let room = rooms
            .get_mut(&room_key)
            .context("chat references an unknown room")?;
        if room.creator_id == user_id {
            room.creator_chat = Some(outbound_tx);
        } else if room.joiner_id.as_ref() == Some(&user_id) {
            room.joiner_chat = Some(outbound_tx);
        } else {
            bail!("user is not a participant in this room");
        }
    }

    let (mut reader, mut writer) = tokio::io::split(stream);
    loop {
        tokio::select! {
            frame = outbound_rx.recv() => {
                let Some(frame) = frame else { break };
                writer.write_all(&frame).await?;
            }
            frame = read_message_frame(&mut reader) => {
                let frame = frame?;
                let recipient = {
                    let rooms = rooms.lock().await;
                    let room = rooms.get(&room_key).context("room was removed")?;
                    if room.creator_id == user_id {
                        room.joiner_chat.clone()
                    } else {
                        room.creator_chat.clone()
                    }
                };

                if let Some(recipient) = recipient {
                    let _ = recipient.send(frame);
                }
            }
        }
    }

    Ok(())
}

async fn read_message_frame(stream: &mut (impl AsyncRead + Unpin)) -> anyhow::Result<Vec<u8>> {
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

    let mut frame =
        Vec::with_capacity(1 + ephemeral_public_key.len() + nonce.len() + 8 + ciphertext.len());
    frame.push(operation);
    frame.extend_from_slice(&ephemeral_public_key);
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&ciphertext_size.to_be_bytes());
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}

async fn read_room_key(stream: &mut (impl AsyncRead + Unpin)) -> anyhow::Result<RoomK> {
    let mut key_bytes = [0; ROOMK_SIZE];
    stream.read_exact(&mut key_bytes).await?;
    Ok(RoomK::from(&key_bytes))
}

async fn notify_invite_accepted(stream: &mut TcpStream, friend_id: &UserId) -> anyhow::Result<()> {
    stream.write_u8(Operation::Accept as u8).await?;
    friend_id.write_to(stream).await
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    #[tokio::test]
    async fn message_frames_are_forwarded_without_modification() {
        let nonce = [7; MESSAGE_NONCE_SIZE];
        let ephemeral_public_key = [3; MESSAGE_PUBLIC_KEY_SIZE];
        let ciphertext = b"opaque ciphertext";
        let mut expected = vec![Operation::Message as u8];
        expected.extend_from_slice(&ephemeral_public_key);
        expected.extend_from_slice(&nonce);
        expected.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
        expected.extend_from_slice(ciphertext);
        let mut input = expected.as_slice();

        let frame = read_message_frame(&mut input).await.unwrap();

        assert_eq!(frame, expected);
    }

    #[tokio::test]
    async fn oversized_message_frames_are_rejected_before_allocation() {
        let mut input = vec![Operation::Message as u8];
        input.extend_from_slice(&[0; MESSAGE_PUBLIC_KEY_SIZE]);
        input.extend_from_slice(&[0; MESSAGE_NONCE_SIZE]);
        input.extend_from_slice(&(MAX_MESSAGE_SIZE + MESSAGE_TAG_SIZE as u64 + 1).to_be_bytes());
        let mut input = input.as_slice();

        assert!(read_message_frame(&mut input).await.is_err());
    }

    #[tokio::test]
    async fn registered_room_participants_receive_each_others_frames() {
        let creator_id = UserId::new().unwrap();
        let joiner_id = UserId::new().unwrap();
        let room_key = RoomK::new().unwrap();
        let rooms = Rooms::default();
        rooms.lock().await.insert(
            room_key.clone(),
            Room {
                creator_id: creator_id.clone(),
                creator_stream: None,
                creator_chat: None,
                joiner_id: Some(joiner_id.clone()),
                joiner_chat: None,
            },
        );

        let (mut creator_client, creator_server) = tokio::io::duplex(1024);
        creator_id.write_to(&mut creator_client).await.unwrap();
        creator_client.write_all(room_key.bytes()).await.unwrap();
        let creator_task = tokio::spawn(register_chat(creator_server, Arc::clone(&rooms)));

        let (mut joiner_client, joiner_server) = tokio::io::duplex(1024);
        joiner_id.write_to(&mut joiner_client).await.unwrap();
        joiner_client.write_all(room_key.bytes()).await.unwrap();
        let joiner_task = tokio::spawn(register_chat(joiner_server, Arc::clone(&rooms)));

        timeout(Duration::from_secs(1), async {
            loop {
                let both_registered = {
                    let rooms = rooms.lock().await;
                    let room = rooms.get(&room_key).unwrap();
                    room.creator_chat.is_some() && room.joiner_chat.is_some()
                };
                if both_registered {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let nonce = [9; MESSAGE_NONCE_SIZE];
        let ephemeral_public_key = [4; MESSAGE_PUBLIC_KEY_SIZE];
        let ciphertext = b"still opaque";
        let mut frame = vec![Operation::Message as u8];
        frame.extend_from_slice(&ephemeral_public_key);
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
        frame.extend_from_slice(ciphertext);
        creator_client.write_all(&frame).await.unwrap();

        let mut received = vec![0; frame.len()];
        timeout(
            Duration::from_secs(1),
            joiner_client.read_exact(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, frame);

        creator_task.abort();
        joiner_task.abort();
    }
}
