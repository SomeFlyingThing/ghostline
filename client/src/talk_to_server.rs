use ghostline_core::{Operation, ROOMK_SIZE, RoomK, UserId};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub async fn accept_invite_notify(
    stream: &mut TcpStream,
    key: &RoomK,
    user_id: &UserId,
) -> anyhow::Result<()> {
    stream.write_all(&[Operation::Accept as u8]).await?;
    user_id.write_to(stream).await?;
    stream.write_all(key.bytes()).await?;
    Ok(())
}

pub fn parse_room_key(key: &str) -> anyhow::Result<RoomK> {
    let key_bytes: [u8; ROOMK_SIZE] = hex::decode(key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invite key must be {} bytes", ROOMK_SIZE))?;
    Ok(RoomK::from(&key_bytes))
}

pub async fn check_if_op_accepted(stream: &mut TcpStream) -> anyhow::Result<UserId> {
    let mut operation_realized = [0u8; 1];
    stream.read_exact(&mut operation_realized).await?;

    anyhow::ensure!(
        operation_realized[0] == Operation::Accept as u8,
        "expected invite acceptance, received operation {}",
        operation_realized[0]
    );
    UserId::read_from(stream).await
}
