use std::{env::args, thread};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use encryption::{Encryption, FriendK, Keys};
use ghostline_core::{Operation, RoomK, SERVE_IP, UserId};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Layout},
    style::Style,
    text::Line,
    widgets::{Block, List, ListItem, ListState, Paragraph, Wrap},
};
use talk_to_server::{accept_invite_notify, check_if_op_accepted, parse_room_key};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::mpsc};
use user_driven_settings::Friend;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    app_data_encryption::storage_password_from_env,
    app_driven_storage::FriendsStore,
    storage::get_friend_store_path,
    user_driven_settings::{Mine, Settings},
};

mod app_data_encryption;
pub mod app_driven_storage;
mod encryption;
mod message;
mod storage;
mod talk_to_server;
mod user_driven_settings;

enum Task {
    GenerateInvite,
    Join(String),
    Talk,
    None,
}

enum MenuAction {
    GenerateInvite,
    Join,
    Talk,
    Exit,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut terminal = ratatui::init();
    let result = run(&mut terminal).await;
    if let Err(error) = &result {
        let _ = show_message(&mut terminal, " Ghostline error ", &error.to_string());
    }
    ratatui::restore();
    result
}

async fn run(terminal: &mut DefaultTerminal) -> anyhow::Result<()> {
    let operation = parse_args()?;
    let user_id = storage::load_or_create_user_id()?;
    let new_store = !get_friend_store_path()?.exists();
    let Some(password) = read_storage_password(terminal, new_store)? else {
        return Ok(());
    };
    let mut friend_store = FriendsStore::load(password.as_bytes())?;
    drop(password);

    match operation {
        Task::None => loop {
            match main_menu(terminal)? {
                MenuAction::GenerateInvite => {
                    create_invite(terminal, &user_id, &mut friend_store).await?
                }
                MenuAction::Join => {
                    if let Some(key) = prompt_text(
                        terminal,
                        " Join an invite ",
                        "Paste the invite key · Esc to cancel",
                        false,
                    )? {
                        join_invite(terminal, &user_id, &mut friend_store, &key).await?;
                    }
                }
                MenuAction::Talk => talk(&user_id, &mut friend_store, terminal).await?,
                MenuAction::Exit => return Ok(()),
            }
        },
        Task::GenerateInvite => create_invite(terminal, &user_id, &mut friend_store).await?,
        Task::Join(key) => join_invite(terminal, &user_id, &mut friend_store, &key).await?,
        Task::Talk => talk(&user_id, &mut friend_store, terminal).await?,
    }

    Ok(())
}
fn parse_args() -> anyhow::Result<Task> {
    let mut args = args().skip(1);
    let task = match args.next().as_deref() {
        Some("--invite") => Task::GenerateInvite,
        Some("--join") => {
            let key = args
                .next()
                .filter(|key| !key.is_empty())
                .ok_or_else(|| anyhow::anyhow!("--join requires an invite key"))?;
            Task::Join(key)
        }
        Some("--talk") => Task::Talk,
        Some(argument) => anyhow::bail!("unknown argument {argument}"),
        None => Task::None,
    };
    anyhow::ensure!(args.next().is_none(), "too many arguments");
    Ok(task)
}

fn read_storage_password(
    terminal: &mut DefaultTerminal,
    confirm: bool,
) -> anyhow::Result<Option<Zeroizing<String>>> {
    if let Some(password) = storage_password_from_env()? {
        return Ok(Some(password));
    }

    let Some(password) = prompt_text(
        terminal,
        " Storage password ",
        "Enter the password used to encrypt your local data · Esc to quit",
        true,
    )?
    else {
        return Ok(None);
    };
    if password.is_empty() {
        anyhow::bail!("storage password cannot be empty");
    }
    let password = Zeroizing::new(password);

    if confirm {
        let Some(confirmation) = prompt_text(
            terminal,
            " Confirm storage password ",
            "Enter it again to create your encrypted local data · Esc to quit",
            true,
        )?
        else {
            return Ok(None);
        };
        let mut confirmation = Zeroizing::new(confirmation);
        if password.as_str() != confirmation.as_str() {
            confirmation.zeroize();
            anyhow::bail!("storage passwords do not match");
        }
        confirmation.zeroize();
    }

    Ok(Some(password))
}

fn main_menu(terminal: &mut DefaultTerminal) -> anyhow::Result<MenuAction> {
    let labels = ["Create invite", "Join invite", "Open conversation", "Exit"];
    let mut state = ListState::default().with_selected(Some(0));
    loop {
        terminal.draw(|frame| {
            let list = List::new(labels.map(ListItem::new))
                .block(Block::bordered().title(" Ghostline "))
                .highlight_style(Style::new().reversed())
                .highlight_symbol("› ");
            frame.render_stateful_widget(list, frame.area(), &mut state);
            frame.render_widget(
                Paragraph::new("↑/↓ or j/k to choose · Enter to select · q to exit")
                    .style(Style::new().dim()),
                Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(frame.area())
                    [1],
            );
        })?;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        let selected = state.selected().unwrap_or(0);
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(MenuAction::Exit),
            KeyCode::Up | KeyCode::Char('k') => state.select(Some(selected.saturating_sub(1))),
            KeyCode::Down | KeyCode::Char('j') => {
                state.select(Some((selected + 1).min(labels.len() - 1)))
            }
            KeyCode::Enter => {
                return Ok(match selected {
                    0 => MenuAction::GenerateInvite,
                    1 => MenuAction::Join,
                    2 => MenuAction::Talk,
                    _ => MenuAction::Exit,
                });
            }
            _ => {}
        }
    }
}

fn prompt_text(
    terminal: &mut DefaultTerminal,
    title: &str,
    hint: &str,
    mask: bool,
) -> anyhow::Result<Option<String>> {
    let mut value = String::new();
    loop {
        terminal.draw(|frame| draw_prompt(frame, title, hint, &value, mask))?;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Esc => return Ok(None),
            KeyCode::Enter => return Ok(Some(value)),
            KeyCode::Backspace => {
                value.pop();
            }
            KeyCode::Char(character) => value.push(character),
            _ => {}
        }
    }
}

async fn create_invite(
    terminal: &mut DefaultTerminal,
    user_id: &UserId,
    friend_store: &mut FriendsStore,
) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(SERVE_IP).await?;
    let key = RoomK::new()?;
    key.notify_server_of_room(&mut stream, user_id).await?;
    let code = hex::encode(key.bytes());
    terminal.draw(|frame| draw_invite(frame, &code))?;

    let friend_id = check_if_op_accepted(&mut stream).await?;
    let friend_key = FriendK::read(&mut stream).await?;
    anyhow::ensure!(
        friend_key.user_id() == &friend_id,
        "server and handshake user IDs do not match"
    );
    let enc_keys = Keys::new();
    enc_keys.share(&mut stream, user_id).await?;
    let mut enc = Encryption::derive_real(&enc_keys, &friend_key);
    let mut me = Settings::<Mine>::new(user_id.clone());
    me.share(&mut stream, &mut enc).await?;
    let friend = Settings::<Friend>::read_friend(&mut stream, &mut enc).await?;
    let name = friend.name_to_string();
    friend_store.remember(friend_id, key, friend, &enc_keys, &friend_key)?;
    show_message(
        terminal,
        " Conversation ready ",
        &format!("Connected with {name}.\n\nPress Enter to continue."),
    )
}

async fn join_invite(
    terminal: &mut DefaultTerminal,
    user_id: &UserId,
    friend_store: &mut FriendsStore,
    key: &str,
) -> anyhow::Result<()> {
    let room_key = parse_room_key(key)?;
    terminal
        .draw(|frame| draw_waiting(frame, " Joining conversation ", "Contacting the relay…"))?;
    let mut stream = TcpStream::connect(SERVE_IP).await?;
    accept_invite_notify(&mut stream, &room_key, user_id).await?;
    let friend_id = check_if_op_accepted(&mut stream).await?;
    let keys = Keys::new();
    keys.share(&mut stream, user_id).await?;
    let friend_key = FriendK::read(&mut stream).await?;
    anyhow::ensure!(
        friend_key.user_id() == &friend_id,
        "server and handshake user IDs do not match"
    );
    let mut enc = Encryption::derive_real(&keys, &friend_key);
    let mut me = Settings::<Mine>::new(user_id.clone());
    me.share(&mut stream, &mut enc).await?;
    let friend = Settings::<Friend>::read_friend(&mut stream, &mut enc).await?;
    let name = friend.name_to_string();
    friend_store.remember(friend_id, room_key, friend, &keys, &friend_key)?;
    show_message(
        terminal,
        " Conversation ready ",
        &format!("Connected with {name}.\n\nPress Enter to continue."),
    )
}

async fn talk(
    user_id: &UserId,
    friend_store: &mut FriendsStore,
    terminal: &mut DefaultTerminal,
) -> anyhow::Result<()> {
    let Some(friend_index) = select_friend(terminal, friend_store)? else {
        return Ok(());
    };

    let (friend_id, room_key, friend_name, (private_key, friend_public_key)) = {
        let friend = &friend_store.friends[friend_index];
        (
            friend.user_id().clone(),
            friend.room_key().clone(),
            friend.settings().name_to_string(),
            friend.chat_key_bytes()?,
        )
    };

    let mut messages = friend_store
        .get(&friend_id)
        .and_then(|friend| friend.messages_history.clone())
        .unwrap_or_default();

    let mut stream = TcpStream::connect(SERVE_IP).await?;
    stream.write_u8(Operation::Talk as u8).await?;
    user_id.write_to(&mut stream).await?;
    stream.write_all(room_key.bytes()).await?;
    let (mut reader, mut writer) = stream.into_split();

    let (input_tx, mut input_rx) = mpsc::unbounded_channel();
    thread::spawn(move || {
        loop {
            match event::read() {
                Ok(event) => {
                    if input_tx.send(event).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut input = String::new();
    let mut status = "Esc or /quit to leave".to_owned();

    loop {
        terminal.draw(|frame| draw_chat(frame, &friend_name, &messages, &input, &status))?;

        tokio::select! {
            event = input_rx.recv() => {
                let Some(event) = event else { break };
                let Event::Key(key) = event else { continue };
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Esc => break,
                    KeyCode::Backspace => { input.pop(); }
                    KeyCode::Char(character) => input.push(character),
                    KeyCode::Enter => {
                        if input == "/quit" {
                            break;
                        }
                        if !input.is_empty() {
                            message::send(&input, &mut writer, &friend_public_key).await?;
                            let history_line = format!("You: {input}");
                            friend_store.record_message(&friend_id, history_line.clone())?;
                            messages.push(history_line);
                            input.clear();
                            status.clear();
                        }
                    }
                    _ => {}
                }
            }
            incoming = message::read(&mut reader, &private_key) => {
                let incoming = incoming?;
                let history_line = format!("{friend_name}: {incoming}");
                friend_store.record_message(&friend_id, history_line.clone())?;
                messages.push(history_line);
                status.clear();
            }
        }
    }

    Ok(())
}

fn select_friend(
    terminal: &mut DefaultTerminal,
    friend_store: &FriendsStore,
) -> anyhow::Result<Option<usize>> {
    if friend_store.is_empty() {
        anyhow::bail!("no friends are configured; create or join an invite first");
    }

    let mut state = ListState::default().with_selected(Some(0));
    loop {
        terminal.draw(|frame| draw_friend_picker(frame, friend_store, &mut state))?;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        let selected = state.selected().unwrap_or(0);
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return Ok(None),
            KeyCode::Enter => return Ok(Some(selected)),
            KeyCode::Up | KeyCode::Char('k') => {
                state.select(Some(selected.saturating_sub(1)));
            }
            KeyCode::Down | KeyCode::Char('j') => {
                state.select(Some((selected + 1).min(friend_store.len() - 1)));
            }
            _ => {}
        }
    }
}

fn draw_friend_picker(frame: &mut Frame, friend_store: &FriendsStore, state: &mut ListState) {
    let area = frame.area();
    let items: Vec<_> = friend_store
        .iter()
        .map(|friend| ListItem::new(friend.settings().name_to_string()))
        .collect();
    let list = List::new(items)
        .block(Block::bordered().title(" Choose a conversation "))
        .highlight_style(Style::new().reversed())
        .highlight_symbol("› ");
    frame.render_stateful_widget(list, area, state);

    let hint = Paragraph::new("↑/↓ or j/k to choose · Enter to chat · q to cancel")
        .style(Style::new().dim());
    frame.render_widget(
        hint,
        Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(area)[1],
    );
}

fn draw_prompt(frame: &mut Frame, title: &str, hint: &str, value: &str, mask: bool) {
    let [content, hint_area] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(frame.area());
    let display = if mask {
        "•".repeat(value.chars().count())
    } else {
        value.to_owned()
    };
    frame.render_widget(
        Paragraph::new(display).block(Block::bordered().title(title)),
        content,
    );
    frame.render_widget(Paragraph::new(hint).style(Style::new().dim()), hint_area);
    frame.set_cursor_position((
        (content.x + 1 + value.chars().count() as u16).min(content.right().saturating_sub(1)),
        content.y + 1,
    ));
}

fn draw_waiting(frame: &mut Frame, title: &str, message: &str) {
    frame.render_widget(
        Paragraph::new(message)
            .block(Block::bordered().title(title))
            .wrap(Wrap { trim: false }),
        frame.area(),
    );
}

fn draw_invite(frame: &mut Frame, code: &str) {
    draw_waiting(
        frame,
        " Invite ready ",
        &format!(
            "Share this invite key with your contact:\n\n{code}\n\nWaiting for them to accept…"
        ),
    );
}

fn show_message(terminal: &mut DefaultTerminal, title: &str, message: &str) -> anyhow::Result<()> {
    loop {
        terminal.draw(|frame| draw_waiting(frame, title, message))?;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Press
            && matches!(key.code, KeyCode::Enter | KeyCode::Esc | KeyCode::Char('q'))
        {
            return Ok(());
        }
    }
}

fn draw_chat(frame: &mut Frame, friend_name: &str, messages: &[String], input: &str, status: &str) {
    let [history_area, input_area, status_area] = Layout::vertical([
        Constraint::Min(1),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    let visible_lines = history_area.height.saturating_sub(2) as usize;
    let scroll = messages.len().saturating_sub(visible_lines) as u16;
    let history = Paragraph::new(
        messages
            .iter()
            .map(|message| Line::from(message.as_str()))
            .collect::<Vec<_>>(),
    )
    .block(Block::bordered().title(format!(" Chat with {friend_name} ")))
    .wrap(Wrap { trim: false })
    .scroll((scroll, 0));
    frame.render_widget(history, history_area);
    frame.render_widget(
        Paragraph::new(input).block(Block::bordered().title(" Message ")),
        input_area,
    );
    frame.render_widget(
        Paragraph::new(status).style(Style::new().dim()),
        status_area,
    );
    frame.set_cursor_position((
        (input_area.x + 1 + input.chars().count() as u16).min(input_area.right().saturating_sub(1)),
        input_area.y + 1,
    ));
}
