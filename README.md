# Ghostline

Ghostline is an experimental terminal chat project written in Rust. It is split
into a small workspace:

- `ghostline-client`: a Ratatui terminal client for creating invites, joining
  invites, and opening conversations.
- `ghostline-server`: a TCP relay that pairs clients by invite room key and
  forwards encrypted message frames.
- `ghostline-core`: shared protocol constants and types.

The server does not decrypt chat messages. Clients exchange keys during the
invite handshake and then send encrypted frames through the relay.

## Current State

This is still a work-in-progress prototype. Some operational details are
placeholder-style and are currently hard-coded in the codebase:

- The relay address is the shared `SERVE_IP` constant in `core/src/lib.rs`.
  Right now it is `127.0.0.1:1278`, so the client and server are set up for
  local testing by default.
- There is not yet a runtime config file, CLI flag, environment variable, or
  deployment profile for choosing a public server address.
- Server rooms live only in memory. Restarting the server drops waiting rooms
  and active chat registrations.
- Invite room keys are used to find the waiting room on the relay. Treat them
  as temporary connection secrets.

Before using Ghostline outside local testing, the server address/configuration
story needs to be finished and the relay should be deployed behind the address
that clients are compiled or configured to use.

## Running Locally

Start the relay:

```sh
cargo run -p ghostline-server
```

In another terminal, create an invite:

```sh
cargo run -p ghostline-client -- --invite
```

In a second client terminal, join that invite:

```sh
cargo run -p ghostline-client -- --join <invite-key>
```

After both clients have exchanged profiles, either client can open the
conversation list:

```sh
cargo run -p ghostline-client -- --talk
```

You can also run the client without arguments to use the interactive menu:

```sh
cargo run -p ghostline-client
```

## Local Data

Ghostline stores local client data under `~/.ghostline`:

- `user_id`: persistent random user ID.
- `friend_ids.toml`: encrypted friend data, room keys, chat keys, and message
  history.

The friend store is encrypted with a storage password. The client prompts for
that password in the terminal, or you can provide it through
`GHOSTLINE_STORAGE_PASSWORD` for non-interactive runs.

## Development

Run the test suite with:

```sh
cargo test
```

Format the workspace with:

```sh
cargo fmt
```

