# p2p-chat

A peer-to-peer, end-to-end encrypted chat app for two people. Built to replace Discord with something we actually own.

## Goals

- **Private.** E2EE, no central server, no telemetry.
- **Small.** Just us. Not building a platform.
- **Self-contained.** Runs on our machines. Nothing in the cloud.

## Non-goals

- Group chats
- Public discovery
- Mobile (desktop only for now)
- Accounts, phone numbers, or identity providers

## Current scope: chat-only MVP

The current implementation covers **text chat only**. The following are deliberately deferred to a later plan:

- Screen sharing / video streaming
- Audio (mic or system audio)
- File transfer
- Multi-peer / group sessions

## Stack

- **Language:** Rust
- **GUI:** `iced` (full GUI, single window)
- **Networking:** `iroh` (QUIC, public relay at `relay.iroh.computer`)
- **Crypto / E2EE:**
  - Handshake: Noise XX (via `snow`)
  - Per-message: Double Ratchet (Signal-style)
- **Identity:** Ed25519 keypair, passphrase-encrypted at rest (Argon2id + XChaCha20-Poly1305)
- **Wire format:** `postcard`, length-prefixed

## Architecture

```
┌────────────────────────────────────────────┐
│        p2pchat (single iced process)       │
│                                            │
│ ┌──────────────┐  ┌──────────────────────┐ │
│ │ Chat panel   │  │ Viewer panel (later) │ │
│ └──────┬───────┘  └──────────┬───────────┘ │
│        │                     │             │
│ ┌──────┴─────────────────────┴────────────┐│
│ │ iced runtime (wgpu, async, subs)        ││
│ └──────────────────┬──────────────────────┘│
│                    │                       │
│ ┌──────────────────▼──────────────────────┐│
│ │ core: identity, transport, crypto,      ││
│ │       storage, message protocol         ││
│ └──────────────────┬──────────────────────┘│
└────────────────────┼───────────────────────┘
                     │ iroh QUIC
                     ▼
                peer (other iced process)
```

## CLI

- `p2pchat` — launch the GUI
- `p2pchat init` — first-run keygen; prints NodeID + QR
- `p2pchat doctor` — sanity check (key loads, relay reachable, prints NodeID)

## Identity

- No accounts. Each instance generates a long-term Ed25519 keypair on first run.
- Trust the peer's public key out-of-band (QR code, fingerprint, in person).
- Private key stored at `$XDG_CONFIG_HOME/p2pchat/identity.enc`, encrypted with a passphrase.

## Features (priority)

1. Connect two peers, send text messages
2. E2EE working end-to-end with verified keys
3. Persistent local message history

Deferred (no current work):

4. File transfer
5. Audio / video streaming
6. Screen share

## Status

Implementing. See the implementation plan in commit history.
