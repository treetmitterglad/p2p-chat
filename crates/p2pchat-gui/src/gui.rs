use std::sync::{Arc, Mutex};
use std::time::Duration;

use iced::widget::{
    button, column, container, row, scrollable, text, text_input, Space,
};
use iced::{Alignment, Length, Subscription, Task};
use p2pchat_core::{identity, session, storage};
use p2pchat_core::session::SessionEvent;

/// Type that can be safely shared between async tasks and the GUI.
type SessionHolder = Arc<Mutex<Option<session::SessionHandle>>>;

/// Launch the iced GUI application. `store` must already be opened.
pub fn run(
    store: storage::Store,
) -> Result<(), iced::Error> {
    iced::application("P2P Chat", App::update, App::view)
        .subscription(App::subscription)
        .run_with(move || App::new(store.clone()))
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Screen {
    Unlock,
    Welcome,
    Chat,
}

#[derive(Debug)]
struct ChatMessage {
    text: String,
    is_outgoing: bool,
    timestamp: String,
}

#[derive(Debug)]
struct App {
    store: storage::Store,
    identity: Option<identity::Identity>,
    screen: Screen,
    /// Shared session handle (written by connect/listen tasks, read by Tick).
    session: SessionHolder,
    messages: Vec<ChatMessage>,
    input: String,
    passphrase: String,
    ticket_input: String,
    status: String,
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Message {
    PassphraseChanged(String),
    UnlockClicked,
    IdentityLoaded(identity::Identity),
    TicketChanged(String),
    ConnectClicked,
    ListenClicked,
    InputChanged(String),
    SendClicked,
    Connected(SessionHolder),
    Errored(String),
    Tick,
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl App {
    fn new(store: storage::Store) -> (Self, Task<Message>) {
        (
            App {
                store,
                identity: None,
                screen: Screen::Unlock,
                session: Arc::new(Mutex::new(None)),
                messages: Vec::new(),
                input: String::new(),
                passphrase: String::new(),
                ticket_input: String::new(),
                status: String::new(),
            },
            Task::none(),
        )
    }

    fn title(&self) -> String {
        "P2P Chat".into()
    }

    fn subscription(&self) -> Subscription<Message> {
        iced::time::every(Duration::from_millis(100)).map(|_| Message::Tick)
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            // ── Passphrase / Unlock ──────────────────────────────────
            Message::PassphraseChanged(p) => {
                self.passphrase = p;
                Task::none()
            }

            Message::UnlockClicked => {
                let pw = self.passphrase.clone();
                self.status = "unlocking...".into();
                Task::perform(
                    async move {
                        match session::load_identity(&pw) {
                            Ok(id) => Message::IdentityLoaded(id),
                            Err(e) => Message::Errored(e.to_string()),
                        }
                    },
                    |msg| msg,
                )
            }

            Message::IdentityLoaded(id) => {
                self.identity = Some(id);
                self.passphrase.clear();
                self.status = "ready".into();
                self.screen = Screen::Welcome;
                Task::none()
            }

            // ── Welcome screen ───────────────────────────────────────
            Message::TicketChanged(t) => {
                self.ticket_input = t;
                Task::none()
            }

            Message::ConnectClicked => {
                let ticket = self.ticket_input.clone();
                let identity = self.identity.clone().unwrap();
                let store = self.store.clone();
                let holder = self.session.clone();

                self.status = format!("connecting to {ticket}...");
                self.ticket_input.clear();
                Task::perform(
                    async move {
                        match session::connect_to_peer(store, identity, &ticket).await {
                            Ok(handle) => {
                                *holder.lock().unwrap() = Some(handle);
                                Message::Connected(holder)
                            }
                            Err(e) => Message::Errored(e.to_string()),
                        }
                    },
                    |msg| msg,
                )
            }

            Message::ListenClicked => {
                let identity = self.identity.clone().unwrap();
                let store = self.store.clone();
                let holder = self.session.clone();

                self.status = "listening...".into();
                Task::perform(
                    async move {
                        match session::listen_for_peer(store, identity).await {
                            Ok((_ticket, handle)) => {
                                *holder.lock().unwrap() = Some(handle);
                                Message::Connected(holder)
                            }
                            Err(e) => Message::Errored(e.to_string()),
                        }
                    },
                    |msg| msg,
                )
            }

            Message::Connected(holder) => {
                self.session = holder;
                let peer_hex = self
                    .session
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|h| hex::encode(h.peer_id))
                    .unwrap_or_default();
                self.status = format!("connected: {peer_hex}");
                self.screen = Screen::Chat;
                Task::none()
            }

            // ── Chat screen ──────────────────────────────────────────
            Message::InputChanged(t) => {
                self.input = t;
                Task::none()
            }

            Message::SendClicked => {
                let text = self.input.trim().to_string();
                if text.is_empty() {
                    return Task::none();
                }
                self.input.clear();

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let secs = now % 86400;
                let h = secs / 3600;
                let m = (secs % 3600) / 60;
                let s = secs % 60;
                let ts = format!("{h:02}:{m:02}:{s:02}");
                self.messages.push(ChatMessage {
                    text: text.clone(),
                    is_outgoing: true,
                    timestamp: ts,
                });

                let send_tx = self
                    .session
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|h| h.send_tx.clone());
                if let Some(send_tx) = send_tx {
                    Task::perform(
                        async move {
                            let _ = send_tx.send(text).await;
                        },
                        |_| Message::Tick,
                    )
                } else {
                    Task::none()
                }
            }

            // ── Shared ───────────────────────────────────────────────
            Message::Errored(e) => {
                self.status = format!("error: {e}");
                Task::none()
            }

            Message::Tick => {
                let mut guard = self.session.lock().unwrap();
                if let Some(ref mut handle) = *guard {
                    loop {
                        match handle.recv_rx.try_recv() {
                            Ok(SessionEvent::Connected { .. }) => {}
                            Ok(SessionEvent::MessageReceived { text, timestamp }) => {
                                let t = timestamp.format("%H:%M:%S").to_string();
                                self.messages.push(ChatMessage {
                                    text,
                                    is_outgoing: false,
                                    timestamp: t,
                                });
                            }
                            Ok(SessionEvent::Disconnected) => {
                                self.status = "disconnected".into();
                                self.screen = Screen::Welcome;
                                *guard = None;
                                break;
                            }
                            Ok(SessionEvent::Error(e)) => {
                                self.status = format!("error: {e}");
                                self.screen = Screen::Welcome;
                                *guard = None;
                                break;
                            }
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                *guard = None;
                                self.status = "disconnected".into();
                                self.screen = Screen::Welcome;
                                break;
                            }
                        }
                    }
                }
                drop(guard);
                Task::none()
            }
        }
    }

    fn view(&self) -> iced::Element<Message> {
        match self.screen {
            Screen::Unlock => self.view_unlock(),
            Screen::Welcome => self.view_welcome(),
            Screen::Chat => self.view_chat(),
        }
    }

    // ── Unlock screen ─────────────────────────────────────────────

    fn view_unlock(&self) -> iced::Element<Message> {
        let pw_input = text_input("identity passphrase", &self.passphrase)
            .on_input(Message::PassphraseChanged)
            .on_submit(Message::UnlockClicked)
            .secure(true)
            .width(Length::Fill);

        let unlock_btn = button("Unlock").on_press(Message::UnlockClicked);

        let controls = column![
            text("P2P Chat").size(28),
            Space::with_height(Length::Shrink),
            text("Enter your passphrase to unlock your identity:").size(14),
            row![pw_input, unlock_btn]
                .spacing(8)
                .align_y(Alignment::Center),
        ]
        .spacing(12)
        .align_x(Alignment::Center)
        .width(Length::Fill);

        let status_bar = container(text(&self.status))
            .width(Length::Fill)
            .padding(8);

        column![
            container(controls)
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill),
            status_bar,
        ]
        .into()
    }

    // ── Welcome screen ────────────────────────────────────────────

    fn view_welcome(&self) -> iced::Element<Message> {
        let ticket_input = text_input("paste peer ticket here...", &self.ticket_input)
            .on_input(Message::TicketChanged)
            .width(Length::Fill);

        let connect_btn = button("Connect").on_press(Message::ConnectClicked);
        let listen_btn = button("Listen").on_press(Message::ListenClicked);

        let controls = column![
            text("P2P Chat").size(28),
            Space::with_height(Length::Shrink),
            text("Enter a peer ticket or listen for incoming:").size(14),
            row![ticket_input, connect_btn]
                .spacing(8)
                .align_y(Alignment::Center),
            listen_btn,
        ]
        .spacing(12)
        .align_x(Alignment::Center)
        .width(Length::Fill);

        let status_bar = container(text(&self.status))
            .width(Length::Fill)
            .padding(8);

        column![
            container(controls)
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill),
            status_bar,
        ]
        .into()
    }

    // ── Chat screen ───────────────────────────────────────────────

    fn view_chat(&self) -> iced::Element<Message> {
        let mut msg_col = column![].spacing(4).width(Length::Fill);
        for msg in &self.messages {
            let prefix = if msg.is_outgoing { "you" } else { "peer" };
            let label = text(format!(
                "[{t}] {p}: {m}",
                t = msg.timestamp,
                p = prefix,
                m = msg.text
            ));
            msg_col = msg_col.push(container(label).width(Length::Fill).padding(4));
        }

        let messages_area = scrollable(
            container(msg_col)
                .width(Length::Fill)
                .height(Length::Fill)
                .padding(8),
        )
        .height(Length::Fill);

        let input = text_input("type a message...", &self.input)
            .on_input(Message::InputChanged)
            .on_submit(Message::SendClicked)
            .width(Length::Fill);

        let send_btn = button("Send").on_press(Message::SendClicked);

        let input_row = row![input, send_btn]
            .spacing(8)
            .align_y(Alignment::Center)
            .padding(8)
            .width(Length::Fill);

        let status_bar = container(text(&self.status))
            .width(Length::Fill)
            .padding(8);

        column![messages_area, input_row, status_bar].into()
    }
}
