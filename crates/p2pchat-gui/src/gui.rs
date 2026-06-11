use std::sync::{Arc, Mutex};
use std::time::Duration;

use iced::widget::{
    button, column, container, row, scrollable, text, text_input, Space,
};
use iced::{window, Alignment, clipboard, Color, Length, Subscription, Task, Theme};
use p2pchat_core::{config, identity, session, storage};
use p2pchat_core::session::SessionEvent;

type SessionHolder = Arc<Mutex<Option<session::SessionHandle>>>;

fn load_icon() -> Option<window::icon::Icon> {
    let bytes = include_bytes!("../../../assets/p2pchat-icon.png");
    let img = image::load_from_memory(bytes).ok()?;
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    window::icon::from_rgba(rgba.into_raw(), w, h).ok()
}

pub fn run(store: storage::Store) -> Result<(), iced::Error> {
    let icon = load_icon();
    iced::application("P2P Chat", App::update, App::view)
        .theme(|_| Theme::Dark)
        .window(window::Settings {
            icon,
            ..window::Settings::default()
        })
        .subscription(App::subscription)
        .run_with(move || App::new(store.clone()))
}

#[derive(Debug, Clone, PartialEq)]
enum Screen {
    CreateIdentity,
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
    session: SessionHolder,
    messages: Vec<ChatMessage>,
    input: String,
    passphrase: String,
    passphrase_confirm: String,
    ticket_input: String,
    listening_ticket: Option<String>,
    status: String,
}

#[derive(Debug, Clone)]
enum Message {
    PassphraseChanged(String),
    PassphraseConfirmChanged(String),
    UnlockClicked,
    CreateClicked,
    IdentityLoaded(identity::Identity),
    TicketChanged(String),
    ConnectClicked,
    ListenClicked,
    InputChanged(String),
    SendClicked,
    Connected(SessionHolder),
    Errored(String),
    Tick,
    CopyId(String),
    TicketReceived(String),
}

// ── Style helpers ──────────────────────────────────────────────

fn muted_text(s: &str) -> iced::widget::Text<'static, Theme> {
    text(s.to_string()).style(|theme: &Theme| {
        let p = theme.extended_palette();
        text::Style { color: Some(p.background.strong.color) }
    })
}

fn card<'a>(content: impl Into<iced::Element<'a, Message>>) -> iced::Element<'a, Message> {
    container(content)
        .max_width(480)
        .padding(32)
        .style(|theme: &Theme| {
            let p = theme.extended_palette();
            container::Style {
                background: Some(p.background.base.color.into()),
                border: iced::border::rounded(12).color(p.background.strong.color),
                ..container::Style::default()
            }
        })
        .into()
}

fn status_bar(text: &str) -> iced::Element<'_, Message> {
    if text.is_empty() {
        return container(Space::with_height(Length::Shrink))
            .height(28)
            .into();
    }
    container(
        muted_text(text).size(12),
    )
    .width(Length::Fill)
    .padding([4, 12])
    .style(|theme: &Theme| {
        let p = theme.extended_palette();
        container::Style {
            background: Some(p.background.weak.color.into()),
            ..container::Style::default()
        }
    })
    .into()
}

impl App {
    fn new(store: storage::Store) -> (Self, Task<Message>) {
        let screen = if config::identity_path().exists() {
            Screen::Unlock
        } else {
            Screen::CreateIdentity
        };
        (
            App {
                store,
                identity: None,
                screen,
                session: Arc::new(Mutex::new(None)),
                messages: Vec::new(),
                input: String::new(),
                passphrase: String::new(),
                passphrase_confirm: String::new(),
                ticket_input: String::new(),
                listening_ticket: None,
                status: String::new(),
            },
            Task::none(),
        )
    }

    fn subscription(&self) -> Subscription<Message> {
        iced::time::every(Duration::from_millis(100)).map(|_| Message::Tick)
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::PassphraseChanged(p) => {
                self.passphrase = p;
                Task::none()
            }

            Message::PassphraseConfirmChanged(p) => {
                self.passphrase_confirm = p;
                Task::none()
            }

            Message::CreateClicked => {
                let pw = self.passphrase.clone();
                let confirm = self.passphrase_confirm.clone();
                if pw.is_empty() {
                    self.status = "passphrase must not be empty".into();
                    return Task::none();
                }
                if pw != confirm {
                    self.status = "passphrases do not match".into();
                    return Task::none();
                }
                self.status = "creating identity...".into();
                Task::perform(
                    async move {
                        let id = identity::Identity::generate();
                        match identity::save_to_path(&id, &pw, &config::identity_path()) {
                            Ok(()) => Message::IdentityLoaded(id),
                            Err(e) => Message::Errored(e.to_string()),
                        }
                    },
                    |msg| msg,
                )
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
                self.passphrase_confirm.clear();
                self.status = String::new();
                self.screen = Screen::Welcome;
                Task::none()
            }

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
                            Ok((ticket, handle)) => {
                                *holder.lock().unwrap() = Some(handle);
                                Message::TicketReceived(ticket.to_string())
                            }
                            Err(e) => Message::Errored(e.to_string()),
                        }
                    },
                    |msg| msg,
                )
            }

            Message::TicketReceived(ticket) => {
                self.listening_ticket = Some(ticket);
                self.status = "waiting for incoming connection...".into();
                Task::none()
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

            Message::CopyId(id) => {
                clipboard::write::<Message>(id)
            }

            Message::Errored(e) => {
                self.status = format!("error: {e}");
                Task::none()
            }

            Message::Tick => {
                let mut guard = self.session.lock().unwrap();
                if let Some(ref mut handle) = *guard {
                    loop {
                        match handle.recv_rx.try_recv() {
                            Ok(SessionEvent::Connected { peer_id, .. }) => {
                                self.status = format!("connected: {}", hex::encode(peer_id));
                                self.screen = Screen::Chat;
                            }
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

    fn view(&self) -> iced::Element<'_, Message> {
        match self.screen {
            Screen::CreateIdentity => self.view_create_identity(),
            Screen::Unlock => self.view_unlock(),
            Screen::Welcome => self.view_welcome(),
            Screen::Chat => self.view_chat(),
        }
    }

    // ── Create Identity screen ──────────────────────────────────

    fn view_create_identity(&self) -> iced::Element<'_, Message> {
        let pw_input = text_input("choose a passphrase", &self.passphrase)
            .on_input(Message::PassphraseChanged)
            .secure(true)
            .padding(10)
            .size(16);

        let confirm_input = text_input("confirm passphrase", &self.passphrase_confirm)
            .on_input(Message::PassphraseConfirmChanged)
            .on_submit(Message::CreateClicked)
            .secure(true)
            .padding(10)
            .size(16);

        let create_btn = button(text("Create").size(16))
            .padding([10, 24])
            .style(button::primary)
            .on_press(Message::CreateClicked);

        let content = column![
            text("P2P Chat").size(32).style(text::primary),
            muted_text("No identity found. Create a new one:").size(14),
            pw_input,
            confirm_input,
            create_btn,
        ]
        .spacing(16)
        .align_x(Alignment::Center)
        .width(Length::Fill);

        column![
            container(card(content))
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill),
            status_bar(&self.status),
        ]
        .into()
    }

    // ── Unlock screen ───────────────────────────────────────────

    fn view_unlock(&self) -> iced::Element<'_, Message> {
        let pw_input = text_input("identity passphrase", &self.passphrase)
            .on_input(Message::PassphraseChanged)
            .on_submit(Message::UnlockClicked)
            .secure(true)
            .padding(10)
            .size(16);

        let unlock_btn = button(text("Unlock").size(16))
            .padding([10, 24])
            .style(button::primary)
            .on_press(Message::UnlockClicked);

        let content = column![
            text("P2P Chat").size(32).style(text::primary),
            muted_text("Enter your passphrase to unlock your identity").size(14),
            row![pw_input, unlock_btn]
                .spacing(12)
                .align_y(Alignment::Center),
        ]
        .spacing(20)
        .align_x(Alignment::Center)
        .width(Length::Fill);

        column![
            container(card(content))
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill),
            status_bar(&self.status),
        ]
        .into()
    }

    // ── Welcome screen ──────────────────────────────────────────

    fn view_welcome(&self) -> iced::Element<'_, Message> {
        let id = self.identity.as_ref().unwrap();
        let node_id = hex::encode(id.node_id());
        let node_id_short = format!("node id: {}…{}", &node_id[..8], &node_id[node_id.len()-8..]);

        let node_id_badge = button(
            text(node_id_short).size(12),
        )
        .padding([4, 10])
        .style(|theme: &Theme, status: button::Status| {
            let p = theme.extended_palette();
            let base = button::Style {
                background: Some(p.background.weak.color.into()),
                text_color: p.background.strong.text,
                border: iced::border::rounded(6),
                ..button::Style::default()
            };
            match status {
                button::Status::Hovered => button::Style {
                    background: Some(p.primary.weak.color.into()),
                    ..base
                },
                _ => base,
            }
        })
        .on_press(Message::CopyId(node_id.to_string()));

        let ticket_input = text_input("paste peer ticket here...", &self.ticket_input)
            .on_input(Message::TicketChanged)
            .padding(10)
            .size(16);

        let connect_btn = button(text("Connect").size(16))
            .padding([10, 20])
            .style(button::primary)
            .on_press(Message::ConnectClicked);

        let listen_btn = button(text("Listen").size(16))
            .padding([10, 20])
            .style(button::secondary)
            .on_press(Message::ListenClicked);

        let mut content = column![
            text("P2P Chat").size(32).style(text::primary),
            node_id_badge,
            muted_text("Enter a ticket or listen for an incoming connection").size(14),
            ticket_input,
            row![connect_btn, listen_btn]
                .spacing(12)
                .align_y(Alignment::Center),
        ]
        .spacing(16)
        .align_x(Alignment::Center)
        .width(Length::Fill);

        if let Some(ticket) = &self.listening_ticket {
            let ticket_row = container(
                column![
                    muted_text("share this ticket with your peer:").size(12),
                    row![
                        muted_text(ticket).size(12),
                        button(text("copy").size(10))
                            .padding([2, 8])
                            .style(button::text)
                            .on_press(Message::CopyId(ticket.clone())),
                    ]
                    .spacing(6)
                    .align_y(Alignment::Center),
                ]
                .spacing(6),
            )
            .padding([10, 14])
            .style(|theme: &Theme| {
                let p = theme.extended_palette();
                container::Style {
                    background: Some(p.background.weak.color.into()),
                    border: iced::border::rounded(8),
                    ..container::Style::default()
                }
            })
            .width(Length::Fill);

            content = content.push(ticket_row);
        }

        column![
            container(card(content))
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill),
            status_bar(&self.status),
        ]
        .into()
    }

    // ── Chat screen ─────────────────────────────────────────────

    fn view_chat_header(&self) -> iced::Element<'_, Message> {
        let peer_hex = self
            .session
            .lock()
            .unwrap()
            .as_ref()
            .map(|h| hex::encode(h.peer_id))
            .unwrap_or_default();

        let title = text(format!("Connected — {peer_hex}"))
            .size(14)
            .style(text::primary);

        container(title)
            .width(Length::Fill)
            .padding([8, 12])
            .style(|theme: &Theme| {
                let p = theme.extended_palette();
                container::Style {
                    background: Some(p.background.weak.color.into()),
                    ..container::Style::default()
                }
            })
            .into()
    }

    fn view_chat(&self) -> iced::Element<'_, Message> {
        let header = self.view_chat_header();

        let mut msg_col = column![].spacing(6).width(Length::Fill);
        for msg in &self.messages {
            let bubble = Self::message_bubble(msg);
            let spacer = Space::with_width(Length::Fill);
            let row = if msg.is_outgoing {
                row![spacer, bubble]
                    .align_y(Alignment::Start)
                    .width(Length::Fill)
            } else {
                row![bubble, spacer]
                    .align_y(Alignment::Start)
                    .width(Length::Fill)
            };
            msg_col = msg_col.push(row);
        }

        let messages_area = scrollable(
            container(msg_col)
                .width(Length::Fill)
                .height(Length::Fill)
                .padding([12, 16]),
        )
        .height(Length::Fill);

        let input = text_input("type a message...", &self.input)
            .on_input(Message::InputChanged)
            .on_submit(Message::SendClicked)
            .padding(10)
            .size(16);

        let send_btn = button(text("Send").size(16))
            .padding([10, 20])
            .style(button::primary)
            .on_press(Message::SendClicked);

        let input_row = container(
            row![input, send_btn]
                .spacing(8)
                .align_y(Alignment::Center),
        )
        .padding([8, 12])
        .style(|theme: &Theme| {
            let p = theme.extended_palette();
            container::Style {
                border: iced::Border {
                    width: 1.0,
                    color: p.background.strong.color,
                    ..Default::default()
                },
                ..container::Style::default()
            }
        });

        column![header, messages_area, input_row].into()
    }

    fn message_bubble(msg: &ChatMessage) -> iced::Element<'_, Message> {
        let txt = text(&msg.text).size(14);
        let ts = text(&msg.timestamp).size(10);

        let (bubble_text, ts_text): (iced::Element<_>, iced::Element<_>) =
            if msg.is_outgoing {
                let c = Color::WHITE;
                (txt.color(c).into(), ts.color(c).into())
            } else {
                (txt.into(), ts.style(|theme: &Theme| {
                    let p = theme.extended_palette();
                    text::Style { color: Some(p.background.strong.color) }
                }).into())
            };

        container(
            column![bubble_text, ts_text].spacing(2),
        )
        .padding([8, 12])
        .style(move |theme: &Theme| {
            let p = theme.extended_palette();
            if msg.is_outgoing {
                container::Style {
                    background: Some(p.primary.strong.color.into()),
                    border: iced::border::rounded(12),
                    ..container::Style::default()
                }
            } else {
                container::Style {
                    background: Some(p.background.weak.color.into()),
                    border: iced::border::rounded(12),
                    ..container::Style::default()
                }
            }
        })
        .into()
    }
}
