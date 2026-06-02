//! p2pchat GUI binary.
//!
//! Subcommands:
//! - (none)  → launch the iced GUI (Phase 5; currently prints a stub message)
//! - `init`  → first-run keygen; prints NodeID + fingerprint + QR
//! - `doctor`→ sanity check + transport tests
//!
//! `doctor` sub-flags:
//! - (none)            → inspect identity file header (no network)
//! - `--print-id`      → bind a transport, print node id, exit
//! - `--dial <addr>`   → connect, send ping, read pong, exit (timeout 20s)
//! - `--accept-echo`   → listen, print id, accept one connection, read up to
//!   64 bytes, reply "pong", exit (timeout 30s)

use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context;
use p2pchat_core::{VERSION, config, identity, init_tracing, transport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Subcommand {
    Gui,
    Init,
    Doctor,
}

fn parse_subcommand() -> Subcommand {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("init") => Subcommand::Init,
        Some("doctor") => Subcommand::Doctor,
        Some("--help") | Some("-h") => {
            print_help();
            std::process::exit(0);
        }
        Some("--version") | Some("-V") => {
            println!("p2pchat {VERSION}");
            std::process::exit(0);
        }
        Some(other) => {
            eprintln!("unknown subcommand: {other}");
            print_help();
            std::process::exit(2);
        }
        None => Subcommand::Gui,
    }
}

fn print_help() {
    println!(
        "p2pchat {VERSION}\n\
         \n\
         Usage:\n  \
           p2pchat                          launch the GUI\n  \
           p2pchat init                     first-run keygen\n  \
           p2pchat doctor                   inspect identity file header\n  \
           p2pchat doctor --print-id        bind transport, print node id, exit\n  \
           p2pchat doctor --dial <addr>     connect, send ping, read pong\n  \
           p2pchat doctor --accept-echo     listen, print id, accept one, reply pong\n  \
           p2pchat --help                   show this help\n  \
           p2pchat --version                print version"
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    init_tracing();
    let cmd = parse_subcommand();
    tracing::debug!(?cmd, "starting p2pchat");

    match cmd {
        Subcommand::Gui => run_gui_stub(),
        Subcommand::Init => run_init(),
        Subcommand::Doctor => parse_doctor_flags().await,
    }
}

fn run_gui_stub() -> anyhow::Result<()> {
    println!("p2pchat {VERSION}");
    println!("GUI is not implemented yet (Phase 5 of the implementation plan).");
    println!("For now, use `p2pchat init` and `p2pchat doctor` from the CLI.");
    Ok(())
}

fn run_init() -> anyhow::Result<()> {
    let path = config::identity_path();
    println!("p2pchat {VERSION}");
    println!(
        "config dir:  {}",
        path.parent().unwrap_or(Path::new(".")).display()
    );
    println!("identity at: {}", path.display());
    println!();

    if path.exists() {
        let overwrite = confirm("Identity file already exists. Overwrite? [y/N] ", false)?;
        if !overwrite {
            println!("aborted.");
            return Ok(());
        }
    }

    let pw1 = rpassword::prompt_password("passphrase: ")?;
    if pw1.is_empty() {
        anyhow::bail!("passphrase must not be empty");
    }
    let pw2 = rpassword::prompt_password("confirm:    ")?;
    if pw1 != pw2 {
        anyhow::bail!("passphrases do not match");
    }

    let id = identity::Identity::generate();
    identity::save_to_path(&id, &pw1, &path)?;

    let node_id_hex = hex::encode(id.node_id());
    let fingerprint_hex = hex::encode(id.fingerprint());
    let short_fp = &fingerprint_hex[..16];

    println!();
    println!("identity generated.");
    println!("node id:     {node_id_hex}");
    println!("fingerprint: {short_fp}  (first 16 hex chars of SHA-256(node id))");
    println!();
    println!("share this with your peer (out-of-band):");
    print_qr(format!("p2pchat:nodeid={node_id_hex}").as_bytes())?;
    println!();
    println!("keep your passphrase safe; it encrypts the key file at rest.");

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DoctorCmd {
    Inspect,
    PrintId,
    Dial(String),
    AcceptEcho,
}

async fn parse_doctor_flags() -> anyhow::Result<()> {
    let mut cmd = DoctorCmd::Inspect;
    let mut args = std::env::args().skip(2); // skip "p2pchat" and "doctor"
    while let Some(a) = args.next() {
        match a.as_str() {
            "--print-id" => cmd = DoctorCmd::PrintId,
            "--dial" => {
                let addr = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--dial requires an address argument"))?;
                cmd = DoctorCmd::Dial(addr);
            }
            "--accept-echo" => cmd = DoctorCmd::AcceptEcho,
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => anyhow::bail!("unknown doctor flag: {other}"),
        }
    }
    match cmd {
        DoctorCmd::Inspect => run_doctor_inspect(),
        DoctorCmd::PrintId => run_doctor_print_id().await,
        DoctorCmd::Dial(addr) => run_doctor_dial(&addr).await,
        DoctorCmd::AcceptEcho => run_doctor_accept_echo().await,
    }
}

fn run_doctor_inspect() -> anyhow::Result<()> {
    let path = config::identity_path();
    println!("p2pchat {VERSION}");
    println!(
        "config dir:  {}",
        path.parent().unwrap_or(Path::new(".")).display()
    );
    println!("identity at: {}", path.display());
    println!();

    if !path.exists() {
        println!("status: no identity yet — run `p2pchat init` to create one");
        return Ok(());
    }

    let blob = std::fs::read(&path)?;
    println!("file size:   {} bytes", blob.len());

    match identity::parse_header(&blob) {
        Ok(h) => {
            println!("magic:       ok");
            println!("version:     {}", h.version);
            println!("kdf:         argon2id");
            println!(
                "kdf params:  m={} KiB, t={}, p={}",
                h.kdf.m_kib, h.kdf.t, h.kdf.p
            );
            println!(
                "status:      identity file present (unlock via `p2pchat unlock` in a later phase)"
            );
        }
        Err(e) => {
            println!("status:      identity file is malformed: {e}");
        }
    }
    Ok(())
}

async fn run_doctor_print_id() -> anyhow::Result<()> {
    println!("p2pchat {VERSION}");
    println!("binding transport (this connects to the relay and takes a few seconds)...");
    let t0 = std::time::Instant::now();
    let tr = transport::Transport::bind()
        .await
        .context("bind transport")?;
    let elapsed = t0.elapsed();
    println!("node id:     {}", tr.node_id_hex());
    println!("ticket:      {} (default n0 relay)", tr.ticket());
    println!("bound in:    {} ms", elapsed.as_millis());
    tr.close().await;
    Ok(())
}

async fn run_doctor_dial(addr_str: &str) -> anyhow::Result<()> {
    println!("p2pchat {VERSION}");
    let ticket: transport::Ticket = addr_str
        .parse()
        .with_context(|| format!("parse ticket: {addr_str:?}"))?;
    println!("peer:        {}", ticket.node_id());
    println!("binding transport...");
    let t0 = std::time::Instant::now();
    let tr = transport::Transport::bind()
        .await
        .context("bind transport")?;
    println!("local id:    {}", tr.node_id_hex());

    println!("connecting (timeout 20s)...");
    let conn = tokio::time::timeout(Duration::from_secs(20), tr.connect(ticket.addr()))
        .await
        .map_err(|_| anyhow::anyhow!("connect timed out"))?
        .context("connect")?;
    println!("connected in {} ms", t0.elapsed().as_millis());

    let (mut send, mut recv) = conn.open_bi().await.context("open bi")?;
    send.write_all(b"ping").await.context("write ping")?;
    send.finish().context("finish send")?;

    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), recv.read_exact(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("read pong timed out"))?
        .context("read pong")?;
    let rtt = t0.elapsed();

    let pong = std::str::from_utf8(&buf).unwrap_or("<non-utf8>");
    println!("got:         {pong:?}  (rtt {} ms)", rtt.as_millis());

    if pong != "pong" {
        anyhow::bail!("unexpected reply: {pong:?}");
    }
    println!("ok:          ping/pong successful");
    tr.close().await;
    Ok(())
}

async fn run_doctor_accept_echo() -> anyhow::Result<()> {
    println!("p2pchat {VERSION}");
    println!("binding transport...");
    let tr = transport::Transport::bind()
        .await
        .context("bind transport")?;
    println!("node id:     {}", tr.node_id_hex());
    println!("ticket:      {}", tr.ticket());
    println!("waiting for one incoming connection (timeout 30s)...");

    // Read 4 bytes ("ping" expected), reply with "pong" — the canonical
    // ping/pong round-trip. Bounded to 64 bytes so a malicious peer
    // can't stream a megabyte through us.
    let accept = async {
        let conn = match tr.accept().await? {
            Some(c) => c,
            None => anyhow::bail!("endpoint closed before accept"),
        };
        let remote = conn.remote_id();
        let (mut send, mut recv) = conn.accept_bi().await.context("accept bi")?;
        let mut buf = vec![0u8; 64];
        let n = recv.read(&mut buf).await.context("read")?.unwrap_or(0);
        buf.truncate(n);
        let got = std::str::from_utf8(&buf).unwrap_or("<non-utf8>").to_owned();
        send.write_all(b"pong").await.context("write pong")?;
        send.finish().context("finish send")?;
        drop(recv);
        // Give the peer time to read the reply before the endpoint tears down.
        tokio::time::sleep(Duration::from_millis(500)).await;
        Ok::<_, anyhow::Error>(format!(
            "from {remote}, got {n} bytes: {got:?}, replied: \"pong\""
        ))
    };

    let summary = tokio::time::timeout(Duration::from_secs(30), accept)
        .await
        .map_err(|_| anyhow::anyhow!("accept timed out (no connection in 30s)"))??;
    println!("ok:          {summary}");
    tr.close().await;
    Ok(())
}

/// Print a QR code for `payload` to stdout using Unicode block characters.
///
/// The `qrcode` crate (MIT) returns a 2D color matrix; we render each module
/// as two terminal cells (`██` for dark, two spaces for light) with a 4-module
/// quiet zone on all sides.
fn print_qr(payload: &[u8]) -> anyhow::Result<()> {
    use qrcode::QrCode;

    let code = QrCode::new(payload).map_err(|e| anyhow::anyhow!("qr encode: {e}"))?;
    let colors = code.to_colors();
    let width = code.width();
    const QUIET: usize = 4;
    const DARK: &str = "██";
    const LIGHT: &str = "  ";
    let indent = LIGHT.repeat(QUIET);

    for _ in 0..QUIET {
        println!();
    }
    for y in 0..width {
        print!("{indent}");
        for x in 0..width {
            let is_dark = matches!(colors[y * width + x], qrcode::Color::Dark);
            print!("{}", if is_dark { DARK } else { LIGHT });
        }
        println!();
    }
    for _ in 0..QUIET {
        println!();
    }
    Ok(())
}

/// Read a single y/n answer from stdin. Default is `default_yes`.
fn confirm(prompt: &str, default_yes: bool) -> io::Result<bool> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(prompt.as_bytes())?;
    stdout.flush()?;
    let stdin = io::stdin();
    let line = stdin.lock().lines().next();
    match line {
        None => Ok(default_yes),
        Some(Err(e)) => Err(e),
        Some(Ok(s)) => {
            let s = s.trim();
            if s.is_empty() {
                return Ok(default_yes);
            }
            let s_lower = s.to_ascii_lowercase();
            Ok(matches!(s_lower.as_str(), "y" | "yes"))
        }
    }
}
