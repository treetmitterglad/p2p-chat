//! p2pchat GUI binary.
//!
//! Subcommands:
//! - (none)  → launch the iced GUI (Phase 5; currently prints a stub message)
//! - `init`  → first-run keygen; prints NodeID + fingerprint + QR
//! - `doctor`→ sanity check; reports identity file status without unlocking

use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process::ExitCode;

use p2pchat_core::{VERSION, config, identity, init_tracing};

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
           p2pchat           launch the GUI\n  \
           p2pchat init      first-run keygen (generates identity, prints NodeID + QR)\n  \
           p2pchat doctor    sanity check (reports identity file status)\n  \
           p2pchat --help    show this help\n  \
           p2pchat --version print version"
    );
}

fn run() -> anyhow::Result<()> {
    init_tracing();
    let cmd = parse_subcommand();
    tracing::debug!(?cmd, "starting p2pchat");

    match cmd {
        Subcommand::Gui => run_gui_stub(),
        Subcommand::Init => run_init(),
        Subcommand::Doctor => run_doctor(),
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

fn run_doctor() -> anyhow::Result<()> {
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

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
