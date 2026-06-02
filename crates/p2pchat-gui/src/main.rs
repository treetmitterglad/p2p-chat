//! p2pchat GUI binary.
//!
//! Subcommands:
//! - (none)  → launch the iced GUI (Phase 5; currently prints a stub message)
//! - `init`  → first-run keygen (Phase 1; currently a stub)
//! - `doctor`→ sanity check (Phase 1; currently a stub)

use std::process::ExitCode;

use p2pchat_core::{VERSION, config, init_tracing};

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
           p2pchat doctor    sanity check (key loads, prints NodeID, pings relay)\n  \
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
        Subcommand::Init => run_init_stub(),
        Subcommand::Doctor => run_doctor(),
    }
}

fn run_gui_stub() -> anyhow::Result<()> {
    println!("p2pchat {VERSION}");
    println!("GUI is not implemented yet (Phase 5 of the implementation plan).");
    println!("For now, use `p2pchat init` and `p2pchat doctor` from the CLI.");
    Ok(())
}

fn run_init_stub() -> anyhow::Result<()> {
    let dir = config::config_dir();
    println!("p2pchat {VERSION}");
    println!("config dir: {}", dir.display());
    println!();
    println!("`p2pchat init` is not implemented yet (Phase 1 of the implementation plan).");
    println!("It will generate an Ed25519 keypair, encrypt it with your passphrase,");
    println!("and print a NodeID + QR code to share with your peer.");
    Ok(())
}

fn run_doctor() -> anyhow::Result<()> {
    let dir = config::config_dir();
    println!("p2pchat {VERSION}");
    println!("config dir: {}", dir.display());
    let key_path = dir.join("identity.enc");
    println!("identity file: {}", key_path.display());
    if key_path.exists() {
        println!("status: identity file present (unlock via GUI in a later phase)");
    } else {
        println!("status: no identity yet — run `p2pchat init` to create one");
    }
    Ok(())
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
