//! # security_toolkit
//!
//! A small CLI that bundles a few security utilities:
//! - **Password** checks & generator
//! - **File hashing** (e.g., SHA-256)
//! - **Network port scanning** (simple TCP reachability)
//! - **Lightweight file analysis** (size, type hints)
//!
//! The code is intentionally straightforward and well-commented to serve as a
//! reference for learning Rust + CLI structure. Nothing here aims to be
//! production-grade security. Treat this as an educational sandbox.

use clap::{Parser, Subcommand};

// Import of custom made modules
mod password;
mod hash;
mod scan;
mod analyse;

// Use the functions from our modules
use password::{check_password_strength, generate_password};
use hash::hash_file;
use scan::network_scan;
use analyse::analyse_file;

/// Command-line arguments and subcommands.
///
/// This uses `clap` derive attributes so `--help` is generated automatically.
/// When adding a new feature, prefer adding a new subcommand to keep the UX
/// discoverable and `main()` readable.
#[derive(Parser)]
#[command(name = "Security Toolkit")]
#[command(author = "Hans Eric Luiz Jingryd")]
#[command(version = "1.0")]
#[command(about = "Comprehensive security toolkit for everyday security tasks")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check password strength and security
    Password {
        /// Password to check (use quotes for special characters)
        #[arg(short, long, conflicts_with = "generate")]
        check: Option<String>,

        /// Generate secure password
        #[arg(short, long, conflicts_with = "check")]
        generate: bool,

        /// Password length for generation
        #[arg(short, long, default_value_t = 16)]
        length: usize,
    },

    /// Calculate file hashes
    Hash {
        /// File to hash
        #[arg(short, long)]
        file: String,

        /// Hash algorithm (sha256, sha512, sha3, md5)
        #[arg(short, long, default_value = "sha256")]
        algorithm: String,

        /// Compare with expected hash
        #[arg(short, long)]
        compare: Option<String>,
    },

    /// Basic network scanning
    Scan {
        /// Target host (domain or IP)
        #[arg(short, long)]
        target: String,

        /// Port range (e.g., "1-1000" or "80,443,8080")
        #[arg(short, long, default_value = "1-1000")]
        ports: String,

        /// Scan timeout in milliseconds
        #[arg(long, default_value_t = 100)]
        timeout: u64,
    },

    /// Analyse file for security issues
    Analyse {
        /// File to analyse
        #[arg(short, long)]
        file: String,
    },
}

/// Entry point for the CLI.
///
/// We parse arguments (via `clap`), dispatch to the appropriate subcommand,
/// print human-readable output, and return a non-zero exit code on errors.
///
/// High-level flow:
/// 1. Parse CLI args → `Cli`/`Args` struct
/// 2. Match on subcommand (`password`, `hash`, `scan`, `analyse`)
/// 3. Call into module functions and pretty-print results
///
/// Design note: Keeping `main()` thin makes it easy to unit-test the real
/// behavior in module functions without needing a process-level harness.
fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Password { check, generate, length } => {
            if generate {
                generate_password(length);
            } else if let Some(password) = check {
                check_password_strength(&password);
            } else {
                // Hidden prompt for interactive password entry
                use rpassword::read_password;
                use std::io::{self, Write};

                print!("Enter password (hidden): ");
                let _ = io::stdout().flush();

                match read_password() {
                    Ok(pw) if !pw.trim().is_empty() => check_password_strength(pw.trim()),
                    _ => eprintln!("Please provide a password with --check or use --generate"),
                }
            }
        }

        Commands::Hash { file, algorithm, compare } => {
            hash_file(&file, &algorithm, compare);
        }

        Commands::Scan { target, ports, timeout } => {
            network_scan(&target, &ports, timeout);
        }

        Commands::Analyse { file } => {
            analyse_file(&file);
        }
    }
}
