//! File hashing utilities (e.g., SHA‑256).
//!
//! Reads the file in fixed-size chunks to avoid loading large files into memory.
//! The chunk size is chosen to balance syscalls and cache friendliness.

use sha2::{Sha256, Sha512, Digest};
use sha3::Sha3_256;
use md5::Md5;
use std::fs::{File, metadata};
use std::io::Read;
use std::path::Path;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use hex;

/// Computes hash of a file using the specified algorithm.
///
/// This function uses streaming to handle arbitrarily large files
/// without loading them entirely into memory. Progress is displayed
/// for files larger than 1MB to provide user feedback.
///
/// # Arguments
/// * `file_path` - Path to the file to hash
/// * `algorithm` - Algorithm name as string ("sha256", "sha512", etc.)
/// * `expected` - Optional expected hash for verification
///
/// # Implementation Notes
/// - Uses 64KB buffer size for optimal I/O performance
/// - Displays progress bar for long operations
/// - Compares hashes case-insensitively for convenience
pub fn hash_file(file_path: &str, algorithm: &str, expected: Option<String>) {
    let path = Path::new(file_path);

    // Validate file exists before proceeding
    if !path.exists() {
        eprintln!("{} File not found: {}", "❌".red(), file_path);
        return;
    }

    println!("\n{}", "🔒 File Hash Calculator".bold().blue());
    println!("{}", "─".repeat(50));

    let metadata = match metadata(path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{} Error reading file metadata: {}", "❌".red(), e);
            return;
        }
    };

    println!("File: {}", file_path);
    println!("Size: {} bytes", metadata.len());
    println!("Algorithm: {}", algorithm.to_uppercase());

    // Create progress bar for user feedback on large files
    let pb = create_progress_bar(metadata.len());

    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{} Error opening file: {}", "❌".red(), e);
            return;
        }
    };

    // Compute hash based on selected algorithm
    let hash_result = match algorithm.to_lowercase().as_str() {
        "sha256" => compute_hash::<Sha256>(&mut file, &pb),
        "sha512" => compute_hash::<Sha512>(&mut file, &pb),
        "sha3" | "sha3-256" => compute_hash::<Sha3_256>(&mut file, &pb),
        "md5" => compute_hash::<Md5>(&mut file, &pb),
        _ => {
            eprintln!("{} Unknown algorithm: {}", "❌".red(), algorithm);
            return;
        }
    };

    pb.finish_and_clear();

    let hash = match hash_result {
        Ok(h) => h,
        Err(e) => {
            eprintln!("{} Read error: {}", "❌".red(), e);
            return;
        }
    };

    display_results(&hash, algorithm, expected);
}

/// Generic hash computation function that works with any Digest implementation.
///
/// This function uses the Rust crypto traits to provide a unified interface
/// for different hash algorithms. The 64KB buffer size is chosen to balance
/// memory usage with I/O efficiency.
///
/// # Type Parameters
/// * `D` - Any type implementing the Digest trait (SHA-256, MD5, etc.)
///
/// # Arguments
/// * `file` - Open file handle to read from
/// * `pb` - Progress bar for user feedback
///
/// # Returns
/// Hex-encoded hash string or I/O error
fn compute_hash<D: Digest + Default>(
    file: &mut File,
    pb: &ProgressBar,
) -> std::io::Result<String> {
    let mut hasher = D::new();
    let mut buffer = [0u8; 64 * 1024]; // 64KB buffer for optimal performance

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break; // End of file reached
        }

        hasher.update(&buffer[..bytes_read]);
        pb.inc(bytes_read as u64);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Creates a progress bar with appropriate styling for hash operations.
///
/// The progress bar provides visual feedback during long hash computations,
/// showing bytes processed, total bytes, elapsed time, and current speed.
fn create_progress_bar(total_bytes: u64) -> ProgressBar {
    let pb = ProgressBar::new(total_bytes);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} {msg}")
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏ "),
    );
    pb.set_message("Calculating hash...");
    pb
}

/// Displays hash results and optional verification against expected value.
///
/// Shows the computed hash prominently and performs case-insensitive
/// comparison with expected hash if provided. Clear visual indicators
/// show whether verification succeeded or failed.
fn display_results(hash: &str, algorithm: &str, expected: Option<String>) {
    println!("\n{}", "Result:".bold());
    println!("{}: {}", algorithm.to_uppercase(), hash.green());

    if let Some(expected_hash) = expected {
        println!("\n{}", "Verification:".bold());
        if hash.eq_ignore_ascii_case(&expected_hash) {
            println!("{} Hash matches! File integrity verified.", "✅".green());
        } else {
            println!("{} Hash mismatch! File may be corrupted or tampered.", "❌".red());
            println!("Expected: {}", expected_hash);
            println!("Actual:   {}", hash);
        }
    }

    println!("{}", "─".repeat(50));
}
