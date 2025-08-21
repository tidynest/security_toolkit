//! Lightweight file analysis helpers.
//!
//! Provides quick signals like: size (bytes), whether the path is a directory,
//! naive type hints based on extension, and an optional content-based sniff
//! for text/binary.

use std::fs;
use std::path::Path;
use colored::*;
use regex::Regex;

/// analyses a file for basic security-relevant information.
///
/// This performs lightweight analysis suitable for quick file inspection.
/// It checks for common sensitive patterns, file metadata, and potential
/// security issues without deep content inspection.
///
/// # Arguments
/// * `file_path` - Path to the file to analyse
///
/// # Analysis performed
/// - File metadata (size, type)
/// - Content pattern matching for sensitive data
/// - Basic file type identification
/// - Security-relevant pattern detection
pub fn analyse_file(file_path: &str) {
    println!("\n{}", "🔍 Security Analysis".bold().blue());
    println!("{}", "─".repeat(50));

    let path = Path::new(file_path);
    if !path.exists() {
        eprintln!("{} File not found: {}", "❌".red(), file_path);
        return;
    }

    // Gather basic file metadata
    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{} Error reading file metadata: {}", "❌".red(), e);
            return;
        }
    };

    display_file_info(file_path, &metadata);

    // Attempt content analysis (handle binary files gracefully)
    let content = fs::read_to_string(path)
        .unwrap_or_else(|_| "[Binary file - content analysis skipped]".to_string());

    if content != "[Binary file - content analysis skipped]" {
        analyse_content_patterns(&content);
    } else {
        analyse_binary_file(path);
    }

    println!("{}", "─".repeat(50));
}

/// Displays basic file information and metadata.
///
/// Shows file path, size, and attempts to identify file type
/// based on extension and other metadata available.
fn display_file_info(file_path: &str, metadata: &fs::Metadata) {
    println!("File: {}", file_path);
    println!("Size: {} bytes", format_file_size(metadata.len()));

    if metadata.is_dir() {
        println!("Type: Directory");
    } else {
        println!("Type: {}", identify_file_type(file_path));
    }
}

/// analyses text file content for security-sensitive patterns.
///
/// Scans the file content for patterns that might indicate:
/// - API keys and tokens
/// - Passwords and secrets
/// - Cryptographic materials
/// - Database connection strings
/// - Other sensitive information
///
/// This helps identify files that might contain security-critical
/// data that should be protected or removed.
fn analyse_content_patterns(content: &str) {
    println!("\n{}", "Checking for sensitive data:".bold());

    let sensitive_patterns = vec![
        // Keep the working patterns from main.rs
        (r"(?i)(api[_-]?key|apikey)", "API Key"),
        (r"(?i)(secret[_-]?key|secret)", "Secret Key"),
        (r#"(?i)password\s*=\s*['"]?[^'"]+['"]?"#, "Hardcoded Password"),
        (r"[a-zA-Z0-9+/]{40,}", "Base64 encoded data"),
        (r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+", "Bearer Token"),
        (r"ssh-rsa\s+[A-Za-z0-9+/]+", "SSH Key"),
        (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "Private Key"),

        // Add a few more simple, reliable patterns
        (r"-----BEGIN\s+CERTIFICATE-----", "X.509 Certificate"),
        (r"(?i)(postgres|mysql|mongodb)://", "Database Connection String"),
        (r"(?i)aws_access_key_id", "AWS Access Key"),
    ];

    let mut found_issues = false;
    
    for (pattern, description) in sensitive_patterns {
        let re = Regex::new(pattern).unwrap();
        if re.is_match(content) {
            println!("  ⚠️  Potential {} detected", description.yellow());
            found_issues = true;
            
            // For debugging, show context (first 50 chars of matches)
            if let Some(captures) = re.captures(content) {
                if let Some(matched) = captures.get(0) {
                    let preview = &matched.as_str()[..matched.as_str().len().min(50)];
                    println!("     Context: {}...", preview.dimmed());
                }
            }
        }
    }

    // Additional checks for suspicious patterns
    check_suspicious_patterns(content, &mut found_issues);

    if !found_issues {
        println!("  ✅ No sensitive patterns detected");
    }
}

/// Checks for additional suspicious patterns that might indicate security issues.
///
/// This includes patterns like:
/// - High entropy strings (possible encrypted data)
/// - Common exploit patterns
/// - Suspicious file paths or commands
fn check_suspicious_patterns(content: &str, found_issues: &mut bool) {
    // Check for high-entropy strings that might be keys or encrypted data
    let lines: Vec<&str> = content.lines().collect();

    for line in lines {
        if line.len() > 50 && calculate_entropy(line) > 4.5 {
            println!("  ⚠️  {}", "High-entropy string (possible encrypted data)".yellow());
            *found_issues = true;
            break; // Only report once
        }
    }

    // Check for suspicious file operations
    let suspicious_ops = vec![
        (r"(?i)rm\s+-rf\s+/", "Dangerous file deletion command"),
        (r"(?i)chmod\s+777", "Overly permissive file permissions"),
        (r"(?i)sudo\s+.*\s+--no-password", "Password-less sudo configuration"),
        (r"(?i)curl\s+.*\|\s*sh", "Pipe-to-shell pattern (potential security risk)"),
    ];

    for (pattern, description) in suspicious_ops {
        let re = Regex::new(pattern).unwrap();
        if re.is_match(content) {
            println!("  ⚠️  {}", description.yellow());
            *found_issues = true;
        }
    }
}

/// analyses binary files for basic security characteristics.
///
/// Since we can't perform text-based pattern matching on binary files,
/// this function focuses on metadata analysis and file type identification
/// that might be security-relevant.
fn analyse_binary_file(path: &Path) {
    println!("\n{}", "Binary file analysis:".bold());

    if let Some(extension) = path.extension() {
        let ext = extension.to_string_lossy().to_lowercase();
        match ext.as_str() {
            "exe" | "dll" | "so" | "dylib" => {
                println!("  ⚠️  {}", "Executable binary file".yellow());
            },
            "key" | "pem" | "p12" | "pfx" => {
                println!("  ⚠️  {}", "Cryptographic key file".yellow());
            },
            "zip" | "tar" | "gz" | "7z" => {
                println!("  ℹ️  Compressed archive (contents not analysed)");
            },
            _ => {
                println!("  ℹ️  Binary file type: {}", ext);
            }
        }
    } else {
        println!("  ℹ️  Binary file with no extension");
    }
}

/// Identifies file type based on extension and other heuristics.
///
/// Provides user-friendly file type identification for common
/// file formats, with special attention to security-relevant types.
fn identify_file_type(file_path: &str) -> String {
    let path = Path::new(file_path);

    if let Some(extension) = path.extension() {
        let ext = extension.to_string_lossy().to_lowercase();
        match ext.as_str() {
            "txt" | "log" => "Text file".to_string(),
            "json" | "xml" | "yaml" | "yml" => format!("Configuration file ({})", ext.to_uppercase()),
            "py" | "js" | "rs" | "c" | "cpp" | "java" => format!("Source code ({})", ext.to_uppercase()),
            "sh" | "bat" | "ps1" => "Script file".to_string(),
            "key" | "pem" | "crt" | "cer" => "Cryptographic file".to_string(),
            "exe" | "dll" | "so" => "Executable binary".to_string(),
            "zip" | "tar" | "gz" => "Archive file".to_string(),
            _ => format!("Unknown ({})", ext),
        }
    } else {
        "Unknown (no extension)".to_string()
    }
}

/// Calculates approximate entropy of a string.
///
/// Higher entropy values suggest more randomness, which might
/// indicate encrypted data, keys, or other cryptographic material.
/// Uses Shannon entropy calculation.
fn calculate_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let mut char_counts = std::collections::HashMap::new();
    let len = text.len() as f64;

    // Count character frequencies
    for ch in text.chars() {
        *char_counts.entry(ch).or_insert(0) += 1;
    }

    // Calculate Shannon entropy
    char_counts.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Formats file size in human-readable format.
///
/// Converts bytes to appropriate units (KB, MB, GB) for better readability.
fn format_file_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}
