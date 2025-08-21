use clap::{Parser, Subcommand};
use colored::*;
use dns_lookup::lookup_host;
use hex;
use indicatif::{ProgressBar, ProgressStyle};
use md5::Md5;
use regex::Regex;
use rpassword::read_password;
use sha2::{Sha256, Sha512};
use sha3::Sha3_256;
use std::io::Read;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::net::{TcpStream, IpAddr};
use std::time::Duration;

fn crack_secs(s: zxcvbn::time_estimates::CrackTimeSeconds) -> f64 {
    // CrackTimeSeconds -> std::time::Duration -> f64 seconds
    std::time::Duration::from(s).as_secs_f64()
}
#[derive(Parser)]
#[command(name = "Security Toolkit")]
#[command(author = "Hans Eric Luiz Jingryd")]
#[command(version = "1.0")]
#[command(about = "Comprehensive security toolkit for everyday security tasks", long_about = None)]
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
    Analyse
 {
        /// File to analyse
        #[arg(short, long)]
        file: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Password { check, generate, length } => {
            if generate {
                generate_password(length);
            } else if let Some(password) = check {
                check_password_strength(&password);
            } else {
                // Hidden prompt (no echo, not stored in shell history)
                use std::io::{self, Write};
                print!("Enter password (hidden): ");
                let _ = io::stdout().flush(); // ensure the prompt is shown

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

fn check_password_strength(password: &str) {
    use colored::*;
    use regex::Regex;

    println!("\n{}", "Password Security Analysis".bold().blue());
    println!("{}", "─".repeat(50));

    // Entropy + feedback
    let entropy = zxcvbn::zxcvbn(password, &[]);

    // Length check
    let length = password.chars().count();
    let length_score = if length >= 16 {
        "✅ Excellent"
    } else if length >= 12 {
        "⚠️ Good"
    } else if length >= 8 {
        "⚠️ Fair"
    } else {
        "❌ Poor"
    };
    println!("Length: {} characters {}", length, length_score);

    // Character diversity
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    println!("\n{}", "Character Types:".bold());
    println!("  {} Lowercase letters", if has_lower { "✅" } else { "❌" });
    println!("  {} Uppercase letters", if has_upper { "✅" } else { "❌" });
    println!("  {} Numbers",           if has_digit { "✅" } else { "❌" });
    println!("  {} Special characters", if has_special { "✅" } else { "❌" });

    // Pattern analysis (avoid backreferences; do repeats check separately)
    println!("\n{}", "Pattern Analysis:".bold());
    let mut found_issues = false;

    let lowered = password.to_lowercase();
    let common_patterns: &[(&str, &str)] = &[
        (r"^[0-9]+$",                       "Only numbers"),
        (r"^[a-zA-Z]+$",                    "Only letters"),
        (r"(password|admin|123456|qwerty)", "Common password"),
        (r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)", "Sequential characters"),
    ];

    for (pattern, description) in common_patterns {
        if Regex::new(pattern).unwrap().is_match(&lowered) {
            println!("  ⚠️  {}", (*description).yellow());
            found_issues = true;
        }
    }

    // Detect 3+ identical characters in a row (no backrefs)
    if password.as_bytes().windows(3).any(|w| w[0] == w[1] && w[1] == w[2]) {
        println!("  ⚠️  {}", "Repeated characters (3+ in a row)".yellow());
        found_issues = true;
    }

    if !found_issues {
        println!("  ✅ No common patterns detected");
    }

    // Overall score — treat as u8 (your zxcvbn returns u8)
    let score: u8 = entropy.score().into();
    let strength = match score {
        0 => "Very Weak".red(),
        1 => "Weak".red(),
        2 => "Fair".yellow(),
        3 => "Strong".green(),
        _ => "Very Strong".bright_green(), // clamp >=4
    };

    println!("\n{}", "Overall Assessment".bold());
    println!("  Strength: {}", strength.bold());
    println!("  Score: {}/4", score.min(4));

    if let Some(feedback) = entropy.feedback() {
        let suggestions = feedback.suggestions();
        if !suggestions.is_empty() {
            println!("\n{}", "Suggestions:".bold());
            for s in suggestions {
                println!("  • {}", s);
            }
        }
    }

    // Time to crack (use zxcvbn’s display strings to avoid type mismatch)
    println!("\n{}", "Time to Crack:".bold());
    let ct = entropy.crack_times();
    println!("  Online (10/s):   ~{}", humanise_seconds(crack_secs(ct.online_no_throttling_10_per_second())));
    println!("  Offline (1e4/s): ~{}", humanise_seconds(crack_secs(ct.offline_slow_hashing_1e4_per_second())));
    println!("  Offline (1e10/s): ~{}", humanise_seconds(crack_secs(ct.offline_fast_hashing_1e10_per_second())));
    println!("\n{}", "─".repeat(50));
}

fn generate_password(length: usize) {
    use rand::Rng;

    let charset: Vec<char> =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
        .chars()
        .collect();

    let mut rng = rand::rng();
    let password: String = (0..length)
        .map(|_| charset[rng.random_range(0..charset.len())])
        .collect();

    println!("\n{}", "🔑 Generated Secure Password".bold().green());
    println!("{}", "─".repeat(50));
    println!("Password: {}", password.bold());
    println!("Length: {} characters", length);
    println!("\n💡 Tip: Store this password in a secure password manager!");
    println!("{}", "─".repeat(50));
}

fn stream_hash<D: digest::Digest + Default>(
    file: &mut File,
    pb: &ProgressBar,
) -> std::io::Result<String> {
    let mut hasher = D::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
        pb.inc(n as u64);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn hash_file(file_path: &str, algorithm: &str, expected: Option<String>) {
    let path = Path::new(file_path);
    if !path.exists() {
        eprintln!("{} File not found: {}", "❌".red(), file_path);
        return;
    }

    println!("\n{}", "🔒 File Hash Calculator".bold().blue());
    println!("{}", "─".repeat(50));

    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => { eprintln!("{} Error reading file: {}", "❌".red(), e); return; }
    };

    println!("File: {}", file_path);
    println!("Size: {} bytes", metadata.len());
    println!("Algorithm: {}", algorithm.to_uppercase());

    let pb = ProgressBar::new(metadata.len());
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} {msg}")
            .unwrap()
            .progress_chars("█▓▒░ "),
    );
    pb.set_message("Calculating hash...");

    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => { eprintln!("{} Error opening file: {}", "❌".red(), e); return; }
    };

    let hash = match algorithm.to_lowercase().as_str() {
        "sha256" => stream_hash::<Sha256>(&mut file, &pb),
        "sha512" => stream_hash::<Sha512>(&mut file, &pb),
        "sha3" | "sha3-256" => stream_hash::<Sha3_256>(&mut file, &pb),
        "md5" => stream_hash::<Md5>(&mut file, &pb),
        _ => { eprintln!("{} Unknown algorithm: {}", "❌".red(), algorithm); return; }
    }
        .unwrap_or_else(|e| { eprintln!("{} Read error: {}", "❌".red(), e); String::new() });

    pb.finish_and_clear();

    if hash.is_empty() { return; }

    println!("\n{}", "Result:".bold());
    println!("{}: {}", algorithm.to_uppercase(), hash.green());

    if let Some(expected_hash) = expected {
        println!("\n{}", "Verification:".bold());
        if hash.eq_ignore_ascii_case(&expected_hash) {
            println!("{} Hash matches! File integrity verified.", "✅".green());
        } else {
            println!("{} Hash mismatch! File may be corrupted or tampered.", "❌".red());
            println!("Expected: {}", expected_hash);
        }
    }

    println!("{}", "─".repeat(50));
}

fn network_scan(target: &str, port_range: &str, timeout_ms: u64) {
    println!("\n{}", "🌐 Network Port Scanner".bold().blue());
    println!("{}", "-".repeat(50));

    // Resolve hostname to IP
    let ip = match target.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            print!("Resolving hostname...");
            match lookup_host(target) {
                Ok(ips) => {
                    if let Some(ip) = ips.into_iter().find(|ip| ip.is_ipv4()) {
                        println!(" {}", ip.to_string().green());
                        ip
                    } else {
                        eprintln!("\n{} Could not resolve hostname", "❌".red());
                        return;
                    }
                },
                Err(e) => {
                    eprintln!("\n{} DNS lookup failed: {}", "❌".red(), e);
                    return;
                }
            }
        }
    };

    println!("Target: {} ({})", target, ip);

    // Parse port range
    let ports: Vec<u16> = if port_range.contains("-") {
        let parts: Vec<&str> = port_range.split("-").collect();
        if parts.len() == 2 {
            let start = parts[0].parse::<u16>().unwrap_or(1);
            let end = parts[1].parse::<u16>().unwrap_or(1000);
            (start..=end).collect()
        } else {
            vec![80, 443]
        }
    } else if port_range.contains(",") {
        port_range.split(",")
            .filter_map(|p| p.trim().parse::<u16>().ok())
            .collect()
    } else {
        vec![port_range.parse::<u16>().unwrap_or(80)]
    };

    println!("Scanning {} ports with {}ms timeout...\n", ports.len(), timeout_ms);

    let pb = ProgressBar::new(ports.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ports")
        .unwrap());

    let mut open_ports = Vec::new();
    let timeout = Duration::from_millis(timeout_ms);

    for port in &ports {
        pb.inc(1);
        let addr = format!("{}:{}", ip, port);

        if TcpStream::connect_timeout(&addr.parse().unwrap(), timeout).is_ok() {
            open_ports.push(*port);
            pb.println(format!("  {} Port {} - {}",
                "✅".green(),
                port.to_string().bold(),
                get_service_name(*port).yellow()
            ));
        }
    }

    pb.finish_and_clear();

    println!("\n{}", "Scan Results:".bold());
    if open_ports.is_empty() {
        println!("  No open ports found in the specified range");
    } else {
        println!("  Found {} open port(s):", open_ports.len());
        for port in open_ports {
            println!("    • Port {}: {}", port, get_service_name(port));
        }
    }

    println!("\n⚠️  Note: This is a basic TCP connect scan for educational purposes");
    println!("{}", "─".repeat(50));
}

fn get_service_name(port: u16) -> &'static str {
    match port {
        20 => "FTP Data",
        21 => "FTP Control",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        8080 => "HTTP Alternate",
        8443 => "HTTPS Alternate",
        _ => "Unknown"
    }
}

fn analyse_file(file_path: &str) {
    println!("\n{}", "🔍 Security Analysis".bold().blue());
    println!("{}", "─".repeat(50));

    let path = Path::new(file_path);
    if !path.exists() {
        eprintln!("{} File not found: {}", "❌".red(), file_path);
        return;
    }

    let metadata = fs::metadata(path).unwrap();
    let contents = fs::read_to_string(path).unwrap_or_else(|_| String::from("[Binary file]"));

    println!("File: {}", file_path);
    println!("Size: {} bytes", metadata.len());

    // Check for sensitive patterns
    println!("\n{}", "Checking for sensitive data:".bold());

    let sensitive_patterns = vec![
        (r"(?i)(api[_-]?key|apikey)", "API Key"),
        (r"(?i)(secret[_-]?key|secret)", "Secret Key"),
        (r#"(?i)password\s*=\s*['"]?[^'"]+['"]?"#, "Hardcoded Password"),
        (r"[a-zA-Z0-9+/]{40,}", "Base64 encoded data"),
        (r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+", "Bearer Token"),
        (r"ssh-rsa\s+[A-Za-z0-9+/]+", "SSH Key"),
        (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "Private Key"),
    ];

    let mut found_issues = false;
    for (pattern, description) in sensitive_patterns {
        let re = Regex::new(pattern).unwrap();
        if re.is_match(&contents) {
            println!("  ⚠️  Potential {} detected", description.yellow());
            found_issues = true;
        }
    }

    if !found_issues {
        println!("  ✅ No sensitive patterns detected");
    }

    println!("{}", "─".repeat(50));
}

fn humanise_seconds(secs: f64) -> String {
    if !secs.is_finite() {
        return "∞".to_string();
    }
    let s = secs;
    const MIN: f64 = 60.0;
    const HOUR: f64 = 60.0 * MIN;
    const DAY: f64 = 24.0 * HOUR;
    const MONTH: f64 = 30.44 * DAY;    // average month
    const YEAR: f64 = 365.25 * DAY;    // average year
    const CENTURY: f64 = 100.0 * YEAR;

    let (val, unit_singular) = if s < 1.0 {
        (1.0, "second")
    } else if s < MIN {
        (s, "second")
    } else if s < HOUR {
        (s / MIN, "minute")
    } else if s < DAY {
        (s / HOUR, "hour")
    } else if s < MONTH {
        (s / DAY, "day")
    } else if s < YEAR {
        (s / MONTH, "month")
    } else if s < CENTURY {
        (s / YEAR, "year")
    } else {
        (s / CENTURY, "century")
    };

    let rounded = if val < 10.0 { format!("{:.1}", val) } else { format!("{:.0}", val) };
    let is_one = rounded == "1" || rounded == "1.0";
    let unit = if is_one {
        unit_singular.to_string()
    } else {
        match unit_singular {
            "century" => "centuries".to_string(),
            "day" => "days".to_string(),
            "hour" => "hours".to_string(),
            "minute" => "minutes".to_string(),
            "month" => "months".to_string(),
            "second" => "seconds".to_string(),
            "year" => "years".to_string(),
            other => format!("{other}s"),
        }
    };
    format!("{rounded} {unit}")
}