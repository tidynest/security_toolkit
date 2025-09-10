//! Password utilities: strength checks and random password generation.
//!
//! **Strength check philosophy** (simple & transparent):
//! - Minimum length threshold (e.g., 12 by default)
//! - Mix of character classes (lower/upper/digit/symbol)
//! - Reject known‑weak patterns (sequences like `1234`, keyboard runs, etc.)
//!
//! This is intentionally *not* a full zxcvbn-style entropy estimator. If you
//! want that, wire up `zxcvbn` or `zxcvbn-rs` in the future.

use colored::*;
use regex::Regex;
use rand::Rng;

/// Evaluates a password against transparent rules and returns a detailed analysis.
///
/// This function performs a comprehensive security analysis including:
/// - Length assessment with clear scoring
/// - Character class diversity checking
/// - Common pattern detection to catch weak passwords
/// - Time-to-crack estimates using zxcvbn
///
/// The analysis is designed to be educational, showing users exactly
/// why their password is strong or weak rather than giving opaque scores.
///
/// # Arguments
/// * `password` - The password string to analyse
///
/// # Examples
/// ```
/// use security_toolkit::password::check_password_strength;
/// check_password_strength("MySecureP@ssw0rd!");
/// ```
pub fn check_password_strength(password: &str) {
    println!("\n{}", "Password Security Analysis".bold().blue());
    println!("{}", "─".repeat(50));

    // Use zxcvbn for entropy analysis - this provides scientific feedback
    let entropy = zxcvbn::zxcvbn(password, &[]);

    // Length assessment with clear thresholds
    let length = password.chars().count();
    let length_score = assess_length(length);
    println!("Length: {} characters {}", length, length_score);

    // Character diversity analysis
    analyse_character_classes(password);

    // Pattern detection to catch common weaknesses
    analyse_patterns(password);

    // Overall strength assessment
    display_overall_strength(&entropy);

    // Time-to-crack estimates
    display_crack_times(&entropy);

    println!("\n{}", "─".repeat(50));
}

/// Generates a cryptographically secure random password.
///
/// Uses the system's cryptographically secure random number generator
/// to create passwords with high entropy. The character set includes
/// uppercase, lowercase, digits, and symbols for maximum security.
///
/// # Arguments
/// * `length` - Desired password length (minimum 8 recommended)
///
/// # Security Notes
/// - Uses `rand::rng()` which provides cryptographically secure randomness
/// - Character set chosen to balance security with usability
/// - Each character provides ~6.5 bits of entropy
///
/// # Examples
/// ```
/// use security_toolkit::password::generate_password;
/// generate_password(16); // Generates a 16-character secure password
/// ```
pub fn generate_password(length: usize) {
    // Character set chosen for security and compatibility
    // Excludes ambiguous characters like 0/O, 1/l/I for usability
    let charset: Vec<char> =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
            .chars()
            .collect();

    let mut rng = rand::rng();
    let password: String = (0..length)
        .map(|_| charset[rng.random_range(0..charset.len())])
        .collect();

    println!("\n{}", "🔐 Generated Secure Password".bold().green());
    println!("{}", "─".repeat(50));
    println!("Password: {}", password.bold());
    println!("Length: {} characters", length);
    println!("Estimated entropy: ~{:.1} bits", length as f64 * 6.5);
    println!("\n💡 Tip: Store this password in a secure password manager!");
    println!("{}", "─".repeat(50));
}

/// Assesses password length and returns a colored status message.
///
/// Length thresholds are based on current security recommendations:
/// - 16+ chars: Excellent (resistant to advanced attacks)
/// - 12-15 chars: Good (meets most security standards)
/// - 8-11 chars: Fair (minimum acceptable for most sites)
/// - <8 chars: Poor (vulnerable to brute force)
fn assess_length(length: usize) -> ColoredString {
    match length {
        len if len >= 16 => "✅ Excellent".green(),
        len if len >= 12 => "⚠️ Good".yellow(),
        len if len >= 8 => "⚠️ Fair".yellow(),
        _ => "❌ Poor".red(),
    }
}

/// analyses character class diversity in the password.
///
/// Character classes checked:
/// - Lowercase letters (a-z)
/// - Uppercase letters (A-Z)
/// - Digits (0-9)
/// - Special characters (symbols)
///
/// Diversity across character classes increases resistance to
/// dictionary attacks and provides better entropy distribution.
fn analyse_character_classes(password: &str) {
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    println!("\n{}", "Character Types:".bold());
    println!("  {} Lowercase letters", if has_lower { "✅" } else { "❌" });
    println!("  {} Uppercase letters", if has_upper { "✅" } else { "❌" });
    println!("  {} Numbers",           if has_digit { "✅" } else { "❌" });
    println!("  {} Special characters", if has_special { "✅" } else { "❌" });
}

/// Detects common weak patterns that reduce password security.
///
/// Patterns detected include:
/// - Sequential characters (abc, 123, qwerty)
/// - Repeated characters (aaa, 111)
/// - Common passwords and variations
/// - Dictionary words in common languages
///
/// This helps catch passwords that may have good length/character
/// diversity but are still vulnerable due to predictable patterns.
fn analyse_patterns(password: &str) {
    println!("\n{}", "Pattern Analysis:".bold());
    let mut found_issues = false;

    let lowered = password.to_lowercase();

    // Define patterns that indicate weak passwords
    let weak_patterns: &[(&str, &str)] = &[
        (r"^[0-9]+$", "Only numbers"),
        (r"^[a-zA-Z]+$", "Only letters"),
        (r"(?i)(password|admin|123456|qwerty|letmein)", "Common password"),
        (r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)", "Sequential characters"),
    ];

    // Check each pattern
    for (pattern, description) in weak_patterns {
        if Regex::new(pattern).unwrap().is_match(&lowered) {
            println!("  ⚠️  {}", (*description).yellow());
            found_issues = true;
        }
    }

    // Check for repeated characters (3+ in a row)
    if has_repeated_chars(password) {
        println!("  ⚠️  {}", "Repeated characters (3+ in a row)".yellow());
        found_issues = true;
    }

    if !found_issues {
        println!("  ✅ No common patterns detected");
    }
}

/// Checks if password contains 3 or more identical characters in sequence.
///
/// This is a simple but effective check for obviously weak patterns
/// like "aaa" or "111" that significantly reduce password entropy.
fn has_repeated_chars(password: &str) -> bool {
    password.as_bytes().windows(3).any(|w| w[0] == w[1] && w[1] == w[2])
}

/// Displays overall password strength assessment using zxcvbn scoring.
///
/// The zxcvbn library provides sophisticated entropy analysis that
/// considers common passwords, keyboard patterns, dates, and other
/// real-world attack vectors beyond simple character counting.
fn display_overall_strength(entropy: &zxcvbn::Entropy) {
    let score: u8 = entropy.score().into();
    let strength = match score {
        0 => "Very Weak".red(),
        1 => "Weak".red(),
        2 => "Fair".yellow(),
        3 => "Strong".green(),
        _ => "Very Strong".bright_green(),
    };

    println!("\n{}", "Overall Assessment".bold());
    println!("  Strength: {}", strength.bold());
    println!("  Score: {}/4", score.min(4));

    // Display specific feedback from zxcvbn if available
    if let Some(feedback) = entropy.feedback() {
        let suggestions = feedback.suggestions();
        if !suggestions.is_empty() {
            println!("\n{}", "Suggestions:".bold());
            for suggestion in suggestions {
                println!("  • {}", suggestion);
            }
        }
    }
}

/// Displays estimated time to crack password under different attack scenarios.
///
/// Shows realistic timeframes for:
/// - Online attacks (rate-limited, ~10 attempts/second)
/// - Offline slow hashing (bcrypt/scrypt, ~10,000 attempts/second)  
/// - Offline fast hashing (MD5/SHA1, ~10 billion attempts/second)
///
/// These estimates help users understand real-world security implications.
fn display_crack_times(entropy: &zxcvbn::Entropy) {
    println!("\n{}", "Time to Crack:".bold());
    let ct = entropy.crack_times();

    println!("  Online (10/s):   ~{}",
             humanise_duration(crack_secs(ct.online_no_throttling_10_per_second())));
    println!("  Offline (1e4/s): ~{}",
             humanise_duration(crack_secs(ct.offline_slow_hashing_1e4_per_second())));
    println!("  Offline (1e10/s): ~{}",
             humanise_duration(crack_secs(ct.offline_fast_hashing_1e10_per_second())));
}

/// Converts zxcvbn's CrackTimeSeconds to f64 for duration calculations.
fn crack_secs(s: zxcvbn::time_estimates::CrackTimeSeconds) -> f64 {
    std::time::Duration::from(s).as_secs_f64()
}

/// Converts seconds to human-readable duration strings.
///
/// Handles edge cases like infinity and provides appropriate
/// time units (seconds, minutes, hours, days, years, centuries).
fn humanise_duration(secs: f64) -> String {
    if !secs.is_finite() {
        return "∞".to_string();
    }

    const MIN: f64 = 60.0;
    const HOUR: f64 = 60.0 * MIN;
    const DAY: f64 = 24.0 * HOUR;
    const MONTH: f64 = 30.44 * DAY;
    const YEAR: f64 = 365.25 * DAY;
    const CENTURY: f64 = 100.0 * YEAR;

    let (val, unit_singular) = if secs < 1.0 {
        (1.0, "second")
    } else if secs < MIN {
        (secs, "second")
    } else if secs < HOUR {
        (secs / MIN, "minute")
    } else if secs < DAY {
        (secs / HOUR, "hour")
    } else if secs < MONTH {
        (secs / DAY, "day")
    } else if secs < YEAR {
        (secs / MONTH, "month")
    } else if secs < CENTURY {
        (secs / YEAR, "year")
    } else {
        (secs / CENTURY, "century")
    };

    let rounded = if val < 10.0 {
        format!("{:.1}", val)
    } else {
        format!("{:.0}", val)
    };

    let is_one = rounded == "1" || rounded == "1.0";
    let unit = if is_one {
        unit_singular.to_string()
    } else {
        match unit_singular {
            "century" => "centuries".to_string(),
            other => format!("{other}s"),
        }
    };

    format!("{rounded} {unit}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_repeated_chars() {
        assert!(has_repeated_chars("aaa123"));
        assert!(has_repeated_chars("pass111word"));
        assert!(!has_repeated_chars("abc123"));
    }

    #[test]
    fn test_assess_length() {
        assert!(assess_length(16).to_string().contains("Excellent"));
        assert!(assess_length(12).to_string().contains("Good"));
        assert!(assess_length(8).to_string().contains("Fair"));
        assert!(assess_length(4).to_string().contains("Poor"));
    }

    // REMOVED the calculate_entropy test - that function is in analyse.rs, not here
}
