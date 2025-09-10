//! Minimal TCP port scanner.
//!
//! Given a target hostname/IP and a set of ports, attempts to establish a TCP
//! connection within a configurable timeout. If the handshake completes, we
//! report the port as *open*; otherwise we treat it as *closed* or *filtered*.
//!
//! This is intentionally single-threaded (or limited concurrency) to keep the
//! code simple. A future improvement is a worker-pool for speed.

use std::net::{TcpStream, IpAddr};
use std::time::Duration;
use dns_lookup::lookup_host;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};

/// Performs a TCP port scan against the specified target.
///
/// This function implements a basic TCP connect scan, which attempts
/// to establish a full TCP connection to each port. While this is
/// easily detectable, it's reliable and doesn't require special privileges.
///
/// # Arguments
/// * `target` - Hostname or IP address to scan
/// * `port_range` - Port specification (e.g., "1-1000", "80,443,8080")
/// * `timeout_ms` - Connection timeout in milliseconds
///
/// # Scanning Method
/// Uses TCP connect() syscall which:
/// - Completes full 3-way handshake
/// - Is easily logged by target systems
/// - Works from unprivileged accounts
/// - Provides definitive open/closed results
pub fn network_scan(target: &str, port_range: &str, timeout_ms: u64) {
    println!("\n{}", "🌐 Network Port Scanner".bold().blue());
    println!("{}", "-".repeat(50));

    // Resolve hostname to IP address for scanning
    let ip = match resolve_target(target) {
        Some(ip) => ip,
        None => return,
    };

    println!("Target: {} ({})", target, ip);

    // Parse port specification into list of ports to scan
    let ports = match parse_port_specification(port_range) {
        Ok(ports) => ports,
        Err(e) => {
            eprintln!("{} Invalid port specification: {}", "❌".red(), e);
            return;
        }
    };

    println!("Scanning {} ports with {}ms timeout...\n", ports.len(), timeout_ms);

    // Perform the actual port scan
    let open_ports = scan_ports(&ip, &ports, timeout_ms);

    // Display results
    display_scan_results(&open_ports);
}

/// Resolves a hostname or validates an IP address.
///
/// If the target is already a valid IP address, returns it directly.
/// Otherwise, performs DNS resolution to convert hostname to IP.
/// Prefers IPv4 addresses for broader compatibility.
///
/// # Arguments
/// * `target` - Hostname or IP address string
///
/// # Returns
/// Some(IpAddr) if resolution successful, None if failed
fn resolve_target(target: &str) -> Option<IpAddr> {
    match target.parse::<IpAddr>() {
        Ok(ip) => Some(ip),
        Err(_) => {
            // Perform DNS resolution for hostname
            print!("Resolving hostname...");
            match lookup_host(target) {
                Ok(ips) => {
                    // Guard: ensure IPv4 address is selected
                    if let Some(ip) = ips.into_iter().find(|ip| ip.is_ipv4()) {
                        println!(" {}", ip.to_string().green());
                        Some(ip)
                    } else {
                        eprintln!("\n{} Could not resolve hostname", "❌".red());
                        None
                    }
                },
                Err(e) => {
                    eprintln!("\n{} DNS lookup failed: {}", "❌".red(), e);
                    None
                }
            }
        }
    }
}

/// Parses port specification string into a vector of port numbers.
///
/// Supports multiple formats:
/// - Range: "1-1000" scans ports 1 through 1000
/// - List: "80,443,8080" scans specific ports
/// - Single: "80" scans just port 80
///
/// # Arguments
/// * `port_spec` - Port specification string
///
/// # Returns
/// Vector of port numbers or error for invalid specifications
///
/// # Examples

fn parse_port_specification(port_spec: &str) -> Result<Vec<u16>, String> {
    if port_spec.contains("-") {
        // Handle range specification (e.g., "1-1000")
        let parts: Vec<&str> = port_spec.split("-").collect();
        if parts.len() != 2 {
            return Err("Range must be in format 'start-end'".to_string());
        }

        let start = parts[0].parse::<u16>()
            .map_err(|_| "Invalid start port number")?;
        let end = parts[1].parse::<u16>()
            .map_err(|_| "Invalid end port number")?;

        if start > end {
            return Err("Start port must be less than end port".to_string());
        }

        Ok((start..=end).collect())
    } else if port_spec.contains(",") {
        // Handle comma-separated list (e.g., "80,443,8080")
        port_spec.split(",")
            .map(|p| p.trim().parse::<u16>())
            .collect::<Result<Vec<u16>, _>>()
            .map_err(|_| "Invalid port number in list".to_string())
    } else {
        // Handle single port (e.g., "80")
        port_spec.parse::<u16>()
            .map(|p| vec![p])
            .map_err(|_| "Invalid port number".to_string())
    }
}

/// Scans a list of ports on the target IP address.
///
/// Attempts TCP connections to each port sequentially with the specified
/// timeout. A successful connection indicates the port is open and accepting
/// connections. Failed connections could indicate the port is closed,
/// filtered by a firewall, or the service is down.
///
/// # Arguments
/// * `ip` - Target IP address
/// * `ports` - List of port numbers to scan
/// * `timeout_ms` - Connection timeout in milliseconds
///
/// # Returns
/// Vector containing only the successfully connected (open) ports
fn scan_ports(ip: &IpAddr, ports: &[u16], timeout_ms: u64) -> Vec<u16> {
    let pb = create_scan_progress_bar(ports.len());
    let mut open_ports = Vec::new();
    let timeout = Duration::from_millis(timeout_ms);

    for &port in ports {
        pb.inc(1);

        // Attempt TCP connection to this port
        let addr = format!("{}:{}", ip, port);

        if TcpStream::connect_timeout(&addr.parse().unwrap(), timeout).is_ok() {
            open_ports.push(port);
            // Display immediate feedback for open ports
            pb.println(format!("  {} Port {} - {}",
                               "✅".green(),
                               port.to_string().bold(),
                               get_service_name(port).yellow()
            ));
        }
    }

    pb.finish_and_clear();
    open_ports
}

/// Creates a progress bar for the port scanning operation.
///
/// Shows current progress through the port list with estimated time
/// remaining and scan rate information.
fn create_scan_progress_bar(total_ports: usize) -> ProgressBar {
    let pb = ProgressBar::new(total_ports as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ports")
        .unwrap());
    pb
}

/// Maps well-known port numbers to their common service names.
///
/// This provides user-friendly service identification for discovered
/// open ports. The mapping includes the most commonly encountered
/// services in network security assessments.
///
/// # Arguments
/// * `port` - Port number to identify
///
/// # Returns
/// String describing the common service for this port
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
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        8080 => "HTTP Alternate",
        8443 => "HTTPS Alternate",
        _ => "Unknown"
    }
}

/// Displays the final results of the port scan.
///
/// Shows a summary of discovered open ports with their associated
/// services, or a message if no open ports were found. Includes
/// educational disclaimer about the scan's limitations.
fn display_scan_results(open_ports: &[u16]) {
    println!("\n{}", "Scan Results:".bold());
    if open_ports.is_empty() {
        println!("  No open ports found in the specified range");
    } else {
        println!("  Found {} open port(s):", open_ports.len());
        for &port in open_ports {
            println!("    • Port {}: {}", port, get_service_name(port));
        }
    }

    println!("\n⚠️  Note: This is a basic TCP connect scan for educational purposes");
    println!("   Real attackers might use stealth techniques to avoid detection");
    println!("{}", "─".repeat(50));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_specification_range() {
        let result = parse_port_specification("80-85").unwrap();
        assert_eq!(result, vec![80, 81, 82, 83, 84, 85]);
    }

    #[test]
    fn test_parse_port_specification_single() {
        let result = parse_port_specification("80").unwrap();
        assert_eq!(result, vec![80]);
    }

    #[test]
    fn test_parse_port_specification_list() {
        let result = parse_port_specification("80,443,8080").unwrap();
        assert_eq!(result, vec![80, 443, 8080]);
    }

    #[test]
    fn test_get_service_name() {
        assert_eq!(get_service_name(22), "SSH");
        assert_eq!(get_service_name(80), "HTTP");
        assert_eq!(get_service_name(443), "HTTPS");
        assert_eq!(get_service_name(9999), "Unknown");
    }
}