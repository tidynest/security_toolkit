# security_toolkit

### A CLI toolkit for password checks, file hashing, basic network scans, and simple file analysis.

---

## Features
▸ **Password Utilities**: Check strength and generate secure passwords  
▸ **File Hashing**: Hash files with algorithms such as SHA-256  
▸ **Network Scanning**: Simple TCP port scanning with timeout control  
▸ **File Analysis**: Quick file inspection for lightweight analysis

---

## About
This project was built as a practical demonstration of **Rust programming**, **CLI design**, and **security-related tooling**.  
It is not intended for production use, but rather to showcase clean code structure, modularity, error handling, and testability.

---

## 📚 Educational Focus

This project demonstrates professional Rust development practices:
- **Modular Architecture**: Clean separation of concerns across focused modules
- **Comprehensive Documentation**: Every public function documented for `cargo doc`
- **Error Handling**: Proper error propagation and user-friendly feedback
- **CLI Design**: Intuitive command-line interface using `clap`
- **Security Concepts**: Real-world security tool implementation patterns

### 🔍 Code Structure
```
src/
├── main.rs      # CLI interface and argument parsing
├── lib.rs       # Library exports for external use
├── password.rs  # Password analysis and generation
├── hash.rs      # File hashing with multiple algorithms  
├── scan.rs      # TCP port scanning functionality
└── analyse.rs   # File security analysis
```

> **Educational Disclaimer**: This toolkit demonstrates Rust programming and CLI design patterns. While functional, it's designed for learning rather than production security work.

---

## Requirements
- Rust (latest stable) → [Install Rust](https://www.rust-lang.org/tools/install)
- Linux, macOS, or WSL (Windows)
- Internet access (for network scanning)

---

## Install
```bash
# Install locally
cargo install --path .

# Or build in release mode
cargo build --release
```

---

## Usage
```bash
# Check password strength
security-toolkit password --check "MyPassw0rd!"

# Generate a secure password (24 characters)
security-toolkit password --generate --length 24

# Hash a file using SHA-256
security-toolkit hash --file /etc/hosts --algorithm sha256

# Run a basic port scan
security-toolkit scan --target example.com --ports 1-1024 --timeout 100

# Analyse a file
security-toolkit analyse --file path/to/file
```

---

## Example Output

$ security-toolkit password --check "Tr0ub4dor&3"

Password strength: Weak ✖  
Reason: Common pattern detected, length < 12

$ security-toolkit scan --target example.com --ports 22,80,443

Open ports found:
- 22/tcp (SSH)
- 80/tcp (HTTP)
- 443/tcp (HTTPS)

---

## Documentation

Generate and view the comprehensive API documentation:

```bash
cargo doc --open
```

This will create detailed documentation for all modules, functions, and implementation details.

---

## Roadmap

🔹 Add multi-threaded scanning for speed

🔹 Add more hashing algorithms (BLAKE2, SHA3)

🔹 Add JSON output for automation

🔹 Improve password strength estimator with zxcvbn-rs

---

## 🤝 Contributing

Contributions are welcome!

Feel free to fork this repository, create a feature branch, and open a pull request.

=> For larger changes, please open an issue first to discuss what you'd like to add.

---

## 📄 License

This project is licensed under the terms of the [MIT License](LICENSE).