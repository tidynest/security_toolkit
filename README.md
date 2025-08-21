# security_toolkit

A CLI toolkit for password checks, file hashing, basic network scans, and simple file analysis.

## Install
```bash
cargo install --path .
# or build
cargo build --release

## Usage
security-toolkit password --check "MyPassw0rd!"
security-toolkit password --generate --length 24
security-toolkit hash --file /etc/hosts --algorithm sha256
security-toolkit scan --target example.com --ports 1-1024 --timeout 100
security-toolkit analyse --file path/to/file
