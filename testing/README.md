# Security Toolkit Testing Suite

This directory contains comprehensive tests for the security toolkit to ensure all functionality works correctly across different scenarios and edge cases.

## Test Files

- `comprehensive_test.sh` - Main test script that validates all functionality
- `unit_tests.rs` - Unit tests for individual functions (future enhancement)
- `integration_tests.rs` - Integration tests (future enhancement)

## Running Tests

### Prerequisites

- Rust and Cargo installed
- Unix-like environment (Linux, macOS, WSL)
- Network access for DNS resolution tests
- Write permissions in the current directory

### Quick Test Run

```bash
# Make the script executable
chmod +x testing/comprehensive_test.sh

# Run all tests
./testing/comprehensive_test.sh
```

### What Gets Tested

#### Password Functionality
- Password generation with various lengths (8, 12, 16, 24, 32 characters)
- Password strength analysis with different complexity levels
- Edge cases: weak passwords, strong passwords, patterns

#### File Hashing
- All supported algorithms (SHA-256, SHA-512, SHA3, MD5)
- Hash verification (both correct and incorrect hashes)
- Binary file hashing
- Error handling for non-existent files

#### Network Scanning
- Localhost scanning (safe and quick)
- Port range parsing (single ports, ranges, lists)
- DNS resolution testing
- Error handling for invalid hostnames
- Timeout functionality (limited to 5-10 seconds for speed)

#### File Analysis
- Text file analysis
- Detection of sensitive patterns (passwords, API keys, SSH keys)
- Binary file handling
- Error handling for missing files

#### CLI Functionality
- Help text display
- Version information
- Subcommand help
- Error handling for invalid commands

#### Performance Tests
- Large password generation
- Multi-algorithm hash performance
- Response time validation

## Test Output

The script provides colored output:
- 🔵 **Blue**: Section headers
- 🟡 **Yellow**: Individual test descriptions
- 🟢 **Green**: Successful tests
- 🔴 **Red**: Failed tests

## Test Data

The script automatically creates temporary test files:
- `simple.txt` - Basic text file
- `config_with_password.txt` - Config file with hardcoded password
- `api_config.txt` - File with API key
- `ssh_key.txt` - SSH public key
- `private_key.pem` - Private key file
- `random.bin` - Binary test file

All test files are cleaned up automatically after testing.

## Safety Considerations

- Network tests only scan localhost (127.0.0.1) for safety
- All scans have short timeouts (50-100ms) for speed
- No external services are contacted unnecessarily
- Test files are created in a temporary directory and cleaned up

## Expected Results

When all tests pass, you should see:
```
🎉 All tests passed! Your security toolkit is working perfectly.
```

## Troubleshooting

### Common Issues

1. **Permission denied**: Make sure the script is executable
   ```bash
   chmod +x testing/comprehensive_test.sh
   ```

2. **Build failures**: Ensure you're in the project root directory
   ```bash
   cd /path/to/security-toolkit
   ./testing/comprehensive_test.sh
   ```

3. **Network tests fail**: This is normal if you don't have certain services running on localhost

4. **Timeout on scans**: Expected behavior - scans are deliberately limited for speed

### Adding New Tests

To add new test cases:

1. Add test functions following the pattern:
   ```bash
   test_new_functionality() {
       print_header "Testing New Functionality"
       run_test "Test description" "command" "expected_pattern"
   }
   ```

2. Call your function in the `main()` function

3. Use the helper functions:
    - `run_test()` for standard command testing
    - `print_test()`, `print_success()`, `print_failure()` for custom tests

## Integration with CI/CD

This script is designed to be CI/CD friendly:
- Returns appropriate exit codes (0 for success, 1 for failure)
- Provides clear, parseable output
- Handles cleanup automatically
- Runs in reasonable time (~30-60 seconds)

Example GitHub Actions usage:
```yaml
- name: Run comprehensive tests
  run: |
    chmod +x testing/comprehensive_test.sh
    ./testing/comprehensive_test.sh
```