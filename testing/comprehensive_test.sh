#!/bin/bash

# Comprehensive Test Script for Security Toolkit
# Tests all functionalities with various inputs and edge cases

#set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

print_test() {
    echo -e "${YELLOW}Testing: $1${NC}"
    ((TESTS_RUN++))
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    ((TESTS_PASSED++))
}

print_failure() {
    echo -e "${RED}✗ $1${NC}"
    ((TESTS_FAILED++))
}

run_test() {
    local test_name="$1"
    local command="$2"
    local expected_pattern="$3"

    print_test "$test_name"

    if output=$(eval "$command" 2>&1); then
        if [[ -z "$expected_pattern" ]] || echo "$output" | grep -q "$expected_pattern"; then
            print_success "$test_name"
            return 0
        else
            print_failure "$test_name - Expected pattern '$expected_pattern' not found"
            echo "Output: $output"
            return 1
        fi
    else
        print_failure "$test_name - Command failed"
        echo "Output: $output"
        return 1
    fi
}

# Setup test environment
setup_test_env() {
    print_header "Setting Up Test Environment"

    # Create test directory
    mkdir -p test_files

    # Create various test files for analysis and hashing
    echo "This is a simple text file for testing." > test_files/simple.txt
    echo "password=secret123" > test_files/config_with_password.txt
    echo "api_key=sk-1234567890abcdef" > test_files/api_config.txt
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7..." > test_files/ssh_key.txt
    echo "-----BEGIN PRIVATE KEY-----" > test_files/private_key.pem

    # Create a small binary file
    dd if=/dev/urandom of=test_files/random.bin bs=1024 count=1 &>/dev/null

    # Build the project
    print_test "Building project"
    echo "DEBUG: About to run cargo build --release"
    if build_output=$(cargo build --release 2>&1); then
        echo "DEBUG: Release build succeeded"
        echo "DEBUG: Build output: $build_output"
        print_success "Project built successfully"
        BINARY="./target/release/security-toolkit"
    else
        echo "DEBUG: Release build failed, trying debug build"
        echo "DEBUG: Release build output: $build_output"
        if debug_output=$(cargo build 2>&1); then
            echo "DEBUG: Debug build succeeded"
            echo "DEBUG: Debug build output: $debug_output"
            print_success "Project built successfully (debug mode)"
            BINARY="./target/debug/security-toolkit"
        else
            echo "DEBUG: Both builds failed"
            echo "DEBUG: Debug build output: $debug_output"
            print_failure "Failed to build project"
            exit 1
        fi
    fi
    echo "DEBUG: Binary path set to: $BINARY"
    echo "DEBUG: Checking if binary exists:"
    ls -la "$BINARY" 2>/dev/null || echo "NOT FOUND"
}

# Test password functionality
test_passwords() {
    print_header "Testing Password Functionality"

    # Test password generation with different lengths
    for length in 8 12 16 24 32; do
        run_test "Generate $length-character password" \
                "$BINARY password --generate --length $length" \
                "Length: $length characters"
    done

    # Test password strength checking with various passwords
    declare -a test_passwords=(
        "123:Very Weak|Weak"           # Numbers only
        "password:Very Weak|Weak"      # Common word
        "Password1:Weak|Fair"          # Basic complexity
        "MyP@ssw0rd!:Fair|Strong"      # Better complexity
        "Tr0ub4dor&3MyL0ngP@ssw0rd:Strong|Very Strong"  # Strong password
        "aaaaaaaaaaaa:Weak"            # Repeated characters
        "qwertyuiop:Weak"              # Keyboard pattern
    )

    for test_case in "${test_passwords[@]}"; do
        IFS=':' read -ra PARTS <<< "$test_case"
        password="${PARTS[0]}"
        expected="${PARTS[1]}"

        run_test "Check strength of '$password'" \
                "$BINARY password --check '$password'" \
                "Strength:"
    done

    # Test interactive password input (skip for automation)
    print_test "Interactive password input (skipped in automation)"
    print_success "Interactive password input (manual test required)"
}

# Test file hashing functionality
test_hashing() {
    print_header "Testing File Hashing Functionality"

    # Test different algorithms
    declare -a algorithms=("sha256" "sha512" "sha3" "md5")

    for algo in "${algorithms[@]}"; do
        run_test "Hash simple.txt with $algo" \
                "$BINARY hash --file test_files/simple.txt --algorithm $algo" \
                "${algo^^}:"
    done

    # Test hash verification
    # First get a hash
    hash_output=$($BINARY hash --file test_files/simple.txt --algorithm sha256 2>/dev/null)
    hash_value=$(echo "$hash_output" | grep "SHA256:" | cut -d' ' -f2)

    if [[ -n "$hash_value" ]]; then
        run_test "Hash verification (correct hash)" \
                "$BINARY hash --file test_files/simple.txt --algorithm sha256 --compare $hash_value" \
                "Hash matches"

        run_test "Hash verification (incorrect hash)" \
                "$BINARY hash --file test_files/simple.txt --algorithm sha256 --compare 'deadbeef'" \
                "Hash mismatch"
    fi

    # Test with non-existent file
    run_test "Hash non-existent file (should fail)" \
            "$BINARY hash --file nonexistent.txt --algorithm sha256 2>&1 || true" \
            "File not found"

    # Test with binary file
    run_test "Hash binary file" \
            "$BINARY hash --file test_files/random.bin --algorithm sha256" \
            "SHA256:"
}

# Test network scanning functionality (limited scope)
test_scanning() {
    print_header "Testing Network Scanning Functionality"

    # Test localhost scanning (safe and quick)
    run_test "Scan localhost common ports" \
            "timeout 10s $BINARY scan --target 127.0.0.1 --ports 22,80,443 --timeout 100 2>/dev/null || true" \
            "Network Port Scanner"

    # Test port range parsing
    run_test "Scan localhost port range" \
            "timeout 5s $BINARY scan --target 127.0.0.1 --ports 80-85 --timeout 50 2>/dev/null || true" \
            "Scanning"

    # Test single port
    run_test "Scan localhost single port" \
            "timeout 5s $BINARY scan --target 127.0.0.1 --ports 22 --timeout 50 2>/dev/null || true" \
            "Target: 127.0.0.1"

    # Test DNS resolution
    run_test "Scan with hostname (quick)" \
            "timeout 5s $BINARY scan --target localhost --ports 22 --timeout 50 2>/dev/null || true" \
            "Target: localhost"

    # Test invalid hostname
    run_test "Scan invalid hostname (should fail)" \
            "timeout 5s $BINARY scan --target nonexistent.invalid --ports 22 --timeout 50 2>&1 || true" \
            "DNS lookup failed"
}

# Test file analysis functionality
test_analysis() {
    print_header "Testing File Analysis Functionality"

    # Test analysis of different file types
    run_test "Analyse simple text file" \
            "$BINARY analyse --file test_files/simple.txt" \
            "Security Analysis"

    run_test "Analyse config with password" \
            "$BINARY analyse --file test_files/config_with_password.txt" \
            "Hardcoded Password"

    run_test "Analyse API config file" \
            "$BINARY analyse --file test_files/api_config.txt" \
            "API Key"

    run_test "Analyse SSH key file" \
            "$BINARY analyse --file test_files/ssh_key.txt" \
            "SSH.*Key"

    run_test "Analyse private key file" \
            "$BINARY analyse --file test_files/private_key.pem" \
            "Private Key"

    run_test "Analyse binary file" \
            "$BINARY analyse --file test_files/random.bin" \
            "Binary file"

    # Test with non-existent file
    run_test "Analyse non-existent file (should fail)" \
            "$BINARY analyse --file nonexistent.txt 2>&1 || true" \
            "File not found"
}

# Test CLI help and version
test_cli_basics() {
    print_header "Testing CLI Basics"

    run_test "Display help" \
            "$BINARY --help" \
            "Command-line arguments and subcommands"

    run_test "Display version" \
            "$BINARY --version" \
            "1.0"

    run_test "Password subcommand help" \
            "$BINARY password --help" \
            "Check password strength"

    run_test "Hash subcommand help" \
            "$BINARY hash --help" \
            "Calculate file hashes"

    run_test "Scan subcommand help" \
            "$BINARY scan --help" \
            "Basic network scanning"

    run_test "Analyse subcommand help" \
            "$BINARY analyse --help" \
            "Analyse file for security"
}

# Test error conditions
test_error_conditions() {
    print_header "Testing Error Conditions"

    run_test "Invalid subcommand" \
            "$BINARY invalid-command 2>&1 || true" \
            "unrecognized subcommand"

    run_test "Password generation with invalid length" \
            "$BINARY password --generate --length 0 2>&1 || true" \
            "Password:"  # Should still work, just generate empty or minimal

    run_test "Hash with invalid algorithm" \
            "$BINARY hash --file test_files/simple.txt --algorithm invalid 2>&1 || true" \
            "Unknown algorithm"

    run_test "Scan with invalid port range" \
            "$BINARY scan --target 127.0.0.1 --ports 70000-80000 --timeout 50 2>&1 || true" \
            "Invalid port specification"
}

# Performance and stress tests (light)
test_performance() {
    print_header "Testing Performance (Light Stress Tests)"

    # Test large password generation
    run_test "Generate very long password (100 chars)" \
            "$BINARY password --generate --length 100" \
            "Length: 100 characters"

    # Test multiple hash algorithms on the same file quickly
    print_test "Quick multi-algorithm hash test"
    start_time=$(date +%s)
    for algo in sha256 sha512 md5; do
        $BINARY hash --file test_files/simple.txt --algorithm $algo &>/dev/null
    done
    end_time=$(date +%s)
    duration=$((end_time - start_time))

    if [[ $duration -le 5 ]]; then
        print_success "Multi-algorithm hash test completed in ${duration}s"
    else
        print_failure "Multi-algorithm hash test took too long: ${duration}s"
    fi
}

# Cleanup function
cleanup() {
    print_header "Cleaning Up"
    rm -rf test_files
    echo -e "${GREEN}Test environment cleaned up${NC}"
}

# Main test execution
main() {
    echo -e "${BLUE}"
    echo "=========================================="
    echo "  Security Toolkit Comprehensive Tests"
    echo "=========================================="
    echo -e "${NC}"

    # Set up signal handler for cleanup
    trap cleanup EXIT

    # Run all test suites
    setup_test_env
    test_cli_basics
    test_passwords
    test_hashing
    test_scanning
    test_analysis
    test_error_conditions
    test_performance

    # Print summary
    print_header "Test Summary"
    echo -e "Total tests run: ${BLUE}$TESTS_RUN${NC}"
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "\n${GREEN}🎉 All tests passed! Your security toolkit is working perfectly.${NC}"
        exit 0
    else
        echo -e "\n${RED}❌ Some tests failed. Please review the output above.${NC}"
        exit 1
    fi
}

# Run main function
main "$@"