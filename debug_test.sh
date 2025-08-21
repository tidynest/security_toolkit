#!/bin/bash

echo "=== Simple Build Test ==="
echo "Current directory: $(pwd)"
echo "Building..."

if cargo build --release 2>&1; then
    echo "✓ Build succeeded"
    BINARY="./target/release/security-toolkit"
    echo "Binary: $BINARY"
    ls -la "$BINARY"
    
    echo "Testing binary..."
    $BINARY --version
    echo "✓ Binary works!"
else
    echo "✗ Build failed"
fi
