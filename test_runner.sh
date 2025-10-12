#!/bin/bash

# Test script for CryptoCore C implementation
# This script tests all encryption modes and verifies round-trip functionality

set -e

echo "=== CryptoCore C Implementation Tests ==="
echo

# Test data
TEST_FILE="test_data.txt"
TEST_KEY="000102030405060708090a0b0c0d0e0f"
TEST_PASSWORD="testpassword123"

# Create test data
echo "Creating test data..."
echo "Hello, CryptoCore! This is a test message for AES encryption." > "$TEST_FILE"
echo "Test data created: $TEST_FILE"
echo

# Function to test a mode
test_mode() {
    local mode=$1
    local encrypted_file="${TEST_FILE}.${mode}.enc"
    local decrypted_file="${TEST_FILE}.${mode}.dec"
    
    echo "Testing $mode mode..."
    
    # Test with key
    echo "  Testing with key..."
    ./cryptocore --algorithm aes --mode "$mode" --encrypt --key "$TEST_KEY" --input "$TEST_FILE" --output "$encrypted_file"
    ./cryptocore --algorithm aes --mode "$mode" --decrypt --key "$TEST_KEY" --input "$encrypted_file" --output "$decrypted_file"
    
    if diff "$TEST_FILE" "$decrypted_file" > /dev/null; then
        echo "  ✓ Key-based $mode test passed"
    else
        echo "  ✗ Key-based $mode test failed"
        return 1
    fi
    
    # Test with password (except ECB which doesn't use IV)
    if [ "$mode" != "ecb" ]; then
        echo "  Testing with password..."
        ./cryptocore --algorithm aes --mode "$mode" --encrypt --password "$TEST_PASSWORD" --input "$TEST_FILE" --output "${encrypted_file}.pwd"
        ./cryptocore --algorithm aes --mode "$mode" --decrypt --password "$TEST_PASSWORD" --input "${encrypted_file}.pwd" --output "${decrypted_file}.pwd"
        
        if diff "$TEST_FILE" "${decrypted_file}.pwd" > /dev/null; then
            echo "  ✓ Password-based $mode test passed"
        else
            echo "  ✗ Password-based $mode test failed"
            return 1
        fi
        
        rm -f "${encrypted_file}.pwd" "${decrypted_file}.pwd"
    fi
    
    echo "  ✓ $mode mode tests completed successfully"
    echo
    
    # Cleanup
    rm -f "$encrypted_file" "$decrypted_file"
}

# Test all modes
test_mode "ecb"
test_mode "cbc"
test_mode "cfb"
test_mode "ofb"
test_mode "ctr"

# Test OpenSSL interoperability for ECB
echo "Testing OpenSSL interoperability (ECB mode)..."
ECB_ENCRYPTED="${TEST_FILE}.ecb.openssl"
ECB_DECRYPTED="${TEST_FILE}.ecb.openssl.dec"

# Encrypt with OpenSSL
openssl enc -aes-128-ecb -K "$TEST_KEY" -in "$TEST_FILE" -out "$ECB_ENCRYPTED" -nopad

# Decrypt with CryptoCore
./cryptocore --algorithm aes --mode ecb --decrypt --key "$TEST_KEY" --input "$ECB_ENCRYPTED" --output "$ECB_DECRYPTED"

if diff "$TEST_FILE" "$ECB_DECRYPTED" > /dev/null; then
    echo "✓ OpenSSL interoperability test passed"
else
    echo "✗ OpenSSL interoperability test failed"
    exit 1
fi

# Encrypt with CryptoCore, decrypt with OpenSSL
CRYPTOCORE_ENCRYPTED="${TEST_FILE}.ecb.cryptocore"
OPENSSL_DECRYPTED="${TEST_FILE}.ecb.openssl.dec2"

./cryptocore --algorithm aes --mode ecb --encrypt --key "$TEST_KEY" --input "$TEST_FILE" --output "$CRYPTOCORE_ENCRYPTED"
openssl enc -aes-128-ecb -K "$TEST_KEY" -in "$CRYPTOCORE_ENCRYPTED" -out "$OPENSSL_DECRYPTED" -d -nopad

if diff "$TEST_FILE" "$OPENSSL_DECRYPTED" > /dev/null; then
    echo "✓ CryptoCore → OpenSSL interoperability test passed"
else
    echo "✗ CryptoCore → OpenSSL interoperability test failed"
    exit 1
fi

echo
echo "=== All tests passed! ==="

# Cleanup
rm -f "$TEST_FILE" "$ECB_ENCRYPTED" "$ECB_DECRYPTED" "$CRYPTOCORE_ENCRYPTED" "$OPENSSL_DECRYPTED"
