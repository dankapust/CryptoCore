#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/rand.h>
#include "crypto.h"

crypto_error_t hex_to_bytes(const char* hex_str, uint8_t* bytes, size_t len) {
    if (strlen(hex_str) != len * 2) {
        return CRYPTO_ERROR_INVALID_KEY;
    }
    
    for (size_t i = 0; i < len; i++) {
        char hex_byte[3] = {hex_str[i*2], hex_str[i*2+1], '\0'};
        char* endptr;
        unsigned long val = strtoul(hex_byte, &endptr, 16);
        
        if (*endptr != '\0' || val > 255) {
            return CRYPTO_ERROR_INVALID_KEY;
        }
        
        bytes[i] = (uint8_t)val;
    }
    
    return CRYPTO_SUCCESS;
}

void bytes_to_hex(const uint8_t* bytes, size_t len, char* hex_str) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_str + i*2, "%02x", bytes[i]);
    }
    hex_str[len*2] = '\0';
}

crypto_error_t pkcs7_pad(const uint8_t* input, size_t input_len, uint8_t* output, size_t* output_len) {
    size_t pad_len = BLOCK_SIZE - (input_len % BLOCK_SIZE);
    size_t padded_len = input_len + pad_len;
    
    if (padded_len < input_len) { // Overflow check
        return CRYPTO_ERROR_MEMORY;
    }
    
    memcpy(output, input, input_len);
    
    for (size_t i = input_len; i < padded_len; i++) {
        output[i] = (uint8_t)pad_len;
    }
    
    *output_len = padded_len;
    return CRYPTO_SUCCESS;
}

crypto_error_t pkcs7_unpad(const uint8_t* input, size_t input_len, uint8_t* output, size_t* output_len) {
    if (input_len == 0 || input_len % BLOCK_SIZE != 0) {
        return CRYPTO_ERROR_INVALID_PADDING;
    }
    
    uint8_t pad_len = input[input_len - 1];
    
    if (pad_len == 0 || pad_len > BLOCK_SIZE || pad_len > input_len) {
        return CRYPTO_ERROR_INVALID_PADDING;
    }
    
    // Verify padding
    for (size_t i = input_len - pad_len; i < input_len; i++) {
        if (input[i] != pad_len) {
            return CRYPTO_ERROR_INVALID_PADDING;
        }
    }
    
    size_t unpadded_len = input_len - pad_len;
    memcpy(output, input, unpadded_len);
    *output_len = unpadded_len;
    
    return CRYPTO_SUCCESS;
}

void generate_random_bytes(uint8_t* bytes, size_t len) {
    RAND_bytes(bytes, len);
}
