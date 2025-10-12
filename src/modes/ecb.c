#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include "modes/ecb.h"
#include "crypto.h"

crypto_error_t aes_ecb_encrypt(const uint8_t* key, const uint8_t* input, size_t input_len, uint8_t** output, size_t* output_len) {
    // Pad input
    size_t padded_len = input_len + (BLOCK_SIZE - (input_len % BLOCK_SIZE));
    uint8_t* padded_input = malloc(padded_len);
    if (!padded_input) {
        return CRYPTO_ERROR_MEMORY;
    }
    
    crypto_error_t err = pkcs7_pad(input, input_len, padded_input, &padded_len);
    if (err != CRYPTO_SUCCESS) {
        free(padded_input);
        return err;
    }
    
    // Allocate output
    *output = malloc(padded_len);
    if (!*output) {
        free(padded_input);
        return CRYPTO_ERROR_MEMORY;
    }
    
    // Encrypt each block
    AES_KEY aes_key;
    if (AES_set_encrypt_key(key, 128, &aes_key) != 0) {
        free(padded_input);
        free(*output);
        return CRYPTO_ERROR_INVALID_KEY;
    }
    
    for (size_t i = 0; i < padded_len; i += BLOCK_SIZE) {
        AES_encrypt(padded_input + i, *output + i, &aes_key);
    }
    
    *output_len = padded_len;
    free(padded_input);
    return CRYPTO_SUCCESS;
}

crypto_error_t aes_ecb_decrypt(const uint8_t* key, const uint8_t* input, size_t input_len, uint8_t** output, size_t* output_len) {
    if (input_len % BLOCK_SIZE != 0) {
        return CRYPTO_ERROR_INVALID_PADDING;
    }
    
    // Allocate output
    *output = malloc(input_len);
    if (!*output) {
        return CRYPTO_ERROR_MEMORY;
    }
    
    // Decrypt each block
    AES_KEY aes_key;
    if (AES_set_decrypt_key(key, 128, &aes_key) != 0) {
        free(*output);
        return CRYPTO_ERROR_INVALID_KEY;
    }
    
    for (size_t i = 0; i < input_len; i += BLOCK_SIZE) {
        AES_decrypt(input + i, *output + i, &aes_key);
    }
    
    // Remove padding
    uint8_t* unpadded_output = malloc(input_len);
    if (!unpadded_output) {
        free(*output);
        return CRYPTO_ERROR_MEMORY;
    }
    
    crypto_error_t err = pkcs7_unpad(*output, input_len, unpadded_output, output_len);
    if (err != CRYPTO_SUCCESS) {
        free(*output);
        free(unpadded_output);
        return err;
    }
    
    free(*output);
    *output = unpadded_output;
    return CRYPTO_SUCCESS;
}
