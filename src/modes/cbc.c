#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include "modes/cbc.h"
#include "crypto.h"

crypto_error_t aes_cbc_encrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* input, size_t input_len, uint8_t** output, size_t* output_len) {
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
    
    // Encrypt using CBC mode
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(padded_input);
        free(*output);
        return CRYPTO_ERROR_MEMORY;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(padded_input);
        free(*output);
        return CRYPTO_ERROR_INVALID_KEY;
    }
    
    int len;
    if (EVP_EncryptUpdate(ctx, *output, &len, padded_input, padded_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(padded_input);
        free(*output);
        return CRYPTO_ERROR_INVALID_KEY;
    }
    
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, *output + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(padded_input);
        free(*output);
        return CRYPTO_ERROR_INVALID_KEY;
    }
    
    *output_len = len + final_len;
    
    EVP_CIPHER_CTX_free(ctx);
    free(padded_input);
    return CRYPTO_SUCCESS;
}

crypto_error_t aes_cbc_decrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* input, size_t input_len, uint8_t** output, size_t* output_len) {
    if (input_len % BLOCK_SIZE != 0) {
        return CRYPTO_ERROR_INVALID_PADDING;
    }
    
    // Allocate output
    *output = malloc(input_len);
    if (!*output) {
        return CRYPTO_ERROR_MEMORY;
    }
    
    // Decrypt using CBC mode
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(*output);
        return CRYPTO_ERROR_MEMORY;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return CRYPTO_ERROR_INVALID_KEY;
    }
    
    int len;
    if (EVP_DecryptUpdate(ctx, *output, &len, input, input_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return CRYPTO_ERROR_INVALID_KEY;
    }
    
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, *output + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return CRYPTO_ERROR_INVALID_PADDING;
    }
    
    *output_len = len + final_len;
    
    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_SUCCESS;
}
