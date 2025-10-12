#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include "modes/cfb.h"
#include "crypto.h"

crypto_error_t aes_cfb_encrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* input, size_t input_len, uint8_t** output, size_t* output_len) {
    // Allocate output
    *output = malloc(input_len);
    if (!*output) {
        return CRYPTO_ERROR_MEMORY;
    }
    
    // Encrypt using CFB mode
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(*output);
        return CRYPTO_ERROR_MEMORY;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb128(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return CRYPTO_ERROR_INVALID_KEY;
    }
    
    int len;
    if (EVP_EncryptUpdate(ctx, *output, &len, input, input_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return CRYPTO_ERROR_INVALID_KEY;
    }
    
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, *output + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return CRYPTO_ERROR_INVALID_KEY;
    }
    
    *output_len = len + final_len;
    
    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_SUCCESS;
}

crypto_error_t aes_cfb_decrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* input, size_t input_len, uint8_t** output, size_t* output_len) {
    // Allocate output
    *output = malloc(input_len);
    if (!*output) {
        return CRYPTO_ERROR_MEMORY;
    }
    
    // Decrypt using CFB mode
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(*output);
        return CRYPTO_ERROR_MEMORY;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb128(), NULL, key, iv) != 1) {
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
        return CRYPTO_ERROR_INVALID_KEY;
    }
    
    *output_len = len + final_len;
    
    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_SUCCESS;
}
