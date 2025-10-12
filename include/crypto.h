#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Constants
#define BLOCK_SIZE 16
#define KEY_SIZE 16
#define IV_SIZE 16
#define SALT_SIZE 16
#define MAX_PASSWORD_LEN 256
#define MAX_FILENAME_LEN 512

// Error codes
typedef enum {
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERROR_INVALID_KEY,
    CRYPTO_ERROR_INVALID_IV,
    CRYPTO_ERROR_INVALID_PADDING,
    CRYPTO_ERROR_FILE_IO,
    CRYPTO_ERROR_MEMORY,
    CRYPTO_ERROR_INVALID_MODE,
    CRYPTO_ERROR_INVALID_ALGORITHM
} crypto_error_t;

// Operation modes
typedef enum {
    MODE_ECB,
    MODE_CBC,
    MODE_CFB,
    MODE_OFB,
    MODE_CTR
} crypto_mode_t;

// Operations
typedef enum {
    OP_ENCRYPT,
    OP_DECRYPT
} crypto_operation_t;

// Key derivation
typedef struct {
    char password[MAX_PASSWORD_LEN];
    uint8_t salt[SALT_SIZE];
    uint8_t key[KEY_SIZE];
} key_derivation_t;

// Utility functions
crypto_error_t hex_to_bytes(const char* hex_str, uint8_t* bytes, size_t len);
void bytes_to_hex(const uint8_t* bytes, size_t len, char* hex_str);
crypto_error_t pkcs7_pad(const uint8_t* input, size_t input_len, uint8_t* output, size_t* output_len);
crypto_error_t pkcs7_unpad(const uint8_t* input, size_t input_len, uint8_t* output, size_t* output_len);
void generate_random_bytes(uint8_t* bytes, size_t len);

#endif // CRYPTO_H
