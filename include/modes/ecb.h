#ifndef ECB_H
#define ECB_H

#include "crypto.h"

// ECB mode function prototypes
crypto_error_t aes_ecb_encrypt(const uint8_t* key, const uint8_t* input, size_t input_len, uint8_t** output, size_t* output_len);
crypto_error_t aes_ecb_decrypt(const uint8_t* key, const uint8_t* input, size_t input_len, uint8_t** output, size_t* output_len);

#endif // ECB_H
