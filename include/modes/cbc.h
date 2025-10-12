#ifndef CBC_H
#define CBC_H

#include "crypto.h"

// CBC mode function prototypes
crypto_error_t aes_cbc_encrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* input, size_t input_len, uint8_t** output, size_t* output_len);
crypto_error_t aes_cbc_decrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* input, size_t input_len, uint8_t** output, size_t* output_len);

#endif // CBC_H
