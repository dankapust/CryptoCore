#ifndef OFB_H
#define OFB_H

#include "crypto.h"

// OFB mode function prototypes
crypto_error_t aes_ofb_encrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* input, size_t input_len, uint8_t** output, size_t* output_len);
crypto_error_t aes_ofb_decrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* input, size_t input_len, uint8_t** output, size_t* output_len);

#endif // OFB_H
