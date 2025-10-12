#ifndef FILE_IO_H
#define FILE_IO_H

#include "crypto.h"

// File I/O function prototypes
crypto_error_t read_file(const char* filename, uint8_t** data, size_t* data_len);
crypto_error_t write_file(const char* filename, const uint8_t* data, size_t data_len);
crypto_error_t write_file_with_iv(const char* filename, const uint8_t* iv, const uint8_t* data, size_t data_len);
crypto_error_t read_file_with_iv(const char* filename, uint8_t* iv, uint8_t** data, size_t* data_len);
crypto_error_t write_file_with_salt_iv(const char* filename, const uint8_t* salt, const uint8_t* iv, const uint8_t* data, size_t data_len);
crypto_error_t read_file_with_salt_iv(const char* filename, uint8_t* salt, uint8_t* iv, uint8_t** data, size_t* data_len);

#endif // FILE_IO_H
