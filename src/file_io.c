#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "file_io.h"

crypto_error_t read_file(const char* filename, uint8_t** data, size_t* data_len) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "[ERROR] Cannot open file %s: %s\n", filename, strerror(errno));
        return CRYPTO_ERROR_FILE_IO;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size < 0) {
        fclose(file);
        fprintf(stderr, "[ERROR] Cannot determine file size for %s\n", filename);
        return CRYPTO_ERROR_FILE_IO;
    }
    
    // Allocate memory
    *data = malloc(file_size);
    if (!*data) {
        fclose(file);
        fprintf(stderr, "[ERROR] Memory allocation failed\n");
        return CRYPTO_ERROR_MEMORY;
    }
    
    // Read file
    size_t bytes_read = fread(*data, 1, file_size, file);
    fclose(file);
    
    if (bytes_read != (size_t)file_size) {
        free(*data);
        fprintf(stderr, "[ERROR] Failed to read entire file %s\n", filename);
        return CRYPTO_ERROR_FILE_IO;
    }
    
    *data_len = bytes_read;
    return CRYPTO_SUCCESS;
}

crypto_error_t write_file(const char* filename, const uint8_t* data, size_t data_len) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "[ERROR] Cannot create file %s: %s\n", filename, strerror(errno));
        return CRYPTO_ERROR_FILE_IO;
    }
    
    size_t bytes_written = fwrite(data, 1, data_len, file);
    fclose(file);
    
    if (bytes_written != data_len) {
        fprintf(stderr, "[ERROR] Failed to write entire file %s\n", filename);
        return CRYPTO_ERROR_FILE_IO;
    }
    
    return CRYPTO_SUCCESS;
}

crypto_error_t write_file_with_iv(const char* filename, const uint8_t* iv, const uint8_t* data, size_t data_len) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "[ERROR] Cannot create file %s: %s\n", filename, strerror(errno));
        return CRYPTO_ERROR_FILE_IO;
    }
    
    // Write IV first
    size_t iv_written = fwrite(iv, 1, IV_SIZE, file);
    if (iv_written != IV_SIZE) {
        fclose(file);
        fprintf(stderr, "[ERROR] Failed to write IV to file %s\n", filename);
        return CRYPTO_ERROR_FILE_IO;
    }
    
    // Write data
    size_t data_written = fwrite(data, 1, data_len, file);
    fclose(file);
    
    if (data_written != data_len) {
        fprintf(stderr, "[ERROR] Failed to write data to file %s\n", filename);
        return CRYPTO_ERROR_FILE_IO;
    }
    
    return CRYPTO_SUCCESS;
}

crypto_error_t read_file_with_iv(const char* filename, uint8_t* iv, uint8_t** data, size_t* data_len) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "[ERROR] Cannot open file %s: %s\n", filename, strerror(errno));
        return CRYPTO_ERROR_FILE_IO;
    }
    
    // Read IV
    size_t iv_read = fread(iv, 1, IV_SIZE, file);
    if (iv_read != IV_SIZE) {
        fclose(file);
        fprintf(stderr, "[ERROR] File %s too short for IV (less than %d bytes)\n", filename, IV_SIZE);
        return CRYPTO_ERROR_FILE_IO;
    }
    
    // Get remaining file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, IV_SIZE, SEEK_SET);
    
    size_t data_size = file_size - IV_SIZE;
    
    // Allocate memory for data
    *data = malloc(data_size);
    if (!*data) {
        fclose(file);
        fprintf(stderr, "[ERROR] Memory allocation failed\n");
        return CRYPTO_ERROR_MEMORY;
    }
    
    // Read data
    size_t data_read = fread(*data, 1, data_size, file);
    fclose(file);
    
    if (data_read != data_size) {
        free(*data);
        fprintf(stderr, "[ERROR] Failed to read data from file %s\n", filename);
        return CRYPTO_ERROR_FILE_IO;
    }
    
    *data_len = data_size;
    return CRYPTO_SUCCESS;
}

crypto_error_t write_file_with_salt_iv(const char* filename, const uint8_t* salt, const uint8_t* iv, const uint8_t* data, size_t data_len) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "[ERROR] Cannot create file %s: %s\n", filename, strerror(errno));
        return CRYPTO_ERROR_FILE_IO;
    }
    
    // Write salt first
    size_t salt_written = fwrite(salt, 1, SALT_SIZE, file);
    if (salt_written != SALT_SIZE) {
        fclose(file);
        fprintf(stderr, "[ERROR] Failed to write salt to file %s\n", filename);
        return CRYPTO_ERROR_FILE_IO;
    }
    
    // Write IV
    size_t iv_written = fwrite(iv, 1, IV_SIZE, file);
    if (iv_written != IV_SIZE) {
        fclose(file);
        fprintf(stderr, "[ERROR] Failed to write IV to file %s\n", filename);
        return CRYPTO_ERROR_FILE_IO;
    }
    
    // Write data
    size_t data_written = fwrite(data, 1, data_len, file);
    fclose(file);
    
    if (data_written != data_len) {
        fprintf(stderr, "[ERROR] Failed to write data to file %s\n", filename);
        return CRYPTO_ERROR_FILE_IO;
    }
    
    return CRYPTO_SUCCESS;
}

crypto_error_t read_file_with_salt_iv(const char* filename, uint8_t* salt, uint8_t* iv, uint8_t** data, size_t* data_len) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "[ERROR] Cannot open file %s: %s\n", filename, strerror(errno));
        return CRYPTO_ERROR_FILE_IO;
    }
    
    // Read salt
    size_t salt_read = fread(salt, 1, SALT_SIZE, file);
    if (salt_read != SALT_SIZE) {
        fclose(file);
        fprintf(stderr, "[ERROR] File %s too short for salt (less than %d bytes)\n", filename, SALT_SIZE);
        return CRYPTO_ERROR_FILE_IO;
    }
    
    // Read IV
    size_t iv_read = fread(iv, 1, IV_SIZE, file);
    if (iv_read != IV_SIZE) {
        fclose(file);
        fprintf(stderr, "[ERROR] File %s too short for IV (less than %d bytes after salt)\n", filename, IV_SIZE);
        return CRYPTO_ERROR_FILE_IO;
    }
    
    // Get remaining file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, SALT_SIZE + IV_SIZE, SEEK_SET);
    
    size_t data_size = file_size - SALT_SIZE - IV_SIZE;
    
    // Allocate memory for data
    *data = malloc(data_size);
    if (!*data) {
        fclose(file);
        fprintf(stderr, "[ERROR] Memory allocation failed\n");
        return CRYPTO_ERROR_MEMORY;
    }
    
    // Read data
    size_t data_read = fread(*data, 1, data_size, file);
    fclose(file);
    
    if (data_read != data_size) {
        free(*data);
        fprintf(stderr, "[ERROR] Failed to read data from file %s\n", filename);
        return CRYPTO_ERROR_FILE_IO;
    }
    
    *data_len = data_size;
    return CRYPTO_SUCCESS;
}
