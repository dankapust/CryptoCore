#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/pbkdf2.h>
#include "crypto.h"
#include "cli_parser.h"
#include "file_io.h"
#include "modes/ecb.h"
#include "modes/cbc.h"
#include "modes/cfb.h"
#include "modes/ofb.h"
#include "modes/ctr.h"

#define PBKDF2_ITERATIONS 100000

static crypto_error_t derive_key_from_password(const char* password, const uint8_t* salt, uint8_t* key) {
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, 
                         PBKDF2_ITERATIONS, EVP_sha256(), KEY_SIZE, key) != 1) {
        return CRYPTO_ERROR_INVALID_KEY;
    }
    return CRYPTO_SUCCESS;
}

static crypto_error_t process_encryption(const cli_args_t* args) {
    uint8_t* input_data = NULL;
    size_t input_len = 0;
    uint8_t* output_data = NULL;
    size_t output_len = 0;
    uint8_t key[KEY_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t salt[SALT_SIZE];
    crypto_error_t err = CRYPTO_SUCCESS;
    
    // Read input file
    err = read_file(args->input_file, &input_data, &input_len);
    if (err != CRYPTO_SUCCESS) {
        return err;
    }
    
    // Prepare key
    if (args->use_password) {
        generate_random_bytes(salt, SALT_SIZE);
        err = derive_key_from_password(args->password, salt, key);
        if (err != CRYPTO_SUCCESS) {
            free(input_data);
            return err;
        }
    } else {
        err = hex_to_bytes(args->key_hex, key, KEY_SIZE);
        if (err != CRYPTO_SUCCESS) {
            free(input_data);
            return err;
        }
    }
    
    // Generate IV for modes that need it
    bool needs_iv = (args->mode != MODE_ECB);
    if (needs_iv) {
        generate_random_bytes(iv, IV_SIZE);
    }
    
    // Encrypt based on mode
    switch (args->mode) {
        case MODE_ECB:
            err = aes_ecb_encrypt(key, input_data, input_len, &output_data, &output_len);
            break;
        case MODE_CBC:
            err = aes_cbc_encrypt(key, iv, input_data, input_len, &output_data, &output_len);
            break;
        case MODE_CFB:
            err = aes_cfb_encrypt(key, iv, input_data, input_len, &output_data, &output_len);
            break;
        case MODE_OFB:
            err = aes_ofb_encrypt(key, iv, input_data, input_len, &output_data, &output_len);
            break;
        case MODE_CTR:
            err = aes_ctr_encrypt(key, iv, input_data, input_len, &output_data, &output_len);
            break;
        default:
            err = CRYPTO_ERROR_INVALID_MODE;
            break;
    }
    
    if (err != CRYPTO_SUCCESS) {
        free(input_data);
        return err;
    }
    
    // Write output file
    if (args->use_password && needs_iv) {
        err = write_file_with_salt_iv(args->output_file, salt, iv, output_data, output_len);
    } else if (needs_iv) {
        err = write_file_with_iv(args->output_file, iv, output_data, output_len);
    } else {
        err = write_file(args->output_file, output_data, output_len);
    }
    
    free(input_data);
    free(output_data);
    
    return err;
}

static crypto_error_t process_decryption(const cli_args_t* args) {
    uint8_t* input_data = NULL;
    size_t input_len = 0;
    uint8_t* output_data = NULL;
    size_t output_len = 0;
    uint8_t key[KEY_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t salt[SALT_SIZE];
    crypto_error_t err = CRYPTO_SUCCESS;
    
    // Prepare key
    if (args->use_password) {
        bool needs_iv = (args->mode != MODE_ECB);
        if (needs_iv) {
            err = read_file_with_salt_iv(args->input_file, salt, iv, &input_data, &input_len);
        } else {
            err = read_file_with_salt_iv(args->input_file, salt, iv, &input_data, &input_len);
            // For ECB with password, we only need salt
            input_len += IV_SIZE; // Adjust for the fact that we read IV_SIZE extra bytes
        }
        
        if (err != CRYPTO_SUCCESS) {
            return err;
        }
        
        err = derive_key_from_password(args->password, salt, key);
        if (err != CRYPTO_SUCCESS) {
            free(input_data);
            return err;
        }
    } else {
        err = hex_to_bytes(args->key_hex, key, KEY_SIZE);
        if (err != CRYPTO_SUCCESS) {
            return err;
        }
        
        bool needs_iv = (args->mode != MODE_ECB);
        if (needs_iv) {
            if (args->iv_provided) {
                err = hex_to_bytes(args->iv_hex, iv, IV_SIZE);
                if (err != CRYPTO_SUCCESS) {
                    return err;
                }
                err = read_file(args->input_file, &input_data, &input_len);
            } else {
                err = read_file_with_iv(args->input_file, iv, &input_data, &input_len);
            }
        } else {
            err = read_file(args->input_file, &input_data, &input_len);
        }
        
        if (err != CRYPTO_SUCCESS) {
            return err;
        }
    }
    
    // Decrypt based on mode
    switch (args->mode) {
        case MODE_ECB:
            err = aes_ecb_decrypt(key, input_data, input_len, &output_data, &output_len);
            break;
        case MODE_CBC:
            err = aes_cbc_decrypt(key, iv, input_data, input_len, &output_data, &output_len);
            break;
        case MODE_CFB:
            err = aes_cfb_decrypt(key, iv, input_data, input_len, &output_data, &output_len);
            break;
        case MODE_OFB:
            err = aes_ofb_decrypt(key, iv, input_data, input_len, &output_data, &output_len);
            break;
        case MODE_CTR:
            err = aes_ctr_decrypt(key, iv, input_data, input_len, &output_data, &output_len);
            break;
        default:
            err = CRYPTO_ERROR_INVALID_MODE;
            break;
    }
    
    if (err != CRYPTO_SUCCESS) {
        free(input_data);
        return err;
    }
    
    // Write output file
    err = write_file(args->output_file, output_data, output_len);
    
    free(input_data);
    free(output_data);
    
    return err;
}

int main(int argc, char* argv[]) {
    cli_args_t args;
    crypto_error_t err = parse_cli_args(argc, argv, &args);
    
    if (err != CRYPTO_SUCCESS) {
        if (err == CRYPTO_ERROR_INVALID_MODE) {
            print_usage(argv[0]);
        }
        return 1;
    }
    
    if (args.operation == OP_ENCRYPT) {
        err = process_encryption(&args);
    } else {
        err = process_decryption(&args);
    }
    
    if (err != CRYPTO_SUCCESS) {
        switch (err) {
            case CRYPTO_ERROR_INVALID_KEY:
                print_error("Invalid key");
                break;
            case CRYPTO_ERROR_INVALID_IV:
                print_error("Invalid IV");
                break;
            case CRYPTO_ERROR_INVALID_PADDING:
                print_error("Invalid padding");
                break;
            case CRYPTO_ERROR_FILE_IO:
                print_error("File I/O error");
                break;
            case CRYPTO_ERROR_MEMORY:
                print_error("Memory allocation error");
                break;
            case CRYPTO_ERROR_INVALID_MODE:
                print_error("Invalid mode");
                break;
            case CRYPTO_ERROR_INVALID_ALGORITHM:
                print_error("Invalid algorithm");
                break;
            default:
                print_error("Unknown error");
                break;
        }
        return 1;
    }
    
    printf("[OK] Done. Output file: %s\n", args.output_file);
    return 0;
}
