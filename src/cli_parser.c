#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cli_parser.h"

static crypto_mode_t parse_mode(const char* mode_str) {
    if (strcmp(mode_str, "ecb") == 0) return MODE_ECB;
    if (strcmp(mode_str, "cbc") == 0) return MODE_CBC;
    if (strcmp(mode_str, "cfb") == 0) return MODE_CFB;
    if (strcmp(mode_str, "ofb") == 0) return MODE_OFB;
    if (strcmp(mode_str, "ctr") == 0) return MODE_CTR;
    return -1; // Invalid mode
}

static crypto_error_t validate_key(const char* key_hex) {
    if (strlen(key_hex) != 32) {
        return CRYPTO_ERROR_INVALID_KEY;
    }
    
    for (int i = 0; i < 32; i++) {
        char c = key_hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return CRYPTO_ERROR_INVALID_KEY;
        }
    }
    
    return CRYPTO_SUCCESS;
}

static crypto_error_t validate_iv(const char* iv_hex) {
    if (strlen(iv_hex) != 32) {
        return CRYPTO_ERROR_INVALID_IV;
    }
    
    for (int i = 0; i < 32; i++) {
        char c = iv_hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return CRYPTO_ERROR_INVALID_IV;
        }
    }
    
    return CRYPTO_SUCCESS;
}

static void generate_default_output_filename(const char* input_file, crypto_operation_t operation, char* output_file) {
    strncpy(output_file, input_file, MAX_FILENAME_LEN - 1);
    output_file[MAX_FILENAME_LEN - 1] = '\0';
    
    if (operation == OP_ENCRYPT) {
        strcat(output_file, ".enc");
    } else {
        strcat(output_file, ".dec");
    }
}

crypto_error_t parse_cli_args(int argc, char* argv[], cli_args_t* args) {
    // Initialize args
    memset(args, 0, sizeof(cli_args_t));
    args->mode = -1; // Invalid mode initially
    args->operation = -1; // Invalid operation initially
    
    bool encrypt_set = false;
    bool decrypt_set = false;
    bool key_set = false;
    bool password_set = false;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--algorithm") == 0) {
            if (i + 1 >= argc) {
                print_error("--algorithm requires a value");
                return CRYPTO_ERROR_INVALID_ALGORITHM;
            }
            strncpy(args->algorithm, argv[++i], sizeof(args->algorithm) - 1);
            args->algorithm[sizeof(args->algorithm) - 1] = '\0';
            
            if (strcmp(args->algorithm, "aes") != 0) {
                print_error("Only 'aes' algorithm is supported");
                return CRYPTO_ERROR_INVALID_ALGORITHM;
            }
        }
        else if (strcmp(argv[i], "--mode") == 0) {
            if (i + 1 >= argc) {
                print_error("--mode requires a value");
                return CRYPTO_ERROR_INVALID_MODE;
            }
            args->mode = parse_mode(argv[++i]);
            if (args->mode == -1) {
                print_error("Invalid mode. Supported modes: ecb, cbc, cfb, ofb, ctr");
                return CRYPTO_ERROR_INVALID_MODE;
            }
        }
        else if (strcmp(argv[i], "--encrypt") == 0) {
            if (decrypt_set) {
                print_error("Cannot specify both --encrypt and --decrypt");
                return CRYPTO_ERROR_INVALID_MODE;
            }
            args->operation = OP_ENCRYPT;
            encrypt_set = true;
        }
        else if (strcmp(argv[i], "--decrypt") == 0) {
            if (encrypt_set) {
                print_error("Cannot specify both --encrypt and --decrypt");
                return CRYPTO_ERROR_INVALID_MODE;
            }
            args->operation = OP_DECRYPT;
            decrypt_set = true;
        }
        else if (strcmp(argv[i], "--key") == 0) {
            if (password_set) {
                print_error("Cannot specify both --key and --password");
                return CRYPTO_ERROR_INVALID_KEY;
            }
            if (i + 1 >= argc) {
                print_error("--key requires a value");
                return CRYPTO_ERROR_INVALID_KEY;
            }
            strncpy(args->key_hex, argv[++i], sizeof(args->key_hex) - 1);
            args->key_hex[sizeof(args->key_hex) - 1] = '\0';
            
            crypto_error_t err = validate_key(args->key_hex);
            if (err != CRYPTO_SUCCESS) {
                print_error("Invalid key format. Key must be 32 hex characters");
                return err;
            }
            key_set = true;
        }
        else if (strcmp(argv[i], "--password") == 0) {
            if (key_set) {
                print_error("Cannot specify both --key and --password");
                return CRYPTO_ERROR_INVALID_KEY;
            }
            if (i + 1 >= argc) {
                print_error("--password requires a value");
                return CRYPTO_ERROR_INVALID_KEY;
            }
            strncpy(args->password, argv[++i], sizeof(args->password) - 1);
            args->password[sizeof(args->password) - 1] = '\0';
            args->use_password = true;
            password_set = true;
        }
        else if (strcmp(argv[i], "--input") == 0) {
            if (i + 1 >= argc) {
                print_error("--input requires a value");
                return CRYPTO_ERROR_FILE_IO;
            }
            strncpy(args->input_file, argv[++i], sizeof(args->input_file) - 1);
            args->input_file[sizeof(args->input_file) - 1] = '\0';
        }
        else if (strcmp(argv[i], "--output") == 0) {
            if (i + 1 >= argc) {
                print_error("--output requires a value");
                return CRYPTO_ERROR_FILE_IO;
            }
            strncpy(args->output_file, argv[++i], sizeof(args->output_file) - 1);
            args->output_file[sizeof(args->output_file) - 1] = '\0';
        }
        else if (strcmp(argv[i], "--iv") == 0) {
            if (i + 1 >= argc) {
                print_error("--iv requires a value");
                return CRYPTO_ERROR_INVALID_IV;
            }
            strncpy(args->iv_hex, argv[++i], sizeof(args->iv_hex) - 1);
            args->iv_hex[sizeof(args->iv_hex) - 1] = '\0';
            
            crypto_error_t err = validate_iv(args->iv_hex);
            if (err != CRYPTO_SUCCESS) {
                print_error("Invalid IV format. IV must be 32 hex characters");
                return err;
            }
            args->iv_provided = true;
        }
        else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return CRYPTO_ERROR_INVALID_MODE;
        }
    }
    
    // Validate required arguments
    if (strlen(args->algorithm) == 0) {
        print_error("--algorithm is required");
        return CRYPTO_ERROR_INVALID_ALGORITHM;
    }
    
    if (args->mode == -1) {
        print_error("--mode is required");
        return CRYPTO_ERROR_INVALID_MODE;
    }
    
    if (args->operation == -1) {
        print_error("Either --encrypt or --decrypt is required");
        return CRYPTO_ERROR_INVALID_MODE;
    }
    
    if (!key_set && !password_set) {
        print_error("Either --key or --password is required");
        return CRYPTO_ERROR_INVALID_KEY;
    }
    
    if (strlen(args->input_file) == 0) {
        print_error("--input is required");
        return CRYPTO_ERROR_FILE_IO;
    }
    
    // Generate default output filename if not provided
    if (strlen(args->output_file) == 0) {
        generate_default_output_filename(args->input_file, args->operation, args->output_file);
    }
    
    // Validate IV requirements
    if (args->operation == OP_ENCRYPT && args->iv_provided) {
        print_error("IV should not be provided during encryption (it will be generated automatically)");
        return CRYPTO_ERROR_INVALID_IV;
    }
    
    return CRYPTO_SUCCESS;
}

void print_usage(const char* program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\n");
    printf("Required arguments:\n");
    printf("  --algorithm ALGORITHM    Cipher algorithm (only 'aes' supported)\n");
    printf("  --mode MODE              Mode of operation (ecb, cbc, cfb, ofb, ctr)\n");
    printf("  --encrypt|--decrypt      Operation to perform (exactly one required)\n");
    printf("  --key KEY|--password PWD Key as hex string or password for PBKDF2\n");
    printf("  --input INPUT_FILE       Input file path\n");
    printf("\n");
    printf("Optional arguments:\n");
    printf("  --output OUTPUT_FILE     Output file path (default: input.enc/.dec)\n");
    printf("  --iv IV                  IV as hex string (only for decryption)\n");
    printf("\n");
    printf("Examples:\n");
    printf("  # Encryption with key\n");
    printf("  %s --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plain.txt --output cipher.bin\n", program_name);
    printf("\n");
    printf("  # Decryption with key\n");
    printf("  %s --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cipher.bin --output decrypted.txt\n", program_name);
    printf("\n");
    printf("  # Encryption with password\n");
    printf("  %s --algorithm aes --mode cbc --encrypt --password mypassword --input plain.txt --output cipher.bin\n", program_name);
}

void print_error(const char* message) {
    fprintf(stderr, "[ERROR] %s\n", message);
}
