#ifndef CLI_PARSER_H
#define CLI_PARSER_H

#include "crypto.h"

// Command line arguments structure
typedef struct {
    char algorithm[16];
    crypto_mode_t mode;
    crypto_operation_t operation;
    char key_hex[33];  // 32 hex chars + null terminator
    char password[MAX_PASSWORD_LEN];
    char input_file[MAX_FILENAME_LEN];
    char output_file[MAX_FILENAME_LEN];
    char iv_hex[33];   // 32 hex chars + null terminator
    bool use_password;
    bool iv_provided;
} cli_args_t;

// Function prototypes
crypto_error_t parse_cli_args(int argc, char* argv[], cli_args_t* args);
void print_usage(const char* program_name);
void print_error(const char* message);

#endif // CLI_PARSER_H
