@echo off
echo Building CryptoCore...

if not exist obj mkdir obj
if not exist obj\modes mkdir obj\modes

echo Compiling source files...
gcc -Wall -Wextra -std=c99 -O2 -Iinclude -c src/main.c -o obj/main.o
gcc -Wall -Wextra -std=c99 -O2 -Iinclude -c src/cli_parser.c -o obj/cli_parser.o
gcc -Wall -Wextra -std=c99 -O2 -Iinclude -c src/file_io.c -o obj/file_io.o
gcc -Wall -Wextra -std=c99 -O2 -Iinclude -c src/crypto_utils.c -o obj/crypto_utils.o
gcc -Wall -Wextra -std=c99 -O2 -Iinclude -c src/modes/ecb.c -o obj/modes/ecb.o
gcc -Wall -Wextra -std=c99 -O2 -Iinclude -c src/modes/cbc.c -o obj/modes/cbc.o
gcc -Wall -Wextra -std=c99 -O2 -Iinclude -c src/modes/cfb.c -o obj/modes/cfb.o
gcc -Wall -Wextra -std=c99 -O2 -Iinclude -c src/modes/ofb.c -o obj/modes/ofb.o
gcc -Wall -Wextra -std=c99 -O2 -Iinclude -c src/modes/ctr.c -o obj/modes/ctr.o

echo Linking...
gcc obj/main.o obj/cli_parser.o obj/file_io.o obj/crypto_utils.o obj/modes/ecb.o obj/modes/cbc.o obj/modes/cfb.o obj/modes/ofb.o obj/modes/ctr.o -o cryptocore -lcrypto

echo Build complete!
echo.
echo Usage examples:
echo   cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input test.txt --output test.enc
echo   cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input test.enc --output test.dec
