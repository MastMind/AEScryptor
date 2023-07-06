# AEScryptor
A linux command line utility for encrypting/decrypting messages and files with AES algorithm.

## Requirements:

libcrypto++ developer packet

        sudo apt-get install libcrypto++-dev

## Build:

Run make in directory

## Install:

        sudo make install

## Examples:

For encrypting a file (some_message.txt in that case) you have to use the next command (encrypted file has name some_message.txt.crypted):

        crypt -e -k SecretKey1 -i some_message.txt -o some_message.txt.crypted

For decrypting a crypted file you have to use the next command:

        crypt -d -k SecretKey1 -i some_message.txt.crypted -o some_message.txt

Also you can use the utility for encrypting a raw string (result will be in stdout):

        crypt -e -k SecretKey1 -m "Very secret message" --hex-output

For decrypting a raw string you have to use the next command:

        crypt -d -k SecretKey1 --hex-input -m 4DC0CAFB7220D7C8F7612C52978DB07D6FEDFD61FDEC19F40750606215463E12

Also you can use keys in hex form:

        crypt -e --hex-key -k 0B055000 -m "Very secret message" --hex-output

        crypt -d --hex-key -k 0B055000 --hex-input -m 0368D7A4FB000A94132792909AD5992FAD3055CD99BB2AD837A411B413A6CFFF

The options --hex-input and --hex-output can be used only for string ciphering. The option --hex-key can be used in any case:

        crypt -e --hex-key -k 0B055000 -i some_message.txt -o some_message.txt.crypted

        crypt -d --hex-key -k 0B055000 -i some_message.txt.crypted -o some_message.txt

For more information about options:

        crypt --help
