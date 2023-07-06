#include <iostream>
#include <fstream>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <string>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>

#include "types.h"


#define MAX_KEY_SIZE    2048
#define MAX_MESSAGE     2048
#define MAX_PATH        4096
#define BLOCK_SIZE      8192


using namespace CryptoPP;
using namespace std;


static char key[MAX_KEY_SIZE];
static char msg[MAX_MESSAGE];
static char iv[MAX_KEY_SIZE];
static char input_filename[MAX_PATH];
static char output_filename[MAX_PATH];
static operation op = NONE;
static ciphermode cipher_mode = UNKNOWN;
static bool hex_input_flag = false;
static bool hex_output_flag = false;
static bool hex_key_flag = false;
static bool file_mode_flag = false;

static int parse_options(int argc, char** argv);
static void print_help(char* progname);
static void encrypt_aes_cbc(string key, string iv, string& src_msg, string& enc_msg);
static void decrypt_aes_cbc(string key, string iv, string& src_msg, string& dec_msg);
static void encrypt_aes_ctr(string key, string iv, string& src_msg, string& enc_msg);
static void decrypt_aes_ctr(string key, string iv, string& src_msg, string& dec_msg);

static void encrypt_file_aes_cbc(string key, string iv, string& src_file, string& enc_file);
static void decrypt_file_aes_cbc(string key, string iv, string& src_file, string& dec_file);
static void encrypt_file_aes_ctr(string key, string iv, string& src_file, string& enc_file);
static void decrypt_file_aes_ctr(string key, string iv, string& src_file, string& dec_file);

static std::string string_to_hex(const std::string& input);
static std::string hex_to_string(const std::string& input);

static ciphermode_table* search_cipher(ciphermode mode);

ciphermode_table c_table[] = {
    { CBC, encrypt_aes_cbc, decrypt_aes_cbc, encrypt_file_aes_cbc, decrypt_file_aes_cbc },
    { CTR, encrypt_aes_ctr, decrypt_aes_ctr, encrypt_file_aes_ctr, decrypt_file_aes_ctr },
    { UNKNOWN, NULL, NULL, NULL, NULL },
};


int main(int argc, char** argv) {
    if (argc == 1) {
        print_help(argv[0]);
        return 1;
    }

    if (parse_options(argc, argv) < 0) {
        print_help(argv[0]);
        return 2;
    }

    string src_msg(msg);
    string out_msg;
    string key_str(key);
    string iv_str(iv);
    ciphermode_table* c_mode = search_cipher(cipher_mode);

    if (!c_mode || c_mode->mode == UNKNOWN) {
        cout << "Bad cipher mode. See --help for details" << endl;
        return 3;
    }

    iv_str = hex_to_string(iv_str);

    if (hex_input_flag) {
        src_msg = hex_to_string(src_msg);
    }

    if (hex_key_flag) {
        key_str = hex_to_string(key_str);
    }

    if (strlen(input_filename) || strlen(output_filename)) {
        if (strlen(msg)) {
            cout << "In file mode message option is forbidden" << endl;
            return 4;
        }

        if (!strlen(input_filename)) {
            cout << "No input file" << endl;
            return 5;
        }

        if (!strlen(output_filename)) {
            cout << "No output file" << endl;
            return 6;
        }

        file_mode_flag = true;
    }

    if (!strlen(msg) && !file_mode_flag) {
        cout << "No message!" << endl;
        return 9;
    }

    switch (op) {
        case ENCRYPT:
            if (!file_mode_flag) {
                c_mode->encrypt_msg_func(key_str, iv_str, src_msg, out_msg);
                if (hex_output_flag) {
                    cout << string_to_hex(out_msg);
                    break;
                }

                cout << out_msg << endl;
            } else {
                string i_file(input_filename);
                string o_file(output_filename);

                c_mode->encrypt_file_func(key_str, iv_str, i_file, o_file);
            }

            break;
        case DECRYPT:
            if (!file_mode_flag) {
                c_mode->decrypt_msg_func(key_str, iv_str, src_msg, out_msg);
                if (hex_output_flag) {
                    cout << string_to_hex(out_msg);
                    break;
                }

                cout << out_msg << endl;
            } else {
                string i_file(input_filename);
                string o_file(output_filename);

                c_mode->decrypt_file_func(key_str, iv_str, i_file, o_file);
            }

            break;
        default:
            break;
    }

    return 0;
}

static int parse_options(int argc, char** argv) {
    int ret = -1;

    const char* short_options = "hk:m:edi:o:";

    const struct option long_options[] = {
        { "help", no_argument, NULL, 'h' },
        { "message", required_argument, NULL, 'm' },
        { "key", required_argument, NULL, 'k' },
        { "encrypt", no_argument, NULL, 'e' },
        { "decrypt", no_argument, NULL, 'd' },
        { "input-file", required_argument, NULL, 'i' },
        { "output-file", required_argument, NULL, 'o' },
        { "hex-input", no_argument, NULL, HEX_INPUT_OPTION },
        { "hex-output", no_argument, NULL, HEX_OUTPUT_OPTION },
        { "hex-key", no_argument, NULL, HEX_KEY_OPTION },
        { "init-vector", required_argument, NULL, INIT_VECTOR_OPTION },
        { "mode", required_argument, NULL, MODE_OPTION },
        { NULL, 0, NULL, 0 }
    };

    int res;
    int option_index;

    memset(msg, 0, MAX_MESSAGE);
    memset(key, 0, MAX_KEY_SIZE);
    memset(iv, 0, MAX_KEY_SIZE);
    memset(input_filename, 0, MAX_PATH);
    memset(output_filename, 0, MAX_PATH);

    cipher_mode = CBC;

    while ((res = getopt_long(argc, argv, short_options,
        long_options, &option_index)) != -1) {

        switch(res) {
            case 'h':
                print_help(argv[0]);
                ret = 1;
                break;
            case 'm':
                if (optarg) {
                    strncpy(msg, optarg, MAX_MESSAGE);
                }
                   
                break;
            case 'k':
                if (optarg) {
                    strncpy(key, optarg, MAX_KEY_SIZE);
                }

                break;
            case 'e':
                if (op == NONE) {
                    op = ENCRYPT;
                    ret = 0;
                }

                break;
            case 'd':
                if (op == NONE) {
                    op = DECRYPT;
                    ret = 0;
                }

                break;
            case 'i':
                if (optarg) {
                    strncpy(input_filename, optarg, MAX_PATH);
                }

                break;
            case 'o':
                if (optarg) {
                    strncpy(output_filename, optarg, MAX_PATH);
                }

                break;
            case HEX_INPUT_OPTION:
                hex_input_flag = true;
                break;
            case HEX_OUTPUT_OPTION:
                hex_output_flag = true;
                break;
            case HEX_KEY_OPTION:
                hex_key_flag = true;
                break;
            case INIT_VECTOR_OPTION:
                if (optarg) {
                    strncpy(iv, optarg, MAX_KEY_SIZE);
                }

                break;
            case MODE_OPTION:
                if (optarg) {
                    if (!strcmp(optarg, "CBC")) {
                        cipher_mode = CBC;
                    } else if (!strcmp(optarg, "CTR")) {
                        cipher_mode = CTR;
                    } else {
                        ret = -1;
                    }
                }

                break;
            default:
                printf("Unknown option\n");
                ret = -1;
                break;
        };
    };

    return ret;
}

static void print_help(char* progname) {
    cout << "Usage: " << std::string(progname) << " <options>" << endl;
    cout << "Options:" << endl;
    cout << "         " << "--key -k - set key for encryption/decryption" << endl;
    cout << "         " << "--message -m - set message for encryption/decryption" << endl;
    cout << "         " << "--encrypt -e - encrypt message" << endl;
    cout << "         " << "--decrypt -d - decrypt message" << endl;
    cout << "         " << "--input-file i - set to file mode and set input file" << endl;
    cout << "         " << "--output-file o - set to file mode and set output file" << endl;
    cout << endl;
    cout << "         " << "--hex-input - turn on hex mode for input message" << endl;
    cout << "         " << "--hex-output - turn on hex mode for output message" << endl;
    cout << "         " << "--hex-key - turn on hex mode for key" << endl;
    cout << "         " << "--init-vector - set up init vector (only in hex mode)" << endl;
    cout << "         " << "--mode - choose cipher mode. Supported: CBC (default), CTR" << endl;
}

static void encrypt_aes_cbc(string key, string iv, string& src_msg, string& enc_msg) {
    CryptoPP::byte crypto_key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte crypto_iv[CryptoPP::AES::BLOCKSIZE];

    memset(crypto_key, 0, CryptoPP::AES::DEFAULT_KEYLENGTH);
    memset(crypto_iv, 0, CryptoPP::AES::BLOCKSIZE);

    //fill key and iv
    memcpy(crypto_key, key.c_str(), key.length());
    memcpy(crypto_iv, iv.c_str(), iv.length());

    //encrypt
    CryptoPP::CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(crypto_key, sizeof(crypto_key), crypto_iv);

    CryptoPP::StringSource s(src_msg, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::StringSink(enc_msg)
            ) // StreamTransformationFilter
        ); // StringSource
}

static void decrypt_aes_cbc(string key, string iv, string& src_msg, string& dec_msg) {
    CryptoPP::byte crypto_key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte crypto_iv[CryptoPP::AES::BLOCKSIZE];

    memset(crypto_key, 0, CryptoPP::AES::DEFAULT_KEYLENGTH);
    memset(crypto_iv, 0, CryptoPP::AES::BLOCKSIZE);

    //fill key and iv
    memcpy(crypto_key, key.c_str(), key.length());
    memcpy(crypto_iv, iv.c_str(), iv.length());

    //decrypt
    CryptoPP::CBC_Mode<AES>::Decryption d;
    d.SetKeyWithIV(crypto_key, sizeof(crypto_key), crypto_iv);

    CryptoPP::StringSource s(src_msg, true,
            new CryptoPP::StreamTransformationFilter(d,
                new CryptoPP::StringSink(dec_msg)
            ) // StreamTransformationFilter
        ); // StringSource
}

static void encrypt_aes_ctr(string key, string iv, string& src_msg, string& enc_msg) {
    CryptoPP::byte crypto_key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte crypto_iv[CryptoPP::AES::BLOCKSIZE];

    memset(crypto_key, 0, CryptoPP::AES::DEFAULT_KEYLENGTH);
    memset(crypto_iv, 0, CryptoPP::AES::BLOCKSIZE);

    //fill key and iv
    memcpy(crypto_key, key.c_str(), key.length());
    memcpy(crypto_iv, iv.c_str(), iv.length());

    //encrypt
    CryptoPP::CTR_Mode<AES>::Encryption e;
    e.SetKeyWithIV(crypto_key, sizeof(crypto_key), crypto_iv);

    CryptoPP::StringSource s(src_msg, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::StringSink(enc_msg)
            ) // StreamTransformationFilter
        ); // StringSource
}

static void decrypt_aes_ctr(string key, string iv, string& src_msg, string& dec_msg) {
    CryptoPP::byte crypto_key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte crypto_iv[CryptoPP::AES::BLOCKSIZE];

    memset(crypto_key, 0, CryptoPP::AES::DEFAULT_KEYLENGTH);
    memset(crypto_iv, 0, CryptoPP::AES::BLOCKSIZE);

    //fill key and iv
    memcpy(crypto_key, key.c_str(), key.length());
    memcpy(crypto_iv, iv.c_str(), iv.length());

    //decrypt
    CryptoPP::CTR_Mode<AES>::Decryption d;
    d.SetKeyWithIV(crypto_key, sizeof(crypto_key), crypto_iv);

    CryptoPP::StringSource s(src_msg, true,
            new CryptoPP::StreamTransformationFilter(d,
                new CryptoPP::StringSink(dec_msg)
            ) // StreamTransformationFilter
        ); // StringSource
}

static void encrypt_file_aes_cbc(string key, string iv, string& src_file, string& enc_file) {
    ifstream ifile;
    ofstream ofile;

    ifile.open(src_file, ios_base::binary);

    if (!ifile.is_open()) {
        cout << "Can't open input file " << string(input_filename) << endl;
        return;
    }

    ofile.open(enc_file, ios_base::binary);

    if (!ofile.is_open()) {
        cout << "Can't write to " << string(output_filename) << endl;
        return;
    }

    CryptoPP::byte crypto_key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte crypto_iv[CryptoPP::AES::BLOCKSIZE];

    memset(crypto_key, 0, CryptoPP::AES::DEFAULT_KEYLENGTH);
    memset(crypto_iv, 0, CryptoPP::AES::BLOCKSIZE);

    //fill key and iv
    memcpy(crypto_key, key.c_str(), key.length());
    memcpy(crypto_iv, iv.c_str(), iv.length());

    //encrypt
    CryptoPP::CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(crypto_key, sizeof(crypto_key), crypto_iv);

    CryptoPP::FileSource s(ifile, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::FileSink(ofile)
            ) // StreamTransformationFilter
        ); // FileSource

    ifile.close();
    ofile.close();
}

static void decrypt_file_aes_cbc(string key, string iv, string& src_file, string& dec_file) {
    ifstream ifile;
    ofstream ofile;

    ifile.open(src_file, ios_base::binary);

    if (!ifile.is_open()) {
        cout << "Can't open input file " << string(input_filename) << endl;
        return;
    }

    ofile.open(dec_file, ios_base::binary);

    if (!ofile.is_open()) {
        cout << "Can't write to " << string(output_filename) << endl;
        return;
    }

    CryptoPP::byte crypto_key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte crypto_iv[CryptoPP::AES::BLOCKSIZE];

    memset(crypto_key, 0, CryptoPP::AES::DEFAULT_KEYLENGTH);
    memset(crypto_iv, 0, CryptoPP::AES::BLOCKSIZE);

    //fill key and iv
    memcpy(crypto_key, key.c_str(), key.length());
    memcpy(crypto_iv, iv.c_str(), iv.length());

    //encrypt
    CryptoPP::CBC_Mode<AES>::Decryption e;
    e.SetKeyWithIV(crypto_key, sizeof(crypto_key), crypto_iv);

    CryptoPP::FileSource s(ifile, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::FileSink(ofile)
            ) // StreamTransformationFilter
        ); // FileSource

    ifile.close();
    ofile.close();
}

static void encrypt_file_aes_ctr(string key, string iv, string& src_file, string& enc_file) {
    ifstream ifile;
    ofstream ofile;

    ifile.open(src_file, ios_base::binary);

    if (!ifile.is_open()) {
        cout << "Can't open input file " << string(input_filename) << endl;
        return;
    }

    ofile.open(enc_file, ios_base::binary);

    if (!ofile.is_open()) {
        cout << "Can't write to " << string(output_filename) << endl;
        return;
    }

    CryptoPP::byte crypto_key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte crypto_iv[CryptoPP::AES::BLOCKSIZE];

    memset(crypto_key, 0, CryptoPP::AES::DEFAULT_KEYLENGTH);
    memset(crypto_iv, 0, CryptoPP::AES::BLOCKSIZE);

    //fill key and iv
    memcpy(crypto_key, key.c_str(), key.length());
    memcpy(crypto_iv, iv.c_str(), iv.length());

    //encrypt
    CryptoPP::CTR_Mode<AES>::Encryption e;
    e.SetKeyWithIV(crypto_key, sizeof(crypto_key), crypto_iv);

    CryptoPP::FileSource s(ifile, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::FileSink(ofile)
            ) // StreamTransformationFilter
        ); // FileSource

    ifile.close();
    ofile.close();
}

static void decrypt_file_aes_ctr(string key, string iv, string& src_file, string& dec_file) {
    ifstream ifile;
    ofstream ofile;

    ifile.open(src_file, ios_base::binary);

    if (!ifile.is_open()) {
        cout << "Can't open input file " << string(input_filename) << endl;
        return;
    }

    ofile.open(dec_file, ios_base::binary);

    if (!ofile.is_open()) {
        cout << "Can't write to " << string(output_filename) << endl;
        return;
    }

    CryptoPP::byte crypto_key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte crypto_iv[CryptoPP::AES::BLOCKSIZE];

    memset(crypto_key, 0, CryptoPP::AES::DEFAULT_KEYLENGTH);
    memset(crypto_iv, 0, CryptoPP::AES::BLOCKSIZE);

    //fill key and iv
    memcpy(crypto_key, key.c_str(), key.length());
    memcpy(crypto_iv, iv.c_str(), iv.length());

    //encrypt
    CryptoPP::CTR_Mode<AES>::Decryption e;
    e.SetKeyWithIV(crypto_key, sizeof(crypto_key), crypto_iv);

    CryptoPP::FileSource s(ifile, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::FileSink(ofile)
            ) // StreamTransformationFilter
        ); // FileSource

    ifile.close();
    ofile.close();
}


static std::string string_to_hex(const std::string& input) {
    CryptoPP::byte in[input.length()];
    std::string encoded;

    memcpy(in, input.c_str(), sizeof(in));

    encoded.clear();
    StringSource(in, sizeof(in), true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource

    return encoded;
}

static std::string hex_to_string(const std::string& input) {
    std::string decoded;

    decoded.clear();
    StringSource ss(input, true,
        new HexDecoder(
            new StringSink(decoded)
        ) // HexDecoder
    ); // StringSource

    return decoded;
}

static ciphermode_table* search_cipher(ciphermode mode) {
    ciphermode_table* c = c_table;

    while (c->mode != UNKNOWN) {
        if (c->mode == mode) {
            break;
        }

        c++;
    }

    return c;
}
