#ifndef TYPES_H
#define TYPES_H

#include <string>


#define HEX_INPUT_OPTION     1
#define HEX_OUTPUT_OPTION    2
#define HEX_KEY_OPTION       3
#define INIT_VECTOR_OPTION   4
#define MODE_OPTION          5


typedef enum {
	NONE = 0,
	ENCRYPT,
	DECRYPT,
} operation;

typedef enum {
	UNKNOWN = 0,
	CBC,
	CTR
} ciphermode;

typedef struct ciphermode_table_s {
	ciphermode mode;
	void (*encrypt_msg_func)(std::string key, std::string iv, std::string& src_msg, std::string& enc_msg);
	void (*decrypt_msg_func)(std::string key, std::string iv, std::string& src_msg, std::string& dec_msg);
	void (*encrypt_file_func)(std::string key, std::string iv, std::string& src_file, std::string& enc_file);
	void (*decrypt_file_func)(std::string key, std::string iv, std::string& src_file, std::string& dec_file);
} ciphermode_table;


#endif
