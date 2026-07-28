// retrieves the AES256 key from the keyfile
// reads the private key from the keyfile
// decrypts the data and saves it to the chosen output path
 
#pragma once

#include <string>
#include <memory>
#include <openssl/evp.h>
#include "secure_memory.h"
#include "consts.h"

using namespace secure_heap;

class decrypt{
public:
    decrypt(std::string  keyfile_path, std::string  input_path, std::string  output_path);
    ~decrypt();

    void AES_decrypt();

private:
    std::string keyfile_path_;
    std::string input_path_;
    std::string output_path_;

    std::string password;
    unsigned char* enc_key = nullptr;
    unsigned char* enc_iv = nullptr;
    unsigned char* hash = nullptr;
    unsigned char* iv = nullptr;
    unsigned char* key = nullptr;
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};

    void get_aes_key(const std::string &keyfile_path);
    unsigned char* get_enc_key(const unsigned char* salt);


};
