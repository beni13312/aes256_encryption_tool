// encrypts the files and folders
// uses AES256 encryption with a randomly generated key
// 
#pragma once

#include <string>
#include <openssl/evp.h>
#include <memory>
#include "secure_heap.h"
using namespace secure_heap;

class encrypt{
public:
    encrypt(std::string   input_path, std::string   output_path,
    std::string   keyfile_path, bool rand_filename,
    unsigned char* password, size_t password_length);

    ~encrypt();

    void AES_encrypt();

private:
    // args
    std::string input_path_;
    std::string output_path_;
    std::string keyfile_path_;
    bool rand_filename_;
    unsigned char* password_ = nullptr;
    size_t password_length_ = 0;

    size_t total_key_size = 0;
    size_t total_enc_key_size = 0;
    unsigned char* key = nullptr;
    unsigned char* encrypted_key = nullptr;
    unsigned char* plain_keyfile = nullptr;
    unsigned char* encrypted_keyfile = nullptr;
    unsigned char* salt = nullptr;
    unsigned char* hashed_password = nullptr;
    unsigned char* iv = nullptr;
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
    std::string filename;

    void aes_keygen(const std::string& keyfile_path);
    static std::string gen_rand_filename();


};