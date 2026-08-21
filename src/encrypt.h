// encrypts the files and folders
// uses AES256 encryption with a randomly generated key
// 
#pragma once

#include <string>
#include <openssl/evp.h>
#include <memory>

#include "args.h"
#include "secure_memory.h"

class encrypt{
public:
    explicit encrypt(const Args &args);

    ~encrypt();

    void run();

private:
    const Args &args_;

    void load_key();
    void create_key();
    void keygen();
    static std::string gen_rand_filename();

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



};