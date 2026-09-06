// encrypts the files and folders
// uses AES256 encryption with a randomly generated key
// 
#pragma once

#include <string>
#include <openssl/evp.h>
#include <memory>

#include "args.h"
#include "consts.h"
#include "secure_memory.h"

class encrypt{
public:
    explicit encrypt(const Args &args);

    ~encrypt();
    void run();

private:
    const Args &args_;

    void load_key(); // loads the key from keyfile
    void generate_key(); // generates key for encryption
    std::array<unsigned char, AES_IV_SIZE> generate_unique_iv(uint64_t n); // generates IV for each cycle
    void generate_kdf(); // generates KDF from the key
    void create_keyfile(); // creates the keyfile
    static std::string gen_rand_filename(); // generates a random filename for encrypted file

    size_t total_key_size = 0;
    size_t total_enc_key_size = 0;

    unsigned char* key = nullptr;
    unsigned char* encrypted_key = nullptr;
    unsigned char salt[SALT_SIZE];
    unsigned char base_iv[AES_IV_SIZE];
    std::string filename;



};