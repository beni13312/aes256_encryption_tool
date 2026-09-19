// retrieves the AES256 key from the keyfile
// reads the private key from the keyfile
// decrypts the data and saves it to the chosen output path
 
#pragma once

#include <string>
#include "consts.h"
#include "cli.h"

class decrypt{
public:
    explicit decrypt(const Args &args);
    ~decrypt();

    void run();

private:
    const Args &args_;

    void load_keyfile(); // loads the key from the keyfile
    void derive_key(); // derive key from user's password
    void derive_iv(); // derive the IV back for each cycle

    unsigned char* key = nullptr;
    unsigned char salt[SALT_SIZE];
    unsigned char base_iv[AES_IV_SIZE];
    unsigned char iv[AES_IV_SIZE];
    uint64_t n_iv = 0;
    std::string filename;



};
