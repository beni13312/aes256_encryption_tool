#include <sys/prctl.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <iostream>
#include <utility>
#include "app.h"
#include "secure_memory.h"
#include "encrypt.h"

App::App(Args args) : args_(std::move(args)) {
    // disable core dumps
    prctl(PR_SET_DUMPABLE, 0);

    // initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // initialize secure heap
    if(secure_memory::secure_memory_init() != 0){
        std::cerr << "Failed to initialize secure memory!\n";
        throw std::runtime_error("Failed to initialize secure memory!");

    }
}

App::~App(){
    if(args_.password) secure_memory::secure_free<char>(args_.password, strlen(args_.password));
    CRYPTO_secure_malloc_done();
}

int App::run(){
    if (args_.method == Args::Method::ENCRYPT){

        std::cout << "Encrypting files\n";
        auto e = encrypt(args_);
        e.run();
    } else if (args_.method == Args::Method::DECRYPT){
        // decrypt
    }
    return 0;
}
