// fast file/folder encryption/decryption program uses AES256GCM with a randomly generated private key
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <sys/prctl.h>
#include "encrypt.h"
#include "decrypt.h"
#include "secure_memory.h"


// frees allocated secure memory in main
void free_secure_memory(){
    if(args.password) secure_heap::secure_free(reinterpret_cast<void*&>(args.password),
    strlen(reinterpret_cast<char*>(args.password)) + 1);
}


int main(int argc, char* argv[]){
    // todo: clean up main()
    // disable core dumps
    prctl(PR_SET_DUMPABLE, 0);

    if(argc < 2){
        std::cerr << "Required arguments are missing!\n";
        help();
        return 1;
    }

    // initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // initialize secure heap
    if(secure_heap::secure_heap_init() != 0){
        std::cerr << "Failed to initialize secure heap!\n";
        return 1;

    }






    // encryption
    if(args.method == ENCRYPT){
        if(args.input_path.empty() || args.output_path.empty()){
            std::cerr << "One or more required arguments are missing!\n";
            free_secure_memory();
            return 1;
        }
        if(args.keyfile_path.empty()){
            std::cerr << "Keyfile path is required! Use '-k' option to specify it\n";
            free_secure_memory();
            return 1;
        }
        
        std::cout << "Encrypting " << args.input_path << " to " << args.output_path << "\n";

        // must free memory in case of exception
        try{

            encrypt e(args.input_path, args.output_path, args.keyfile_path, args.rand_filename,
                args.password, args.password_length);
            e.AES_encrypt();
        }catch (std::runtime_error& e){
            std::cerr << e.what() << "\n";
            free_secure_memory();
            return 1;
        }
    }
    // decryption
    else if(args.method == DECRYPT){
        if(args.input_path.empty() || args.output_path.empty()){
            std::cerr << "One or more required arguments are missing!\n";
            free_secure_memory();
            return 1;
        }
        if(args.keyfile_path.empty()){
            std::cerr << "Keyfile path is required! Use '-k' option to specify it\n";
            free_secure_memory();
            return 1;

        }
        if(args.rand_filename || args.password){
            std::cerr << "Invalid option! Use '-h' option for help\n";
            free_secure_memory();
            return 1;
        }

        std::cout << "Decrypting " << args.input_path << " to " << args.output_path << "\n";

        // must free memory in case of exception
        try{
            decrypt d(args.keyfile_path, args.input_path, args.output_path);
            d.AES_decrypt();
        }catch (std::runtime_error& e){
            std::cerr << e.what() << "\n";
            free_secure_memory();
            return 1;
        }

    }else{
        std::cerr << "Invalid or missing arguments!\n";
        help();
        free_secure_memory();
        return 1;
    }
    free_secure_memory();
    CRYPTO_secure_malloc_done();
    return 0;
}