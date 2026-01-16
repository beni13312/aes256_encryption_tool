// fast file/folder encryption/decryption program uses AES256GCM with a randomly generated private key
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <sys/prctl.h>
#include "encrypt.h"
#include "decrypt.h"
#include "getpasswd.h"
#include "secure_heap.h"

constexpr int ENCRYPT = 1;
constexpr int DECRYPT = 2;
constexpr int  MIN_PASSWORD_LENGTH = 8; // character
constexpr int MAX_PASSWORD_LENGTH = 56; // character


void help(){
        std::cout << "... [encrypt/decrypt] [what to encrypt/decrypt: (file/folder) path] [destination: (file/folder) path] [options]\n";
        std::cout << "Options:\n";
        std::cout << "  -e, --encrypt          : encrypt the specified file/folder\n";
        std::cout << "  -d, --decrypt          : decrypt the specified file/folder\n";
        std::cout << "  -r, --random-filename  : generates random 24 character long filename for encryption\n";
        std::cout << "  -k, --keyfile          : using an existing keyfile\n";
        std::cout << "  -p, --password         : protect keyfile with password (min 8 character)\n";
        std::cout << "  -h, --help             : display this help message\n";
}

struct args{
    int method = 0;
    bool rand_filename = false;
    std::string keyfile_path;
    std::string input_path;
    std::string output_path;
    unsigned char* password = nullptr;
    size_t password_length = 0;
}args;

// frees allocated secure memory in main
void free_secure_memory(){
    if(args.password) secure_heap::secure_free(reinterpret_cast<void*&>(args.password),
    strlen(reinterpret_cast<char*>(args.password)) + 1);
}


int main(int argc, char* argv[]){
    // disable core dumps
    prctl(PR_SET_DUMPABLE, 0);

    if(argc < 2){
        std::cout << "Required arguments are missing!\n";
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

    for(int i = 0; i < argc; ++i){

        const std::string arg = argv[i];

        if(arg == "-h"){
            help();
            return 0;
        }
        if (arg == "-e" || arg == "--encrypt"){
            if(i+1 < argc){
                args.method = ENCRYPT;
                args.input_path = argv[i+1];
            }
            if(i+2 < argc){
                args.output_path = argv[i+2];
            }
        }
        if (arg == "-d" || arg == "--decrypt"){
            if(i+1 < argc){
                args.method = DECRYPT;
                args.input_path = argv[i+1];
            }
            if(i+2 < argc){
                args.output_path = argv[i+2];
            }
        }
        if (arg == "-r" || arg == "--random-filename"){
            args.rand_filename = true;
        }
        if (arg == "-k" || arg == "--keyfile"){
            if(i+1 < argc){
                args.keyfile_path = argv[i+1];
            }
        }
        if (arg == "-p" || arg == "--password"){
            std::cout << "Enter password to protect the keyfile: \n";
            std::string password_input;

            getpasswd::getpasswd(password_input);

            int passlength = static_cast<int>(password_input.size());
            if(passlength > 0){
                if(passlength < MIN_PASSWORD_LENGTH || passlength > MAX_PASSWORD_LENGTH){
                    std::cerr << "Password must be at least 8 and maximum 56 characters long\n";
                    return 1;
                }

                args.password_length = passlength + 1;
                args.password = secure_heap::secure_malloc<unsigned char>(args.password_length);
                if(!args.password){
                    std::cerr << "Failed to allocate memory for password!\n";
                    return 1;
                }
                memcpy(args.password, password_input.c_str(), passlength + 1);

            }else{
                std::cerr << "Password cannot be empty!\n";
                return 1;
            }
        }
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