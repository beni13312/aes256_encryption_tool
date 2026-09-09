#include <iostream>
#include <complex>
#include <cstring>

#include "cli.h"

#include <filesystem>

#include "getpasswd.h"
#include "secure_memory.h"
#include "consts.h"

void cli::help(){
    std::cout << "program [OPTION] [ARGUMENT]\n";
    std::cout << "Options:\n";
    std::cout << "  -e, --encrypt          : Encryption\n";
    std::cout << "  -d, --decrypt          : Decryption\n";
    std::cout << "  -i, --input            : Input file/folder\n";
    std::cout << "  -o, --output           : Output file/folder\n";
    std::cout << "  -r, --random-filename  : Generates random 24 character filename\n";
    std::cout << "  -k, --keyfile          : Creating or using keyfile\n";
    std::cout << "  -h, --help             : Display help\n";
}

Args cli::get_args(int argc, char *argv[]){
    Args args{};

    if(argc < 2){
        std::cerr << "Required arguments are missing!\n";
        help();
        exit(1);
    }

    for(int i = 1; i < argc; ++i){
        const std::string_view arg = argv[i];

        if(arg == "-h"){
            help();
            exit(0);
        }
        if (arg == "-e" || arg == "--encrypt"){
            args.method = Args::Method::ENCRYPT;
        }
        if (arg == "-d" || arg == "--decrypt"){
            args.method = Args::Method::DECRYPT;
        }
        if (arg == "-i" || arg == "--input"){
            if(i+1 < argc){
                args.input_path = argv[i+1];
            }else{
                std::cerr << "File must be provided!\n";
                exit(1);
            }
        }
        if (arg == "-o" || arg == "--output"){
            if(i+1 < argc){
                args.output_path = argv[i+1];
            }else{
                std::cerr << "File must be provided!\n";
                exit(1);
            }
        }
        if (arg == "-r" || arg == "--random-filename"){
            args.rand_filename = true;
        }
        if (arg == "-k" || arg == "--keyfile"){
            if (i+1 < argc){
                args.keyfile_path = argv[i+1];
            }else{
                std::cerr << "File must be provided!\n";
                exit(1);
            }
        }
    }

    if (args.method == Args::Method::ENCRYPT){
        // random filename
        if (args.output_path.empty() && !args.rand_filename){
            std::cerr << "Output file must be provided unless you use random filename!\n";
            exit(1);
        }

        // when keyfile option used
        if (!args.keyfile_path.empty() && !std::filesystem::exists(args.keyfile_path)){
            std::cout << "Keyfile does not exists, creating new...\n\n";
        }

        // when keyfile option not used
        if (args.keyfile_path.empty()){
            std::cout << "Enter a password: ";
            args.password = getpasswd::getpasswd();

            std::cout << "Confirm password: ";
            char* confirm_password = getpasswd::getpasswd();

            if (strcmp(args.password, confirm_password) != 0){
                std::cerr << "Password mismatch!\n";
                secure_memory::secure_free<char>(confirm_password, PASSWORD_BUF_SIZE);
                exit(1);
            }

            const int passlength = static_cast<int>(strlen(args.password));
            if(passlength < MIN_PASSWORD_LENGTH || passlength > MAX_PASSWORD_LENGTH){
                std::cerr << "Password must be at least 8 and maximum 56 characters long\n";
                secure_memory::secure_free<char>(args.password, passlength);
                exit(1);
            }
        }
    }else{ // decrypt
        if(args.keyfile_path.empty()){
            std::cout << "Enter password: ";
            args.password = getpasswd::getpasswd();
        }
    }

    return args;
}