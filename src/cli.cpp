#include <iostream>
#include <complex>
#include <cstring>

#include "cli.h"
#include "getpasswd.h"
#include "consts.h"

void cli::help(){
    std::cout << "program [options] [arguments]\n";
    std::cout << "Options:\n";
    std::cout << "  -e, --encrypt          : encrypt the specified file/folder\n";
    std::cout << "  -d, --decrypt          : decrypt the specified file/folder\n";
    std::cout << "  -r, --random-filename  : generates random 24 character long filename for encryption\n";
    std::cout << "  -k, --keyfile          : using an existing keyfile\n";
    std::cout << "  -p, --password         : protect keyfile with password (min 8 character)\n";
    std::cout << "  -h, --help             : display help\n";
}

Args cli::get_args(int argc, char *argv[]){
    Args args{};

    if(argc < 2){
        std::cerr << "Required arguments are missing!\n";
        help();
        return args;
    }

    for(int i = 1; i < argc; ++i){
        const std::string_view arg = argv[i];

        if(arg == "-h"){
            help();
            return args;
        }
        if (arg == "-e" || arg == "--encrypt"){
            if(i+1 < argc){
                args.method = Args::Method::ENCRYPT;
                args.input_path = argv[i+1];
            }
            if(i+2 < argc){
                args.output_path = argv[i+2];
            }
        }
        if (arg == "-d" || arg == "--decrypt"){
            if(i+1 < argc){
                args.method = Args::Method::DECRYPT;
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
            args.kdf_password = getpasswd::getpasswd();

            int passlength = static_cast<int>(strlen(args.kdf_password));
            if(passlength < MIN_PASSWORD_LENGTH || passlength > MAX_PASSWORD_LENGTH){
                std::cerr << "Password must be at least 8 and maximum 56 characters long\n";
                return args;

            }
            std::cerr << "Password cannot be empty!\n";
            return args;
        }
    }
    return args;
}