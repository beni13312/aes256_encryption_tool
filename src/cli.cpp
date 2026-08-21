#include <iostream>
#include <complex>
#include <cstring>

#include "cli.h"

#include <filesystem>

#include "getpasswd.h"
#include "consts.h"

void cli::help(){
    std::cout << "program [OPTION] [ARGUMENT]\n";
    std::cout << "Options:\n";
    std::cout << "  -e, --encrypt          : Encrypt the specified file/folder\n";
    std::cout << "  -d, --decrypt          : Decrypt the specified file/folder\n";
    std::cout << "  -r, --random-filename  : Generates random 24 character filename\n";
    std::cout << "  -k, --keyfile          : Creating or using keyfile\n";
    std::cout << "  -h, --help             : Display help\n";
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
            if (i+1 < argc && std::filesystem::exists(argv[i+1])){
                args.keyfile_path = argv[i+1];
            }else{
                std::cout << "Enter a password to protect the keyfile (press Enter for none): \n";
                args.password = getpasswd::getpasswd();
                args.keyfile_path = argv[i+1];

                // std::cout << "Confirm password to protect the keyfile (press Enter for none): \n";


                int passlength = static_cast<int>(strlen(args.password));
                if((passlength > 0 && passlength < MIN_PASSWORD_LENGTH) || passlength > MAX_PASSWORD_LENGTH){
                    std::cerr << "Password must be at least 8 and maximum 56 characters long\n";
                    secure_memory::secure_free<char>(args.password, passlength);
                    exit(1);

                }
            }
        }
    }

    // when keyfile option not used
    if (args.keyfile_path.empty())
    {
        std::cout << "Enter a password: \n";
        args.password = getpasswd::getpasswd();

        // std::cout << "Confirm password: \n";

        int passlength = static_cast<int>(strlen(args.password));
        if(passlength < MIN_PASSWORD_LENGTH || passlength > MAX_PASSWORD_LENGTH){
            std::cerr << "Password must be at least 8 and maximum 56 characters long\n";
            secure_memory::secure_free<char>(args.password, passlength);
            exit(1);
        }
    }

    return args;
}