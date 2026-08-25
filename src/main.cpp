// fast file/folder encryption/decryption program uses AES256GCM with a randomly generated private key

#include <iostream>
#include <ostream>

#include "app.h"
#include "cli.h"

int main(int argc, char* argv[]){
    try{
        App app(cli::get_args(argc, argv));
        app.run();
    }catch(std::exception& e){
        std::cerr << e.what() << '\n';
    }
    return 0;
}