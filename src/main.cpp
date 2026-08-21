// fast file/folder encryption/decryption program uses AES256GCM with a randomly generated private key

#include "app.h"
#include "cli.h"

int main(int argc, char* argv[]){
    App app(cli::get_args(argc, argv));
    return 0;
}