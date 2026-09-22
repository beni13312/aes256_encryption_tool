#include "decrypt.h"
#include <filesystem>
#include <openssl/evp.h>
#include <sodium.h>
#include <fstream>
#include <fcntl.h>
#include <cstring>
#include <stdexcept>
#include <utility>
#include <vector>
#include <iostream>
#include <arpa/inet.h>
#include "getpasswd.h"

decrypt::decrypt(const Args &args): args_(args){}

decrypt::~decrypt(){
    if (key) secure_memory::secure_free<unsigned char>(key, AES_KEY_SIZE);
}

void decrypt::run(){
    const std::filesystem::path input_path = args_.input_path;

    if(!std::filesystem::exists(input_path)){
        throw std::runtime_error("Input path does not exist!\n");
    }


    // decrypt

    std::ifstream infile(input_path, std::ios::binary);
    if(!infile.is_open()){
        throw std::runtime_error("Failed to open file for decryption!\n");
    }

    const std::filesystem::path output_path = args_.output_path;

    std::ofstream outfile;


    // read iv from infile
    infile.read(reinterpret_cast<char*>(iv), AES_IV_SIZE);


    // read salt from input file
    infile.read(reinterpret_cast<char*>(salt), SALT_SIZE);

    if (!args_.keyfile_path.empty()){
        // retrieve the AES key
        load_keyfile();
    }else{
        derive_key();
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};

    if (!ctx) {
        infile.close();
        throw std::runtime_error("Failed to create EVP context");
    }

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1){
        infile.close();
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr) != 1){
        infile.close();
        throw std::runtime_error("Failed to set IV length");
    }

    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key, iv) != 1){
        infile.close();
        throw std::runtime_error("Failed to set key and IV");
    }

    // read filename size
    u_int32_t filename_size = 0;

    infile.read(reinterpret_cast<char*>(ntohl(filename_size)), FILENAME_SIZE_INT);
    std::streamsize filename_size_bytes_read = infile.gcount();

    if(filename_size_bytes_read != static_cast<std::streamsize>(FILENAME_SIZE_INT)){
        infile.close();
        throw std::runtime_error("Failed to get filename size!");

    }


    // read filename
    std::vector<unsigned char> filename_readbuf(FILENAME_MAX_LENGTH);
    std::vector<unsigned char> filename_writebuf(FILENAME_MAX_LENGTH);
    int filename_write_buffer_size = 0;

    infile.read(reinterpret_cast<char*>(filename_readbuf.data()), filename_size);
    std::streamsize filename_bytes_read = infile.gcount();

    if(filename_bytes_read == 0 || filename_bytes_read > static_cast<std::streamsize>(FILENAME_MAX_LENGTH)){
        infile.close();
        throw std::runtime_error("Failed to read filename!");

    }

    derive_iv();
    if (1 != EVP_DecryptUpdate(ctx.get(), filename_writebuf.data(), &filename_write_buffer_size, filename_readbuf.data(), static_cast<int>(filename_bytes_read))){
        infile.close();
        throw std::runtime_error("Failed to decrypt buffer");
    }

    filename.assign(reinterpret_cast<char*>(filename_writebuf.data()), filename_write_buffer_size);
    std::cout << "Decrypted filename: " << filename << "\n";

    const std::filesystem::path file_full = output_path / filename; // user input + filename

    // open the file after the filename is known
    outfile.open(file_full, std::ios::binary);
    if (!outfile.is_open()) {
        infile.close();
        throw std::runtime_error("Failed to open file for writing decrypted data!\n");
    }

    // read encrypted data size
    size_t encrypted_data_size = 0;

    infile.read(reinterpret_cast<char*>(ntohl(encrypted_data_size)), sizeof(uint32_t));


    // decrypt data
    std::vector<unsigned char> readbuf(BUFFER_SIZE);
    std::vector<unsigned char> writebuf(BUFFER_SIZE);

    std::streamsize bytes_read;
    int write_buffer_size = 0;

    while(true){
        size_t to_read = std::min(encrypted_data_size, BUFFER_SIZE);
        infile.read(reinterpret_cast<char*>(readbuf.data()), static_cast<std::streamsize>(to_read));
        bytes_read = infile.gcount();
        if(bytes_read <= 0){
            break;
        }
        derive_iv();
        if (1 != EVP_DecryptUpdate(ctx.get(), writebuf.data(), &write_buffer_size, readbuf.data(), static_cast<int>(bytes_read))){
            infile.close();
            outfile.close();
            throw std::runtime_error("Failed to decrypt buffer");
        }

        outfile.write(reinterpret_cast<const char*>(writebuf.data()), write_buffer_size);
        encrypted_data_size -= bytes_read;
    }
    // set GCM tag (16 bytes typical)
    unsigned char tag[AES_TAG_SIZE];
    infile.read(reinterpret_cast<char*>(tag),AES_TAG_SIZE);

    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE, tag)) {
        infile.close();
        outfile.close();
        throw std::runtime_error("Filed to set GCM tag, maybe the file is corrupted!\n");
    }
    // finalize
    int final_out = 0;
    if (1 != EVP_DecryptFinal_ex(ctx.get(), nullptr, &final_out)) {
        infile.close();
        outfile.close();
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }





    infile.close();
    outfile.close();



}

// generates the hash from user password with the given salt
void decrypt::derive_key() {
    if (!key){
        throw std::runtime_error("Failed to generate kdf key!");
    }

    if (crypto_pwhash
    (key, AES_KEY_SIZE, args_.password, strlen(args_.password), salt,
         crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
         crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("Failed to generate kdf key! - out of memory");
         }
}

void decrypt::derive_iv() {
    // incrementing n_iv to make the iv unique
    n_iv++;
    memcpy(iv, base_iv, AES_IV_SIZE);
    // copy n into iv last 8 byte
    memcpy(iv+4, &n_iv, sizeof(uint64_t));
}



// loads key from keyfile
void decrypt::load_keyfile(){
    const int keyfile = open(args_.keyfile_path.c_str(), O_RDONLY);

    if(keyfile == -1){
        throw std::runtime_error("Failed to open AES keyfile!");
    }

    key = secure_memory::secure_malloc<unsigned char>(AES_KEY_SIZE);

    if(!key){
        close(keyfile);
        throw std::runtime_error("Failed to allocate memory for AES key!");
    }
    const size_t read_bytes = read(keyfile, key, AES_KEY_SIZE);
    if (read_bytes != AES_KEY_SIZE){
        close(keyfile);
        throw std::runtime_error("Failed to read keyfile!");
    }
    close(keyfile);
}


