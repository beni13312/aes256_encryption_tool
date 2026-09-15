#include "decrypt.h"
#include <filesystem>
#include <openssl/evp.h>
#include <argon2.h>
#include <fstream>
#include <stdexcept>
#include <utility>
#include <vector>
#include <iostream>
#include <arpa/inet.h>
#include "getpasswd.h"

decrypt::decrypt(const Args &args): args_(args){}

void decrypt::run(){

}

// generates the hash from user password
unsigned char* decrypt::get_enc_key(const unsigned char* salt) {
    hash = secure_malloc<unsigned char>(AES_KEY_SIZE);
    if (!hash) {
        throw std::runtime_error("Failed to allocate memory for hashed password!");
    }

    const int result = argon2id_hash_raw(
        3,            // iterations
        1 << 16,      // memory (64 MB)
        4,            // parallelism
         &password,
        password.size(),
        salt,         // salt
        SALT_SIZE,
        hash,          // output buffer
        AES_KEY_SIZE   // output length
    );

    if(result != ARGON2_OK) {
        std::cerr << "Argon2 hashing failed: " << argon2_error_message(result) << "\n";
        throw std::runtime_error("Failed to hash password for key encryption!\n");
    }

    return hash;
}

void decrypt::get_aes_key(const std::string& keyfile_path){
    std::ifstream keyfile(keyfile_path, std::ios::binary);

    if(!keyfile.is_open()){
        throw std::runtime_error("Failed to open AES keyfile!\n");
    }

    key = secure_malloc<unsigned char>(AES_KEY_SIZE);
    uint32_t keyfile_id = 0;

    if(!key){
        throw std::runtime_error("Failed to allocate memory for AES key!");
    }

    // read the id fom the keyfile

    keyfile.read(reinterpret_cast<char*>(keyfile_id), KEYFILE_ID_SIZE);

    keyfile_id = ntohl(keyfile_id); // deserialize

    if (keyfile_id == ENCRYPTED_KEYFILE) {
        std::cout << "Enter keyfile password: \n";
        getpasswd::getpasswd(password);

        unsigned char salt[SALT_SIZE];
        enc_key = secure_malloc<unsigned char>(AES_KEY_SIZE);
        enc_iv = secure_malloc<unsigned char>(AES_IV_SIZE + AES_TAG_SIZE);


        if(!enc_key || !enc_iv){
            throw std::runtime_error("Failed to allocate memory for keyfile credentials!");
        }

        // getting salt and iv from file
        keyfile.read(reinterpret_cast<char*>(salt), SALT_SIZE);
        keyfile.read(reinterpret_cast<char*>(enc_iv), AES_IV_SIZE);

        std::vector<unsigned char> ciphertext(AES_KEY_SIZE);


        enc_key = get_enc_key(salt);

        if (!ctx) {
            throw std::runtime_error("Failed to create EVP context");
        }

        if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr)){

            throw std::runtime_error("EVP_DecryptInit_ex failed");
        }

        if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr)){

            throw std::runtime_error("Failed to set IV length");
        }

        if (1 != EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, enc_key, enc_iv)){
            throw std::runtime_error("Failed to set key and IV");
        }

        int write_buffer_size = 0;
        if (1 != EVP_DecryptUpdate(ctx.get(), key, &write_buffer_size, ciphertext.data(),AES_KEY_SIZE)){
            throw std::runtime_error("Failed to decrypt buffer");
        }

        // set GCM tag (16 bytes typical)
        unsigned char tag[AES_TAG_SIZE];
        keyfile.read(reinterpret_cast<char*>(tag), AES_TAG_SIZE);


        if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE, tag)) {
            throw std::runtime_error("Filed to set GCM tag, maybe the file is corrupted!\n");
        }
        // finalize
        int final_out = 0;
        if (1 != EVP_DecryptFinal_ex(ctx.get(), nullptr, &final_out)) {
            throw std::runtime_error("EVP_DecryptFinal_ex failed");
        }


    }else if (keyfile_id == PLAIN_KEYFILE) {
        keyfile.read(reinterpret_cast<char*>(key), AES_KEY_SIZE);
        keyfile.close();

    }



}




decrypt::decrypt(std::string  keyfile_path, std::string  input_path, std::string  output_path):
keyfile_path_(std::move(keyfile_path)), input_path_(std::move(input_path)), output_path_(std::move(output_path)) {}



decrypt::~decrypt(){
    if (enc_key) secure_free(enc_key, AES_KEY_SIZE);
    if (enc_iv) secure_free(key, AES_IV_SIZE);
    if (hash) secure_free(hash, AES_KEY_SIZE);
    if(key) secure_free(key, AES_KEY_SIZE);
    if(iv) secure_free(iv, AES_IV_SIZE);
}



void decrypt::AES_decrypt(){
    const std::filesystem::path in_path = input_path_;

    if(!std::filesystem::exists(in_path)){
        throw std::runtime_error("Path does not exist!\n");
    }

    // retrieve the AES key
    get_aes_key(keyfile_path_);

    // decrypt
    if (std::filesystem::is_regular_file(in_path)){

        std::ifstream infile(in_path, std::ios::binary);
        if(!infile.is_open()){
            throw std::runtime_error("Failed to open file for decryption!\n");
        }

        const std::filesystem::path out_path = output_path_;
        if(!std::filesystem::is_directory(out_path)){
            infile.close();
            throw std::runtime_error("Output path must be a directory when decrypting a file!\n");
        }

        std::ofstream outfile;


        // read iv from infile
        iv = secure_malloc<unsigned char>(AES_IV_SIZE);
        if(!iv){
            infile.close();
            throw std::runtime_error("Failed to allocate memory for AES iv!");
        }
        infile.read(reinterpret_cast<char*>(iv), AES_IV_SIZE);

        
        if (!ctx) {
            infile.close();
            throw std::runtime_error("Failed to create EVP context");
        }

        if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr)){
            infile.close();
            throw std::runtime_error("EVP_DecryptInit_ex failed");
        }

        if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr)){
            infile.close();
            throw std::runtime_error("Failed to set IV length");
        }

        if (1 != EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key, iv)){
            infile.close();
            throw std::runtime_error("Failed to set key and IV");
        }

        // read filename size
        u_int32_t filename_size;
        int filename_size_write_buffer_size = 0;
        std::vector<unsigned char> filename_readbuf(FILENAME_MAX_LENGTH);
        std::vector<unsigned char> filename_writebuf(FILENAME_MAX_LENGTH);

        infile.read(reinterpret_cast<char*>(filename_readbuf.data()), FILENAME_SIZE_INT);
        std::streamsize filename_size_bytes_read = infile.gcount();

        if(filename_size_bytes_read != static_cast<std::streamsize>(FILENAME_SIZE_INT)){
            infile.close();
            throw std::runtime_error("Failed to get filename size!");

        }
        
        if (1 != EVP_DecryptUpdate(ctx.get(), reinterpret_cast<unsigned char*>(&filename_size), &filename_size_write_buffer_size, filename_readbuf.data(), static_cast<int>(filename_size_bytes_read))){
            infile.close();
            throw std::runtime_error("Failed to decrypt buffer");
        }
        filename_size = ntohl(filename_size);

        // read filename        
        std::string filename;
        int filename_write_buffer_size = 0;

        infile.read(reinterpret_cast<char*>(filename_readbuf.data()), filename_size);
        std::streamsize filename_bytes_read = infile.gcount();

        if(filename_bytes_read == 0 || filename_bytes_read > static_cast<std::streamsize>(FILENAME_MAX_LENGTH)){
            infile.close();
            throw std::runtime_error("Failed to read filename!");

        }

        if (1 != EVP_DecryptUpdate(ctx.get(), filename_writebuf.data(), &filename_write_buffer_size, filename_readbuf.data(), static_cast<int>(filename_bytes_read))){
            infile.close();
            throw std::runtime_error("Failed to decrypt buffer");
        }

        filename.assign(reinterpret_cast<char*>(filename_writebuf.data()), filename_write_buffer_size);
        std::cout << "Decrypted filename: " << filename << "\n";

        const std::filesystem::path file_full = out_path / filename; // user input + filename

        // open the file after the filename is known
        outfile.open(file_full, std::ios::binary);
        if (!outfile.is_open()) {
            infile.close();
            throw std::runtime_error("Failed to open file for writing decrypted data!\n");
        }

        size_t ciphertext_size = std::filesystem::file_size(in_path) - AES_IV_SIZE - FILENAME_SIZE_INT - filename_size - AES_TAG_SIZE;
        std::vector<unsigned char> readbuf(BUFFER_SIZE);
        std::vector<unsigned char> writebuf(BUFFER_SIZE);
        
        std::streamsize bytes_read;
        int write_buffer_size = 0;
        
        while(true){
            size_t to_read = std::min(ciphertext_size, BUFFER_SIZE);
            infile.read(reinterpret_cast<char*>(readbuf.data()), static_cast<std::streamsize>(to_read));
            bytes_read = infile.gcount();
            if(bytes_read <= 0){
                break;
            }
            
            if (1 != EVP_DecryptUpdate(ctx.get(), writebuf.data(), &write_buffer_size, readbuf.data(), static_cast<int>(bytes_read))){
                infile.close();
                outfile.close();
                throw std::runtime_error("Failed to decrypt buffer");
            }

            outfile.write(reinterpret_cast<const char*>(writebuf.data()), write_buffer_size);
            ciphertext_size -= bytes_read;
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


    }else{
        std::cerr << "Only files can be specified\n";
        return;
    }

}