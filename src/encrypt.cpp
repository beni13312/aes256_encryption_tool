#include "encrypt.h"
#include <filesystem>
#include <stdexcept>
#include <openssl/evp.h>
#include <fstream>
#include <cstring>
#include <iostream>
#include <utility>
#include <vector>
#include <arpa/inet.h>
#include <argon2.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/rand.h>
#include "consts.h"
#include "secure_memory.h"

encrypt::encrypt(const Args &args): args_(args){}



encrypt::~encrypt(){
    if (key) secure_memory::secure_free<unsigned char>(key, AES_KEY_SIZE);
}



// encrypts the file or folder
void encrypt::run(){

    const std::filesystem::path input_path = args_.input_path;

    if(!std::filesystem::exists(input_path)){
        throw std::runtime_error("Input path does not exist!");
    }

    // if specified, using existing private key, else generate the encryption key
    if(!args_.keyfile_path.empty()){

        std::ifstream keyfile(args_.keyfile_path, std::ios::binary);

        if(!keyfile.is_open()){
            throw std::runtime_error("Failed to open AES keyfile!");
        }

        key = secure_memory::secure_malloc<unsigned char>(AES_KEY_SIZE);

        if(!key){
            keyfile.close();
            throw std::runtime_error("Failed to allocate memory for AES key!");
        }

        if (!keyfile.read(reinterpret_cast<char*>(key), AES_KEY_SIZE).good()){
            keyfile.close();
            throw std::runtime_error("Failed to read keyfile!");
        }
        keyfile.close();

    }else{
        keygen();
    }

    iv = secure_malloc<unsigned char>(AES_IV_SIZE);

    if(!iv){
        throw std::runtime_error("Failed to allocate memory for AES iv!");
    }

    // generating iv
    if(RAND_bytes(iv, AES_IV_SIZE) != 1){
        throw std::runtime_error("Failed to generate random AES iv!");
    }


    if (std::filesystem::is_regular_file(in_path)){

        std::ifstream infile(in_path, std::ios::binary);
        if(!infile.is_open()){
            throw std::runtime_error("Failed to open file for encryption!\n");
        }


        std::filesystem::path out_path = output_path_;

        if(!std::filesystem::exists(out_path)){
            throw std::runtime_error("Output path does not exist!\n");
        }

        // getting file name if the user specified a directory
        if(std::filesystem::is_directory(out_path)){

            filename = in_path.filename().string();

            if(filename.size() >= FILENAME_MAX_LENGTH){
                std::cerr << "Generated filename too long to encrypt!\n";
                infile.close();
                throw std::runtime_error("Filename too long to encrypt!\n");
                }

            if(rand_filename_){

                const std::string generated_filename = gen_rand_filename();

                out_path /= generated_filename;

            }else{
                out_path /= in_path.filename();

                std::cout << "Filename: " << filename << "\n";
                std::cout << "Filepath: " << out_path << "\n";
                }

        }else{
            filename = in_path.filename().string();

            if(filename.size() >= FILENAME_MAX_LENGTH){
                std::cerr << "Filename too long to encrypt!\n";
                infile.close();
                throw std::runtime_error("Filename too long to encrypt!\n");
            }

            std::cout << "Filename: " << filename << "\n";
            std::cout << "Filepath: " << out_path << "\n";

        }

        std::ofstream outfile(out_path,  std::ios::binary);
        if(!outfile.is_open()){
            std::cerr << "Failed to open file for writing encrypted data!\n";
            infile.close();
            throw std::runtime_error("Failed to open file for writing encrypted data!\n");
        }

        // writing iv to the beginning of the file
        outfile.write(reinterpret_cast<const char*>(iv), AES_IV_SIZE);

        if (!ctx) {
            infile.close();
            outfile.close();
            throw std::runtime_error("Failed to create EVP context");
        }

        if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr)){
            infile.close();
            outfile.close();
            throw std::runtime_error("EVP_EncryptInit_ex failed");
        }

        if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr)){
            infile.close();
            outfile.close();
            throw std::runtime_error("Failed to set IV length");
        }

        if (1 != EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key, iv)){
            infile.close();
            outfile.close();
            throw std::runtime_error("Failed to set key and IV");
        }



        // writing filename
        if(filename.empty()){
            infile.close();
            outfile.close();
            throw std::runtime_error("Filename is empty!");
        }

        // write filename size
        int filename_bytes_read = 0;
        int filename_write_buffer_size = 0;
        uint32_t filename_size = htonl(static_cast<uint32_t>(filename.size()));

        std::vector<unsigned char> filename_writebuf(FILENAME_MAX_LENGTH + FILENAME_SIZE_INT);


        if (1 != EVP_EncryptUpdate(ctx.get(), filename_writebuf.data(), &filename_write_buffer_size, reinterpret_cast<unsigned char*>(&filename_size),sizeof(filename_size))){
            infile.close();
            outfile.close();
            throw std::runtime_error("Failed to encrypt buffer");
        }


        outfile.write(reinterpret_cast<const char*>(filename_writebuf.data()), filename_write_buffer_size);

        filename_bytes_read = static_cast<int>(filename.size());

        // write filename
        if (1 != EVP_EncryptUpdate(ctx.get(), filename_writebuf.data(), &filename_write_buffer_size, reinterpret_cast<unsigned char*>(filename.data()), filename_bytes_read)){
            infile.close();
            outfile.close();
            throw std::runtime_error("Failed to encrypt buffer");
        }

        outfile.write(reinterpret_cast<const char*>(filename_writebuf.data()), filename_write_buffer_size);




        // encrypt file data
        size_t file_size = std::filesystem::file_size(in_path);
        std::vector<unsigned char> readbuf(BUFFER_SIZE);
        std::vector<unsigned char> writebuf(BUFFER_SIZE);

        std::streamsize bytes_read = 0;
        int write_buffer_size = 0;

        while(true){
            const size_t to_read = std::min(file_size, BUFFER_SIZE);
            // read file data in chunks
            infile.read(reinterpret_cast<char*>(readbuf.data()), static_cast<std::streamsize>(to_read));
            bytes_read = infile.gcount();

            if(bytes_read <= 0){
                break;
            }

            if (1 != EVP_EncryptUpdate(ctx.get(), writebuf.data(), &write_buffer_size, readbuf.data(), static_cast<int>(bytes_read))){
                infile.close();
                outfile.close();
                throw std::runtime_error("Failed to encrypt buffer");
            }

            // write encrypted data to output file
            outfile.write(reinterpret_cast<const char*>(writebuf.data()), write_buffer_size);
            file_size -= bytes_read;
        }
        // finalize
        int final_out = 0;
        if (1 != EVP_EncryptFinal_ex(ctx.get(), nullptr, &final_out)) {
            infile.close();
            outfile.close();
            throw std::runtime_error("EVP_EncryptFinal_ex failed");
        }

        // get GCM tag
        unsigned char tag[AES_TAG_SIZE];

        if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag)) {
            infile.close();
            outfile.close();
            throw std::runtime_error("Failed to get GCM tag");
        }

        // write tag at the end of file
        outfile.write(reinterpret_cast<const char*>(tag), AES_TAG_SIZE);

    }else if(std::filesystem::is_directory(in_path)){
        // TODO: implement folder encryption use async for better performance
        return;
    }

}
// random generates an AES256 key
void encrypt::aes_keygen(const std::string& keyfile_path){
    key = secure_malloc<unsigned char>(AES_KEY_SIZE);


    if(!key){
        throw std::runtime_error("Failed to allocate memory for AES key!");
    }

    // generate random key
    if(RAND_bytes(key, AES_KEY_SIZE) != 1){
        throw std::runtime_error("Failed to generate random AES key!\n");
    }

    // open keyfile as read write only to the owner
    const int keyfile = open(keyfile_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (keyfile == -1) {
        perror("open");
        throw std::runtime_error("Failed to open keyfile!\n");
    }


    // encrypt the key with password (if provided)
    if(password_){
    // [4 bytes]  Keyfile ID (ENCRYPTED_KEYFILE)
    // [16 bytes] Salt
    // [12 bytes] iv
    // [32 bytes] Encrypted AES key
    // [16 bytes] Auth tag

        if (!ctx) {
            close(keyfile);
            throw std::runtime_error("Failed to create EVP context");
        }

        total_enc_key_size =
            KEYFILE_ID_SIZE +
            SALT_SIZE +
            AES_IV_SIZE +
            AES_KEY_SIZE +
            AES_TAG_SIZE;

        encrypted_keyfile = secure_malloc<unsigned char>(total_enc_key_size); // ciphertext + tag
        if(!encrypted_keyfile){
            close(keyfile);
            throw std::runtime_error("Failed to allocate memory for encrypted AES key!");
        }

        const uint32_t id = htonl(ENCRYPTED_KEYFILE);


        // hash the password with argon2
        salt = secure_malloc<unsigned char>(SALT_SIZE);
        if(!salt) {
            close(keyfile);
            throw std::runtime_error("Failed to allocate memory for salt!");
        }

        if(RAND_bytes(salt, SALT_SIZE) != 1){
            close(keyfile);
            throw std::runtime_error("Failed to generate salt for key encryption!\n");
        }

        hashed_password = secure_malloc<unsigned char>(AES_KEY_SIZE);
        if (!hashed_password) {
            close(keyfile);
            throw std::runtime_error("Failed to allocate memory for hashed password!");
        }

        const int result = argon2id_hash_raw(
            3,            // iterations
            1 << 16,      // memory (64 MB)
            4,            // parallelism
            password_,
            strlen(reinterpret_cast<const char*>(password_)),
            salt,         // salt
            SALT_SIZE,
            hashed_password,          // output buffer
            AES_KEY_SIZE   // output length
        );

        if(result != ARGON2_OK) {
            std::cerr << "Argon2 hashing failed: " << argon2_error_message(result) << "\n";
            close(keyfile);
            throw std::runtime_error("Failed to hash password for key encryption!\n");
        }



        // encrypt the key with hashed password
        unsigned char enc_iv[AES_IV_SIZE];


        if(RAND_bytes(enc_iv, AES_IV_SIZE) != 1){
            close(keyfile);
            throw std::runtime_error("Failed to generate nonce for key encryption!\n");
        }

        // encrypt key

        if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr)){
            throw std::runtime_error("EVP_EncryptInit_ex failed");
        }

        if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr)){
            throw std::runtime_error("Failed to set IV length");
        }

        // using hashed_password as key
        if (1 != EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, hashed_password, enc_iv)){
            throw std::runtime_error("Failed to set key and IV");
        }

        int outlen = 0;

        if(1 != EVP_EncryptUpdate(ctx.get(), encrypted_key, &outlen, key, AES_KEY_SIZE)){
            close(keyfile);
            throw std::runtime_error("Failed to encrypt AES key with password!\n");

        }


        // finalize
        int final_out = 0;
        if (1 != EVP_EncryptFinal_ex(ctx.get(), nullptr, &final_out)) {
            throw std::runtime_error("EVP_EncryptFinal_ex failed");
        }

        // get auth tag
        unsigned char tag[AES_TAG_SIZE];

        if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag)) {
            throw std::runtime_error("Failed to get GCM tag");
        }

        // reset cipher context
        EVP_CIPHER_CTX_reset(ctx.get());

        // adding each data to memory buffer
        unsigned char* p = encrypted_keyfile;
        memcpy(p,  &id, KEYFILE_ID_SIZE); p += KEYFILE_ID_SIZE;
        memcpy(p,  &salt, SALT_SIZE); p += SALT_SIZE;
        memcpy(p,  &enc_iv, AES_IV_SIZE); p += AES_IV_SIZE;
        memcpy(p,  &encrypted_key, AES_KEY_SIZE); p += AES_KEY_SIZE;
        memcpy(p,  &tag, AES_TAG_SIZE);


        // write the constructed data
        ssize_t write_n = write(keyfile, encrypted_keyfile, total_enc_key_size);
        if(write_n != static_cast<ssize_t>(total_enc_key_size)) {
            throw std::runtime_error("Failed to write AES key file!");
        }

    } else {
        // plaintext keyfile
        total_key_size = KEYFILE_ID_SIZE + AES_KEY_SIZE;
        plain_keyfile = secure_malloc<unsigned char>(total_key_size);

        const uint32_t id = htonl(ENCRYPTED_KEYFILE);

        if(!plain_keyfile) {
            close(keyfile);
            throw std::runtime_error("Failed to allocate memory for keyfile!");
        }

        unsigned char* p = plain_keyfile;
        memcpy(p,  &id, KEYFILE_ID_SIZE); p += KEYFILE_ID_SIZE;
        memcpy(p,  &key, AES_KEY_SIZE);

        ssize_t write_n = write(keyfile, plain_keyfile, total_key_size);
        if(write_n != static_cast<ssize_t>(total_key_size)) {
            throw std::runtime_error("Failed to write AES key file!");
        }
    }

    close(keyfile);

}



// generates a random filename for the encrypted file
std::string encrypt::gen_rand_filename(){
    constexpr int filename_length = 12; // 12 bytes = 24 hex characters
    unsigned char filename_bytes[filename_length];

    if(RAND_bytes(filename_bytes, filename_length) != 1){
        throw std::runtime_error("Failed to generate random filename!\n");
    }

    // creating readable string
    std::ostringstream hexStr;
    for(const unsigned char filename_byte : filename_bytes){
        hexStr << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(filename_byte);
    }
    std::cout << "Generated random filename: " << hexStr.str() << "\n";
    return hexStr.str();

}



