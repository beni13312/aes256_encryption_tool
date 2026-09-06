#include "encrypt.h"

#include <array>
#include <filesystem>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <fstream>
#include <iostream>
#include <cstring>
#include <vector>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <sodium.h>
#include "consts.h"
#include "secure_memory.h"

encrypt::encrypt(const Args &args): args_(args){}



encrypt::~encrypt(){
    if (key) secure_memory::secure_free<unsigned char>(key, AES_KEY_SIZE);
    if (iv) secure_memory::secure_free<unsigned char>(iv, AES_IV_SIZE);

}



// encrypts the file or folder
void encrypt::run(){

    const std::filesystem::path input_path = args_.input_path;

    if(!std::filesystem::exists(input_path)){
        throw std::runtime_error("Input path does not exist!");
    }

    // if specified, using existing private key, else generate the encryption key
    if(!args_.keyfile_path.empty()){
        load_key();

    }else{
        generate_key();
    }

    iv = secure_memory::secure_malloc<unsigned char>(AES_IV_SIZE);

    if(!iv){
        throw std::runtime_error("Failed to allocate memory for AES iv!");
    }

    // generating iv
    if(RAND_bytes(iv, AES_IV_SIZE) != 1){
        throw std::runtime_error("Failed to generate random AES iv!");
    }


    if (std::filesystem::is_regular_file(input_path)){

        std::ifstream infile(input_path, std::ios::binary);
        if(!infile.is_open()){
            throw std::runtime_error("Failed to open file for encryption!\n");
        }


        std::filesystem::path out_path = args_.output_path;

        if(std::filesystem::exists(out_path)){
            throw std::runtime_error("Output path already exist!\n");
        }


        filename = input_path.filename().string();

        if(filename.size() >= FILENAME_MAX_LENGTH){
            infile.close();
            throw std::runtime_error("Filename too long to encrypt!\n");
        }

        // getting file name if the user specified a directory
        if(std::filesystem::is_directory(out_path)){

            if(args_.rand_filename){

                const std::string generated_filename = gen_rand_filename();

                out_path /= generated_filename;

            }else{
                out_path /= input_path.filename();
            }

        }
        std::cout << "Filename: " << filename << "\n";
        std::cout << "Filepath: " << out_path << "\n";

        std::ofstream outfile(out_path,  std::ios::binary);
        if(!outfile.is_open()){
            infile.close();
            throw std::runtime_error("Failed to open file for writing encrypted data!\n");
        }

        // writing iv to the beginning of the file
        outfile.write(reinterpret_cast<const char*>(iv), AES_IV_SIZE);

        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};

        if (!ctx) {
            infile.close();
            outfile.close();
            throw std::runtime_error("Failed to create EVP context");
        }

        if (EVP_EncryptInit_ex2(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1){
            infile.close();
            outfile.close();
            throw std::runtime_error("EVP_EncryptInit_ex failed");
        }

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr) != 1){
            infile.close();
            outfile.close();
            throw std::runtime_error("Failed to set IV length");
        }

        if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key, iv) != 1){
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
        size_t file_size = std::filesystem::file_size(input_path);
        auto readbuf = secure_memory::secure_malloc<unsigned char>(BUFFER_SIZE);
        auto writebuf = secure_memory::secure_malloc<unsigned char>(BUFFER_SIZE);


        std::streamsize bytes_read = 0;
        int write_buffer_size = 0;

        while(true){
            const size_t to_read = std::min(file_size, BUFFER_SIZE);
            // read file data in chunks
            infile.read(reinterpret_cast<char*>(readbuf), static_cast<std::streamsize>(to_read));
            bytes_read = infile.gcount();

            if(bytes_read <= 0){
                break;
            }

            if (1 != EVP_EncryptUpdate(ctx.get(), writebuf, &write_buffer_size, readbuf, static_cast<int>(bytes_read))){
                infile.close();
                outfile.close();
                throw std::runtime_error("Failed to encrypt buffer");
            }

            // write encrypted data to output file
            outfile.write(reinterpret_cast<const char*>(writebuf), write_buffer_size);
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

    }else if(std::filesystem::is_directory(input_path)){
        // TODO: implement folder encryption use async for better performance
    }

}


// loads key from encrypted file and keyfile
void encrypt::load_key(){
    const int keyfile = open(args_.keyfile_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

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

// generates keys, keyfiles for encryption
void encrypt::generate_key(){
     key = secure_memory::secure_malloc<unsigned char>(AES_KEY_SIZE);
    if (!key){
        throw std::runtime_error("Failed to allocate memory for key!");
    }
    if (RAND_bytes(key, AES_KEY_SIZE) != 1){
        throw std::runtime_error("Failed to generate random key!");
    }
}

// generate uniqe IV for each cycle
std::array<unsigned char, AES_IV_SIZE> encrypt::generate_unique_iv(const uint64_t n){
    if constexpr (sizeof(base_iv) < AES_IV_SIZE){
        throw std::runtime_error("base IV does not exists");
    }

    std::array<unsigned char, AES_IV_SIZE> iv{};
    memcpy(iv.data(), base_iv, AES_IV_SIZE);
    // copy n into iv last 8 byte
    memcpy(iv.data()+4, &n, sizeof(uint64_t));


    return iv;


}

void encrypt::create_keyfile(){
    if (args_.keyfile_path.empty()){
        throw std::runtime_error("Keyfile path is empty!");
    }
    const int keyfile = open(args_.keyfile_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (keyfile == -1) {
        throw std::runtime_error("Failed to open keyfile!\n");
    }
    if (!key){
        throw std::runtime_error("Key does not exists");
        close(keyfile);
    }
    const size_t wrote_bytes = write(keyfile, key, AES_KEY_SIZE);
    if (wrote_bytes != AES_KEY_SIZE){
        throw std::runtime_error("Failed to write key into keyfile!");
        close(keyfile);
    }
    close(keyfile);

}

void encrypt::generate_kdf(){
    if (!key){
        throw std::runtime_error("Failed to generate kdf key!");
    }

    randombytes_buf(salt, sizeof salt);

    if (crypto_pwhash
    (key, AES_KEY_SIZE, args_.password, strlen(args_.password), salt,
         crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
         crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("Failed to generate kdf key! - out of memory");
         }
    
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
