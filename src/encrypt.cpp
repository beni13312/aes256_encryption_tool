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

}



// encrypts the file or folder
void encrypt::run(){

    const std::filesystem::path input_path = args_.input_path;

    if(!std::filesystem::exists(input_path)){
        throw std::runtime_error("Input file or folder does not exist!");
    }

    // if specified, using existing private key, else generate the encryption key
    if(!args_.keyfile_path.empty()){
        if (std::filesystem::exists(args_.keyfile_path)){
            load_key();

        }else{ // create keyfile if it does not exist
            generate_key();
            create_keyfile();
        }

    }else{
        generate_key();
    }

    // generating base iv
    if(RAND_bytes(base_iv, AES_IV_SIZE) != 1){
        throw std::runtime_error("Failed to generate random AES iv!");
    }


    if (std::filesystem::is_regular_file(input_path)){

        std::ifstream input_fs(input_path, std::ios::binary);
        if(!input_fs.is_open()){
            throw std::runtime_error("Failed to open file for encryption!\n");
        }


        std::filesystem::path output_path = args_.output_path;

        if(!std::filesystem::is_directory(output_path) && std::filesystem::exists(output_path)){
            throw std::runtime_error("Output file already exist  with the same filename!\n");
        }

        const bool is_output_path_dir = std::filesystem::is_directory(output_path);

        // getting or generating the filename
        if (args_.rand_filename){
            filename = gen_rand_filename();
        }else if(is_output_path_dir){
            filename = input_path.filename().string();
        }else{
            filename = output_path.filename().string();
        }

        if (is_output_path_dir){
            output_path /= filename;
        }else if (args_.rand_filename){
            output_path = output_path.parent_path() / filename;
        }

        if(filename.size() >= FILENAME_MAX_LENGTH){
            input_fs.close();
            throw std::runtime_error("Filename too long to encrypt!\n");
        }


        std::cout << "Filename: " << filename << "\n";
        std::cout << "Filepath: " << output_path << "\n";

        std::ofstream output_fs(output_path,  std::ios::binary);
        if(!output_fs.is_open()){
            input_fs.close();
            throw std::runtime_error("Failed to open file for writing encrypted data!\n");
        }

        // writing iv to the beginning of the file
        output_fs.write(reinterpret_cast<const char*>(iv), AES_IV_SIZE);
        std::cout << "Wrote IV" << "\n";

        // write salt for KDF
        output_fs.write(reinterpret_cast<const char*>(salt), SALT_SIZE);

        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};

        if (!ctx) {
            input_fs.close();
            output_fs.close();
            throw std::runtime_error("Failed to create EVP context");
        }

        if (EVP_EncryptInit_ex2(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1){
            input_fs.close();
            output_fs.close();
            throw std::runtime_error("EVP_EncryptInit_ex failed");
        }

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr) != 1){
            input_fs.close();
            output_fs.close();
            throw std::runtime_error("Failed to set IV length");
        }

        if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key, iv) != 1){
            input_fs.close();
            output_fs.close();
            throw std::runtime_error("Failed to set key and IV");
        }

        if(filename.empty()){
            input_fs.close();
            output_fs.close();
            throw std::runtime_error("Filename is empty!");
        }


        generate_unique_iv();

        // if input filename is the same as the output, skip the filename from writing
        if (filename != input_path.filename().string()){
            // write filename size
            uint32_t filename_size = htonl(static_cast<uint32_t>(filename.size()));

            output_fs.write(reinterpret_cast<const char*>(&filename_size), FILENAME_SIZE_INT);
            std::cout << "Wrote filename size" << "\n";

            int filename_bytes_read = 0;
            int filename_write_buffer_size = 0;
            std::vector<unsigned char> filename_writebuf(FILENAME_MAX_LENGTH);

            filename_bytes_read = static_cast<int>(filename.size());

            // write filename
            if (1 != EVP_EncryptUpdate(ctx.get(), filename_writebuf.data(), &filename_write_buffer_size, reinterpret_cast<unsigned char*>(filename.data()), filename_bytes_read)){
                input_fs.close();
                output_fs.close();
                throw std::runtime_error("Failed to encrypt buffer");
            }

            output_fs.write(reinterpret_cast<const char*>(filename_writebuf.data()), filename_write_buffer_size);
            std::cout << "Wrote encrypted filename" << "\n";

        }

        // write the size of the estimated encrypted data
        size_t file_size_to_read = std::filesystem::file_size(input_path);
        uint32_t encrypted_data_size = htonl(static_cast<uint32_t>(file_size_to_read));

        output_fs.write(reinterpret_cast<const char*>(&encrypted_data_size), sizeof(uint32_t));
        std::cout << "Wrote encrypted data size" << "\n";



        // encrypt file data
        auto readbuf = secure_memory::secure_malloc<unsigned char>(BUFFER_SIZE);
        auto writebuf = secure_memory::secure_malloc<unsigned char>(BUFFER_SIZE);


        std::streamsize bytes_read = 0;
        int write_buffer_size = 0;

        while(true){
            const size_t bytes_to_read = std::min(file_size_to_read, BUFFER_SIZE);
            // read file data in chunks
            input_fs.read(reinterpret_cast<char*>(readbuf), static_cast<std::streamsize>(bytes_to_read));
            bytes_read = input_fs.gcount();

            if(bytes_read <= 0){
                break;
            }

            generate_unique_iv();

            if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key, iv) != 1){
                input_fs.close();
                output_fs.close();
                throw std::runtime_error("Failed to set key and IV");
            }

            if (1 != EVP_EncryptUpdate(ctx.get(), writebuf, &write_buffer_size, readbuf, static_cast<int>(bytes_read))){
                input_fs.close();
                output_fs.close();
                throw std::runtime_error("Failed to encrypt buffer");
            }

            // write encrypted data to output file
            output_fs.write(reinterpret_cast<const char*>(writebuf), write_buffer_size);
            file_size_to_read -= bytes_read;
        }
        std::cout << "Wrote encrypted data" << "\n";

        // finalize
        int final_out = 0;
        if (EVP_EncryptFinal_ex(ctx.get(), nullptr, &final_out) != 1) {
            input_fs.close();
            output_fs.close();
            throw std::runtime_error("Failed to close encryption process");
        }

        // get GCM tag
        unsigned char tag[AES_TAG_SIZE];

        if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag)) {
            input_fs.close();
            output_fs.close();
            throw std::runtime_error("Failed to get GCM tag");
        }

        // write tag at the end of file
        output_fs.write(reinterpret_cast<const char*>(tag), AES_TAG_SIZE);
        std::cout << "Wrote GCM tag" << "\n";

    }else if(std::filesystem::is_directory(input_path)){
        // TODO: implement folder encryption
        for (auto &entry : std::filesystem::recursive_directory_iterator(input_path)){
            if (entry.is_regular_file()){
                std::cout << "Encrypting: " << entry.path().string() << "\n";
                // TODO: implement encryption

            }
        }

    }

}


// loads key from keyfile
void encrypt::load_key(){
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

// generate unique IV for each cycle
void encrypt::generate_unique_iv(){
    // incrementing n_iv to make the iv unique
    n_iv++;
    memcpy(iv, base_iv, AES_IV_SIZE);
    // copy n into iv last 8 byte
    memcpy(iv+4, &n_iv, sizeof(uint64_t));

}

void encrypt::create_keyfile() const{
    if (args_.keyfile_path.empty()){
        throw std::runtime_error("Keyfile path is empty!");
    }
    const int keyfile = open(args_.keyfile_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (keyfile == -1) {
        throw std::runtime_error("Failed to open keyfile!\n");
    }
    if (!key){
        close(keyfile);
        throw std::runtime_error("Key does not exists");
    }
    const size_t wrote_bytes = write(keyfile, key, AES_KEY_SIZE);
    if (wrote_bytes != AES_KEY_SIZE){
        close(keyfile);
        throw std::runtime_error("Failed to write key into keyfile!");
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
