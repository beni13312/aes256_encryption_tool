#ifndef ENCRYPTION_PROJ_ARGS_H
#define ENCRYPTION_PROJ_ARGS_H
#include <string>

struct Args{
    enum class Method {ENCRYPT, DECRYPT};
    Method method;

    bool rand_filename = false;
    std::string keyfile_path;
    std::string input_path;
    std::string output_path;
    unsigned char* kdf_password = nullptr;
    size_t kdf_password_len = 0;
};


#endif //ENCRYPTION_PROJ_ARGS_H
