#pragma once

#include <string>

struct Args{
    enum class Method {ENCRYPT, DECRYPT};
    Method method;

    bool rand_filename = false;
    bool encrypted_keyfile = false;
    std::string keyfile_path;
    std::string input_path;
    std::string output_path;
    char* password = nullptr;
};
