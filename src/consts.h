#pragma once
#include <cstdint>

constexpr int  MIN_PASSWORD_LENGTH = 8; // character
constexpr int MAX_PASSWORD_LENGTH = 56; // character

inline constexpr size_t FILENAME_MAX_LENGTH = 255;
inline constexpr size_t FILENAME_SIZE_INT = sizeof(uint32_t);

// AES256-GCM parameters
inline constexpr size_t AES_KEY_SIZE = 32; // 32 bytes 
inline constexpr size_t AES_KEY_LENGTH = 256; // 256 bits
inline constexpr size_t AES_TAG_SIZE = 16; // 16 bytes
inline constexpr size_t AES_IV_SIZE = 12; // 12 bytes
inline constexpr size_t BUFFER_SIZE = 64 *  1024; // 64KB


// Argon2 parameters
inline constexpr size_t HASH_SIZE = 128; // 128 bytes
inline constexpr size_t SALT_SIZE = 16; // 16 bytes
