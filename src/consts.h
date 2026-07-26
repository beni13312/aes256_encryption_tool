#pragma once

constexpr int  MIN_PASSWORD_LENGTH = 8; // character
constexpr int MAX_PASSWORD_LENGTH = 56; // character

inline constexpr size_t FILENAME_MAX_LENGTH = 255;
inline constexpr size_t FILENAME_SIZE_INT = sizeof(uint32_t);

inline constexpr uint32_t PLAIN_KEYFILE = 0x304B4631; // "0KF1"
inline constexpr uint32_t ENCRYPTED_KEYFILE = 0x454B4631; // "EKF1"
inline constexpr size_t KEYFILE_ID_SIZE = sizeof(uint32_t);



// AES256-GCM parameters 
inline constexpr size_t AES_KEY_SIZE = 32; // 32 bytes 
inline constexpr size_t AES_KEY_LENGTH = 256; // 256 bits
inline constexpr size_t AES_TAG_SIZE = 16; // 16 bytes
inline constexpr size_t AES_IV_SIZE = 12; // 12 bytes
inline constexpr size_t BUFFER_SIZE = 64 *  1024; // 64KB



// ChaCha20-Poly1305 parameters
inline constexpr size_t CHACHA20_KEY_SIZE = 32; // 32 bytes
inline constexpr size_t CHACHA20_NONCE_SIZE = 12; // 12 bytes
inline constexpr size_t CHACHA20_AUTH_TAG_SIZE = 16; // 16 bytes 



// Argon2 parameters
inline constexpr size_t ARGON2_HASH_SIZE = 32; // 64 bytes
inline constexpr size_t SALT_SIZE = 16; // 16 bytes
