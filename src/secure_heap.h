// Uses OpenSSL's secure heap to allocate and free memory securely.
// This class initializes the secure heap upon construction and cleans it up upon destruction.

#pragma once
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdexcept>
#include <string>
#include <vector>

// namespace secure_heap{
//     // initializes the secure heap
//     inline int secure_heap_init(const size_t pool_size = 16 * 1024 * 1024, const size_t min_alloc = 4096){
//         if(CRYPTO_secure_malloc_init(pool_size, min_alloc) != 1){
//             return 1;
//         }
//         if(CRYPTO_secure_malloc_initialized() != 1){
//             return 1;
//         }
//             return 0;
//     }
//     // securely allocates memory from the secure heap
//     template<typename T>
//     inline T* secure_malloc(const size_t size){
//         void* ptr = OPENSSL_secure_malloc(size);
//         if(!ptr){
//             return nullptr;
//         }
//         return static_cast<T*>(ptr);
//     }
//     // securely frees memory allocated from the secure heap
//     template<typename T>
//     inline void secure_free(T* &ptr, const size_t size){
//         if (ptr){
//             OPENSSL_cleanse(ptr, size);
//             OPENSSL_secure_free(ptr);
//             ptr = nullptr;
//         }
//
//     }
//     // allocators




// RAII

// TODO: implement the whole class properly
class SecureHeap{
    public:
        explicit SecureHeap(size_t pool_size = 16 * 1024 * 1024, size_t min_alloc = 4096);
        ~SecureHeap();

        void* secure_malloc(size_t size);

    private:
        void* ptr = nullptr;
        // size_t size = 0;
        template<typename T>
        struct secure_alloc;
        void cleanup();

};