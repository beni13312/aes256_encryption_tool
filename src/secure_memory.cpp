#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdexcept>
#include "secure_memory.h"

namespace secure_memory{
    // initializes the secure alloc
    inline int secure_memory_init(const size_t pool_size, const size_t min_alloc){
        if(CRYPTO_secure_malloc_init(pool_size, min_alloc) != 1){
            return 1;
        }
        if(CRYPTO_secure_malloc_initialized() != 1){
            return 1;
        }
        return 0;
    }
    // securely allocates memory from the pool
    template<typename T>
    inline T* secure_malloc(const size_t size){
        void* ptr = OPENSSL_secure_malloc(sizeof(T) * size);
        if(!ptr){
            return nullptr;
        }
        return static_cast<T*>(ptr);
    }
    // securely frees memory allocated from the pool
    template<typename T>
    inline void secure_free(T* &ptr, const size_t size){
        if (ptr){
            OPENSSL_cleanse(ptr, sizeof(T) * size);
            OPENSSL_secure_free(ptr);
            ptr = nullptr;
        }

    }
}