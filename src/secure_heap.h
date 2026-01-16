// Uses OpenSSL's secure heap to allocate and free memory securely.
// This class initializes the secure heap upon construction and cleans it up upon destruction.

#pragma once
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace secure_heap{
    // initializes the secure heap
    inline int secure_heap_init(const size_t pool_size = 16 * 1024 * 1024, const size_t min_alloc = 4096){
        if(CRYPTO_secure_malloc_init(pool_size, min_alloc) != 1){
            return 1;
        }
        if(CRYPTO_secure_malloc_initialized() != 1){
            return 1;
        }
            return 0;
    }
    // securely allocates memory from the secure heap
    template<typename T>
    inline T* secure_malloc(const size_t size){
        void* ptr = OPENSSL_secure_malloc(size);
        if(!ptr){
            return nullptr;
        }
        return static_cast<T*>(ptr);
    }
    // securely frees memory allocated from the secure heap
    template<typename T>
    inline void secure_free(T* &ptr, const size_t size){
        if (ptr){
            OPENSSL_cleanse(ptr, size);
            OPENSSL_secure_free(ptr);
            ptr = nullptr;
        }
        
    }
    // allocators

    template<typename T>
    struct secure_alloc {
        using value_type = T;

        secure_alloc() noexcept = default;

        template<typename U>
        explicit secure_alloc(const secure_alloc<U>&) noexcept {}

        [[nodiscard]]
        T* allocate(const size_t n) {
            if(n == 0) {
                return nullptr;
            }
            if (n > static_cast<size_t>(-1) / sizeof(T)) {
                throw std::bad_alloc();
            }

            void* ptr = OPENSSL_secure_malloc(n * sizeof(T));
            if(!ptr){
                throw std::runtime_error("Failed to allocate memory from OpenSSL secure heap!");
            }
            return static_cast<T*>(ptr);
        }
        void deallocate(T* p, const size_t n) {
            if (!p) return;
            OPENSSL_cleanse(p, n * sizeof(T));
            OPENSSL_secure_free(p);
        }

        template<typename U>
        bool operator==(const secure_alloc<U>&) const noexcept { return true; }

        template<typename U>
        bool operator!=(const secure_alloc<U>&) const noexcept { return false; }
    };

};

// RAII

// TODO: implement the whole class properly
class secure_heap_raii{
    public:
        explicit secure_heap_raii(const size_t pool_size = 16 * 1024 * 1024, const size_t min_alloc = 4096){
            if(CRYPTO_secure_malloc_init(pool_size, min_alloc) != 1){
                throw std::runtime_error("Failed to initialize OpenSSL secure heap!");
            }
            if(CRYPTO_secure_malloc_initialized() != 1){
                throw std::runtime_error("Failed to initialize OpenSSL secure heap!");
            }
        }

        ~secure_heap_raii(){
            cleanup();
        }

        void* secure_malloc(const size_t size){
            ptr = OPENSSL_secure_malloc(size);
            if(!ptr){
                throw std::runtime_error("Failed to allocate memory from OpenSSL secure heap!");
            }
            return ptr;
        }

    private:
        void* ptr = nullptr;
        // size_t size = 0;

        void cleanup(){
            if(ptr){
                OPENSSL_secure_free(ptr);
                ptr = nullptr;
            }

        }

};