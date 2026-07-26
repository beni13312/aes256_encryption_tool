#include "secure_heap.h"


SecureHeap::SecureHeap(const size_t pool_size, const size_t min_alloc){
    if(CRYPTO_secure_malloc_init(pool_size, min_alloc) != 1){
        throw std::runtime_error("Failed to initialize OpenSSL secure malloc!");
    }
    if(CRYPTO_secure_malloc_initialized() != 1){
        throw std::runtime_error("Failed to initialize OpenSSL secure malloc!");
    }
}

SecureHeap::~SecureHeap(){
    cleanup();
}

void* SecureHeap::secure_malloc(const size_t size){
    ptr = OPENSSL_secure_malloc(size);
    if(!ptr){
        throw std::runtime_error("Failed to allocate memory from OpenSSL secure heap!");
    }
    return ptr;
}

void SecureHeap::cleanup(){
    if(ptr){
        OPENSSL_secure_free(ptr);
        ptr = nullptr;
    }

}

template<typename T>
struct SecureHeap::secure_alloc {
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