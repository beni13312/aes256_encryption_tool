// Uses OpenSSL's secure heap to allocate and free memory securely.
// This class initializes the secure heap upon construction and cleans it up upon destruction.

#pragma once

namespace secure_memory{
    // initializes the secure alloc
    int secure_memory_init(size_t pool_size = 16 * 1024 * 1024, size_t min_alloc = 4096);
    // securely allocates memory from the pool
    template<typename T>
    T* secure_malloc(size_t size);
    // securely frees memory allocated from the pool
    template<typename T>
    void secure_free(T* &ptr, size_t size);
}