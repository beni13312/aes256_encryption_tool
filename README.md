# AES-256 Encryption tool
Fast file and folder encryption program using AES-256-GCM

## Features
- File/folder encryption and decryption
- KDF based password authentication
- Random file name generation

## Encryption/decryption
`user password -> KDF -> key -> file/folder`

| Structure of encrypted file |
|:----------------------------|
| **base IV**                 | 
| **filename size**           | 
| **filename (encrypted)**    | 
| **encrypted data size**     | 
| **encrypted data**          | 
| **AEAD tag**                |

## CMake build Debug

`cmake --build build --config Debug --target all -j 12 --`

## CMake build Release

`cmake --build build --config Release --target all -j 12 --`
