cmake_minimum_required(VERSION 3.10)
project(encryption_proj VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(encrypt_tool
		src/main.cpp
		#src/encrypt.cpp
		#src/decrypt.cpp
        src/secure_memory.h
		src/consts.h
		src/getpasswd.h
		src/cli.cpp
		src/cli.h
		src/args.h
		src/app.cpp
		src/app.h
)
target_compile_options(encrypt_tool PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_include_directories(encrypt_tool PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(encrypt_tool PRIVATE OpenSSL::Crypto OpenSSL::SSL)

find_package(PkgConfig QUIET)
set(ARGON2_LIB_FOUND FALSE)
if(PkgConfig_FOUND)
	pkg_check_modules(ARGON2_PKG QUIET IMPORTED_TARGET argon2)
	if(ARGON2_PKG_FOUND)
		target_link_libraries(encrypt_tool PRIVATE PkgConfig::ARGON2_PKG)
		set(ARGON2_LIB_FOUND TRUE)
	endif()
endif()

if(NOT ARGON2_LIB_FOUND)
	find_library(ARGON2_LIB NAMES argon2 libargon2)
	if(ARGON2_LIB)
		target_link_libraries(encrypt_tool PRIVATE ${ARGON2_LIB})
		set(ARGON2_LIB_FOUND TRUE)
	endif()
endif()

if(NOT ARGON2_LIB_FOUND)
	message(FATAL_ERROR "Argon2 library not found.")
endif()

