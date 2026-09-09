#pragma once
#include <iostream>
#include "secure_memory.h"
#include "consts.h"

// collects the password from the user via terminal input
#ifdef __linux__
#include <termios.h>
#include <unistd.h>

constexpr size_t PASSWORD_BUF_SIZE = MAX_PASSWORD_LENGTH + 10 + 1;

namespace  getpasswd {
    inline char* getpasswd() {
        termios oldt{}, newt{};

        tcgetattr(STDIN_FILENO, &oldt);      // get current terminal settings
        newt = oldt;
        newt.c_lflag &= ~ECHO;               // disable echo
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);

        constexpr int max_input_length = PASSWORD_BUF_SIZE;
        char* buffer = secure_memory::secure_malloc<char>(max_input_length);
        std::cin.getline(buffer, max_input_length);

        tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // restore settings
        std::cout << std::endl;
        return buffer;
    }
}

#endif

#ifdef WIN32
#include <windows.h>

inline void get_password(std::string &str) {
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);

    std::getline(std::cin, str);

    SetConsoleMode(hStdin, mode); // restore
    std::cout << std::endl;
}

#endif
