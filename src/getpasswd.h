#pragma once
#include <iostream>

// collects the password from the user via terminal input
#ifdef __linux__
#include <termios.h>
#include <unistd.h>

namespace  getpasswd {
    inline void getpasswd(std::string &str) {
        termios oldt{}, newt{};

        tcgetattr(STDIN_FILENO, &oldt);      // get current terminal settings
        newt = oldt;
        newt.c_lflag &= ~ECHO;               // disable echo
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);

        std::getline(std::cin, str);

        tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // restore settings
        std::cout << std::endl;
    }
};

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
