#pragma once

#include "args.h"

class App{
    public:
    explicit App(Args  args);
    ~App();
    int run();

    private:
        Args args_;
};
