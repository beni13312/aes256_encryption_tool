#pragma once

#include "args.h"

namespace  cli{
    void help();
    Args get_args(int argc, char *argv[]);
};
