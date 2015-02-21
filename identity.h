#ifndef _IDENTITY_H
#define _IDENTITY_H

#include <string>
#include <vector>
#include "minimal/stdlib.h"

class Identity
{
void *impl;
public:
    Identity(const std::string &name);
    bool found();
    std::vector<uint8_t> signMessage(const char *msg, int len);
};

#endif//_IDENTITY_H
