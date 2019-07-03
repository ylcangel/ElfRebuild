#include "Xor.h"

void XOR(void* base, int len, unsigned factor) {
    char* addr = (char*) base;
    for(int i = 0 ; i < len ; i++)
        *(addr + i) = *(addr + i) ^ factor;
}
