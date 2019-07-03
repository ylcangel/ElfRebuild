/* 
 * File:   Cryptor.cpp
 * Author: AngelToms
 * 
 */

#include "Cryptor.h"

#include "../QupLog.h"
#include "../Types.h"
#include "Xor.h"
#include "StrangeChar.h"
#include "AsciiChange.h"

bool CryptFactory::encrypt(u1* base, int len, void* addition, EncryptType type) {
    if (!base) {
        QUP_LOGI("[-] base was null");
        return false;
    }
    switch (type) {
        case XorConvert:
            XOR((void*) base, len, *((u4*) addition));
            return true;
        case StrangeConvert:
            simpleChange((char*) base, '-', *(int*) addition);
            return true;
        case AsciiChange:
            asciiChange((char*) base);
            return true;
        default:
            break;
    }
    return false;
}

