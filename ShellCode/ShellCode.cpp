/* 
 * File:   ShellCode.cpp
 * Author: AngelToms
 * 
 */

#include "ShellCode.h"

#include "../QupLog.h"
#include "../HexLog.h"

#include <stdlib.h>
#include <string.h>

extern char enc_dynstr_shellcode[];
extern char enc_rodata_shellcode[];

ShellCode::ShellCode(ShellCodeType type, bool flag) : mShellcode(NULL), mSize(0),
mNewShellcode(NULL)  {
    switch (type) {
        case EncryptDynstr:
            mShellcode = (u1*) enc_dynstr_shellcode;
            break;
        case EncryptRodata:
            mShellcode = (u1*) enc_rodata_shellcode;
            break;
        default:
            break;
    }
}

ShellCode::~ShellCode() {
    if (mNewShellcode) {
        delete mNewShellcode;
        mNewShellcode = NULL;
    }
}

void ShellCode::setParams(std::map<std::string, Elf_Off> params) {
    if(params.size() <= 0) {
        QUP_LOGI("[-] shellcode params were empyt");
        exit(-1);
    }
    mParams = params;
}

u1* ShellCode::getShellcode() {
    return mNewShellcode;
}

size_t ShellCode::getShellcodeSize() {
    return mSize;
}

void ShellCode::printNewShellCode() {
//    HEX_LOG(mNewShellcode, mSize);
}
