/* 
 * File:   EncryptRodataShellCode.cpp
 * Author: angel-toms
 * 
 */

#include "EncryptRodataShellCode.h"

#include "EncRodataShellcode.h"
#include "../QupLog.h"

#include <string.h>
#include <stdlib.h>

EncryptRodataShellCode::EncryptRodataShellCode(ShellCodeType type, bool flag) :
ShellCode(type, flag), mShellcodeAddr(0), mRodataAddr(0), mRodataLen(0) {
    //#ifdef __LP64__
    //#else
    //#ifdef __x86__
    //#endif
    //#ifdef __arm__
    mSize = scrodataSZ() + 0xc;
    QUP_LOGI("[*] new rodata shell code size = %u", mSize);
    mNewShellcode = new u1[mSize];
    if (!mNewShellcode) {
        QUP_LOGI("[-] alloc new shell code fail");
        exit(-1);
    }
    memset(mNewShellcode, 0, mSize);
    memcpy(mNewShellcode, mShellcode, (mSize - 0xc));
    //#endif
    //#endif
}

EncryptRodataShellCode::~EncryptRodataShellCode() {
}

void EncryptRodataShellCode::appendDataInShellcodeTail() {
    QUP_LOGI("[*] append data after shell code");
    //#ifdef __LP64__
    //#else
    //#ifdef __x86__
    //#endif
    //#ifdef __arm__
    size_t sz = mSize - 0xc;
    u1* p = mNewShellcode + sz;
    int tmp = sizeof (mShellcodeAddr);
    memcpy(p, &mShellcodeAddr, tmp);
    p += tmp;
    tmp = sizeof (mRodataAddr);
    memcpy(p, &mRodataAddr, tmp);
    p += tmp;
    tmp = sizeof (mRodataLen);
    memcpy(p, &mRodataLen, tmp);
    //#endif
    //#endif
}

void EncryptRodataShellCode::resolveParams() {
    if (mParams.size() < 3) {
        QUP_LOGI("[-] enc rodata params were not 3");
        exit(-1);
    }

    std::map<std::string, Elf_Off>::iterator it;
    for (it = mParams.begin(); it != mParams.end(); it++) {
        if (it->first.compare(std::string("shellcodeaddr")) == 0) {
            QUP_LOGI("[*] param shellcodeaddr = 0x%.8x", it->second);
            setShellcodeAddr(it->second);
            continue;
        }
        if (it->first.compare(std::string("rodataaddr")) == 0) {
            QUP_LOGI("[*] param rodataaddr = 0x%.8x", it->second);
            setRodataAddr(it->second);
            continue;
        }

        if (it->first.compare(std::string("rodatalen")) == 0) {
            QUP_LOGI("[*] param rodatalen = 0x%.8x", (size_t) it->second);
            setRodatalen((size_t) it->second);
            continue;
        }
    }
}

void EncryptRodataShellCode::setShellcodeAddr(Elf_Off addr) {
    mShellcodeAddr = addr;
}

void EncryptRodataShellCode::setRodataAddr(Elf_Off addr) {
    mRodataAddr = addr;
}

void EncryptRodataShellCode::setRodatalen(size_t len) {
    mRodataLen = len;
}