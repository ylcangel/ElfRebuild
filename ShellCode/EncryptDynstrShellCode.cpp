/* 
 * File:   EncryptDynstrShellCode.cpp
 * Author: angel-toms
 * 
 */

#include "EncryptDynstrShellCode.h"

#include "EncDynstrShellcode.h"
#include "../QupLog.h"

#include <stdlib.h>
#include <string.h>
#include <string>
#include <map>

EncryptDynstrShellCode::EncryptDynstrShellCode(ShellCodeType type, bool isHasNewDynstr) :
ShellCode(type, isHasNewDynstr), mIsHasNewDynstr(isHasNewDynstr), mShellcodeAddr(0),
        mDynstrAddr(0), mDynstrLen(0)/*, mDynsymAddr(0)*/,
mOldDynstrAddr(0) {
    //#ifdef __LP64__
    //#else
    //#ifdef __x86__
    //#endif
    //#ifdef __arm__
    if (mIsHasNewDynstr)
        mSize = scdynSZ() + 0x14; //末尾20个字节分别记录着需要的地址
    else
        mSize = scdynSZ() + 0x10;
    QUP_LOGI("[*] new dynstr shell code size = %u", mSize);
    mNewShellcode = new u1[mSize];
    if (!mNewShellcode) {
        QUP_LOGI("[-] alloc new shell code fail");
        exit(-1);
    }
    memset(mNewShellcode, 0, mSize);
    if (mIsHasNewDynstr)
        memcpy(mNewShellcode, mShellcode, (mSize - 0x14));
    else
        memcpy(mNewShellcode, mShellcode, (mSize - 0x10));
    //#endif
    //#endif
}

EncryptDynstrShellCode::~EncryptDynstrShellCode() {
}

void EncryptDynstrShellCode::resolveParams() {
    if (mParams.size() < 4) {
        QUP_LOGI("[-] enc dynstr params were not 4");
        exit(-1);
    }

    std::map<std::string, Elf_Off>::iterator it;
    for (it = mParams.begin(); it != mParams.end(); it++) {
        if (it->first.compare(std::string("shellcodeaddr")) == 0) {
            QUP_LOGI("[*] param shellcodeaddr = 0x%.8x", it->second);
            setShellcodeAddr(it->second);
            continue;
        }
        if (it->first.compare(std::string("dynstraddr")) == 0) {
            QUP_LOGI("[*] param dynstraddr = 0x%.8x", it->second);
            setDynstrAddr(it->second);
            continue;
        }
        if (it->first.compare(std::string("olddynstraddr")) == 0) {
            QUP_LOGI("[*] param olddynstraddr = 0x%.8x", it->second);
            setOldDynstrAddr(it->second);
            continue;
        }
        if (it->first.compare(std::string("dynstrlen")) == 0) {
            QUP_LOGI("[*] param dynstrlen = 0x%.8x", (size_t) it->second);
            setDynstrLength((size_t) it->second);
            continue;
        }
    }
}

void EncryptDynstrShellCode::setShellcodeAddr(Elf_Off shellcodeAddr) {
    mShellcodeAddr = shellcodeAddr;
}

void EncryptDynstrShellCode::setDynstrAddr(Elf_Off dynsymAddr) {
    mDynstrAddr = dynsymAddr;
}

void EncryptDynstrShellCode::setOldDynstrAddr(Elf_Off oldDynsymAddr) {
    mOldDynstrAddr = oldDynsymAddr;
}

void EncryptDynstrShellCode::setDynstrLength(int dynstrLen) {
    mDynstrLen = dynstrLen;
}

void EncryptDynstrShellCode::appendDataInShellcodeTail() {
    QUP_LOGI("[*] append data after shell code");
    //#ifdef __LP64__
    //#else
    //#ifdef __x86__
    //#endif
    //#ifdef __arm__
    size_t sz = 0;
    if (mIsHasNewDynstr)
        sz = mSize - 0x14;
    else
        sz = mSize - 0x10;
    u1* p = mNewShellcode + sz;
    int tmp = sizeof (mShellcodeAddr);
    memcpy(p, &mShellcodeAddr, tmp);
    p += tmp;
    tmp = sizeof (mDynstrAddr);
    memcpy(p, &mDynstrAddr, tmp);
    p += tmp;
    if (mIsHasNewDynstr) {
        tmp = sizeof (mOldDynstrAddr);
        memcpy(p, &mOldDynstrAddr, tmp);
        p += tmp;
    }
    tmp = sizeof (mDynstrLen);
    memcpy(p, &mDynstrLen, tmp);

    //TODO;
    //    p += tmp;
    //    tmp = sizeof (mDynsymAddr);
    //    memcpy(p, &mDynsymAddr, tmp);

    //#endif
    //#endif
}

