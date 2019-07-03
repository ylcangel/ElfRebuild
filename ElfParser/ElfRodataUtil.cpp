/* 
 * File:   ElfRodataUtil.cpp
 * Author: angel-toms
 * 
 */

#include "ElfRodataUtil.h"
#include "../Crypt/Cryptor.h"
#include "../QupLog.h"

ElfRodataUtil::ElfRodataUtil(ElfParser& elfParser) : mElfParser(elfParser),
mRodataShdr(NULL), mIsRodataEmpty(false), mRodataSize(0), mRodataAddr(0),
mRodataOff(0), mRodataBase(NULL) {
    init();
}

ElfRodataUtil::~ElfRodataUtil() {
}

void ElfRodataUtil::init() {
    Elf_Shdr* shdr = mElfParser.getShdrByShdrName(".rodata");
    if (!shdr) {
        mIsRodataEmpty = true;
        QUP_LOGI("[+] this elf file doesn't have rodata section");
        return;
    }
    mRodataShdr = shdr;
    mRodataSize = shdr->sh_size;
    mRodataAddr = shdr->sh_addr;
    mRodataOff = shdr->sh_offset;
    
    mRodataBase = mElfParser.getElfBase() + mRodataOff;
    encrptyRodata();
}

bool ElfRodataUtil::isRodataEmpty() {
    return mIsRodataEmpty;
}

Elf_Addr ElfRodataUtil::getRodataAddr() {
    return mRodataAddr;
}

Elf_Off ElfRodataUtil::getRodataOff() {
    return mRodataOff;
}

size_t ElfRodataUtil::getRodataSize() {
    return mRodataSize;
}

void ElfRodataUtil::encrptyRodata() {
    if (!mIsRodataEmpty) {
        CryptFactory crypt;
        int factor = XOR_FACTORY;
        crypt.encrypt((u1*) mRodataBase, mRodataSize, (void*) &factor, XorConvert);
    }
}

