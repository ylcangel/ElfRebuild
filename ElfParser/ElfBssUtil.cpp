/* 
 * File:   ElfBssUtil.cpp
 * Author: AngelToms
 * 
 */

#include "ElfBssUtil.h"
#include "../QupLog.h"

ElfBssUtil::ElfBssUtil(ElfParser& elfParser) : mElfParser(elfParser), mBssShdr(NULL),
mIsBssEmpty(false), mBssSize(0), mBssAddr(0), mBssOff(0) {
    init();
}

ElfBssUtil::~ElfBssUtil() {
}

Elf_Shdr* ElfBssUtil::getBssShdr() {
    return mBssShdr;
}

void ElfBssUtil::init() {
    Elf_Shdr* shdr = mElfParser.getShdrByShdrName(".bss");
    if (!shdr) {
        QUP_LOGI("[-] can not find bss section");
        exit(-1);
    }
    mBssAddr = shdr->sh_addr;
    mBssOff = shdr->sh_offset;
    mBssShdr = shdr;
    mBssSize = shdr->sh_size;
    QUP_LOGI("[*] bss off = 0x%.8x, addr = 0x%.8x, size = 0x%.8x", mBssOff, mBssAddr, mBssSize);

    if (mBssSize == 0) {
        mIsBssEmpty = true;
    }
}

bool ElfBssUtil::isBssEmpty() {
    return mIsBssEmpty;
}

size_t ElfBssUtil::getBssSize() {
    return mBssSize;
}

Elf_Off ElfBssUtil::getBssAddr() {
    return mBssAddr;
}

Elf_Off ElfBssUtil::getBssOff() {
    return mBssOff;
}

int ElfBssUtil::getBssShdrIndex() {
    static int index = 0;
    if (index == 0) {
        index = mElfParser.getShdrIndexByShdrName(".bss");
    }
    return index;
}
