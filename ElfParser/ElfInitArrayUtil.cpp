/* 
 * File:   ElfInitArrayUtil.cpp
 * Author: AngelToms
 * 
 */

#include "ElfInitArrayUtil.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "../QupLog.h"

ElfInitArrayUtil::ElfInitArrayUtil(ElfParser& elfParser) : mElfParser(elfParser),
mOldInitArrayShdr(NULL), mOldInitArray(NULL), mNewInitArray(NULL),
mOldInitArrayCount(0), mNewInitArrayCount(0), mOldInitArrayLen(0), mNewInitArrayLen(0),
mOldInitArrayVaddr(0), mOldInitArrayOff(0) {
    init();
}

ElfInitArrayUtil::~ElfInitArrayUtil() {
    if (mOldInitArray)
        delete mOldInitArray;
    if (mNewInitArray)
        delete mNewInitArray;
}

void ElfInitArrayUtil::init() {
    //Not find , it doesn't matter,i think compiler will give ELF a 4bit fill 0 data
    Elf_Shdr* shdr = mElfParser.getShdrByShdrName(".init_array");
    if (!shdr) {
        QUP_LOGI("[-] find .init.array section fail");
        exit(-1);
    }

    mOldInitArrayShdr = shdr;
    mOldInitArrayVaddr = mOldInitArrayShdr->sh_addr;
    mOldInitArrayOff = mOldInitArrayShdr->sh_offset;

    Elf_Dyn* d = mElfParser.getDynamicByDtTag(DT_INIT_ARRAYSZ);
    if (!d) {
        QUP_LOGI("[-] get DT_INIT_ARRAYSZ fail");
        exit(-1);
    }
    size_t size = d->d_un.d_val;
    QUP_LOGI("[*] old .init_array size = %u", size);
    mOldInitArrayLen = size;

    size_t count = mOldInitArrayLen / sizeof (Elf_Addr);
    QUP_LOGI("[*] init array count = %u", count);
    mOldInitArrayCount = count;

    int initArrayMemSize = mOldInitArrayCount * sizeof (void*);
    QUP_LOGI("[+] old init array len in mem = %d", initArrayMemSize);

    mOldInitArray = new size_t[mOldInitArrayCount];
    if (!mOldInitArray) {
        QUP_LOGI("[-] calloc old init array fail");
        exit(-1);
    }
    memset((u1*) mOldInitArray, 0, initArrayMemSize);
    QUP_LOGI("[+] init array off in file = 0x%.8x", mOldInitArrayShdr->sh_offset);
    u1* addr = (u1*) mElfParser.getElfBase() + mOldInitArrayShdr->sh_offset;
    memcpy(mOldInitArray, addr, initArrayMemSize);

}

void ElfInitArrayUtil::extendInitArray(int elementSize) {
    int ptrSize = sizeof (void*);
    size_t initArrayMemSize = elementSize * ptrSize + mOldInitArrayLen;
    mNewInitArrayLen = initArrayMemSize;
    QUP_LOGI("[*] new init array len in mem = %d", mNewInitArrayLen);
    mNewInitArray = new size_t[elementSize + mOldInitArrayCount];
    if (!mNewInitArray) {
        QUP_LOGI("[-] alloc new init array fail");
        exit(-1);
    }
    memset(mNewInitArray, 0, mNewInitArrayLen);
    size_t newSize = mNewInitArrayLen - mOldInitArrayLen;
    //copy old init array data
    memcpy(((u1*) mNewInitArray + newSize), mOldInitArray, mOldInitArrayLen);
    //new size = count + old count
    mNewInitArrayCount = elementSize + mOldInitArrayCount;
}

void ElfInitArrayUtil::setNewInitArrayData(size_t* newInitArray, int count) {
    QUP_LOGI("[*] add new init array ptr = 0x%.8x", *newInitArray);
    int ptrSize = sizeof (size_t*);
    int len = ptrSize * count;
    QUP_LOGI("[*] add new init array len = %d", len);
    memcpy(mNewInitArray, newInitArray, len);
}

void ElfInitArrayUtil::printInitArray(u1* initArray, int count) {
    QUP_LOGI("[+] init array size = %u", count);
    Elf_Addr* ea = (Elf_Addr*) initArray;
    for (int i = 0; i < count; i++) {
        QUP_LOGI("[+] %d init_array ptr = 0x%x", i, *(ea + i));
    }
}

void ElfInitArrayUtil::printOldInitArray() {
    printInitArray((u1*) mOldInitArray, mOldInitArrayCount);
}

void ElfInitArrayUtil::printNewInitArray() {
    printInitArray((u1*) mNewInitArray, mNewInitArrayCount);
}

Elf_Shdr* ElfInitArrayUtil::getOldInitArrayShdr() {
    return mOldInitArrayShdr;
}

bool ElfInitArrayUtil::isOldInitArrayWasNullVal() {
    if (mOldInitArrayCount == 1 && *mOldInitArray == 0)
        return true;
    return false;
}

size_t ElfInitArrayUtil::getOldInitArrayLen() {
    return mOldInitArrayLen;
}

size_t ElfInitArrayUtil::getNewInitArrayLen() {
    return mNewInitArrayLen;
}

size_t ElfInitArrayUtil::getOldInitArrayCount() {
    return mOldInitArrayCount;
}

size_t ElfInitArrayUtil::getNewInitArrayCount() {
    return mNewInitArrayCount;
}

size_t* ElfInitArrayUtil::getOldInitArray() {
    return mOldInitArray;
}

size_t* ElfInitArrayUtil::getNewInitArray() {
    return mNewInitArray;
}

Elf_Addr ElfInitArrayUtil::getOldInitArrayVaddr() {
    return mOldInitArrayVaddr;
}

Elf_Off ElfInitArrayUtil::getOldInitArrayOff() {
    return mOldInitArrayOff;
}


