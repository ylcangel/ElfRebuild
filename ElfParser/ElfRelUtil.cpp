/* 
 * File:   ElfRelUtil.cpp
 * Author: AngelToms
 * 
 */

#include "ElfRelUtil.h"
#include <stdlib.h>
#include <string.h>

#include "../QupLog.h"

ElfRelUtil::ElfRelUtil(ElfParser& elfParser)
: mElfParser(elfParser), mRelDynShdr(NULL), mRelPltShdr(NULL),
mRelDyn(NULL), mRelPlt(NULL), mRelDynAddr(0), mRelDynOff(0), mNewReldyn(NULL) {
    init();
}

ElfRelUtil::~ElfRelUtil() {
    if (mNewReldyn)
        delete mNewReldyn;
}

void ElfRelUtil::init() {
    Elf_Shdr* shdr = mElfParser.getShdrByShdrName(".rel.plt");
    mRelPltShdr = shdr;
    if (!shdr) {
        QUP_LOGI("[+] this elf has no .rel.plt");
    } else {
#ifdef __LP64__
        mRelPlt = (Elf_RelA*) (mElfParser.getElfBase() + shdr->st_value);
#else
        mRelPlt = (Elf_Rel*) (mElfParser.getElfBase() + shdr->sh_offset);
#endif
    }
    shdr = mElfParser.getShdrByShdrName(".rel.dyn");
    mRelDynShdr = shdr;
    if (!shdr) {
        QUP_LOGI("[+] this elf has no .rel.dyn");
    } else {
#ifdef __LP64__
        mRelDyn = (Elf_RelA*) (mElfParser.getElfBase() + shdr->sh_offset);
#else
        mRelDyn = (Elf_Rel*) (mElfParser.getElfBase() + shdr->sh_offset);
#endif
        mRelDynAddr = mRelDynShdr->sh_addr;
        mRelDynOff = mRelDynShdr->sh_offset;
        size_t nReldynSz = mRelDynShdr->sh_size;
        QUP_LOGI("[*] old rel dyn size = %.8x", nReldynSz);
        //add new init array first addr
        nReldynSz += mRelDynShdr->sh_entsize;
        QUP_LOGI("[*] new rel dyn size = %.8x", nReldynSz);
        mNewReldyn = new u1[nReldynSz];
        if (!mNewReldyn) {
            QUP_LOGI("[-] calloc new rel dyn fail");
            exit(-1);
        }
        memset(mNewReldyn, 0, nReldynSz);
        memcpy(mNewReldyn + mRelDynShdr->sh_entsize, (u1*) mRelDyn, mRelDynShdr->sh_size);
    }
}

Elf_Shdr* ElfRelUtil::getRelDynShdr() {
    return mRelDynShdr;
}

Elf_Shdr* ElfRelUtil::getRelPltShdr() {
    return mRelPltShdr;

}
#ifdef __LP64__
Elf_RelA*
#else

Elf_Rel*
#endif
ElfRelUtil::getRelDyn() {
    return mRelDyn;
}
#ifdef __LP64__
Elf_RelA*
#else

Elf_Rel*
#endif
ElfRelUtil::getRelPlt() {
    return mRelPlt;
}

void ElfRelUtil::printRelDyn() {
    if (mRelDynShdr) {
        int count = mRelDynShdr->sh_size / mRelDynShdr->sh_entsize;
        QUP_LOGI("[*] .rel.dyn elements size = %d", count);

        for (int i = 0; i < count; i++) {
#ifdef __LP64__
            Elf_RelA * rel = mRelDyn + i;
#else
            Elf_Rel* rel = mRelDyn + i;
#endif
            QUP_LOGI("[*] .rel.dyn [%d] = 0x%.8x", i, rel->r_offset);
        }
    }
}

void ElfRelUtil::printRelPlt() {
    if (mRelPltShdr) {
        int count = mRelPltShdr->sh_size / mRelPltShdr->sh_entsize;
        QUP_LOGI("[*] .rel.plt elements size = %d", count);

        for (int i = 0; i < count; i++) {
#ifdef __LP64__
            Elf_RelA * rel = mRelPlt + i;
#else
            Elf_Rel* rel = mRelPlt + i;
#endif
            QUP_LOGI("[*] .rel.plt [%d] = 0x%.8x", i, rel->r_offset);
        }
    }
}

u1* ElfRelUtil::getNewRelDyn() {
    return mNewReldyn;
}

void ElfRelUtil::setNewRelDynInitArray(Elf32_Addr offset) {
    QUP_LOGI("[*] REL init array off = 0x%.8x", offset);
#ifdef __LP64__
    Elf_RelA rel;
#else
    Elf_Rel rel;
#endif
    memset(&rel, 0, sizeof (rel));
#ifdef __LP64__
    rel.r_offset = offset;
    rel.r_info = ELF32_R_INFO(0, R_ARM_RELATIVE); //nest relation
    rel.r_addend = 0; //TODO;
#else
    rel.r_offset = offset;
    rel.r_info = ELF32_R_INFO(0, R_ARM_RELATIVE); //nest relation
#endif
    memcpy(mNewReldyn, &rel, sizeof (rel));
}

size_t ElfRelUtil::getNewReldynLen() {
    static size_t size = 0;
    if (size == 0) {
        QUP_LOGI("[*] old reldyn size = %u, count = %u", mRelDynShdr->sh_size, (mRelDynShdr->sh_size / mRelDynShdr->sh_entsize));
        size = mRelDynShdr->sh_size + mRelDynShdr->sh_entsize; //add new init_array
        QUP_LOGI("[*] new reldyn size = %u, count = %u", size, size / mRelDynShdr->sh_entsize);
    }
    return size;
}

Elf_Addr ElfRelUtil::getReldynAddr() {
    return mRelDynAddr;
}

Elf_Off ElfRelUtil::getReldynOff() {
    return mRelDynOff;
}
