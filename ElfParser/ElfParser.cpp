#include "ElfParser.h"

#include "../QupLog.h"
#include "../Utils/StringUtil.h"
#include "../Crypt/Xor.h"
#include "../Crypt/StrangeChar.h"
#include "../Crypt/AsciiChange.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

u1* ElfParser::getElfBase() {
    return mElfBase;
}

Elf_Ehdr* ElfParser::getElfHeader() {
    return mElfHeader;
}

Elf_Phdr* ElfParser::getElfPhdrTab() {
    return mElfPhdrBase;
}

Elf_Shdr* ElfParser::getElfShdrTab() {
    return mElfShdrBase;
}

Elf_Dyn* ElfParser::getElfDynamic() {
    return mDynymicBase;
}

Elf_Sym* ElfParser::getShdrDynsym() {
    return mShdrDynsymBase;
}

char* ElfParser::getShdrDynstr() {
    return mShdrDynstrBase;
}

Elf_Ehdr* ElfParser::initElfHeader() {
    return (Elf_Ehdr*) mElfBase;
}

Elf_Phdr* ElfParser::initElfPhdrTab() {
    return (Elf_Phdr*) ((u1*) mElfBase + mElfHeader->e_phoff);
}

Elf_Shdr* ElfParser::initElfShdrTab() {
    return (Elf_Shdr*) ((u1*) mElfBase + mElfHeader->e_shoff);
}

int ElfParser::getShdrNum() {
    return ((Elf_Ehdr*) mElfBase)->e_shnum;
}

int ElfParser::getPhdrNum() {
    return ((Elf_Ehdr*) mElfBase)->e_phnum;
}

size_t ElfParser::getFileLen() {
    return mElfFileLen;
}

char* ElfParser::getShdrNameByShdr(Elf_Shdr* shdr) {
    return getShdrNameFromShdrStrtab(shdr->sh_name);
}

char* ElfParser::getShdrNameFromShdrStrtab(u4 index) {
    static u1* strBase = NULL;
    if (!strBase) {
        Elf_Shdr* strSection = mElfShdrBase + mElfHeader->e_shstrndx;
        strBase = (u1*) (mElfBase + strSection->sh_offset);
    }

    char* str = (char*) (strBase + index);
#ifdef DEBUG_ALL
    QUP_LOGI("[*] search string : %s", str);
#endif
    return str;
}

Elf_Dyn* ElfParser::initElfDynamic() {
    for (int i = 0; i < mElfHeader->e_phnum; i++) {
        Elf_Phdr* phdr = mElfPhdrBase + i;
        if (phdr->p_type == PT_DYNAMIC) {
            return ((Elf_Dyn*) ((u1*) mElfBase + phdr->p_offset));
        }
    }
    return NULL;
}

Elf_Dyn* ElfParser::getDynamicByDtTag(Elf_Sword tag) {
    size_t dynamicCount = 0;
    static Elf_Phdr* phdrDyn = NULL;

    if (!phdrDyn) {
        for (int i = 0; i < mElfHeader->e_phnum; i++) {
            Elf_Phdr* phdr = mElfPhdrBase + i;
            if (phdr->p_type == PT_DYNAMIC) {
                phdrDyn = phdr;
                break;
            }
        }
    }

    dynamicCount = (unsigned) (phdrDyn->p_memsz / sizeof (Elf_Dyn));
#ifdef DEBUG_ALL
    QUP_LOGI("[*] dynamic section size = %u", dynamicCount);
#endif
    for (int i = 0; i < dynamicCount; i++) {
        Elf_Dyn* tmpDyn = mDynymicBase + i;
        if (tmpDyn->d_tag == tag) {
            return tmpDyn;
        }
    }
    QUP_LOGI("[+] this elf dont have tag type = %d section", tag);
    return NULL;
}

Elf_Shdr* ElfParser::getShdrByShdrName(const char* name) {
    for (int i = 0; i < mElfHeader->e_shnum; i++) {
        Elf_Shdr* shdr = mElfShdrBase + i;
        const char* shdrName = (const char*) getShdrNameFromShdrStrtab(shdr->sh_name);
#ifdef DEBUG_ALL
        QUP_LOGI("[*] shdr name: %s, index: %d", shdrName, i);
#endif
        if (strcmp(shdrName, name) == 0) {
            return shdr;
        }
    }
    QUP_LOGI("[+] this elf dont have section name of %s", name);
    return NULL;
}

int ElfParser::getShdrIndexByShdrName(const char* name) {
    for (int i = 0; i < mElfHeader->e_shnum; i++) {
        Elf_Shdr* shdr = mElfShdrBase + i;
        const char* shdrName = (const char*) getShdrNameFromShdrStrtab(shdr->sh_name);
#ifdef DEBUG_ALL
        QUP_LOGI("[*] shdr name: %s, index: %d", shdrName, i);
#endif
        if (strcmp(shdrName, name) == 0) {
            return i;
        }
    }
    QUP_LOGI("[+] this elf dont have section name of %s", name);
    return -1;
}

Elf_Shdr* ElfParser::getShdrByShdrIndex(int index) {
    if (mElfHeader->e_shnum < index) {
        QUP_LOGI("[-] index is larger than e_shnum");
        return NULL;
    }

    return mElfShdrBase + index;
}

Elf_Sym* ElfParser::initShdrDynsym() {
    Elf_Shdr* shdr = getShdrByShdrName(".dynsym");

#ifdef __CYGWIN__
    if (!shdr) {
        QUP_LOGI("[-] find .dynsym section fail");
        exit(-1);
    }
#else
    assert(!shdr);
#endif
    Elf_Sym* dynSym = (Elf_Sym*) ((u1*) mElfBase + shdr->sh_offset);
    size_t dynsymSize = shdr->sh_size;
    mDynSymCount = dynsymSize / shdr->sh_entsize;
    QUP_LOGI("[*] dyn sym addr = 0x%.8x, sym tab size = %u, entry size = %u",
            shdr->sh_addr, dynsymSize, mDynSymCount);

    return dynSym;
}

int ElfParser::getSymCount() {
    return mDynSymCount;
}

char* ElfParser::initShdrDynstr() {
    Elf_Shdr* strshdr = getShdrByShdrName(".dynstr");
#ifdef __CYGWIN__
    if (!strshdr) {
        QUP_LOGI("[-] find .dynstr section fail");
        exit(-1);
    }
#else
    assert(!strshdr);
#endif
    char* dynStrBase = (char*) (mElfBase + strshdr->sh_offset);
    QUP_LOGI("[*] dyn str addr = 0x%.8x", strshdr->sh_addr);
    return dynStrBase;
}

bool ElfParser::initIsLittleEndian() {
    return (mElfHeader->e_ident[EI_DATA] == 1) ? true : false;
}

bool ElfParser::getIsLittleEndian() {
    return mIsLittleEndian;
}
