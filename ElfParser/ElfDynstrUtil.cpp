/* 
 * File:   ElfDynstrUtil.cpp
 * Author: AngelToms
 * 
 */
#include "ElfDynstrUtil.h"

#include <vector>
#include <map>
#include <string.h>

#include "../Utils/StringUtil.h"
#include "../QupLog.h"
#include "../Crypt/Cryptor.h"

ElfDynstrUtil::ElfDynstrUtil(ElfParser& elfParser, bool isConfuse,
        bool isConfuseAll) : mElfParser(elfParser),
mDynstrBase(NULL), mDynstrShdrLen(0), mNewDynstr(NULL), mIsConfuse(isConfuse),
mIsNeedToConfuse(false), mIsConfuseAll(isConfuseAll),
mDynstrOff(0), mDynstrAddr(0) {
    init();
}

ElfDynstrUtil::~ElfDynstrUtil() {
    mAllExportTabStrs.clear();
    mNeedExpTabStrs.clear();
    mChangedExpTabStrs.clear();
    if (mNewDynstr) {
        delete mNewDynstr;
        mNewDynstr = NULL;
    }
}

void ElfDynstrUtil::init() {
    mAllExportTabStrs = std::vector<std::string>();
    mNeedExpTabStrs = std::vector<std::string>();
    mChangedExpTabStrs = std::vector<std::string>();

    Elf_Shdr* shdr = mElfParser.getShdrByShdrName(".dynstr");
    if (!shdr) {
        QUP_LOGI("[-] this elf file has no .dynstr section");
        mIsNeedToConfuse = false;
        mIsConfuseAll = false;
        return;
    }

    mDynstrShdr = shdr;
    mDynstrShdrLen = mDynstrShdr->sh_size;
    QUP_LOGI("[*] dynstr size = %u", mDynstrShdrLen);
    mDynstrOff = mDynstrShdr->sh_offset;
    mDynstrAddr = mDynstrShdr->sh_addr;

    initAllVectors();
    if (mNeedExpTabStrs.size() > 0)
        mIsNeedToConfuse = true;

    if (mIsNeedToConfuse) {
        mNewDynstr = new u1[mDynstrShdrLen];
        if (!mDynstrShdrLen) {
            QUP_LOGI("[-] alloc new dynstr fail");
            exit(-1);
        }
        memcpy(mNewDynstr, mDynstrBase, mDynstrShdrLen);
        if (mIsConfuseAll) {
            encryptOldDynstr();
            confuseNewExportTab();
        } else {
            confuseOldExportTab();
        }
    }
}

bool ElfDynstrUtil::confuseOldExportTab() {
    if (mIsNeedToConfuse > 0 && mIsConfuse) {
        Elf_Sym* dynsym = mElfParser.getShdrDynsym();
        u1* strtab = mDynstrBase;
        for (int i = 0; i < mElfParser.getSymCount(); i++) {
            Elf_Sym* sym = dynsym + i;
            //import symtab
            if (sym->st_shndx == STN_UNDEF)
                continue;
            const char* name = (const char*) (strtab + sym->st_name);
            //filter like __gnu_xxxx, _Unwind_xxxx, import sym tab,
            //ads sym,  restore_core_regs
            if (isBeginWith(name, "__", 2) || isBeginWith(name, "_Unwind_", 8) ||
                    sym->st_shndx == SHN_ABS || strcmp("restore_core_regs", name) == 0
                    || strcmp("JNI_OnLoad", name) == 0) {
                continue;
            }
#ifdef DEBUG_ALL
            QUP_LOGI("[*] sym name        = %s", name);
#endif
            CryptFactory crypt;
            int factor = XOR_FACTORY;
            crypt.encrypt((u1*) name, strlen(name), (void*) &factor, XorConvert);
#ifdef DEBUG_ALL
            QUP_LOGI("[*] sym change name = %s", name);
#endif
            mChangedExpTabStrs.push_back(std::string(name));
        }
        return true;
    }
    QUP_LOGI("[+] no sys need to confuse");
    return false;
}

bool ElfDynstrUtil::confuseNewExportTab() {
    if (mIsNeedToConfuse > 0 && mIsConfuse) {
        Elf_Sym* dynsym = mElfParser.getShdrDynsym();
        u1* strtab = mNewDynstr;
        for (int i = 0; i < mElfParser.getSymCount(); i++) {
            Elf_Sym* sym = dynsym + i;
            //import symtab
            if (sym->st_shndx == STN_UNDEF)
                continue;
            const char* name = (const char*) (strtab + sym->st_name);
            //filter like __gnu_xxxx, _Unwind_xxxx, import sym tab,
            //ads sym,  restore_core_regs
            if (isBeginWith(name, "__", 2) || isBeginWith(name, "_Unwind_", 8) ||
                    sym->st_shndx == SHN_ABS || strcmp("restore_core_regs", name) == 0
                    || strcmp("JNI_OnLoad", name) == 0) {
                continue;
            }
#ifdef DEBUG_ALL
            QUP_LOGI("[*] new sym name        = %s", name);
#endif
            CryptFactory crypt;
            crypt.encrypt((u1*) name, 0/*NOT NEED*/, NULL/*NOT NEED*/, AsciiChange);
#ifdef DEBUG_ALL
            QUP_LOGI("[*] new sym change name = %s", name);
#endif
            mChangedExpTabStrs.push_back(std::string(name));
        }
        return true;
    }
    QUP_LOGI("[+] no sys need to confuse");
    return false;
}

void ElfDynstrUtil::initAllVectors() {
    Elf_Sym* dynsym = mElfParser.getShdrDynsym();
    u1* strtab = (u1*) mElfParser.getShdrDynstr();
    mDynstrBase = strtab;
    for (int i = 0; i < mElfParser.getSymCount(); i++) {
        Elf_Sym* sym = dynsym + i;
        //import symtab
        if (sym->st_shndx == STN_UNDEF)
            continue;
        const char* name = (const char*) (strtab + sym->st_name);
        mAllExportTabStrs.push_back(std::string(name));
        //filter like __gnu_xxxx, _Unwind_xxxx, import sym tab,
        //ads sym,  restore_core_regs
        if (isBeginWith(name, "__", 2) || isBeginWith(name, "_Unwind_", 8) ||
                sym->st_shndx == SHN_ABS || strcmp("restore_core_regs", name) == 0 ||
                strcmp("JNI_OnLoad", name) == 0) {
            continue;
        }
        mNeedExpTabStrs.push_back(std::string(name));
    }
}

void ElfDynstrUtil::printAllStr() {
    char* p = (char*) mDynstrBase;
    int j = 0;
    for (int i = 1; i < mDynstrShdr->sh_size; j++) {
        QUP_LOGI("[*] [%d] str = %s", j, p + i);
        i += (strlen(p + i) + 1);
    }
}

void ElfDynstrUtil::printExportStr() {
    Elf_Sym* dynsym = mElfParser.getShdrDynsym();
    u1* strtab = (u1*) mElfParser.getShdrDynstr();
    int j = 0;
    for (int i = 0; i < mElfParser.getSymCount(); i++) {
        Elf_Sym* sym = dynsym + i;
        const char* name = (const char*) (strtab + sym->st_name);
        if (sym->st_shndx == STN_UNDEF)
            continue;
        QUP_LOGI("[*] export [%d] = %s", j++, name);
    }
}

void ElfDynstrUtil::printImportStr() {
    Elf_Sym* dynsym = mElfParser.getShdrDynsym();
    u1* strtab = (u1*) mElfParser.getShdrDynstr();
    int j = 0;
    for (int i = 0; i < mElfParser.getSymCount(); i++) {
        Elf_Sym* sym = dynsym + i;
        const char* name = (const char*) (strtab + sym->st_name);
        if (sym->st_shndx == STN_UNDEF) {
            if (name != NULL)
                QUP_LOGI("[*] import [%d] = %s", j++, name);
        }
    }
}

Elf_Shdr* ElfDynstrUtil::getDynstrShdr() {
    Elf_Shdr* shdr = mElfParser.getShdrByShdrName(".dynstr");
    if (!shdr) {
        QUP_LOGI("[-] this elf file has no .dynstr section");
        return NULL;
    }
    return shdr;
}

size_t ElfDynstrUtil::initDynstrShdrLen() {
    Elf_Word sz = mDynstrShdr->sh_size;
    QUP_LOGI("[*] dynstr size = %u", sz);
    return sz;
}

size_t ElfDynstrUtil::getDynstrShdrLen() {
    return mDynstrShdrLen;
}

size_t ElfDynstrUtil::getNeedChangeExportSymNum() {
    return mNeedExpTabStrs.size();
}

size_t ElfDynstrUtil::getAllExportTabSymNum() {
    return mAllExportTabStrs.size();
}

std::vector<std::string> ElfDynstrUtil::getAllExportTabStrs() {
    return mAllExportTabStrs;
}

std::vector<std::string> ElfDynstrUtil::getNeedExportTabStrs() {
    return mNeedExpTabStrs;
}

std::vector<std::string> ElfDynstrUtil::getChangedExportTabStrs() {
    return mChangedExpTabStrs;
}

Elf_Off ElfDynstrUtil::getDynstrOff() {
    return mDynstrOff;
}

Elf_Addr ElfDynstrUtil::getDynstrAddr() {
    return mDynstrAddr;
}

bool ElfDynstrUtil::initIsNeedToConfuse() {
    if (mNeedExpTabStrs.size() > 0)
        return true;
    return false;
}

bool ElfDynstrUtil::getIsNeedToConfuse() {
    return mIsNeedToConfuse;
}

u1* ElfDynstrUtil::getNewDynstr() {
    return mNewDynstr;
}

bool ElfDynstrUtil::getIsConfuseAll() {
    return mIsConfuseAll;
}

bool ElfDynstrUtil::getIsConfuse() {
    return mIsConfuse;
}

//对旧的整个块加密

void ElfDynstrUtil::encryptOldDynstr() {
    if (mIsConfuse) {
        CryptFactory crypt;
        int factor = XOR_FACTORY;
        crypt.encrypt((u1*) mDynstrBase, mDynstrShdrLen, (void*) &factor, XorConvert);
    }
}
