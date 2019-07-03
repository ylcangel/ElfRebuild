/**
 *
 * For Elf parse by Dynmic segment
 * For android exe protect
 *
 * Author : AngelToms
 *
 **/
#ifndef ELF_PARSER_H_
#define ELF_PARSER_H_

#include "../Types.h"
#include "../ExElf.h"

#include <map>
#include <vector>
#include <string>

#define MAX_STRTAB_NAME_LEN	25

class ElfParser {
public:

    ElfParser(u1* elfBase, size_t filesize) : mElfBase(elfBase), mElfFileLen(filesize),
    mElfHeader(NULL), mElfPhdrBase(NULL), mElfShdrBase(NULL), mDynymicBase(NULL),
    mShdrDynsymBase(NULL), mShdrDynstrBase(NULL), mDynSymCount(0), mIsLittleEndian(false) {
        mElfHeader = initElfHeader();
        mElfPhdrBase = initElfPhdrTab();
        mElfShdrBase = initElfShdrTab();
        mDynymicBase = initElfDynamic();
        mShdrDynsymBase = initShdrDynsym();
        mShdrDynstrBase = initShdrDynstr();
        mIsLittleEndian = initIsLittleEndian();
    };

    ~ElfParser() {
    }

public:
    u1* getElfBase();
    Elf_Ehdr* getElfHeader();
    Elf_Phdr* getElfPhdrTab();
    Elf_Shdr* getElfShdrTab();
    Elf_Dyn* getElfDynamic();
    Elf_Sym* getShdrDynsym();
    char* getShdrDynstr();
    size_t getFileLen();
    int getShdrNum();
    int getPhdrNum();
    int getSymCount();
    char* getShdrNameByShdr(Elf_Shdr* shdr);
    //android get shdr name from .dynstr
    char* getShdrNameFromShdrStrtab(u4 index);
    Elf_Dyn* getDynamicByDtTag(Elf_Sword tag);
    Elf_Shdr* getShdrByShdrName(const char* name);
    Elf_Shdr* getShdrByShdrIndex(int index);
    int getShdrIndexByShdrName(const char* name);
    bool getIsLittleEndian();
    
private:
    Elf_Ehdr* initElfHeader();
    Elf_Phdr* initElfPhdrTab();
    Elf_Shdr* initElfShdrTab();
    Elf_Dyn* initElfDynamic();
    Elf_Sym* initShdrDynsym();
    char* initShdrDynstr();
    bool initIsLittleEndian();
    
protected:
    Elf_Ehdr* mElfHeader;
    Elf_Phdr* mElfPhdrBase;
    Elf_Shdr* mElfShdrBase;
    Elf_Dyn* mDynymicBase;
    Elf_Sym* mShdrDynsymBase;
    char* mShdrDynstrBase;
    //android only has .dynsym ,so dynsym size = .dynsym's element size
    size_t mDynSymCount;
    bool mIsLittleEndian; //is little endin e_ident[EI_DATA] == 1
    
private:
    u1* mElfBase;
    size_t mElfFileLen;
};

#endif //ELF_PARSER_H_