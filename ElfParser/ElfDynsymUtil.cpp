/* 
 * File:   ElfDynsymUtil.cpp
 * Author: angeltoms
 * 
 */

#include "ElfDynsymUtil.h"

#include <stdlib.h>
#include <string.h>

#include "../QupLog.h"

ElfDynsymUtil::ElfDynsymUtil(ElfParser& elfParser) : mElfParser(elfParser) {
    
}

ElfDynsymUtil::~ElfDynsymUtil() {
}

Elf_Addr ElfDynsymUtil::findSymAddrByName(char* name) {
    Elf_Sym* sym = mElfParser.getShdrDynsym();
    char* strtab = mElfParser.getShdrDynstr();
    for(int i = 0 ; i < mElfParser.getSymCount(); i++) {
        Elf_Sym* esym = sym + i;
        char* tname = strtab + esym->st_name;
        if(strcmp(tname, name) == 0) {
            QUP_LOGI("[*] sym name = %s, vmaddr = 0x%.8x", name , esym->st_value);
            return esym->st_value;
        }
    }
    return -1;
}
