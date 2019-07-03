/* 
 * File:   ElfRelUtil.cpp
 * Author: AngelToms
 * 
 */

#ifndef ELFRELUTIL_H
#define	ELFRELUTIL_H

#include "ElfParser.h"
#include "../Types.h"

class ElfRelUtil {
public:
    ElfRelUtil(ElfParser& elfParser);
    virtual ~ElfRelUtil();

    Elf_Shdr* getRelDynShdr();
    Elf_Shdr* getRelPltShdr();
    
#ifdef __LP64__
    Elf_RelA*
#else
    Elf_Rel*
#endif
    getRelDyn();
#ifdef __LP64__
    Elf_RelA*
#else
    Elf_Rel*
#endif
    getRelPlt();
    u1* getNewRelDyn();
    void setNewRelDynInitArray(Elf32_Addr offset);
    size_t getNewReldynLen();
    void printRelDyn();
    void printRelPlt();
    Elf_Addr getReldynAddr();
    Elf_Off getReldynOff();

private:
    void init();

private:
    Elf_Shdr* mRelDynShdr;
    Elf_Shdr* mRelPltShdr; 

#ifdef __LP64__
    Elf_RelA* mRelDyn;
#else
    Elf_Rel* mRelDyn;
#endif
#ifdef __LP64__
    Elf_RelA* mRelPlt;
#else
    Elf_Rel* mRelPlt;
#endif
    Elf_Addr mRelDynAddr;
    Elf_Off mRelDynOff;
    u1* mNewReldyn;
    ElfParser& mElfParser;
};

#endif	/* ELFRELUTIL_H */

