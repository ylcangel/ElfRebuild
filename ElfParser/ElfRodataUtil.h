/* 
 * File:   ElfRodataUtil.h
 * Author: angel-toms
 *
 */

#ifndef ELFRODATAUTIL_H
#define	ELFRODATAUTIL_H

#include <stdlib.h>

#include "ElfParser.h"

class ElfRodataUtil {
public:
    ElfRodataUtil(ElfParser& elfParser);
    virtual ~ElfRodataUtil();
    
    bool isRodataEmpty();
    Elf_Addr getRodataAddr();
    Elf_Off getRodataOff();
    size_t getRodataSize();
    
private:
    void init();
    void encrptyRodata();
    
private:
    ElfParser& mElfParser;
    Elf_Shdr* mRodataShdr;
    bool mIsRodataEmpty;
    size_t mRodataSize;
    Elf_Addr mRodataAddr;
    Elf_Off mRodataOff;
    u1* mRodataBase;
};

#endif	/* ELFRODATAUTIL_H */

