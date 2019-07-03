/* 
 * File:   ElfBssUtil.h
 * Author: AngelToms
 *
 */

#ifndef ELFBSSUTIL_H
#define	ELFBSSUTIL_H

#include <stdlib.h>

#include "ElfParser.h"

class ElfBssUtil {
public:
    ElfBssUtil(ElfParser& elfParser);
    virtual ~ElfBssUtil();
    
    Elf_Shdr* getBssShdr();
    bool isBssEmpty();
    size_t getBssSize();
    Elf_Addr getBssAddr();
    Elf_Off getBssOff();
    int getBssShdrIndex();
    
    
private:
    void init();
    
private:
    ElfParser& mElfParser;
    Elf_Shdr* mBssShdr;
    bool mIsBssEmpty;
    size_t mBssSize;
    Elf_Addr mBssAddr;
    Elf_Off mBssOff;
};

#endif	/* ELFBSSUTIL_H */

