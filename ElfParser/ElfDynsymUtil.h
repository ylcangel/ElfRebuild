/* 
 * File:   ElfDynsymUtil.h
 * Author: angeltoms
 *
 */

#ifndef ELFDYNSYMUTIL_H
#define	ELFDYNSYMUTIL_H

#include "ElfParser.h"

class ElfDynsymUtil {
public:
    ElfDynsymUtil(ElfParser& elfParser);
    virtual ~ElfDynsymUtil();
    
    Elf_Addr findSymAddrByName(char* name);
private:
    ElfParser& mElfParser;  

};

#endif	/* ELFDYNSYMUTIL_H */

