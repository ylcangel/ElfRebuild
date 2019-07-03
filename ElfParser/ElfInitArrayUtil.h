/* 
 * File:   ElfInitArrayUtil.h
 * Author: Author: AngelToms
 *
 */

#ifndef ELFINITARRAYUTIL_H
#define	ELFINITARRAYUTIL_H

#include "ElfParser.h"

#include "../Types.h"

#include <unistd.h>
#include <stdlib.h>

class ElfInitArrayUtil {
public:
    ElfInitArrayUtil(ElfParser& elfParser);
    virtual ~ElfInitArrayUtil();
    
    size_t getOldInitArrayLen();
    size_t getNewInitArrayLen();
    size_t getOldInitArrayCount();
    size_t getNewInitArrayCount();
    size_t* getOldInitArray();
    size_t* getNewInitArray();
    void printInitArray(u1* initArray, int count);
    void printOldInitArray();
    void printNewInitArray();
    Elf_Shdr* getOldInitArrayShdr();
    void extendInitArray(int elementSize);
    void setNewInitArrayData(size_t* newInitArray, int count);
    bool isOldInitArrayWasNullVal();
    Elf_Addr getOldInitArrayVaddr();
    Elf_Off getOldInitArrayOff();
    
private:
    void init();
    
private:
    ElfParser& mElfParser;
    Elf_Shdr* mOldInitArrayShdr;//Need modify
    Elf_Addr mOldInitArrayVaddr;
    Elf_Off mOldInitArrayOff;
    size_t* mOldInitArray;
    size_t* mNewInitArray;//old init data + add ptr data 
    size_t mOldInitArrayCount;
    size_t mNewInitArrayCount;//old + add count
    size_t mOldInitArrayLen;
    size_t mNewInitArrayLen;
};

#endif	/* ELFINITARRAYUTIL_H */

