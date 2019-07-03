/* 
 * File:   ShellCode.h
 * Author: AngelToms
 *
 */

#ifndef SHELLCODE_H
#define	SHELLCODE_H

#include <stdlib.h>
#include <unistd.h>
#include <map>
#include <string>

#include "../Types.h"
#include "../ExElf.h"
#include "../Common.h"

class ShellCode {
public:
    ShellCode(ShellCodeType type, bool flag);// flag used for encrypt dynstr mIsHasNewDynstr
    virtual ~ShellCode();

    u1* getShellcode();
    size_t getShellcodeSize();
    void setParams(std::map<std::string, Elf_Off> params);
    
    virtual void resolveParams() = 0;
    virtual void appendDataInShellcodeTail() = 0;
    void printNewShellCode();

protected:
    std::map<std::string, Elf_Off> mParams;//key was paramname ,value type can be Elf_Off or Int
    u1* mShellcode;
    u1* mNewShellcode;
    size_t mSize;
};

#endif	/* SHELLCODE_H */

