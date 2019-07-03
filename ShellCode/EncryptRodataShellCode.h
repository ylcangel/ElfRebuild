/* 
 * File:   EncryptRodataShellCode.h
 * Author: angel-toms
 *
 */

#ifndef ENCRYPTRODATASHELLCODE_H
#define	ENCRYPTRODATASHELLCODE_H

#include "ShellCode.h"

class EncryptRodataShellCode : public ShellCode {
public:
    EncryptRodataShellCode(ShellCodeType type, bool isHasNewDynstr);
    virtual ~EncryptRodataShellCode();

    virtual void appendDataInShellcodeTail();
    virtual void resolveParams();
    
    void setShellcodeAddr(Elf_Off addr);
    void setRodataAddr(Elf_Off addr);
    void setRodatalen(size_t len);
    
private:
    Elf_Off mShellcodeAddr;
    Elf_Off mRodataAddr;
    size_t mRodataLen;
};

#endif	/* ENCRYPTRODATASHELLCODE_H */

