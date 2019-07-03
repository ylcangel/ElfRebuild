/* 
 * File:   EncryptDynstrShellCode.h
 * Author: angel-toms
 *
 */

#ifndef ENCRYPTDYNSTRSHELLCODE_H
#define	ENCRYPTDYNSTRSHELLCODE_H

#include "ShellCode.h"

class EncryptDynstrShellCode : public ShellCode {
public:
    EncryptDynstrShellCode(ShellCodeType type, bool isHasNewDynstr);
    virtual ~EncryptDynstrShellCode();

    virtual void appendDataInShellcodeTail();
    virtual void resolveParams();

private:
    void setShellcodeAddr(Elf_Off shellcodeAddr);
    void setDynstrAddr(Elf_Off dynsymAddr);
    void setOldDynstrAddr(Elf_Off oldDynsymAddr);
    void setDynstrLength(int dynstrLen);

private:
    //此值为false的时候，是配合底下属性mDynsymAddr，一起使用
    //方法是原dynstr按照dynsym处理，然后运行前，按照dynsym还原。 因为这个方法比较
    //复杂这里不实现。
    //如果此值为true，就是新添加了一个新的dynstr节，但是这个新节系统的符号不做处理，
    //旧的加密，运行前，读取旧的解密，填充这个新的。
    bool mIsHasNewDynstr;
    //在shellcode尾
    Elf_Off mShellcodeAddr; //data
    Elf_Off mDynstrAddr; //data
    Elf_Off mOldDynstrAddr; //data
    size_t mDynstrLen; //data

//    Elf_Off mDynsymAddr; //data，TODO; 暂时不用这种方案，这种比较复杂。
};

#endif	/* ENCRYPTDYNSTRSHELLCODE_H */

