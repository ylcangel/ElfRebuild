/* 
 * File:   ElfEncDynstrBuilder.h
 * Author: angel-toms
 *
 * Add area
 *  .bss  
 * +----------------+
 * | 16 bits 0      |
 * +----------------+
 * | new .init_array|
 * +----------------+
 * | 16 bits 0      |
 * +----------------+
 * |new .plt.dyn   | 
 * +----------------+
 * | 16 bits 0      |
 * +----------------+
 * |new .dynstr  #  | 如果存在的话，否则这段没有
 * +----------------+
 * | 16 bits 0   #  | 如果存在新的.dynstr则有这段，否则没有
 * +----------------+
 * |shellcode       |
 * +----------------+
 * | 32 bits 0      |
 * +----------------+
 * 以上除新的.init_ayyay是不需要对齐的，其他尾部都按四字节对齐
 * 
 * 
 * */

#ifndef ELFENCDYNSTRBUILDER_H
#define	ELFENCDYNSTRBUILDER_H

#include "ElfBuilder.h"
#include "../ElfParser/ElfDynstrUtil.h"
#include "../ShellCode/ShellCode.h"

class ElfEncDynstrBuilder : public ElfBuilder {
public:
    ElfEncDynstrBuilder(ElfParser& elfParser,
            ElfInitArrayUtil& initArrayUtil,
            ElfRelUtil& relUtil,
            ElfBssUtil& bssUtil,
            ElfDynstrUtil& dynstrUtil);

    virtual ~ElfEncDynstrBuilder();

public:
    virtual bool initIsNeedRebuild();
    virtual size_t calculateAddSize();
    virtual void preinit(); //new init array addr and other addr must be setted
    virtual void buildNewAddSection(); //begin with .bss
    virtual bool rebuild(int fd);

    virtual Elf_Off getShellcodeAddr();

private:
    Elf_Off getNewDynstrOff();
    Elf_Off getDynstrAdded();
    void modifyDynstrShdr();
    void modifyDynamicDynstrAddr();
    void addNewDynstr(u1* addr, size_t len);
    void writeRelationsOfExptabs();

private:
    ElfDynstrUtil& mDynstrUtil;
    Elf_Off mNewDynstrOff;
    bool mIsHasNewDynstr;
};

#endif	/* ELFENCDYNSTRBUILDER_H */

