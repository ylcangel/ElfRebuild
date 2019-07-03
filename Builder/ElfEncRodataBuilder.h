/* 
 * File:   ElfEncRodataBuilder.h
 * Author: AngelToms
 * 
 * +--------------------+
 * .rodata was encrypted
 * +--------------------+
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
 * | 16 bits 0     |
 * +----------------+
 * |shellcode       |
 * +----------------+
 * | 32 bits 0      |
 * +----------------+
 * 以上除新的.init_ayyay是不需要对齐的，其他尾部都按四字节对齐
 */

#ifndef ELFENCRODATABUILDER_H
#define	ELFENCRODATABUILDER_H

#include <stdlib.h>

#include "ElfBuilder.h"
#include "../ElfParser/ElfRodataUtil.h"
#include "../ShellCode/ShellCode.h"

class ElfEncRodataBuilder : public ElfBuilder {
public:
    ElfEncRodataBuilder(ElfParser& elfParser,
            ElfInitArrayUtil& initArrayUtil,
            ElfRelUtil& relUtil,
            ElfBssUtil& bssUtil,
            ElfRodataUtil& rodataUtil);

    virtual ~ElfEncRodataBuilder();

public:
    virtual bool initIsNeedRebuild();
    virtual size_t calculateAddSize();
    virtual void preinit(); //new init array addr and other addr must be setted
    virtual void buildNewAddSection(); //begin with .bss
    virtual bool rebuild(int fd);
    void modifyPhdrSeg1AndPerm();//rodata in seg1

    virtual Elf_Off getShellcodeAddr();

private:
    ElfRodataUtil& mRodataUtil;

};

#endif	/* ELFENCRODATABUILDER_H */

