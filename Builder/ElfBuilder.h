/* 
 * File:   ElfBuilder.h
 * Author: angel-toms
 *
 */

#ifndef ELFBUILDER_H
#define	ELFBUILDER_H

#include "../ElfParser/ElfParser.h"
#include "../ElfParser/ElfInitArrayUtil.h"
#include "../ElfParser/ElfBssUtil.h"
#include "../ElfParser/ElfRelUtil.h"
#include "../ShellCode/ShellCode.h"

#include <string>
#include <map>

#define BETWEEN_DATA_AND_NEW_DATA_SIZE 0x10

class ElfBuilder {
public:
    ElfBuilder(ElfParser& elfParser,
            ElfInitArrayUtil& initArrayUtil,
            ElfRelUtil& relUtil,
            ElfBssUtil& bssUtil);
    virtual ~ElfBuilder();

public:
    virtual bool initIsNeedRebuild() = 0;
    virtual size_t calculateAddSize() = 0;
    virtual void preinit() = 0; //new init array addr and other addr must be setted
    virtual void buildNewAddSection() = 0; //create add section ,the core
    virtual bool rebuild(int fd) = 0;
    virtual Elf_Off getShellcodeAddr() = 0;

    bool getIsNeedRebuild();
    Elf_Off getNewInitArrayOff();

protected:
    Elf_Off getBetweenAddrAndOffAdded();
    Elf_Off getReldynAdded();
    Elf_Addr getNewReldynOff();
    void makeNewInitArray();

    void modifyElfHeaderShdrTabAddr();
    void modifyBssShdrType();
    void modifyShdrBeginWithBss();
    void modifyInitArrayShdr();
    //rel.dyn the element init_array
    void relocInitArray();
    void modifyDynamicInitArrayAddrAndSz();
    void modifyReldynShdr();
    void modifyDynamicReldynAddr();
    void modifyPhdrSeg2AndPerm();
    //abs:00004138 _edata = 0x4004
    //abs:0000413C __bss_start = 0x4004
    //abs:00004140 _end = 0x4004
    //    void changeABSEdataBssStartEnd();
    void writeToBssShdrBegin(u1* p, size_t len);
    void addNewSection(u1* p, size_t len);
    void writeToEnd(u1* p, size_t len);

    void fill16bit0(u1* addr);
    void addNewInitArray(u1* addr, size_t len);
    void addNewReldyn(u1* addr, size_t len);
    void addShellcode(u1* addr, size_t len);
    void alignFileAndFill0();
    size_t getAligned4Added();

    void printHexData();

private:
    Elf_Off getInitArrayAdded();

protected:
    int mFd;
    u1* mNewSection;
    size_t mAligned4Added;
    size_t mAdded;
    int mAddInitArrayPtrNum;
    Elf_Off mNewInitArrayOff;
    Elf_Off mNewRelDynOff;
    Elf_Off mShellcodeAddr;
    bool mIsNeedRebuild;
    std::map<std::string, Elf_Off> mShellcodeParams;

    ElfParser& mElfParser;
    ElfInitArrayUtil& mInitArrayUtil;
    ElfRelUtil& mRelUtil;
    ElfBssUtil& mBssUtil;
    ShellCode* mShellcode;
};

#endif	/* ELFBUILDER_H */

