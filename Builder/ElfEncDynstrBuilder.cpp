/* 
 * File:   ElfEncDynstrBuilder.cpp
 * Author: angel-toms
 * 
 */

#include "ElfEncDynstrBuilder.h"

#include "../QupLog.h"
#include "../Page.h"
#include "../ShellCode/EncryptDynstrShellCode.h"

#include <string.h>
#include <stdlib.h>

ElfEncDynstrBuilder::ElfEncDynstrBuilder(ElfParser& elfParser,
        ElfInitArrayUtil& initArrayUtil,
        ElfRelUtil& relUtil,
        ElfBssUtil& bssUtil,
        ElfDynstrUtil& dynstrUtil) :
ElfBuilder(elfParser, initArrayUtil, relUtil, bssUtil),
mDynstrUtil(dynstrUtil), mNewDynstrOff(0), mIsHasNewDynstr(false) {
    mIsNeedRebuild = initIsNeedRebuild();
    if (mIsNeedRebuild) {
        mShellcodeParams = std::map<std::string, Elf_Off>();
        mIsHasNewDynstr = mDynstrUtil.getIsConfuseAll();
        mNewInitArrayOff = getNewInitArrayOff(); //init new init array addr
        makeNewInitArray();
        mNewRelDynOff = getNewReldynOff();
        mShellcode = new EncryptDynstrShellCode(EncryptDynstr, dynstrUtil.getIsConfuse());
        if (!mShellcode) {
            QUP_LOGI("[-] alloc shell code obj fail");
            exit(-1);
        }
        preinit();
        mNewSection = new u1[mAligned4Added];
        if (!mNewSection) {
            QUP_LOGI("[-] alloc new section fail");
            exit(-1);
        }
        memset(mNewSection, 0, mAligned4Added);
    }
}

ElfEncDynstrBuilder::~ElfEncDynstrBuilder() {
    if (mShellcode) {
        delete mShellcode;
        mShellcode = NULL;
    }
}

bool ElfEncDynstrBuilder::initIsNeedRebuild() {
    return mDynstrUtil.getIsNeedToConfuse();
}

size_t ElfEncDynstrBuilder::calculateAddSize() {
    //.bss align 4 , .init_array align 1, don't align, text align 4
    size_t size = 0;
    QUP_LOGI("[*] bss shdr size = %u", mBssUtil.getBssSize());
    if (mBssUtil.getBssSize() > 0) {
        size += mBssUtil.getBssSize();
        size = ROUND_UP(size, 4);
        QUP_LOGI("[*] bss shdr align4 size = %u", size);
    }
    size += BETWEEN_DATA_AND_NEW_DATA_SIZE;
    QUP_LOGI("[*] add 16 bit size = %u", size);
    size += mInitArrayUtil.getNewInitArrayLen();
    QUP_LOGI("[*] add new init array size = %u", size);
    size = ROUND_UP(size, 4);
    QUP_LOGI("[*] align4 size = %u", size);
    size += BETWEEN_DATA_AND_NEW_DATA_SIZE;
    QUP_LOGI("[*] add 16 bit size = %u", size);
    size += mRelUtil.getNewReldynLen();
    QUP_LOGI("[*] add new rel dyn size = %u", size);
    size = ROUND_UP(size, 4);
    QUP_LOGI("[*] align4 size = %u", size);
    size += BETWEEN_DATA_AND_NEW_DATA_SIZE;
    QUP_LOGI("[*] add 16 bit size = %u", size);
    if (mIsHasNewDynstr) {
        size += mDynstrUtil.getDynstrShdrLen();
        QUP_LOGI("[*] add dynstr size = %u", size);
        size = ROUND_UP(size, 4);
        QUP_LOGI("[*] align4 size = %u", size);
        size += BETWEEN_DATA_AND_NEW_DATA_SIZE;
        QUP_LOGI("[*] add 16 bit size = %u", size);
    }
    size += mShellcode->getShellcodeSize();
    QUP_LOGI("[*] add shell size = %u", size);
    size = ROUND_UP(size, 4);
    QUP_LOGI("[*] align 4 = %u", size);
    size += 2 * BETWEEN_DATA_AND_NEW_DATA_SIZE;
    QUP_LOGI("[*] add 32 bit size = %u", size);
    return size;
}

Elf_Off ElfEncDynstrBuilder::getNewDynstrOff() {
    static Elf_Off off = 0;
    if (off == 0) {
        off = mNewRelDynOff + mRelUtil.getNewReldynLen();
        QUP_LOGI("[*] new reldyn tail off = 0x%.8x", off);
        off = ROUND_UP(off, 4);
        QUP_LOGI("[*] align4 off = 0x%.8x", off);
        off += BETWEEN_DATA_AND_NEW_DATA_SIZE;
        QUP_LOGI("[*] new dynstr off = 0x%.8x", off);
    }
    return off;
}

Elf_Off ElfEncDynstrBuilder::getShellcodeAddr() {
    static Elf_Off off = 0;
    if (off == 0) {
        if (mIsHasNewDynstr) {
            off = mNewDynstrOff + mDynstrUtil.getDynstrShdrLen();
            QUP_LOGI("[*] new dynstr tail off = 0x%.8x", mNewDynstrOff);
        } else {
            off = mNewRelDynOff + mRelUtil.getNewReldynLen();
            QUP_LOGI("[*] new reldyn tail off = 0x%.8x", off);
        }
        off = ROUND_UP(off, 4);
        QUP_LOGI("[*] align4 offset = 0x%.8x", off);
        off += BETWEEN_DATA_AND_NEW_DATA_SIZE;
        QUP_LOGI("[*] add 16 bit off = 0x%.8x", off);
        off += getBetweenAddrAndOffAdded();
        QUP_LOGI("[*] vaddr = 0x%.8x, shellcode off = 0x%.8x", getBetweenAddrAndOffAdded(), off);
    }
    return off;
}

void ElfEncDynstrBuilder::preinit() {
    mAdded = calculateAddSize();
    mAligned4Added = ROUND_UP(mAdded, 4);
    QUP_LOGI("[*] added size = %u, align4 added size = %u", mAdded, mAligned4Added);
    if (mIsHasNewDynstr)
        mNewDynstrOff = getNewDynstrOff();

    mShellcodeAddr = getShellcodeAddr();
    QUP_LOGI("[*] set shell code addr = 0x%.8x", mShellcodeAddr);
    mShellcodeParams[std::string("shellcodeaddr")] = mShellcodeAddr;

    if (mIsHasNewDynstr) {
        Elf_Off dynstrvaddr = mNewDynstrOff + getBetweenAddrAndOffAdded();
        QUP_LOGI("[*] set new dynstr addr = 0x%.8x", dynstrvaddr);
        mShellcodeParams[std::string("dynstraddr")] = dynstrvaddr;
    }

    QUP_LOGI("[*] set old dynstr addr = 0x%.8x", mDynstrUtil.getDynstrAddr());
    mShellcodeParams[std::string("olddynstraddr")] = mDynstrUtil.getDynstrAddr();
    QUP_LOGI("[*] set dynstr len = 0x%.8x", mDynstrUtil.getDynstrShdrLen());
    mShellcodeParams[std::string("dynstrlen")] = mDynstrUtil.getDynstrShdrLen();
    mShellcode->setParams(mShellcodeParams);
    mShellcode->resolveParams();
    mShellcode->printNewShellCode();
    mShellcode->appendDataInShellcodeTail();
}

Elf_Off ElfEncDynstrBuilder::getDynstrAdded() {
    static Elf_Off added = 0;
    if (added == 0) {
        Elf_Off oldOff = mDynstrUtil.getDynstrOff();
        added = mNewDynstrOff - oldOff;
        QUP_LOGI("[*] dynstr added = 0x%.8x", added);
    }
    return added;
}

void ElfEncDynstrBuilder::modifyDynstrShdr() {
    if (mIsHasNewDynstr) {
        Elf_Off added = getDynstrAdded();
        Elf_Shdr* shdr = mDynstrUtil.getDynstrShdr();
        QUP_LOGI("[*] old dynstr sh_addr = 0x%.8x, sh_off = 0x%.8x",
                shdr->sh_addr, shdr->sh_offset);
        shdr->sh_addr += (added + getBetweenAddrAndOffAdded());//原来在第一页，后在第二页
        shdr->sh_offset += added;
        QUP_LOGI("[*] new dynstr sh_addr = 0x%.8x, sh_off = 0x%.8x",
                shdr->sh_addr, shdr->sh_offset);
    }
}

void ElfEncDynstrBuilder::modifyDynamicDynstrAddr() {
    if (mIsHasNewDynstr) {
        Elf_Dyn* dynstr = mElfParser.getDynamicByDtTag(DT_STRTAB);
        QUP_LOGI("[*] old dynamic, dynstr off = 0x%.8x", dynstr->d_un.d_ptr);
        dynstr->d_un.d_ptr = mNewDynstrOff + getBetweenAddrAndOffAdded();
        QUP_LOGI("[*] new dynamic, dynstr off = 0x%.8x", dynstr->d_un.d_ptr);
    }
}

void ElfEncDynstrBuilder::addNewDynstr(u1* addr, size_t len) {
    memcpy(addr, mDynstrUtil.getNewDynstr(), len);
}

void ElfEncDynstrBuilder::buildNewAddSection() {
    QUP_LOGI("[*] begin to build new section");
    u1* p = mNewSection;
    //fill bss section
    if (!mBssUtil.isBssEmpty()) {
        p += ROUND_UP(mBssUtil.getBssSize(), 4);
        QUP_LOGI("[*] fill bss section success");
    }
    //fill 16 bits 0
    p += BETWEEN_DATA_AND_NEW_DATA_SIZE;
    //fill init array new data, new .init_array[0] = shellcode virtual address
    QUP_LOGI("[*] shell code addr = 0x%.8x", mShellcodeAddr);
    mInitArrayUtil.setNewInitArrayData(&mShellcodeAddr, mAddInitArrayPtrNum);
    QUP_LOGI("[*] fill new init array data success");
    //copy new init array data
    size_t tmpsz = mInitArrayUtil.getNewInitArrayLen();
    addNewInitArray(p, tmpsz);
    size_t step = ROUND_UP(tmpsz, 4);
    p += tmpsz;
    QUP_LOGI("[*] new init array size = %u, init array step = %u", step);
    //fill 16 bits 0
    p += BETWEEN_DATA_AND_NEW_DATA_SIZE;
    QUP_LOGI("[*] after init array, fill 16 bits 0");
    //rel.dyn
    QUP_LOGI("[*] begin to fill new reldyn");
    tmpsz = mRelUtil.getNewReldynLen();
    //add new init_array first rel element
    mRelUtil.setNewRelDynInitArray(mNewInitArrayOff + getBetweenAddrAndOffAdded());
    relocInitArray();
    addNewReldyn(p, tmpsz);
    step = ROUND_UP(tmpsz, 4);
    QUP_LOGI("[*] new rel.dyn size = %u, step = %u", tmpsz, step);
    step += BETWEEN_DATA_AND_NEW_DATA_SIZE;
    p += step;
    QUP_LOGI("[*] end   to fill new reldyn");
    //if new .dynstr exist
    if (mIsHasNewDynstr) {
        QUP_LOGI("[*] begin to fill new dynstr");
        tmpsz = mDynstrUtil.getDynstrShdrLen();
        addNewDynstr(p, tmpsz);
        step = ROUND_UP(tmpsz, 4);
        step += BETWEEN_DATA_AND_NEW_DATA_SIZE;
        p += step;
        QUP_LOGI("[*] end   to fill new dynstr");
    }
    QUP_LOGI("[*] begin to fill new shellcode");
    tmpsz = mShellcode->getShellcodeSize();
    addShellcode(p, tmpsz);
    QUP_LOGI("[*] end   to fill new shellcode");
#ifdef DEBUG_ALL
    HEX_LOG((u1*) mNewDataShdrContent, 0x200);
#endif
}

void ElfEncDynstrBuilder::writeRelationsOfExptabs() {
    //TODO; Write to file
}

bool ElfEncDynstrBuilder::rebuild(int fd) {
    if (mIsNeedRebuild) {
        mFd = fd;
        QUP_LOGI("[++] begin to rebuild");
        buildNewAddSection();
        modifyElfHeaderShdrTabAddr();
        modifyBssShdrType();
        modifyShdrBeginWithBss();
        modifyInitArrayShdr();
        modifyDynamicInitArrayAddrAndSz();
        modifyReldynShdr();
        modifyDynamicReldynAddr();
        modifyDynstrShdr();
        modifyDynamicDynstrAddr();
        modifyPhdrSeg2AndPerm();
        
        u1* pt = mElfParser.getElfBase();
        writeToBssShdrBegin(mElfParser.getElfBase(), mBssUtil.getBssOff());
        addNewSection(mNewSection, mAligned4Added);
        pt += mBssUtil.getBssOff();
        writeToEnd(pt, (mElfParser.getFileLen() - mBssUtil.getBssOff()));
        alignFileAndFill0();
        
        writeRelationsOfExptabs();
        QUP_LOGI("[++] end   to rebuild");
    } else {
        QUP_LOGI("[++] this elf does't need rebuild");
    }
    return true;
}



