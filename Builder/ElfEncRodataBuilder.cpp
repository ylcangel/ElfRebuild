/* 
 * File:   ElfEncRodataBuilder.cpp
 * Author: AngelToms
 * 
 */

#include "ElfEncRodataBuilder.h"

#include "../ShellCode/EncryptRodataShellCode.h"
#include "../QupLog.h"
#include "../Page.h"

#include <stdlib.h>
#include <string.h>

ElfEncRodataBuilder::ElfEncRodataBuilder(ElfParser& elfParser,
        ElfInitArrayUtil& initArrayUtil,
        ElfRelUtil& relUtil,
        ElfBssUtil& bssUtil,
        ElfRodataUtil& rodataUtil) :
ElfBuilder(elfParser, initArrayUtil, relUtil, bssUtil),
mRodataUtil(rodataUtil) {
    mIsNeedRebuild = initIsNeedRebuild();
    if (mIsNeedRebuild) {
        mShellcodeParams = std::map<std::string, Elf_Off>();
        mNewInitArrayOff = getNewInitArrayOff(); //init new init array addr
        makeNewInitArray();
        mNewRelDynOff = getNewReldynOff();
        mShellcode = new EncryptRodataShellCode(EncryptRodata, true);
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

ElfEncRodataBuilder::~ElfEncRodataBuilder() {
    if (mShellcode) {
        delete mShellcode;
        mShellcode = NULL;
    }
}

bool ElfEncRodataBuilder::initIsNeedRebuild() {
    return mRodataUtil.isRodataEmpty() ? false : true;
}

size_t ElfEncRodataBuilder::calculateAddSize() {
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
    QUP_LOGI("[*] shell code size = %u", mShellcode->getShellcodeSize());
    size += mShellcode->getShellcodeSize();
    QUP_LOGI("[*] add shell size = %u", size);
    size = ROUND_UP(size, 4);
    QUP_LOGI("[*] align 4 = %u", size);
    size += 2 * BETWEEN_DATA_AND_NEW_DATA_SIZE;
    QUP_LOGI("[*] add 32 bit size = %u", size);
    return size;
}

void ElfEncRodataBuilder::preinit() {
    mAdded = calculateAddSize();
    mAligned4Added = ROUND_UP(mAdded, 4);
    QUP_LOGI("[*] added size = %u, align4 added size = %u", mAdded, mAligned4Added);
    mShellcodeAddr = getShellcodeAddr();
    QUP_LOGI("[*] set shell code addr = 0x%.8x", mShellcodeAddr);
    mShellcodeParams[std::string("shellcodeaddr")] = mShellcodeAddr;
    Elf_Off rodatavaddr = mRodataUtil.getRodataAddr();
    QUP_LOGI("[*] set rodata addr = 0x%.8x", rodatavaddr);
    mShellcodeParams[std::string("rodataaddr")] = rodatavaddr;
    QUP_LOGI("[*] set rodata len = 0x%.8x", mRodataUtil.getRodataSize());
    mShellcodeParams[std::string("rodatalen")] = mRodataUtil.getRodataSize();

    mShellcode->setParams(mShellcodeParams);
    mShellcode->resolveParams();
    mShellcode->printNewShellCode();
    mShellcode->appendDataInShellcodeTail();
}

Elf_Off ElfEncRodataBuilder::getShellcodeAddr() {
    static Elf_Off off = 0;
    if (off == 0) {
        off = mNewRelDynOff + mRelUtil.getNewReldynLen();
        QUP_LOGI("[*] new reldyn tail off = 0x%.8x", off);

        off = ROUND_UP(off, 4);
        QUP_LOGI("[*] align4 offset = 0x%.8x", off);
        off += BETWEEN_DATA_AND_NEW_DATA_SIZE;
        QUP_LOGI("[*] add 16 bit off = 0x%.8x", off);
        off += getBetweenAddrAndOffAdded();
        QUP_LOGI("[*] vaddr = 0x%.8x, shellcode off = 0x%.8x", getBetweenAddrAndOffAdded(), off);
    }
    return off;
}

void ElfEncRodataBuilder::buildNewAddSection() {
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
    //copy new init array data
    QUP_LOGI("[*] fill new init array data");
    size_t tmpsz = mInitArrayUtil.getNewInitArrayLen();
    addNewInitArray(p, tmpsz);
    size_t step = ROUND_UP(tmpsz, 4);
    p += step;
    QUP_LOGI("[*] new init array size = %u, init array step = %u", step);
    //fill 16 bits 0
    p += BETWEEN_DATA_AND_NEW_DATA_SIZE;
    QUP_LOGI("[*] after init array, fill 16 bits 0");
    //new rel.dyn
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
    QUP_LOGI("[*] begin to fill new shellcode");
    tmpsz = mShellcode->getShellcodeSize();
    addShellcode(p, tmpsz);
    QUP_LOGI("[*] end   to fill new shellcode");
#ifdef DEBUG_ALL
    HEX_LOG((u1*) mNewDataShdrContent, 0x200);
#endif
}

void ElfEncRodataBuilder::modifyPhdrSeg1AndPerm() {
    //0 phdr self 1 pt_load 2 pt_load
    //    Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
    Elf_Phdr* phdr = mElfParser.getElfPhdrTab() + 1;

    QUP_LOGI("[*] phdr pt_load1 info: off = 0x%.8x, virtAddr = 0x%.8x,"
            " flg = %.8x", phdr->p_offset, phdr->p_vaddr,
            phdr->p_flags);

    phdr->p_flags = phdr->p_flags | PF_W;

    QUP_LOGI("[*] phdr pt_load1 info: off = 0x%.8x, virtAddr = 0x%.8x,"
            " flg = %.8x", phdr->p_offset, phdr->p_vaddr,
            phdr->p_flags);
}

bool ElfEncRodataBuilder::rebuild(int fd) {//TODO;
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
        modifyPhdrSeg1AndPerm();
        modifyPhdrSeg2AndPerm();

        u1* pt = mElfParser.getElfBase();
        writeToBssShdrBegin(mElfParser.getElfBase(), mBssUtil.getBssOff());
        addNewSection(mNewSection, mAligned4Added);
        pt += mBssUtil.getBssOff();
        writeToEnd(pt, (mElfParser.getFileLen() - mBssUtil.getBssOff()));
        alignFileAndFill0();
        QUP_LOGI("[++] end   to rebuild");
    } else {
        QUP_LOGI("[++] this elf does't need rebuild");
    }
    return true;
}

