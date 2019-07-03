/* 
 * File:   ElfBuilder.cpp
 * Author: angel-toms
 * 
 */

#include "ElfBuilder.h"

#include "../QupLog.h"
#include "../Page.h"

#include <stdlib.h>
#include <string.h>

ElfBuilder::ElfBuilder(ElfParser& elfParser,
        ElfInitArrayUtil& initArrayUtil,
        ElfRelUtil& relUtil,
        ElfBssUtil& bssUtil) : mElfParser(elfParser), mInitArrayUtil(initArrayUtil),
mRelUtil(relUtil), mBssUtil(bssUtil), mShellcode(NULL),
mNewSection(NULL), mAligned4Added(0), mAdded(0), mNewInitArrayOff(0),
mNewRelDynOff(0), mShellcodeAddr(0), mAddInitArrayPtrNum(1), mIsNeedRebuild(false) {
}

ElfBuilder::~ElfBuilder() {
    if (mNewSection) {
        delete mNewSection;
        mNewSection = NULL;
    }
    mShellcodeParams.clear();
}

void ElfBuilder::makeNewInitArray() {
    mInitArrayUtil.extendInitArray(mAddInitArrayPtrNum);
}

void ElfBuilder::modifyElfHeaderShdrTabAddr() {
    Elf_Ehdr* header = mElfParser.getElfHeader();
    QUP_LOGI("[*] old ehdr e_shoff = 0x%.8x", header->e_shoff);
    header->e_shoff += mAligned4Added;
    QUP_LOGI("[*] new ehdr e_shoff = 0x%.8x", header->e_shoff);
}

void ElfBuilder::modifyBssShdrType() {
    if (!mBssUtil.isBssEmpty()) {
        Elf_Shdr* shdr = mBssUtil.getBssShdr();
        QUP_LOGI("[*] old bss sh_type = 0x%.8x", shdr->sh_type);
        shdr->sh_type = SHT_PROGBITS;
        QUP_LOGI("[*] new bss sh_type = 0x%.8x", shdr->sh_type);
    }
}

void ElfBuilder::modifyShdrBeginWithBss() {
    int startIndex = mBssUtil.getBssShdrIndex() + 1;
    for (int i = 0; i < mElfParser.getShdrNum(); i++) {
        if (i < startIndex) {
            continue;
        }
        Elf_Shdr* shdr = mElfParser.getShdrByShdrIndex(i);
        char* name = mElfParser.getShdrNameByShdr(shdr);
        QUP_LOGI("[*] %s section sh_offset = 0x%.8x", name, shdr->sh_offset);
        shdr->sh_offset = shdr->sh_offset + mAligned4Added;
        QUP_LOGI("[*] %s after section sh_offset = 0x%.8x", name, shdr->sh_offset);
    }
}

void ElfBuilder::modifyPhdrSeg2AndPerm() {
    //0 phdr self 1 pt_load 2 pt_load
    //    Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
    Elf_Phdr* phdr = mElfParser.getElfPhdrTab() + 2;

    QUP_LOGI("[*] phdr pt_load2 info: off = 0x%.8x, virtAddr = 0x%.8x,"
            " physAddr = 0x%.8x, fileSiz = 0x%.8x, memSiz = 0x%.8x,"
            " flg = %.8x", phdr->p_offset, phdr->p_vaddr, phdr->p_paddr,
            phdr->p_filesz, phdr->p_memsz, phdr->p_flags);

    phdr->p_flags = phdr->p_flags | PF_X;
    size_t addSz = mAligned4Added;
    QUP_LOGI("[*] phdr pt_load2 add =0x%.8x", addSz);

    phdr->p_filesz += addSz;
    phdr->p_memsz += addSz;

    QUP_LOGI("[*] phdr after pt_load2 info: off = 0x%.8x, virtAddr = 0x%.8x,"
            " physAddr = 0x%.8x, fileSiz = 0x%.8x, memSiz = 0x%.8x,"
            " flg = %.8x", phdr->p_offset, phdr->p_vaddr, phdr->p_paddr,
            phdr->p_filesz, phdr->p_memsz, phdr->p_flags);
}

Elf_Off ElfBuilder::getNewInitArrayOff() {
    static Elf_Off bssOff = 0;
    if (bssOff == 0) {
        bssOff = mBssUtil.getBssOff();
        if (mBssUtil.getBssSize() > 0) {
            bssOff += mBssUtil.getBssSize();
            bssOff = ROUND_UP(bssOff, 4);
        }
        bssOff += BETWEEN_DATA_AND_NEW_DATA_SIZE; //16 BITS
        QUP_LOGI("[*] bss off = 0x%.8x, new init array off = 0x%.8x, add size = %u",
                mBssUtil.getBssOff(), bssOff, (bssOff - mBssUtil.getBssOff()));
    }
    return bssOff;
}

bool ElfBuilder::getIsNeedRebuild() {
    return mIsNeedRebuild;
}

Elf_Off ElfBuilder::getInitArrayAdded() {
    static Elf_Off added = 0;
    if (added == 0) {
        Elf_Off oldOff = mInitArrayUtil.getOldInitArrayOff();
        QUP_LOGI("[*] old init array = 0x%.8x", oldOff);
        added = mNewInitArrayOff - oldOff;
        QUP_LOGI("[*] new init array = 0x%.8x", mNewInitArrayOff);
        QUP_LOGI("[*] init array added = 0x%.8x", added);
    }
    return added;
}

void ElfBuilder::modifyInitArrayShdr() {
    Elf_Off added = getInitArrayAdded();
    Elf_Shdr* shdr = mInitArrayUtil.getOldInitArrayShdr();
    QUP_LOGI("[*] old init array sh_addr = 0x%.8x, sh_off = 0x%.8x, sh_size = %u",
            shdr->sh_addr, shdr->sh_offset, shdr->sh_size);
    shdr->sh_addr += added;
    shdr->sh_offset += added;
    shdr->sh_size = mInitArrayUtil.getNewInitArrayLen();
    QUP_LOGI("[*] new init array sh_addr = 0x%.8x, sh_off = 0x%.8x, sh_size = %u",
            shdr->sh_addr, shdr->sh_offset, shdr->sh_size);
}

Elf_Off ElfBuilder::getBetweenAddrAndOffAdded() {
    static Elf_Off off = 0;
    if (off == 0) {
        off = mInitArrayUtil.getOldInitArrayVaddr() - mInitArrayUtil.getOldInitArrayOff();
        QUP_LOGI("[*] mem addr - file off = 0x%.8x", off);
    }
    return off;
}

void ElfBuilder::modifyDynamicInitArrayAddrAndSz() {
    Elf_Dyn* initArray = mElfParser.getDynamicByDtTag(DT_INIT_ARRAY);
    Elf_Dyn* initArraySz = mElfParser.getDynamicByDtTag(DT_INIT_ARRAYSZ);
    QUP_LOGI("[*] dynamic old init array ptr = 0x%.8x, size = %u",
            initArray->d_un.d_ptr, initArraySz->d_un.d_val);
    initArray->d_un.d_ptr = mNewInitArrayOff + getBetweenAddrAndOffAdded();
    initArraySz->d_un.d_val = mInitArrayUtil.getNewInitArrayLen();
    QUP_LOGI("[*] dynamic new init array ptr = 0x%.8x, size = %u",
            initArray->d_un.d_ptr, initArraySz->d_un.d_val);
}

//rel.dyn the element init_array

void ElfBuilder::relocInitArray() {
    Elf_Addr oldInitArrayAddr = mInitArrayUtil.getOldInitArrayVaddr();
    QUP_LOGI("[*] old init array vm addr = 0x%.8x", oldInitArrayAddr);
    int initSz = mInitArrayUtil.getOldInitArrayCount() - 1; //因为最后一个是填充的0
    Elf_Addr initStartAddr = mNewInitArrayOff + getBetweenAddrAndOffAdded();
    int j = 0;
#ifdef __LP64__
    Elf_RelA * rel = (Elf_RelA*) mRelUtil.getNewRelDyn();
#else
    Elf_Rel* rel = (Elf_Rel*) mRelUtil.getNewRelDyn();
#endif
    int count = mRelUtil.getNewReldynLen() / mRelUtil.getRelDynShdr()->sh_entsize;
    QUP_LOGI("[*] reldyn elements size = %d", count);
    for (int i = 0; i < count; i++) {
        if (j == initSz)
            break;
        Elf_Rel* relp = rel + i;
        if (relp->r_offset == (oldInitArrayAddr + (j * sizeof (size_t)))) {//old init array 里面的数据向后移动了一个指针的长度
            QUP_LOGI("[*] REL old init_array [%d] r_offset = 0x%.8x", j, relp->r_offset);
            relp->r_offset = initStartAddr + ((j + 1) * sizeof (size_t));
            QUP_LOGI("[*] REL new init_array [%d] r_offset = 0x%.8x", j, relp->r_offset);
            j++;
        }
    }
}

Elf_Off ElfBuilder::getNewReldynOff() {
    static Elf_Off off = 0;
    if (off == 0) {
        off = mNewInitArrayOff + mInitArrayUtil.getNewInitArrayLen();
        QUP_LOGI("[*] new init array tail off = 0x%.8x", off);
        off = ROUND_UP(off, 4);
        QUP_LOGI("[*] align4 off = 0x%.8x", off);
        off += BETWEEN_DATA_AND_NEW_DATA_SIZE;
        QUP_LOGI("[*] new reldyn off = 0x%.8x", off);
    }
    return off;
}

Elf_Off ElfBuilder::getReldynAdded() {
    static Elf_Off added = 0;
    if (added == 0) {
        Elf_Off oldOff = mRelUtil.getReldynOff();
        added = mNewRelDynOff - oldOff;
        QUP_LOGI("[*] reldyn added = 0x%.8x", added);
    }
    return added;
}

void ElfBuilder::modifyReldynShdr() {
    Elf_Off added = getReldynAdded();
    Elf_Shdr* shdr = mRelUtil.getRelDynShdr();
    QUP_LOGI("[*] old rel dyn sh_addr = 0x%.8x, sh_off = 0x%.8x, sh_size = %u",
            shdr->sh_addr, shdr->sh_offset, shdr->sh_size);
    shdr->sh_addr += (added + getBetweenAddrAndOffAdded());//原来在第一页，后在第二页
    shdr->sh_offset += added;
    shdr->sh_size = mRelUtil.getNewReldynLen();
    QUP_LOGI("[*] new rel dyn sh_addr = 0x%.8x, sh_off = 0x%.8x, sh_size = %u",
            shdr->sh_addr, shdr->sh_offset, shdr->sh_size);
}

void ElfBuilder::modifyDynamicReldynAddr() {
    Elf_Dyn* reldyn = mElfParser.getDynamicByDtTag(DT_REL);
    QUP_LOGI("[*] old dynamic, reldyn off = 0x%.8x", reldyn->d_un.d_ptr);
    reldyn->d_un.d_ptr = mNewRelDynOff + getBetweenAddrAndOffAdded();
    QUP_LOGI("[*] new dynamic, reldyn off = 0x%.8x", reldyn->d_un.d_ptr);
    Elf_Dyn* reldynSz = mElfParser.getDynamicByDtTag(DT_RELSZ);
    QUP_LOGI("[*] old dynamic, reldyn size = 0x%.8x", reldynSz->d_un.d_val);
    reldynSz->d_un.d_val = mRelUtil.getNewReldynLen();
    QUP_LOGI("[*] new dynamic, reldyn size = 0x%.8x", reldynSz->d_un.d_val);
}

void ElfBuilder::fill16bit0(u1* addr) {
    memset(addr, 0, BETWEEN_DATA_AND_NEW_DATA_SIZE);
}

void ElfBuilder::addNewInitArray(u1* addr, size_t len) {
    memcpy(addr, (u1*) mInitArrayUtil.getNewInitArray(), len);
}

void ElfBuilder::addNewReldyn(u1* addr, size_t len) {
    memcpy(addr, (u1*) mRelUtil.getNewRelDyn(), len);
}

void ElfBuilder::addShellcode(u1* addr, size_t len) {
    memcpy(addr, mShellcode->getShellcode(), len);
}

size_t ElfBuilder::getAligned4Added() {
    return mAligned4Added;
}

void ElfBuilder::writeToBssShdrBegin(u1* p, size_t len) {
    write(mFd, p, len);
    fsync(mFd);
}

void ElfBuilder::addNewSection(u1* p, size_t len) {
    writeToBssShdrBegin(p, len);
}

void ElfBuilder::writeToEnd(u1* p, size_t len) {
    writeToBssShdrBegin(p, len);
}

void ElfBuilder::alignFileAndFill0() {
    size_t oldFilesize = mElfParser.getFileLen();
    size_t newFilesize = oldFilesize + mAligned4Added;
    QUP_LOGI("[*] old file size = %u, new file size = %u", oldFilesize, newFilesize);
    size_t align4Sz = ROUND_UP(newFilesize, 4);
    size_t fill0Size = align4Sz - newFilesize;
    QUP_LOGI("[*] align4 fill size = %u, fill 0 size = %u ", align4Sz, fill0Size);
    if (fill0Size > 0) {
        char buf[fill0Size];
        memset(buf, 0, fill0Size);
        write(mFd, buf, fill0Size);
        fsync(mFd);
    }
}

void ElfBuilder::printHexData() {
    //TODO;
}

