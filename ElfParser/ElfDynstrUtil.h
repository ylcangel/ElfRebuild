/* 
 * File:   ElfDynstrUtil.cpp
 * Author: AngelToms
 * eq length change
 * bool isConfuse 这个是总开关，混淆时它必须为true
 * bool isConfuseAll 它代表两个分支的混淆，如果值为false，只是将符号表对应的字符串
 * 表混淆（只混淆导出表，除系统的导出表和它的导入表），
 * 如果它的值为true，原符号表对应的字符串表整块加密，并添加新的字符串表，该表操作同值为false的操作
 * 添加这个节，修正偏移
 * 
 * Note：
 * 两种不同的混淆对应两种不同的shellcode
 * 
 */

#ifndef ELFDYNSTRUTIL_H
#define	ELFDYNSTRUTIL_H

#include "ElfParser.h"

#include <vector>
#include <string>
#include <stdlib.h>

#include "../Types.h"
#include "../Types.h"

class ElfDynstrUtil {
public:
    ElfDynstrUtil(ElfParser& elfParser, bool isConfuse, bool isConfuseAll);
    virtual ~ElfDynstrUtil();

    void iterExportSyms();
    size_t getDynstrShdrLen();
    size_t getNeedChangeExportSymNum(); //if == 0 ,don rebuild elf
    size_t getAllExportTabSymNum();
    Elf_Off getDynstrOff();
    Elf_Addr getDynstrAddr();
    std::vector<std::string> getAllExportTabStrs();
    std::vector<std::string> getNeedExportTabStrs();
    std::vector<std::string> getChangedExportTabStrs();
    bool confuseOldExportTab();
    bool confuseNewExportTab();
    bool getIsNeedToConfuse();
    u1* getNewDynstr();
    bool getIsConfuseAll();
    bool getIsConfuse();
    Elf_Shdr* getDynstrShdr();
    void printAllStr();
    void printExportStr();
    void printImportStr();
    
private:
    void init();
    size_t initDynstrShdrLen();
    void initAllVectors();
    bool initIsNeedToConfuse();
    void encryptOldDynstr();

private:
    Elf_Shdr* mDynstrShdr;
    u1* mDynstrBase;
    u1* mNewDynstr;

    std::vector<std::string> mAllExportTabStrs;
    std::vector<std::string> mNeedExpTabStrs; //need to change
    std::vector<std::string> mChangedExpTabStrs;
    bool mIsConfuse;//外部传入,作为是否混淆的标准，如果为true，则符号不混淆,作为混淆的总开关
    bool mIsNeedToConfuse;//如果过滤掉的符号集合size大于1为true
    bool mIsConfuseAll;//新添加dynstr节，整个节是否混淆的判断依据
    
    size_t mDynstrShdrLen;
    Elf_Off mDynstrOff;
    Elf_Addr mDynstrAddr;

    ElfParser& mElfParser;
};

#endif	/* ELFDYNSTRUTIL_H */

