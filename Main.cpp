/**
 *
 * File   : Main.cpp
 * Entry of Protector
 * Author : AngelToms
 *
 **/

#include "QupLog.h"
#include "Types.h"
#include "Export.h"
#include "Page.h"
#include "Common.h"

#include "Utils/SysUtil.h"
#include "ElfParser/ElfParser.h"
#include "ElfParser/ElfInitArrayUtil.h"
#include "ElfParser/ElfDynstrUtil.h"
#include "ElfParser/ElfRelUtil.h"
#include "ElfParser/ElfDynsymUtil.h"
#include "ElfParser/ElfBssUtil.h"
#include "ElfParser/ElfRodataUtil.h"
#include "Builder/ElfEncDynstrBuilder.h"
#include "Builder/ElfEncRodataBuilder.h"

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

void useAge() {
    QUP_LOGI("[++] elfprotector useage:");
    QUP_LOGI("					elfbuilder -t [dynstr | rodata] [input]");
    QUP_LOGI("[++] For example:");
    QUP_LOGI("					elfbuilder -t dynstr libtest.so");
    exit(-1);
}

int main(int argc, char** argv) {
    QUP_LOGI("[**] begin to exec protector");
    if (argc < 4)
        useAge();

    int opt;
    ShellCodeType encType = EncryptDynstr;
    char *optstring = (char*) "t:";
    while ((opt = getopt(argc, argv, optstring)) != -1) {
        QUP_LOGI("[**] optarg = %s", optarg);
        if (strcmp(optarg, "dynstr") != 0 && strcmp(optarg, "rodata") != 0)
            useAge();
        if (strcmp(optarg, "rodata") == 0) {
            encType = EncryptRodata;
            break;
        }
    }

    QUP_LOGI("[**] enc type = %d", encType);
    const char* inputDir = argv[3];
    std::string outputPath(inputDir);
    outputPath.append(".1");
    QUP_LOGI("[**] input file name = %s, output file name = %s", inputDir, outputPath.c_str());

    if (access(inputDir, R_OK) < 0) {
        QUP_LOGI("[--] input file : %s was not exist", inputDir);
        exit(-1);
    }

    int fd = open(inputDir, O_RDONLY);
    if (fd < 0) {
        QUP_LOGI("[--] open file %s fail : %s", inputDir, strerror(errno));
        exit(-1);
    }

    int fod = -1;
    struct MemMapping mmap;
    memset(&mmap, 0, sizeof (mmap));
    QUP_LOGI("[**] mmap file in shem");
    if (sysMapFileInShmemWritableReadOnly(fd, &mmap) < 0) {
        QUP_LOGI("[--] mmap file %d in shem fail", fd);
        exit(-1);
    }

    u1* addr = (u1*) mmap.addr;
    size_t fileLen = mmap.length;
    QUP_LOGI("[**] mmap file in shem addr = %p, file length = %u", addr, fileLen);
    bool firstFlags = true;
    bool secondFlags = true;
    ElfParser* elfParser = new ElfParser(addr, fileLen);
    ElfInitArrayUtil initUtil = ElfInitArrayUtil(*elfParser);
    //initUtil.printOldInitArray();
    //    ElfDynsymUtil dynsymUtil = ElfDynsymUtil(*elfParser);
    //    QUP_LOGI("[*] find sym __cxa_atexit addr = 0x%.8x", dynsymUtil.findSymAddrByName("__cxa_atexit"));
    //    QUP_LOGI("[*] find sym __aeabi_atexit addr = 0x%.8x", dynsymUtil.findSymAddrByName("__aeabi_atexit"));

    ElfRelUtil relUtil = ElfRelUtil(*elfParser);
    ElfBssUtil bssUtil = ElfBssUtil(*elfParser);
    //relUtil.printRelDyn();
    ElfBuilder* builder = NULL;
    ElfDynstrUtil* dynstrUtil = NULL;
    ElfRodataUtil* rodataUtil = NULL;
    
#ifndef TEST
    switch (encType) {
        case EncryptDynstr:
            QUP_LOGI("[**] alloc ElfEncDynstrBuilder");
            dynstrUtil = new ElfDynstrUtil(*elfParser, firstFlags, secondFlags);
            if (!dynstrUtil) {
                QUP_LOGI("[--] alloc dynstrUtil fail");
                goto fail;
            }
            builder = new ElfEncDynstrBuilder(*elfParser, initUtil, relUtil, bssUtil, *dynstrUtil);
            break;
        case EncryptRodata:
            QUP_LOGI("[**] alloc ElfEncRodataBuilder");
            rodataUtil = new ElfRodataUtil(*elfParser);
            if (!rodataUtil) {
                QUP_LOGI("[--] alloc rodataUtil fail");
                goto fail;
            }
            builder = new ElfEncRodataBuilder(*elfParser, initUtil, relUtil, bssUtil, *rodataUtil);
            break;
        default:
            QUP_LOGI("[++] not support");
            break;
    }

    if (!builder) {
        QUP_LOGI("[--] alloc elf builder fail");
        goto fail;
    }
    if (builder->getIsNeedRebuild()) {
        fod = open(outputPath.c_str(), O_CREAT | O_RDWR /*| O_APPEND*/, 0755);
        if (fod < 0) {
            QUP_LOGI("[--] create file %s fail : %s", outputPath.c_str(), strerror(errno));
            exit(-1);
        }
        builder->rebuild(fod);
    } else {
        QUP_LOGI("[++] this elf does't neet to rebuild");
    }
#endif

fail:
    QUP_LOGI("[**] release file in shem");
    sysReleaseShmem(&mmap);
    if (dynstrUtil) {
        delete dynstrUtil;
        dynstrUtil = NULL;
    }
    if (rodataUtil) {
        delete rodataUtil;
        rodataUtil = NULL;
    }
    if (builder) {
        delete builder;
        builder = NULL;
    }
    delete elfParser;
    elfParser = NULL;
    if (fd > 0)
        close(fd);
    if (fod > 0)
        close(fod);
    QUP_LOGI("[**] end to exec protector");
}