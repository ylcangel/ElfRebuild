/**
 * for print hex log
 *
 *
 */

#include "HexLog.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#define	MAX_LINE_LEN				40960

void hexLog(const char *function, int lineNo, void *addr, u4 len) {

    char data[MAX_LINE_LEN] = {0};
    char outHex[MAX_LINE_LEN] = {0};
    char str[MAX_LINE_LEN] = {0};
    int modLen = 0;
    int i = 0;

    QUP_LOGI("****************************************************************\n");
    QUP_LOGI("[ hexLog ] %s(%d), Data Size: %d\n", function, lineNo, len);

    if (len * sizeof (u2) >= MAX_LINE_LEN) {
        QUP_LOGI("[ hexLog ] Org Size Skip: %d\n", len);
        return;
    }
    memcpy(data, addr, len);

    if (len % 0x10 == 0) {
        modLen = len;
    } else {
        modLen = len - len % 0x10 + 0x10;
    }
    if (len * sizeof (u2) >= MAX_LINE_LEN) {
        QUP_LOGI("[ hexLog ] New Size Skip: %d\n", modLen);
        return;
    }

    for (i = 0; i < modLen; i++) {
        if ((i & 0x0F) == 0) {
            sprintf(outHex, "%s%08X: ", outHex, i);
        }
        if ((i & 0x03) == 0) {
            sprintf(outHex, "%s %02X", outHex, data[i]);
        } else {
            sprintf(outHex, "%s%02X", outHex, data[i]);
        }
        sprintf(str, "%s%c", str, (data[i] < 32) || (data[i] > 126) ? '.' : data[i]);

        if ((i & 0x0F) == 0x0F) {
            sprintf(outHex, "%s  %s\n", outHex, str);
            memset(str, 0, MAX_LINE_LEN);
        }
    }

    QUP_LOGI("%s", outHex);
    QUP_LOGI("****************************************************************\n");
}



