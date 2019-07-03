#include "StringUtil.h"

#include <string.h>
#include <stdlib.h>

bool isBeginWith(const char* str, const char* prefix, int len) {
    for(int i = 0 ; i < len; i++) {
        if(*(str + i) != *(prefix + i))
            return false;
    }
    return true;
}
