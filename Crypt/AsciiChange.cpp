#include "AsciiChange.h"

#include <string.h>
//#include <time.h>//需要修改导入表，并且需要添加额外的符号，这里暂时不用

#define UPER_CHAR_MIN_BOUND         65
#define UPER_CHAR_MAX_BOUND         90
#define LOWER_CHAR_MIN_BOUND        97
#define LOWER_CHAR_MAX_BOUND        122
#define NUM_MIN_BOUND              48
#define NUM_MAX_BOUND              57
#define UNDERLINE_VAL              95

void asciiChange(char* src) {
    int len = strlen(src);
    for(int i = 0 ; i < len; i++) {
        int r = *(src + i) + 4;
        if(r < NUM_MIN_BOUND ||
                (r > UNDERLINE_VAL && r < LOWER_CHAR_MIN_BOUND) ||
                (r > NUM_MAX_BOUND && r < UPER_CHAR_MIN_BOUND) ||
                (r > UPER_CHAR_MAX_BOUND && r < UNDERLINE_VAL) ||
                (r > LOWER_CHAR_MAX_BOUND)) {
//             *(src + i) = UNDERLINE_VAL;
            continue;
        } else {
            *(src + i) = r;
        }
    }
}
