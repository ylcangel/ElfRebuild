#include "StrangeChar.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void simpleChange(char* src, char strangeChar, int index) {
    char suffix[4];
    memset(suffix, 0 , 4);
    sprintf(suffix, "%d", index);
    int suflen = strlen(suffix);
    int len = strlen(src);
    int last = len - suflen;
    for(int i = 0 ; i < last; i++ ) {
        *(src + i) =  strangeChar;
    }
    
    for(int i = last , j = 0; i < len; i++, j++) {
        *(src + i) =  suffix[j];
    }
}
