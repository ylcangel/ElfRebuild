/* 
 * File:   AsciiChange.h
 * Author: AngelToms
 *
 */

#ifndef ASCIICHANGE_H
#define	ASCIICHANGE_H

#include <stdlib.h>

#define UPER_CHAR_MIN_BOUND         65
#define UPER_CHAR_MAX_BOUND         90
#define LOWER_CHAR_MIN_BOUND        97
#define LOWER_CHAR_MAX_BOUND        122
#define NUM_MIN_BOUND              48
#define NUM_MAX_BOUND              57
#define UNDERLINE_VAL              95

#ifdef	__cplusplus
extern "C" {
#endif

    void asciiChange(char* src);

#ifdef	__cplusplus
}
#endif

#endif	/* ASCIICHANGE_H */

