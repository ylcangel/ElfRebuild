/* 
 * File:   Common.h
 * Author: angel-toms
 *
 */

#ifndef COMMON_H
#define	COMMON_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
    EncryptDynstr = 0,
    EncryptRodata,
} ShellCodeType;

#define NR_Clear_cache 0x0f0002


#ifdef	__cplusplus
}
#endif

#endif	/* COMMON_H */

