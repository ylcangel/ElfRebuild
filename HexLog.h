/**
 * for print hex log
 *
 *
*/

#ifndef __HEX_LOG_H__
#define __HEX_LOG_H__

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "QupLog.h"
#include "Types.h"


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#ifdef LOGGER_ON
#define HEX_LOG(addr, len)	hexLog(__FUNCTION__, __LINE__, addr, len)
#else
#define HEX_LOG(addr, len)	
#endif


void hexLog(const char *funtion, int lineNo, void *addr, u4 len);


#ifdef __cplusplus
}
#endif //__cplusplus

#endif // __HEX_LOG_H__