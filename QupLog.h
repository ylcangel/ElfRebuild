#ifndef __QUP_LOG_H__
#define __QUP_LOG_H__
#define LOGGER_ON
#ifdef LOGGER_ON

// #include <android/log.h>
// #define QUP_LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "QUP", __VA_ARGS__))
#include <stdio.h>
//#define QUP_LOGI(...)                            printf("%s",__FILE__);             \
//                                                printf( ", %s", __FUNCTION__ );     \
//                                                printf( ", %d ", __LINE__ );        \
//                                                printf(__VA_ARGS__);                \
//                                                printf("\n")


#define QUP_LOGI(...)                           printf(__VA_ARGS__);                \
                                                printf("\n")

#else // LOGGER_ON

#define QUP_LOGI(...)

#endif

#endif // __QUP_LOG_H__
