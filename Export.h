#ifndef EXPORT_H_
#define EXPORT_H_

#define ELF_EXPORT_MY_TEXT                             __attribute__ ((__section__ (".my.text1")))
#define ELF_EXPORT_INIT_ARRAY                          __attribute__((constructor))
#define EXPORT_SYM                                    __attribute__ ((visibility("default")))

#endif //EXPORT_H_