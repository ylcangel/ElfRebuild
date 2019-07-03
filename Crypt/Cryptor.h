/* 
 * File:   Cryptor.h
 * Author: AngelToms
 *
 */

#ifndef CRYPTOR_H
#define	CRYPTOR_H

#define ENCRYPT_TYPE_XOR            1
#define ENCRYPT_TYPE_STRANGE        2
#define XOR_FACTORY 0x12

#include "../Types.h"

typedef enum {
    XorConvert = 1,
    StrangeConvert,
    AsciiChange,
} EncryptType;

class Cryptor {
public:

    Cryptor() {
    }

    virtual ~Cryptor() {
    }
    //@param addition can cast real type, such as xor ,it can be casted int*
    //*addition = factor
    virtual bool encrypt(u1* base, int len, void* addition, EncryptType type) = 0;
};

class CryptFactory : public Cryptor {
public:

    CryptFactory() : Cryptor() {
    }

    ~CryptFactory() {
    }

    bool encrypt(u1* base, int len, void* addition, EncryptType type);
};
#endif	/* CRYPTOR_H */

