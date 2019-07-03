/* 
 * File:   Page.h
 * Author: AngelToms
 *
 */

#ifndef PAGE_H
#define	PAGE_H

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <endian.h>

#include "Types.h"
//#define PAGE_SHIFT 12
#define PAGE_SIZE getpagesize()
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
#define PAGE_MASK (~(PAGE_SIZE-1))
// Returns the address of the page containing address 'x'.
#define PAGE_START(x)  ((x) & PAGE_MASK)
#define PAGE_END(x)    PAGE_START((x) + (PAGE_SIZE-1))
// Returns the address of the next page after address 'x', unless 'x' is
// itself at the start of a page.
#define PAGE_END(x)    PAGE_START((x) + (PAGE_SIZE-1))
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)

//for align
// Round up n to be a multiple of sz, where sz is a power of 2.
#define ROUND_UP(x, align) ((x + (align - 1)) & ~(align - 1))
#define ROUND_TO_PAGE(address) ((address + PAGE_SIZE - 1) & (~(PAGE_SIZE - 1)))
////////////////TEST ALIGN/////////////////////////////////////////////////
typedef size_t Addr;
#define IS_2_ALIGNED(aaa_p)    (0 == (((Addr)(aaa_p)) & ((Addr)0x1)))
#define IS_4_ALIGNED(aaa_p)    (0 == (((Addr)(aaa_p)) & ((Addr)0x3)))
#define IS_8_ALIGNED(aaa_p)    (0 == (((Addr)(aaa_p)) & ((Addr)0x7)))
#define IS_16_ALIGNED(aaa_p)   (0 == (((Addr)(aaa_p)) & ((Addr)0xf)))
#define IS_32_ALIGNED(aaa_p)   (0 == (((Addr)(aaa_p)) & ((Addr)0x1f)))
#define IS_WORD_ALIGNED(aaa_p) (0 == (((Addr)(aaa_p)) & ((Addr)(sizeof(Addr)-1))))
#define IS_PAGE_ALIGNED(aaa_p) (0 == (((Addr)(aaa_p)) & ((Addr)(PAGE_SIZE-1))))

////////////////////linux kernel little endian and  big endian//////////////////
static union {
    char c[4];
    unsigned long l;
} endian_test = {
    { 'l', '?', '?', 'b'}
};
#define ENDIANNESS ((char)endian_test.l)
///////////////crc endian and  big endian///////////////////////////////////////
__inline__ bool isLittleEndian() {
u4 endian;        
endian = 1;
if (*((unsigned char *)(&endian)))
    return true;
else
    return false;
}
// -----------------------------------------------------------------------------
// Constants
typedef uint8_t byte;
typedef byte* Address;

const int KB = 1024;
const int MB = KB * KB;
const int GB = KB * KB * KB;
const int kMaxInt = 0x7FFFFFFF;
const int kMinInt = -kMaxInt - 1;
const int kMaxInt8 = (1 << 7) - 1;
const int kMinInt8 = -(1 << 7);
const int kMaxUInt8 = (1 << 8) - 1;
const int kMinUInt8 = 0;
const int kMaxInt16 = (1 << 15) - 1;
const int kMinInt16 = -(1 << 15);
const int kMaxUInt16 = (1 << 16) - 1;
const int kMinUInt16 = 0;

const uint32_t kMaxUInt32 = 0xFFFFFFFFu;

const int kCharSize = sizeof (char); // NOLINT
const int kShortSize = sizeof (short); // NOLINT
const int kIntSize = sizeof (int); // NOLINT
const int kInt32Size = sizeof (int32_t); // NOLINT
const int kInt64Size = sizeof (int64_t); // NOLINT
const int kDoubleSize = sizeof (double); // NOLINT
const int kIntptrSize = sizeof (intptr_t); // NOLINT
const int kPointerSize = sizeof (void*); // NOLINT
#if V8_TARGET_ARCH_X64 && V8_TARGET_ARCH_32_BIT
const int kRegisterSize = kPointerSize + kPointerSize;
#else
const int kRegisterSize = kPointerSize;
#endif
const int kPCOnStackSize = kRegisterSize;
const int kFPOnStackSize = kRegisterSize;

const int kDoubleSizeLog2 = 3;

#if V8_HOST_ARCH_64_BIT
const int kPointerSizeLog2 = 3;
1const intptr_t kIntptrSignBit = V8_INT64_C(0x8000000000000000);
const uintptr_t kUintptrAllBitsSet = V8_UINT64_C(0xFFFFFFFFFFFFFFFF);
const bool kRequiresCodeRange = true;
const size_t kMaximalCodeRangeSize = 512 * MB;
#else
const int kPointerSizeLog2 = 2;
const intptr_t kIntptrSignBit = 0x80000000;
const uintptr_t kUintptrAllBitsSet = 0xFFFFFFFFu;
#if V8_TARGET_ARCH_X64 && V8_TARGET_ARCH_32_BIT
// x32 port also requires code range.
const bool kRequiresCodeRange = true;
const size_t kMaximalCodeRangeSize = 256 * MB;
#else
const bool kRequiresCodeRange = false;
const size_t kMaximalCodeRangeSize = 0 * MB;
#endif
#endif

const int kBitsPerByte = 8;
const int kBitsPerByteLog2 = 3;
const int kBitsPerPointer = kPointerSize * kBitsPerByte;
const int kBitsPerInt = kIntSize * kBitsPerByte;

// IEEE 754 single precision floating point number bit layout.
const uint32_t kBinary32SignMask = 0x80000000u;
const uint32_t kBinary32ExponentMask = 0x7f800000u;
const uint32_t kBinary32MantissaMask = 0x007fffffu;
const int kBinary32ExponentBias = 127;
const int kBinary32MaxExponent = 0xFE;
const int kBinary32MinExponent = 0x01;
const int kBinary32MantissaBits = 23;
const int kBinary32ExponentShift = 23;

// Quiet NaNs have bits 51 to 62 set, possibly the sign bit, and no
// other bits set.
const uint64_t kQuietNaNMask = static_cast<uint64_t> (0xfff) << 51;

// Latin1/UTF-16 constants
// Code-point values in Unicode 4.0 are 21 bits wide.
// Code units in UTF-16 are 16 bits wide.
typedef uint16_t uc16;
typedef int32_t uc32;
const int kOneByteSize = kCharSize;
const int kUC16Size = sizeof (uc16); // NOLINT

// FUNCTION_ADDR(f) gets the address of a C function f.
#define FUNCTION_ADDR(f)                                        \
  (reinterpret_cast<v8::internal::Address>(reinterpret_cast<intptr_t>(f)))


// FUNCTION_CAST<F>(addr) casts an address into a function
// of type F. Used to invoke generated code from within C.

template <typename F>
F FUNCTION_CAST(Address addr) {
    return reinterpret_cast<F> (reinterpret_cast<intptr_t> (addr));
}


#endif	/* PAGE_H */

