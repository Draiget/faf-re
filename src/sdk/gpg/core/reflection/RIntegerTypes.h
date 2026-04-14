#pragma once

#include <cstdint>
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"

/**
 * Generic integer reflection type templates.
 *
 * The original binary defines one `RIntType_X` per primitive integer width and
 * signedness. They share the same `GetLexical`/`SetLexical` shape and only
 * differ in the underlying integer type and the size value passed to `Init`.
 *
 * The corresponding `XTypeInfo` class registers itself in the gpg pre-RType
 * map under the appropriate typeid.
 */

template <class T>
class RIntType : public gpg::RType
{
public:
  /** Returns string form of `*ref.mObj` cast to `long long`. */
  [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
  /** Parses `str` as integer and stores at `*ref.mObj`. */
  bool SetLexical(const gpg::RRef& ref, const char* str) const override;
};

// Concrete instantiations - signed
using RIntType_char = RIntType<char>;
using RIntType_schar = RIntType<signed char>;
using RIntType_short = RIntType<short>;
using RIntType_int = RIntType<int>;
using RIntType_long = RIntType<long>;

// Concrete instantiations - unsigned
using RIntType_uchar = RIntType<unsigned char>;
using RIntType_ushort = RIntType<unsigned short>;
using RIntType_uint = RIntType<unsigned int>;
using RIntType_ulong = RIntType<unsigned long>;

#define DECLARE_INT_TYPE_INFO(NAME, T)                                                       \
  class NAME : public RIntType<T>                                                            \
  {                                                                                          \
  public:                                                                                    \
    NAME();                                                                                  \
    ~NAME() override;                                                                        \
    [[nodiscard]] const char* GetName() const override;                                      \
    void Init() override;                                                                    \
  };                                                                                         \
  void register_##NAME##Startup();

/**
 * Address: 0x008DFAD0 (FUN_008DFAD0, charTypeInfo::charTypeInfo)
 *
 * What it does:
 * Registers reflection metadata type for `char`.
 */
DECLARE_INT_TYPE_INFO(charTypeInfo, char)
/**
 * Address: 0x008DFE50 (FUN_008DFE50, signedcharTypeInfo::signedcharTypeInfo)
 *
 * What it does:
 * Registers reflection metadata type for `signed char`.
 */
DECLARE_INT_TYPE_INFO(signedcharTypeInfo, signed char)
/**
 * Address: 0x008DFF30 (FUN_008DFF30, unsignedcharTypeInfo::unsignedcharTypeInfo)
 *
 * What it does:
 * Registers reflection metadata type for `unsigned char`.
 */
DECLARE_INT_TYPE_INFO(unsignedcharTypeInfo, unsigned char)
/**
 * Address: 0x008DFBB0 (FUN_008DFBB0, shortTypeInfo::shortTypeInfo)
 *
 * What it does:
 * Registers reflection metadata type for `short`.
 */
DECLARE_INT_TYPE_INFO(shortTypeInfo, short)
/**
 * Address: 0x008E0010 (FUN_008E0010, unsignedshortTypeInfo::unsignedshortTypeInfo)
 *
 * What it does:
 * Registers reflection metadata type for `unsigned short`.
 */
DECLARE_INT_TYPE_INFO(unsignedshortTypeInfo, unsigned short)
/**
 * Address: 0x008DFC90 (FUN_008DFC90, intTypeInfo::intTypeInfo)
 *
 * What it does:
 * Registers reflection metadata type for `int`.
 */
DECLARE_INT_TYPE_INFO(intTypeInfo, int)
/**
 * Address: 0x008E00F0 (FUN_008E00F0, unsignedintTypeInfo::unsignedintTypeInfo)
 *
 * What it does:
 * Registers reflection metadata type for `unsigned int`.
 */
DECLARE_INT_TYPE_INFO(unsignedintTypeInfo, unsigned int)
/**
 * Address: 0x008DFD70 (FUN_008DFD70, longTypeInfo::longTypeInfo)
 *
 * What it does:
 * Registers reflection metadata type for `long`.
 */
DECLARE_INT_TYPE_INFO(longTypeInfo, long)
/**
 * Address: 0x008E01D0 (FUN_008E01D0, unsignedlongTypeInfo::unsignedlongTypeInfo)
 *
 * What it does:
 * Registers reflection metadata type for `unsigned long`.
 */
DECLARE_INT_TYPE_INFO(unsignedlongTypeInfo, unsigned long)

#undef DECLARE_INT_TYPE_INFO
