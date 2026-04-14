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
  /**
   * Address family - scalar deleting destructor thunks by specialization:
   * 0x008DDC20 (FUN_008DDC20, RIntType_char::dtr)
   * 0x008DDE90 (FUN_008DDE90, RIntType_short::dtr)
   * 0x008DE040 (FUN_008DE040, RIntType_int::dtr)
   * 0x008DE2A0 (FUN_008DE2A0, RIntType_long::dtr)
   * 0x008DE500 (FUN_008DE500, RIntType_schar::dtr)
   * 0x008DE750 (FUN_008DE750, RIntType_uchar::dtr)
   * 0x008DE9C0 (FUN_008DE9C0, RIntType_ushort::dtr)
   * 0x008DEC10 (FUN_008DEC10, RIntType_uint::dtr)
   * 0x008DEE70 (FUN_008DEE70, RIntType_ulong::dtr)
   *
   * What it does:
   * Releases `gpg::RType` field/base vectors and participates in scalar-delete
   * thunk paths for concrete integer type-info specializations.
   */
  ~RIntType() override;

  /**
   * Address family - callback-lane binder by specialization:
   * 0x008E2F90 (FUN_008E2F90, RIntType_char::Init)
   * 0x008E2FC0 (FUN_008E2FC0, RIntType_short::Init)
   * 0x008E2FF0 (FUN_008E2FF0, RIntType_int::Init)
   * 0x008E3020 (FUN_008E3020, RIntType_long::Init)
   * 0x008E3050 (FUN_008E3050, RIntType_schar::Init)
   * 0x008E3080 (FUN_008E3080, RIntType_uchar::Init)
   * 0x008E30B0 (FUN_008E30B0, RIntType_ushort::Init)
   * 0x008E30E0 (FUN_008E30E0, RIntType_uint::Init)
   * 0x008E3110 (FUN_008E3110, RIntType_ulong::Init)
   *
   * What it does:
   * Binds integer-ref New/Copy/Ctor/Move/Delete/Destruct callbacks for the
   * concrete integer specialization.
   */
  void Init() override;

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
 * Address: 0x008E3140 (FUN_008E3140, charTypeInfo::Init)
 *
 * What it does:
 * Registers and initializes reflection metadata type for `char`.
 */
DECLARE_INT_TYPE_INFO(charTypeInfo, char)
/**
 * Address: 0x008DFE50 (FUN_008DFE50, signedcharTypeInfo::signedcharTypeInfo)
 * Address: 0x008E3240 (FUN_008E3240, signedcharTypeInfo::Init)
 *
 * What it does:
 * Registers and initializes reflection metadata type for `signed char`.
 */
DECLARE_INT_TYPE_INFO(signedcharTypeInfo, signed char)
/**
 * Address: 0x008DFF30 (FUN_008DFF30, unsignedcharTypeInfo::unsignedcharTypeInfo)
 * Address: 0x008E3280 (FUN_008E3280, unsignedcharTypeInfo::Init)
 *
 * What it does:
 * Registers and initializes reflection metadata type for `unsigned char`.
 */
DECLARE_INT_TYPE_INFO(unsignedcharTypeInfo, unsigned char)
/**
 * Address: 0x008DFBB0 (FUN_008DFBB0, shortTypeInfo::shortTypeInfo)
 * Address: 0x008E3180 (FUN_008E3180, shortTypeInfo::Init)
 *
 * What it does:
 * Registers and initializes reflection metadata type for `short`.
 */
DECLARE_INT_TYPE_INFO(shortTypeInfo, short)
/**
 * Address: 0x008E0010 (FUN_008E0010, unsignedshortTypeInfo::unsignedshortTypeInfo)
 * Address: 0x008E32C0 (FUN_008E32C0, unsignedshortTypeInfo::Init)
 *
 * What it does:
 * Registers and initializes reflection metadata type for `unsigned short`.
 */
DECLARE_INT_TYPE_INFO(unsignedshortTypeInfo, unsigned short)
/**
 * Address: 0x008DFC90 (FUN_008DFC90, intTypeInfo::intTypeInfo)
 * Address: 0x008E31C0 (FUN_008E31C0, intTypeInfo::Init)
 *
 * What it does:
 * Registers and initializes reflection metadata type for `int`.
 */
DECLARE_INT_TYPE_INFO(intTypeInfo, int)
/**
 * Address: 0x008E00F0 (FUN_008E00F0, unsignedintTypeInfo::unsignedintTypeInfo)
 * Address: 0x008E3300 (FUN_008E3300, unsignedintTypeInfo::Init)
 *
 * What it does:
 * Registers and initializes reflection metadata type for `unsigned int`.
 */
DECLARE_INT_TYPE_INFO(unsignedintTypeInfo, unsigned int)
/**
 * Address: 0x008DFD70 (FUN_008DFD70, longTypeInfo::longTypeInfo)
 * Address: 0x008E3200 (FUN_008E3200, longTypeInfo::Init)
 *
 * What it does:
 * Registers and initializes reflection metadata type for `long`.
 */
DECLARE_INT_TYPE_INFO(longTypeInfo, long)
/**
 * Address: 0x008E01D0 (FUN_008E01D0, unsignedlongTypeInfo::unsignedlongTypeInfo)
 * Address: 0x008E3340 (FUN_008E3340, unsignedlongTypeInfo::Init)
 *
 * What it does:
 * Registers and initializes reflection metadata type for `unsigned long`.
 */
DECLARE_INT_TYPE_INFO(unsignedlongTypeInfo, unsigned long)

#undef DECLARE_INT_TYPE_INFO
