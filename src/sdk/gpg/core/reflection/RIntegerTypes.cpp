#include "gpg/core/reflection/RIntegerTypes.h"

#include <cstdio>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/BadRefCast.h"

namespace
{
  template <class TValue>
  using IntegerMakeRefFunc = gpg::RRef* (*)(gpg::RRef*, TValue*);

  template <class TValue>
  [[nodiscard]] TValue* TryUpcastIntegerValue(gpg::RRef* const sourceRef)
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(TValue));
    }

    const gpg::RRef upcastRef = gpg::REF_UpcastPtr(*sourceRef, sType);
    if (!upcastRef.mObj) {
      const char* const sourceName = sourceRef->mType ? sourceRef->mType->GetName() : "null";
      const char* const targetName = sType ? sType->GetName() : typeid(TValue).name();
      throw gpg::BadRefCast(nullptr, sourceName, targetName);
    }
    return static_cast<TValue*>(upcastRef.mObj);
  }

  template <class TValue>
  [[nodiscard]] gpg::RRef CopyIntegerValueRef(
    gpg::RRef* const sourceRef,
    const IntegerMakeRefFunc<TValue> makeRefFunc
  )
  {
    TValue* valueCopy = static_cast<TValue*>(::operator new(sizeof(TValue)));
    try {
      if (valueCopy != nullptr) {
        *valueCopy = *TryUpcastIntegerValue<TValue>(sourceRef);
      }
    } catch (...) {
      ::operator delete(valueCopy);
      throw;
    }

    gpg::RRef outRef{};
    makeRefFunc(&outRef, valueCopy);
    return outRef;
  }

  template <class TValue>
  [[nodiscard]] gpg::RRef MoveIntegerValueRef(
    void* const slotObject,
    gpg::RRef* const sourceRef,
    const IntegerMakeRefFunc<TValue> makeRefFunc
  )
  {
    TValue* slot = static_cast<TValue*>(slotObject);
    if (slot != nullptr) {
      *slot = *TryUpcastIntegerValue<TValue>(sourceRef);
    }

    gpg::RRef outRef{};
    makeRefFunc(&outRef, slot);
    return outRef;
  }

  /**
   * Address: 0x008E1D30 (FUN_008E1D30, RIntType_char::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopyCharRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<char>(sourceRef, &gpg::RRef_char);
  }

  /**
   * Address: 0x008E1EA0 (FUN_008E1EA0, RIntType_short::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopyShortRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<short>(sourceRef, &gpg::RRef_short);
  }

  /**
   * Address: 0x008E2010 (FUN_008E2010, RIntType_int::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopyIntRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<int>(sourceRef, &gpg::RRef_int);
  }

  /**
   * Address: 0x008E2180 (FUN_008E2180, RIntType_long::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopyLongRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<long>(sourceRef, &gpg::RRef_long);
  }

  /**
   * Address: 0x008E22F0 (FUN_008E22F0, RIntType_schar::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopySignedCharRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<signed char>(sourceRef, &gpg::RRef_schar);
  }

  /**
   * Address: 0x008E2460 (FUN_008E2460, RIntType_uchar::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopyUnsignedCharRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<unsigned char>(sourceRef, &gpg::RRef_uchar);
  }

  /**
   * Address: 0x008E2520 (FUN_008E2520, RIntType_uchar::MovRef)
   */
  [[nodiscard]] gpg::RRef MoveUnsignedCharRef(void* const slotObject, gpg::RRef* const sourceRef)
  {
    return MoveIntegerValueRef<unsigned char>(slotObject, sourceRef, &gpg::RRef_uchar);
  }

  /**
   * Address: 0x008E25D0 (FUN_008E25D0, RIntType_ushort::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopyUnsignedShortRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<unsigned short>(sourceRef, &gpg::RRef_ushort);
  }

  /**
   * Address: 0x008E2740 (FUN_008E2740, RIntType_uint::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopyUnsignedIntRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<unsigned int>(sourceRef, &gpg::RRef_uint);
  }

  /**
   * Address: 0x008E28B0 (FUN_008E28B0, RIntType_ulong::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopyUnsignedLongRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<unsigned long>(sourceRef, &gpg::RRef_ulong);
  }
} // namespace

// ---------------------------------------------------------------------------
// RIntType<T> template impls
// ---------------------------------------------------------------------------

/**
 * Address family — `RIntType<T>::GetLexical` per-type instantiations:
 *   0x008DDB50 (FUN_008DDB50, RIntType_char::GetLexical)
 *   0x008DDDC0 (FUN_008DDDC0, RIntType_short::GetLexical)
 *   0x008DDF70 (FUN_008DDF70, RIntType_int::GetLexical)
 *   0x008DE1D0 (FUN_008DE1D0, RIntType_long::GetLexical)
 *   0x008DE430 (FUN_008DE430, RIntType_schar::GetLexical)
 *   0x008DE680 (FUN_008DE680, RIntType_uchar::GetLexical)
 *   0x008DE8F0 (FUN_008DE8F0, RIntType_ushort::GetLexical)
 *   0x008DEB40 (FUN_008DEB40, RIntType_uint::GetLexical)
 *   0x008DEDA0 (FUN_008DEDA0, RIntType_ulong::GetLexical)
 *
 * What it does:
 * Formats the integer at `ref.mObj` as decimal into a 30-char msvc8::string
 * and truncates to the actual written length. The binary writes per-type
 * bodies with the matching printf width specifier; this template
 * consolidates all nine into one via `%lld` and explicit instantiation.
 */
template <class T>
msvc8::string RIntType<T>::GetLexical(const gpg::RRef& ref) const
{
  const T value = *static_cast<const T*>(ref.mObj);
  msvc8::string result;
  result.resize(30, '\0');
  const int n = std::sprintf(result.raw_data_mut_unsafe(), "%lld", static_cast<long long>(value));
  result.resize(static_cast<std::size_t>(n));
  return result;
}

template <class T>
bool RIntType<T>::SetLexical(const gpg::RRef& ref, const char* const str) const
{
  *static_cast<T*>(ref.mObj) = static_cast<T>(std::strtoll(str, nullptr, 10));
  return true;
}

// Explicit instantiations for the binary's concrete types
template class RIntType<char>;
template class RIntType<signed char>;
template class RIntType<unsigned char>;
template class RIntType<short>;
template class RIntType<unsigned short>;
template class RIntType<int>;
template class RIntType<unsigned int>;
template class RIntType<long>;
template class RIntType<unsigned long>;

// ---------------------------------------------------------------------------
// XTypeInfo registration boilerplate
// ---------------------------------------------------------------------------

#define IMPLEMENT_INT_TYPE_INFO(NAME, T, NAME_STR, CPY_REF_FUNC, MOV_REF_FUNC)               \
  namespace                                                                                  \
  {                                                                                          \
    alignas(NAME) unsigned char gStorage_##NAME[sizeof(NAME)];                               \
    bool gConstructed_##NAME = false;                                                        \
    [[nodiscard]] NAME& Acquire_##NAME()                                                     \
    {                                                                                        \
      if (!gConstructed_##NAME) {                                                            \
        new (gStorage_##NAME) NAME();                                                        \
        gConstructed_##NAME = true;                                                          \
      }                                                                                      \
      return *reinterpret_cast<NAME*>(gStorage_##NAME);                                      \
    }                                                                                        \
    void cleanup_##NAME()                                                                    \
    {                                                                                        \
      if (!gConstructed_##NAME) return;                                                      \
      auto& ti = *reinterpret_cast<NAME*>(gStorage_##NAME);                                  \
      ti.fields_ = msvc8::vector<gpg::RField>{};                                             \
      ti.bases_ = msvc8::vector<gpg::RField>{};                                              \
    }                                                                                        \
    struct Bootstrap_##NAME { Bootstrap_##NAME() { register_##NAME##Startup(); } };          \
    Bootstrap_##NAME gBootstrap_##NAME;                                                      \
  }                                                                                          \
  NAME::NAME()                                                                               \
  {                                                                                          \
    gpg::PreRegisterRType(typeid(T), this);                                                  \
  }                                                                                          \
  NAME::~NAME() = default;                                                                   \
  const char* NAME::GetName() const { return NAME_STR; }                                     \
  void NAME::Init()                                                                          \
  {                                                                                          \
    size_ = static_cast<int>(sizeof(T));                                                     \
    cpyRefFunc_ = CPY_REF_FUNC;                                                              \
    movRefFunc_ = MOV_REF_FUNC;                                                              \
    Finish();                                                                                \
  }                                                                                          \
  void register_##NAME##Startup()                                                            \
  {                                                                                          \
    (void)Acquire_##NAME();                                                                  \
    (void)std::atexit(&cleanup_##NAME);                                                      \
  }

/**
 * Address: 0x008DFAD0 (FUN_008DFAD0, charTypeInfo::charTypeInfo)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `char`.
 */
IMPLEMENT_INT_TYPE_INFO(charTypeInfo, char, "char", &CopyCharRef, nullptr)
/**
 * Address: 0x008DFE50 (FUN_008DFE50, signedcharTypeInfo::signedcharTypeInfo)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `signed char`.
 */
IMPLEMENT_INT_TYPE_INFO(signedcharTypeInfo, signed char, "signed char", &CopySignedCharRef, nullptr)
/**
 * Address: 0x008DFF30 (FUN_008DFF30, unsignedcharTypeInfo::unsignedcharTypeInfo)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `unsigned char`.
 */
IMPLEMENT_INT_TYPE_INFO(unsignedcharTypeInfo, unsigned char, "unsigned char", &CopyUnsignedCharRef, &MoveUnsignedCharRef)
/**
 * Address: 0x008DFBB0 (FUN_008DFBB0, shortTypeInfo::shortTypeInfo)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `short`.
 */
IMPLEMENT_INT_TYPE_INFO(shortTypeInfo, short, "short", &CopyShortRef, nullptr)
/**
 * Address: 0x008E0010 (FUN_008E0010, unsignedshortTypeInfo::unsignedshortTypeInfo)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `unsigned short`.
 */
IMPLEMENT_INT_TYPE_INFO(unsignedshortTypeInfo, unsigned short, "unsigned short", &CopyUnsignedShortRef, nullptr)
/**
 * Address: 0x008DFC90 (FUN_008DFC90, intTypeInfo::intTypeInfo)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `int`.
 */
IMPLEMENT_INT_TYPE_INFO(intTypeInfo, int, "int", &CopyIntRef, nullptr)
/**
 * Address: 0x008E00F0 (FUN_008E00F0, unsignedintTypeInfo::unsignedintTypeInfo)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `unsigned int`.
 */
IMPLEMENT_INT_TYPE_INFO(unsignedintTypeInfo, unsigned int, "unsigned int", &CopyUnsignedIntRef, nullptr)
/**
 * Address: 0x008DFD70 (FUN_008DFD70, longTypeInfo::longTypeInfo)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `long`.
 */
IMPLEMENT_INT_TYPE_INFO(longTypeInfo, long, "long", &CopyLongRef, nullptr)
/**
 * Address: 0x008E01D0 (FUN_008E01D0, unsignedlongTypeInfo::unsignedlongTypeInfo)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `unsigned long`.
 */
IMPLEMENT_INT_TYPE_INFO(unsignedlongTypeInfo, unsigned long, "unsigned long", &CopyUnsignedLongRef, nullptr)

#undef IMPLEMENT_INT_TYPE_INFO
