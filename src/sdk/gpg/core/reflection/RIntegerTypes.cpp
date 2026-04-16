#include "gpg/core/reflection/RIntegerTypes.h"

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <new>
#include <type_traits>
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

  template <class TValue>
  [[nodiscard]] gpg::RRef ConstructIntegerValueRef(
    void* const slotObject,
    const IntegerMakeRefFunc<TValue> makeRefFunc
  )
  {
    gpg::RRef outRef{};
    makeRefFunc(&outRef, static_cast<TValue*>(slotObject));
    return outRef;
  }

  template <class TValue>
  [[nodiscard]] gpg::RRef NewIntegerValueRef(const IntegerMakeRefFunc<TValue> makeRefFunc)
  {
    TValue* const slot = static_cast<TValue*>(::operator new(sizeof(TValue)));
    gpg::RRef outRef{};
    makeRefFunc(&outRef, slot);
    return outRef;
  }

  template <class TValue>
  void DeleteIntegerValue(void* const slotObject)
  {
    static_cast<void>(sizeof(TValue));
    ::operator delete(slotObject);
  }

  template <class TValue>
  void DestructIntegerValue(void* const slotObject)
  {
    static_cast<void>(sizeof(TValue));
    static_cast<void>(slotObject);
  }

  template <class TValue>
  [[nodiscard]] bool ParseLegacyIntegerLexicalBounded(
    const char* const text,
    const char* const end,
    TValue* const outValue
  ) noexcept
  {
    using UnsignedValue = std::make_unsigned_t<TValue>;

    const char* cursor = text;
    bool isNegative = false;
    if (*cursor == '-') {
      isNegative = true;
      ++cursor;
    }

    std::uint32_t radix = 10u;
    if (*cursor == '0') {
      if (cursor[1] == 'x') {
        radix = 16u;
        cursor += 2;
      } else {
        radix = 8u;
      }
    }

    UnsignedValue value = 0;
    char ch = *cursor;
    do {
      int digit = 0;
      const unsigned char decimalDigit = static_cast<unsigned char>(ch - '0');
      if (decimalDigit <= 9u) {
        digit = static_cast<int>(ch - '0');
      } else {
        const unsigned char lowerAlphaDigit = static_cast<unsigned char>(ch - 'a');
        if (lowerAlphaDigit > 0x19u && ch != 'A') {
          return false;
        }
        digit = static_cast<int>(ch - 'W');
      }

      if (digit >= static_cast<int>(radix)) {
        return false;
      }

      value = static_cast<UnsignedValue>(
        static_cast<UnsignedValue>(value * static_cast<UnsignedValue>(radix))
        + static_cast<UnsignedValue>(digit)
      );

      ++cursor;
      ch = *cursor;
    } while (ch != '\0' && cursor != end);

    if (isNegative) {
      value = static_cast<UnsignedValue>(0u - value);
    }

    *outValue = static_cast<TValue>(value);
    return true;
  }

  /**
   * Address: 0x008DDA60 (FUN_008DDA60)
   *
   * What it does:
   * Parses one bounded lexical integer lane into one `char` destination.
   */
  [[nodiscard]] bool ParseRIntTypeCharLexical(
    const char* const text,
    const char* const end,
    char* const outValue
  ) noexcept
  {
    return ParseLegacyIntegerLexicalBounded<char>(text, end, outValue);
  }

  /**
   * Address: 0x008DDCC0 (FUN_008DDCC0)
   *
   * What it does:
   * Parses one bounded lexical integer lane into one `short` destination.
   */
  [[nodiscard]] bool ParseRIntTypeShortLexical(
    const char* const text,
    const char* const end,
    short* const outValue
  ) noexcept
  {
    return ParseLegacyIntegerLexicalBounded<short>(text, end, outValue);
  }

  /**
   * Address: 0x008DE0E0 (FUN_008DE0E0)
   *
   * What it does:
   * Parses one bounded lexical integer lane into one `long` destination.
   */
  [[nodiscard]] bool ParseRIntTypeLongLexical(
    const char* const text,
    const char* const end,
    long* const outValue
  ) noexcept
  {
    return ParseLegacyIntegerLexicalBounded<long>(text, end, outValue);
  }

  /**
   * Address: 0x008DE340 (FUN_008DE340)
   *
   * What it does:
   * Parses one bounded lexical integer lane into one `signed char` destination.
   */
  [[nodiscard]] bool ParseRIntTypeSignedCharLexical(
    const char* const text,
    const char* const end,
    signed char* const outValue
  ) noexcept
  {
    return ParseLegacyIntegerLexicalBounded<signed char>(text, end, outValue);
  }

  /**
   * Address: 0x008DE590 (FUN_008DE590)
   *
   * What it does:
   * Parses one bounded lexical integer lane into one `unsigned char`
   * destination.
   */
  [[nodiscard]] bool ParseRIntTypeUnsignedCharLexical(
    const char* const text,
    const char* const end,
    unsigned char* const outValue
  ) noexcept
  {
    return ParseLegacyIntegerLexicalBounded<unsigned char>(text, end, outValue);
  }

  /**
   * Address: 0x008DE7F0 (FUN_008DE7F0)
   *
   * What it does:
   * Parses one bounded lexical integer lane into one `unsigned short`
   * destination.
   */
  [[nodiscard]] bool ParseRIntTypeUnsignedShortLexical(
    const char* const text,
    const char* const end,
    unsigned short* const outValue
  ) noexcept
  {
    return ParseLegacyIntegerLexicalBounded<unsigned short>(text, end, outValue);
  }

  /**
   * Address: 0x008DEA50 (FUN_008DEA50)
   *
   * What it does:
   * Parses one bounded lexical integer lane into one `unsigned int`
   * destination.
   */
  [[nodiscard]] bool ParseRIntTypeUnsignedIntLexical(
    const char* const text,
    const char* const end,
    unsigned int* const outValue
  ) noexcept
  {
    return ParseLegacyIntegerLexicalBounded<unsigned int>(text, end, outValue);
  }

  /**
   * Address: 0x008DECB0 (FUN_008DECB0)
   *
   * What it does:
   * Parses one bounded lexical integer lane into one `unsigned long`
   * destination.
   */
  [[nodiscard]] bool ParseRIntTypeUnsignedLongLexical(
    const char* const text,
    const char* const end,
    unsigned long* const outValue
  ) noexcept
  {
    return ParseLegacyIntegerLexicalBounded<unsigned long>(text, end, outValue);
  }

  /**
   * Address: 0x008E1D00 (FUN_008E1D00, RIntType_char::NewRef)
   */
  [[nodiscard]] gpg::RRef NewCharRef()
  {
    return NewIntegerValueRef<char>(&gpg::RRef_char);
  }

  /**
   * Address: 0x008E1DC0 (FUN_008E1DC0, RIntType_char::CtrRef)
   */
  [[nodiscard]] gpg::RRef ConstructCharRef(void* const slotObject)
  {
    return ConstructIntegerValueRef<char>(slotObject, &gpg::RRef_char);
  }

  /**
   * Address: 0x008E1D30 (FUN_008E1D30, RIntType_char::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopyCharRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<char>(sourceRef, &gpg::RRef_char);
  }

  /**
   * Address: 0x008E1DF0 (FUN_008E1DF0, RIntType_char::MovRef)
   */
  [[nodiscard]] gpg::RRef MoveCharRef(void* const slotObject, gpg::RRef* const sourceRef)
  {
    return MoveIntegerValueRef<char>(slotObject, sourceRef, &gpg::RRef_char);
  }

  /**
   * Address: 0x008DDA40 (FUN_008DDA40, RIntType_char::Delete)
   *
   * What it does:
   * Releases one `char` integer-ref allocation lane via `operator delete`.
   */
  void DeleteCharRef(void* const slotObject)
  {
    ::operator delete(slotObject);
  }

  /**
   * Address: 0x008DDA50 (FUN_008DDA50, RIntType_char::Destruct)
   *
   * What it does:
   * No-op destructor lane for `char` integer-ref storage.
   */
  void DestructCharRef(void* const slotObject)
  {
    static_cast<void>(slotObject);
  }

  /**
   * Address: 0x008E1E70 (FUN_008E1E70, RIntType_short::NewRef)
   */
  [[nodiscard]] gpg::RRef NewShortRef()
  {
    return NewIntegerValueRef<short>(&gpg::RRef_short);
  }

  /**
   * Address: 0x008E1F30 (FUN_008E1F30, RIntType_short::CtrRef)
   */
  [[nodiscard]] gpg::RRef ConstructShortRef(void* const slotObject)
  {
    return ConstructIntegerValueRef<short>(slotObject, &gpg::RRef_short);
  }

  /**
   * Address: 0x008E1EA0 (FUN_008E1EA0, RIntType_short::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopyShortRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<short>(sourceRef, &gpg::RRef_short);
  }

  /**
   * Address: 0x008E1F60 (FUN_008E1F60, RIntType_short::MovRef)
   */
  [[nodiscard]] gpg::RRef MoveShortRef(void* const slotObject, gpg::RRef* const sourceRef)
  {
    return MoveIntegerValueRef<short>(slotObject, sourceRef, &gpg::RRef_short);
  }

  /**
   * Address: 0x008DDC90 (FUN_008DDC90, RIntType_short::Delete)
   *
   * What it does:
   * Releases one `short` integer-ref allocation lane via `operator delete`.
   */
  void DeleteShortRef(void* const slotObject)
  {
    ::operator delete(slotObject);
  }

  /**
   * Address: 0x008DDCA0 (FUN_008DDCA0, RIntType_short::Destruct)
   *
   * What it does:
   * No-op destructor lane for `short` integer-ref storage.
   */
  void DestructShortRef(void* const slotObject)
  {
    static_cast<void>(slotObject);
  }

  /**
   * Address: 0x008E1FE0 (FUN_008E1FE0, RIntType_int::NewRef)
   */
  [[nodiscard]] gpg::RRef NewIntRef()
  {
    return NewIntegerValueRef<int>(&gpg::RRef_int);
  }

  /**
   * Address: 0x008E20A0 (FUN_008E20A0, RIntType_int::CtrRef)
   */
  [[nodiscard]] gpg::RRef ConstructIntRef(void* const slotObject)
  {
    return ConstructIntegerValueRef<int>(slotObject, &gpg::RRef_int);
  }

  /**
   * Address: 0x008E2010 (FUN_008E2010, RIntType_int::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopyIntRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<int>(sourceRef, &gpg::RRef_int);
  }

  /**
   * Address: 0x008E20D0 (FUN_008E20D0, RIntType_int::MovRef)
   */
  [[nodiscard]] gpg::RRef MoveIntRef(void* const slotObject, gpg::RRef* const sourceRef)
  {
    return MoveIntegerValueRef<int>(slotObject, sourceRef, &gpg::RRef_int);
  }

  /**
   * Address: 0x008DDF00 (FUN_008DDF00, RIntType_int::Delete)
   *
   * What it does:
   * Releases one `int` integer-ref allocation lane via `operator delete`.
   */
  void DeleteIntRef(void* const slotObject)
  {
    ::operator delete(slotObject);
  }

  /**
   * Address: 0x008DDF10 (FUN_008DDF10, RIntType_int::Destruct)
   *
   * What it does:
   * No-op destructor lane for `int` integer-ref storage.
   */
  void DestructIntRef(void* const slotObject)
  {
    static_cast<void>(slotObject);
  }

  /**
   * Address: 0x008E2150 (FUN_008E2150, RIntType_long::NewRef)
   */
  [[nodiscard]] gpg::RRef NewLongRef()
  {
    return NewIntegerValueRef<long>(&gpg::RRef_long);
  }

  /**
   * Address: 0x008E2210 (FUN_008E2210, RIntType_long::CtrRef)
   */
  [[nodiscard]] gpg::RRef ConstructLongRef(void* const slotObject)
  {
    return ConstructIntegerValueRef<long>(slotObject, &gpg::RRef_long);
  }

  /**
   * Address: 0x008E2180 (FUN_008E2180, RIntType_long::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopyLongRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<long>(sourceRef, &gpg::RRef_long);
  }

  /**
   * Address: 0x008E2240 (FUN_008E2240, RIntType_long::MovRef)
   */
  [[nodiscard]] gpg::RRef MoveLongRef(void* const slotObject, gpg::RRef* const sourceRef)
  {
    return MoveIntegerValueRef<long>(slotObject, sourceRef, &gpg::RRef_long);
  }

  /**
   * Address: 0x008DE0B0 (FUN_008DE0B0, RIntType_long::Delete)
   *
   * What it does:
   * Releases one `long` integer-ref allocation lane via `operator delete`.
   */
  void DeleteLongRef(void* const slotObject)
  {
    ::operator delete(slotObject);
  }

  /**
   * Address: 0x008DE0C0 (FUN_008DE0C0, RIntType_long::Destruct)
   *
   * What it does:
   * No-op destructor lane for `long` integer-ref storage.
   */
  void DestructLongRef(void* const slotObject)
  {
    static_cast<void>(slotObject);
  }

  /**
   * Address: 0x008E22C0 (FUN_008E22C0, RIntType_schar::NewRef)
   */
  [[nodiscard]] gpg::RRef NewSignedCharRef()
  {
    return NewIntegerValueRef<signed char>(&gpg::RRef_schar);
  }

  /**
   * Address: 0x008E2380 (FUN_008E2380, RIntType_schar::CtrRef)
   */
  [[nodiscard]] gpg::RRef ConstructSignedCharRef(void* const slotObject)
  {
    return ConstructIntegerValueRef<signed char>(slotObject, &gpg::RRef_schar);
  }

  /**
   * Address: 0x008E22F0 (FUN_008E22F0, RIntType_schar::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopySignedCharRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<signed char>(sourceRef, &gpg::RRef_schar);
  }

  /**
   * Address: 0x008E23B0 (FUN_008E23B0, RIntType_schar::MovRef)
   */
  [[nodiscard]] gpg::RRef MoveSignedCharRef(void* const slotObject, gpg::RRef* const sourceRef)
  {
    return MoveIntegerValueRef<signed char>(slotObject, sourceRef, &gpg::RRef_schar);
  }

  /**
   * Address: 0x008DE310 (FUN_008DE310, RIntType_schar::Delete)
   *
   * What it does:
   * Releases one `signed char` integer-ref allocation lane via `operator delete`.
   */
  void DeleteSignedCharRef(void* const slotObject)
  {
    ::operator delete(slotObject);
  }

  /**
   * Address: 0x008DE320 (FUN_008DE320, RIntType_schar::Destruct)
   *
   * What it does:
   * No-op destructor lane for `signed char` integer-ref storage.
   */
  void DestructSignedCharRef(void* const slotObject)
  {
    static_cast<void>(slotObject);
  }

  /**
   * Address: 0x008E2430 (FUN_008E2430, RIntType_uchar::NewRef)
   */
  [[nodiscard]] gpg::RRef NewUnsignedCharRef()
  {
    return NewIntegerValueRef<unsigned char>(&gpg::RRef_uchar);
  }

  /**
   * Address: 0x008E24F0 (FUN_008E24F0, RIntType_uchar::CtrRef)
   */
  [[nodiscard]] gpg::RRef ConstructUnsignedCharRef(void* const slotObject)
  {
    return ConstructIntegerValueRef<unsigned char>(slotObject, &gpg::RRef_uchar);
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
   * Address: 0x008DE570 (FUN_008DE570, RIntType_uchar::Delete)
   *
   * What it does:
   * Releases one `unsigned char` integer-ref allocation lane via `operator delete`.
   */
  void DeleteUnsignedCharRef(void* const slotObject)
  {
    ::operator delete(slotObject);
  }

  /**
   * Address: 0x008DE580 (FUN_008DE580, RIntType_uchar::Destruct)
   *
   * What it does:
   * No-op destructor lane for `unsigned char` integer-ref storage.
   */
  void DestructUnsignedCharRef(void* const slotObject)
  {
    static_cast<void>(slotObject);
  }

  /**
   * Address: 0x008E25A0 (FUN_008E25A0, RIntType_ushort::NewRef)
   */
  [[nodiscard]] gpg::RRef NewUnsignedShortRef()
  {
    return NewIntegerValueRef<unsigned short>(&gpg::RRef_ushort);
  }

  /**
   * Address: 0x008E2660 (FUN_008E2660, RIntType_ushort::CtrRef)
   */
  [[nodiscard]] gpg::RRef ConstructUnsignedShortRef(void* const slotObject)
  {
    return ConstructIntegerValueRef<unsigned short>(slotObject, &gpg::RRef_ushort);
  }

  /**
   * Address: 0x008E25D0 (FUN_008E25D0, RIntType_ushort::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopyUnsignedShortRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<unsigned short>(sourceRef, &gpg::RRef_ushort);
  }

  /**
   * Address: 0x008E2690 (FUN_008E2690, RIntType_ushort::MovRef)
   */
  [[nodiscard]] gpg::RRef MoveUnsignedShortRef(void* const slotObject, gpg::RRef* const sourceRef)
  {
    return MoveIntegerValueRef<unsigned short>(slotObject, sourceRef, &gpg::RRef_ushort);
  }

  /**
   * Address: 0x008DE7C0 (FUN_008DE7C0, RIntType_ushort::Delete)
   *
   * What it does:
   * Releases one `unsigned short` integer-ref allocation lane via `operator delete`.
   */
  void DeleteUnsignedShortRef(void* const slotObject)
  {
    ::operator delete(slotObject);
  }

  /**
   * Address: 0x008DE7D0 (FUN_008DE7D0, RIntType_ushort::Destruct)
   *
   * What it does:
   * No-op destructor lane for `unsigned short` integer-ref storage.
   */
  void DestructUnsignedShortRef(void* const slotObject)
  {
    static_cast<void>(slotObject);
  }

  /**
   * Address: 0x008E2710 (FUN_008E2710, RIntType_uint::NewRef)
   */
  [[nodiscard]] gpg::RRef NewUnsignedIntRef()
  {
    return NewIntegerValueRef<unsigned int>(&gpg::RRef_uint);
  }

  /**
   * Address: 0x008E27D0 (FUN_008E27D0, RIntType_uint::CtrRef)
   */
  [[nodiscard]] gpg::RRef ConstructUnsignedIntRef(void* const slotObject)
  {
    return ConstructIntegerValueRef<unsigned int>(slotObject, &gpg::RRef_uint);
  }

  /**
   * Address: 0x008E2740 (FUN_008E2740, RIntType_uint::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopyUnsignedIntRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<unsigned int>(sourceRef, &gpg::RRef_uint);
  }

  /**
   * Address: 0x008E2800 (FUN_008E2800, RIntType_uint::MovRef)
   */
  [[nodiscard]] gpg::RRef MoveUnsignedIntRef(void* const slotObject, gpg::RRef* const sourceRef)
  {
    return MoveIntegerValueRef<unsigned int>(slotObject, sourceRef, &gpg::RRef_uint);
  }

  /**
   * Address: 0x008DEA30 (FUN_008DEA30, RIntType_uint::Delete)
   *
   * What it does:
   * Releases one `unsigned int` integer-ref allocation lane via `operator delete`.
   */
  void DeleteUnsignedIntRef(void* const slotObject)
  {
    ::operator delete(slotObject);
  }

  /**
   * Address: 0x008DEA40 (FUN_008DEA40, RIntType_uint::Destruct)
   *
   * What it does:
   * No-op destructor lane for `unsigned int` integer-ref storage.
   */
  void DestructUnsignedIntRef(void* const slotObject)
  {
    static_cast<void>(slotObject);
  }

  /**
   * Address: 0x008E2880 (FUN_008E2880, RIntType_ulong::NewRef)
   */
  [[nodiscard]] gpg::RRef NewUnsignedLongRef()
  {
    return NewIntegerValueRef<unsigned long>(&gpg::RRef_ulong);
  }

  /**
   * Address: 0x008E2940 (FUN_008E2940, RIntType_ulong::CtrRef)
   */
  [[nodiscard]] gpg::RRef ConstructUnsignedLongRef(void* const slotObject)
  {
    return ConstructIntegerValueRef<unsigned long>(slotObject, &gpg::RRef_ulong);
  }

  /**
   * Address: 0x008E28B0 (FUN_008E28B0, RIntType_ulong::CpyRef)
   */
  [[nodiscard]] gpg::RRef CopyUnsignedLongRef(gpg::RRef* const sourceRef)
  {
    return CopyIntegerValueRef<unsigned long>(sourceRef, &gpg::RRef_ulong);
  }

  /**
   * Address: 0x008E2970 (FUN_008E2970, RIntType_ulong::MovRef)
   */
  [[nodiscard]] gpg::RRef MoveUnsignedLongRef(void* const slotObject, gpg::RRef* const sourceRef)
  {
    return MoveIntegerValueRef<unsigned long>(slotObject, sourceRef, &gpg::RRef_ulong);
  }

  /**
   * Address: 0x008DEC80 (FUN_008DEC80, RIntType_ulong::Delete)
   *
   * What it does:
   * Releases one `unsigned long` integer-ref allocation lane via `operator delete`.
   */
  void DeleteUnsignedLongRef(void* const slotObject)
  {
    ::operator delete(slotObject);
  }

  /**
   * Address: 0x008DEC90 (FUN_008DEC90, RIntType_ulong::Destruct)
   *
   * What it does:
   * No-op destructor lane for `unsigned long` integer-ref storage.
   */
  void DestructUnsignedLongRef(void* const slotObject)
  {
    static_cast<void>(slotObject);
  }

  /**
   * Address: 0x008E2C30 (FUN_008E2C30)
   *
   * What it does:
   * Binds the `char` create/destroy callback subset on one reflected type
   * descriptor lane (`new/ctor/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindCharCreateDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->newRefFunc_ = &NewCharRef;
    typeInfo->ctorRefFunc_ = &ConstructCharRef;
    typeInfo->deleteFunc_ = &DeleteCharRef;
    typeInfo->dtrFunc_ = &DestructCharRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2C60 (FUN_008E2C60)
   *
   * What it does:
   * Binds the `char` copy/move callback subset on one reflected type
   * descriptor lane (`copy/move/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindCharCopyMoveDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->cpyRefFunc_ = &CopyCharRef;
    typeInfo->movRefFunc_ = &MoveCharRef;
    typeInfo->deleteFunc_ = &DeleteCharRef;
    typeInfo->dtrFunc_ = &DestructCharRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2C90 (FUN_008E2C90)
   *
   * What it does:
   * Binds the `short` create/destroy callback subset on one reflected type
   * descriptor lane (`new/ctor/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindShortCreateDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->newRefFunc_ = &NewShortRef;
    typeInfo->ctorRefFunc_ = &ConstructShortRef;
    typeInfo->deleteFunc_ = &DeleteShortRef;
    typeInfo->dtrFunc_ = &DestructShortRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2CC0 (FUN_008E2CC0)
   *
   * What it does:
   * Binds the `short` copy/move callback subset on one reflected type
   * descriptor lane (`copy/move/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindShortCopyMoveDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->cpyRefFunc_ = &CopyShortRef;
    typeInfo->movRefFunc_ = &MoveShortRef;
    typeInfo->deleteFunc_ = &DeleteShortRef;
    typeInfo->dtrFunc_ = &DestructShortRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2CF0 (FUN_008E2CF0)
   *
   * What it does:
   * Binds the `int` create/destroy callback subset on one reflected type
   * descriptor lane (`new/ctor/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindIntCreateDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->newRefFunc_ = &NewIntRef;
    typeInfo->ctorRefFunc_ = &ConstructIntRef;
    typeInfo->deleteFunc_ = &DeleteIntRef;
    typeInfo->dtrFunc_ = &DestructIntRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2D20 (FUN_008E2D20)
   *
   * What it does:
   * Binds the `int` copy/move callback subset on one reflected type
   * descriptor lane (`copy/move/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindIntCopyMoveDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->cpyRefFunc_ = &CopyIntRef;
    typeInfo->movRefFunc_ = &MoveIntRef;
    typeInfo->deleteFunc_ = &DeleteIntRef;
    typeInfo->dtrFunc_ = &DestructIntRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2D50 (FUN_008E2D50)
   *
   * What it does:
   * Binds the `long` create/destroy callback subset on one reflected type
   * descriptor lane (`new/ctor/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindLongCreateDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->newRefFunc_ = &NewLongRef;
    typeInfo->ctorRefFunc_ = &ConstructLongRef;
    typeInfo->deleteFunc_ = &DeleteLongRef;
    typeInfo->dtrFunc_ = &DestructLongRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2D80 (FUN_008E2D80)
   *
   * What it does:
   * Binds the `long` copy/move callback subset on one reflected type
   * descriptor lane (`copy/move/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindLongCopyMoveDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->cpyRefFunc_ = &CopyLongRef;
    typeInfo->movRefFunc_ = &MoveLongRef;
    typeInfo->deleteFunc_ = &DeleteLongRef;
    typeInfo->dtrFunc_ = &DestructLongRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2DB0 (FUN_008E2DB0)
   *
   * What it does:
   * Binds the `signed char` create/destroy callback subset on one reflected
   * type descriptor lane (`new/ctor/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindSignedCharCreateDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->newRefFunc_ = &NewSignedCharRef;
    typeInfo->ctorRefFunc_ = &ConstructSignedCharRef;
    typeInfo->deleteFunc_ = &DeleteSignedCharRef;
    typeInfo->dtrFunc_ = &DestructSignedCharRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2DE0 (FUN_008E2DE0)
   *
   * What it does:
   * Binds the `signed char` copy/move callback subset on one reflected type
   * descriptor lane (`copy/move/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindSignedCharCopyMoveDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->cpyRefFunc_ = &CopySignedCharRef;
    typeInfo->movRefFunc_ = &MoveSignedCharRef;
    typeInfo->deleteFunc_ = &DeleteSignedCharRef;
    typeInfo->dtrFunc_ = &DestructSignedCharRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2E10 (FUN_008E2E10)
   *
   * What it does:
   * Binds the `unsigned char` create/destroy callback subset on one reflected
   * type descriptor lane (`new/ctor/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindUnsignedCharCreateDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->newRefFunc_ = &NewUnsignedCharRef;
    typeInfo->ctorRefFunc_ = &ConstructUnsignedCharRef;
    typeInfo->deleteFunc_ = &DeleteUnsignedCharRef;
    typeInfo->dtrFunc_ = &DestructUnsignedCharRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2E40 (FUN_008E2E40)
   *
   * What it does:
   * Binds the `unsigned char` copy/move callback subset on one reflected
   * type descriptor lane (`copy/move/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindUnsignedCharCopyMoveDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->cpyRefFunc_ = &CopyUnsignedCharRef;
    typeInfo->movRefFunc_ = &MoveUnsignedCharRef;
    typeInfo->deleteFunc_ = &DeleteUnsignedCharRef;
    typeInfo->dtrFunc_ = &DestructUnsignedCharRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2E70 (FUN_008E2E70)
   *
   * What it does:
   * Binds the `unsigned short` create/destroy callback subset on one reflected
   * type descriptor lane (`new/ctor/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindUnsignedShortCreateDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->newRefFunc_ = &NewUnsignedShortRef;
    typeInfo->ctorRefFunc_ = &ConstructUnsignedShortRef;
    typeInfo->deleteFunc_ = &DeleteUnsignedShortRef;
    typeInfo->dtrFunc_ = &DestructUnsignedShortRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2EA0 (FUN_008E2EA0)
   *
   * What it does:
   * Binds the `unsigned short` copy/move callback subset on one reflected type
   * descriptor lane (`copy/move/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindUnsignedShortCopyMoveDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->cpyRefFunc_ = &CopyUnsignedShortRef;
    typeInfo->movRefFunc_ = &MoveUnsignedShortRef;
    typeInfo->deleteFunc_ = &DeleteUnsignedShortRef;
    typeInfo->dtrFunc_ = &DestructUnsignedShortRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2ED0 (FUN_008E2ED0)
   *
   * What it does:
   * Binds the `unsigned int` create/destroy callback subset on one reflected
   * type descriptor lane (`new/ctor/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindUnsignedIntCreateDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->newRefFunc_ = &NewUnsignedIntRef;
    typeInfo->ctorRefFunc_ = &ConstructUnsignedIntRef;
    typeInfo->deleteFunc_ = &DeleteUnsignedIntRef;
    typeInfo->dtrFunc_ = &DestructUnsignedIntRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2F00 (FUN_008E2F00)
   *
   * What it does:
   * Binds the `unsigned int` copy/move callback subset on one reflected type
   * descriptor lane (`copy/move/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindUnsignedIntCopyMoveDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->cpyRefFunc_ = &CopyUnsignedIntRef;
    typeInfo->movRefFunc_ = &MoveUnsignedIntRef;
    typeInfo->deleteFunc_ = &DeleteUnsignedIntRef;
    typeInfo->dtrFunc_ = &DestructUnsignedIntRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2F30 (FUN_008E2F30)
   *
   * What it does:
   * Binds the `unsigned long` create/destroy callback subset on one reflected
   * type descriptor lane (`new/ctor/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindUnsignedLongCreateDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->newRefFunc_ = &NewUnsignedLongRef;
    typeInfo->ctorRefFunc_ = &ConstructUnsignedLongRef;
    typeInfo->deleteFunc_ = &DeleteUnsignedLongRef;
    typeInfo->dtrFunc_ = &DestructUnsignedLongRef;
    return typeInfo;
  }

  /**
   * Address: 0x008E2F60 (FUN_008E2F60)
   *
   * What it does:
   * Binds the `unsigned long` copy/move callback subset on one reflected type
   * descriptor lane (`copy/move/delete/dtor`).
   */
  [[maybe_unused]] gpg::RType* BindUnsignedLongCopyMoveDestroyRefLanes(gpg::RType* const typeInfo)
  {
    typeInfo->cpyRefFunc_ = &CopyUnsignedLongRef;
    typeInfo->movRefFunc_ = &MoveUnsignedLongRef;
    typeInfo->deleteFunc_ = &DeleteUnsignedLongRef;
    typeInfo->dtrFunc_ = &DestructUnsignedLongRef;
    return typeInfo;
  }
} // namespace

// ---------------------------------------------------------------------------
// RIntType<T> template impls
// ---------------------------------------------------------------------------

/**
 * Address family - scalar deleting destructor thunks by specialization:
 *   0x008DDC20 (FUN_008DDC20, RIntType_char::dtr)
 *   0x008DDE90 (FUN_008DDE90, RIntType_short::dtr)
 *   0x008DE040 (FUN_008DE040, RIntType_int::dtr)
 *   0x008DE2A0 (FUN_008DE2A0, RIntType_long::dtr)
 *   0x008DE500 (FUN_008DE500, RIntType_schar::dtr)
 *   0x008DE750 (FUN_008DE750, RIntType_uchar::dtr)
 *   0x008DE9C0 (FUN_008DE9C0, RIntType_ushort::dtr)
 *   0x008DEC10 (FUN_008DEC10, RIntType_uint::dtr)
 *   0x008DEE70 (FUN_008DEE70, RIntType_ulong::dtr)
 *
 * What it does:
 * Reuses `gpg::RType` destruction semantics for integer reflection
 * specializations and participates in the deleting-thunk lane.
 */
template <class T>
RIntType<T>::~RIntType() = default;

/**
 * Address family - `RIntType<T>::GetLexical` per-type instantiations:
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
  T* const destination = static_cast<T*>(ref.mObj);
  if constexpr (std::is_same_v<T, char>) {
    return ParseRIntTypeCharLexical(str, nullptr, destination);
  } else if constexpr (std::is_same_v<T, short>) {
    return ParseRIntTypeShortLexical(str, nullptr, destination);
  } else if constexpr (std::is_same_v<T, long>) {
    return ParseRIntTypeLongLexical(str, nullptr, destination);
  } else if constexpr (std::is_same_v<T, signed char>) {
    return ParseRIntTypeSignedCharLexical(str, nullptr, destination);
  } else if constexpr (std::is_same_v<T, unsigned char>) {
    return ParseRIntTypeUnsignedCharLexical(str, nullptr, destination);
  } else if constexpr (std::is_same_v<T, unsigned short>) {
    return ParseRIntTypeUnsignedShortLexical(str, nullptr, destination);
  } else if constexpr (std::is_same_v<T, unsigned int>) {
    return ParseRIntTypeUnsignedIntLexical(str, nullptr, destination);
  } else if constexpr (std::is_same_v<T, unsigned long>) {
    return ParseRIntTypeUnsignedLongLexical(str, nullptr, destination);
  } else {
    return ParseLegacyIntegerLexicalBounded<T>(str, nullptr, destination);
  }
}

/**
 * Address: 0x008E2F90 (FUN_008E2F90, RIntType_char::Init)
 *
 * What it does:
 * Binds callback lanes for reflected `char` value refs.
 */
template <>
void RIntType<char>::Init()
{
  (void)BindCharCreateDestroyRefLanes(this);
  (void)BindCharCopyMoveDestroyRefLanes(this);
}

/**
 * Address: 0x008E2FC0 (FUN_008E2FC0, RIntType_short::Init)
 *
 * What it does:
 * Binds callback lanes for reflected `short` value refs.
 */
template <>
void RIntType<short>::Init()
{
  (void)BindShortCreateDestroyRefLanes(this);
  (void)BindShortCopyMoveDestroyRefLanes(this);
}

/**
 * Address: 0x008E2FF0 (FUN_008E2FF0, RIntType_int::Init)
 *
 * What it does:
 * Binds callback lanes for reflected `int` value refs.
 */
template <>
void RIntType<int>::Init()
{
  (void)BindIntCreateDestroyRefLanes(this);
  (void)BindIntCopyMoveDestroyRefLanes(this);
}

/**
 * Address: 0x008E3020 (FUN_008E3020, RIntType_long::Init)
 *
 * What it does:
 * Binds callback lanes for reflected `long` value refs.
 */
template <>
void RIntType<long>::Init()
{
  (void)BindLongCreateDestroyRefLanes(this);
  (void)BindLongCopyMoveDestroyRefLanes(this);
}

/**
 * Address: 0x008E3050 (FUN_008E3050, RIntType_schar::Init)
 *
 * What it does:
 * Binds callback lanes for reflected `signed char` value refs.
 */
template <>
void RIntType<signed char>::Init()
{
  (void)BindSignedCharCreateDestroyRefLanes(this);
  (void)BindSignedCharCopyMoveDestroyRefLanes(this);
}

/**
 * Address: 0x008E3080 (FUN_008E3080, RIntType_uchar::Init)
 *
 * What it does:
 * Binds callback lanes for reflected `unsigned char` value refs.
 */
template <>
void RIntType<unsigned char>::Init()
{
  (void)BindUnsignedCharCreateDestroyRefLanes(this);
  (void)BindUnsignedCharCopyMoveDestroyRefLanes(this);
}

/**
 * Address: 0x008E30B0 (FUN_008E30B0, RIntType_ushort::Init)
 *
 * What it does:
 * Binds callback lanes for reflected `unsigned short` value refs.
 */
template <>
void RIntType<unsigned short>::Init()
{
  (void)BindUnsignedShortCreateDestroyRefLanes(this);
  (void)BindUnsignedShortCopyMoveDestroyRefLanes(this);
}

/**
 * Address: 0x008E30E0 (FUN_008E30E0, RIntType_uint::Init)
 *
 * What it does:
 * Binds callback lanes for reflected `unsigned int` value refs.
 */
template <>
void RIntType<unsigned int>::Init()
{
  (void)BindUnsignedIntCreateDestroyRefLanes(this);
  (void)BindUnsignedIntCopyMoveDestroyRefLanes(this);
}

/**
 * Address: 0x008E3110 (FUN_008E3110, RIntType_ulong::Init)
 *
 * What it does:
 * Binds callback lanes for reflected `unsigned long` value refs.
 */
template <>
void RIntType<unsigned long>::Init()
{
  (void)BindUnsignedLongCreateDestroyRefLanes(this);
  (void)BindUnsignedLongCopyMoveDestroyRefLanes(this);
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

#define IMPLEMENT_INT_TYPE_INFO(                                                                             \
  NAME,                                                                                                      \
  T,                                                                                                         \
  NAME_STR,                                                                                                  \
  NEW_REF_FUNC,                                                                                              \
  CPY_REF_FUNC,                                                                                              \
  CTR_REF_FUNC,                                                                                              \
  MOV_REF_FUNC,                                                                                              \
  DEL_REF_FUNC,                                                                                              \
  DTR_REF_FUNC                                                                                               \
)                                                                                                            \
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
    newRefFunc_ = NEW_REF_FUNC;                                                              \
    cpyRefFunc_ = CPY_REF_FUNC;                                                              \
    deleteFunc_ = DEL_REF_FUNC;                                                              \
    ctorRefFunc_ = CTR_REF_FUNC;                                                             \
    movRefFunc_ = MOV_REF_FUNC;                                                              \
    dtrFunc_ = DTR_REF_FUNC;                                                                 \
    Finish();                                                                                \
  }                                                                                          \
  void register_##NAME##Startup()                                                            \
  {                                                                                          \
    (void)Acquire_##NAME();                                                                  \
    (void)std::atexit(&cleanup_##NAME);                                                      \
  }

/**
 * Address: 0x008DFAD0 (FUN_008DFAD0, charTypeInfo::charTypeInfo)
 * Address: 0x008E3140 (FUN_008E3140, charTypeInfo::Init)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `char`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  charTypeInfo, char, "char", &NewCharRef, &CopyCharRef, &ConstructCharRef, &MoveCharRef, &DeleteCharRef,
  &DestructCharRef
)
/**
 * Address: 0x008DFE50 (FUN_008DFE50, signedcharTypeInfo::signedcharTypeInfo)
 * Address: 0x008E3240 (FUN_008E3240, signedcharTypeInfo::Init)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `signed char`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  signedcharTypeInfo, signed char, "signed char", &NewSignedCharRef, &CopySignedCharRef, &ConstructSignedCharRef,
  &MoveSignedCharRef, &DeleteSignedCharRef, &DestructSignedCharRef
)
/**
 * Address: 0x008DFF30 (FUN_008DFF30, unsignedcharTypeInfo::unsignedcharTypeInfo)
 * Address: 0x008E3280 (FUN_008E3280, unsignedcharTypeInfo::Init)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `unsigned char`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  unsignedcharTypeInfo, unsigned char, "unsigned char", &NewUnsignedCharRef, &CopyUnsignedCharRef,
  &ConstructUnsignedCharRef, &MoveUnsignedCharRef, &DeleteUnsignedCharRef, &DestructUnsignedCharRef
)
/**
 * Address: 0x008DFBB0 (FUN_008DFBB0, shortTypeInfo::shortTypeInfo)
 * Address: 0x008E3180 (FUN_008E3180, shortTypeInfo::Init)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `short`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  shortTypeInfo, short, "short", &NewShortRef, &CopyShortRef, &ConstructShortRef, &MoveShortRef,
  &DeleteShortRef, &DestructShortRef
)
/**
 * Address: 0x008E0010 (FUN_008E0010, unsignedshortTypeInfo::unsignedshortTypeInfo)
 * Address: 0x008E32C0 (FUN_008E32C0, unsignedshortTypeInfo::Init)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `unsigned short`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  unsignedshortTypeInfo, unsigned short, "unsigned short", &NewUnsignedShortRef, &CopyUnsignedShortRef,
  &ConstructUnsignedShortRef, &MoveUnsignedShortRef, &DeleteUnsignedShortRef, &DestructUnsignedShortRef
)
/**
 * Address: 0x008DFC90 (FUN_008DFC90, intTypeInfo::intTypeInfo)
 * Address: 0x008E31C0 (FUN_008E31C0, intTypeInfo::Init)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `int`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  intTypeInfo, int, "int", &NewIntRef, &CopyIntRef, &ConstructIntRef, &MoveIntRef, &DeleteIntRef,
  &DestructIntRef
)
/**
 * Address: 0x008E00F0 (FUN_008E00F0, unsignedintTypeInfo::unsignedintTypeInfo)
 * Address: 0x008E3300 (FUN_008E3300, unsignedintTypeInfo::Init)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `unsigned int`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  unsignedintTypeInfo, unsigned int, "unsigned int", &NewUnsignedIntRef, &CopyUnsignedIntRef, &ConstructUnsignedIntRef,
  &MoveUnsignedIntRef, &DeleteUnsignedIntRef, &DestructUnsignedIntRef
)
/**
 * Address: 0x008DFD70 (FUN_008DFD70, longTypeInfo::longTypeInfo)
 * Address: 0x008E3200 (FUN_008E3200, longTypeInfo::Init)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `long`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  longTypeInfo, long, "long", &NewLongRef, &CopyLongRef, &ConstructLongRef, &MoveLongRef, &DeleteLongRef,
  &DestructLongRef
)
/**
 * Address: 0x008E01D0 (FUN_008E01D0, unsignedlongTypeInfo::unsignedlongTypeInfo)
 * Address: 0x008E3340 (FUN_008E3340, unsignedlongTypeInfo::Init)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `unsigned long`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  unsignedlongTypeInfo, unsigned long, "unsigned long", &NewUnsignedLongRef, &CopyUnsignedLongRef,
  &ConstructUnsignedLongRef, &MoveUnsignedLongRef, &DeleteUnsignedLongRef, &DestructUnsignedLongRef
)

#undef IMPLEMENT_INT_TYPE_INFO
