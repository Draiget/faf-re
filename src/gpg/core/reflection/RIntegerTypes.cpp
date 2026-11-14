#include "gpg/core/reflection/RIntegerTypes.h"

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <type_traits>
#include <typeinfo>

#include "gpg/core/reflection/BadRefCast.h"

namespace
{

  // The binary emits one upcast function per reflected integer type
  // (0x008E15B0 char .. 0x008E1AD0 uint) and every Copy/Construct/Move lane
  // below funnels through it, so dispatch to those rather than re-deriving
  // the lookup-and-throw here - a private copy would leave nine recovered
  // `RRef::TryUpcast*` bodies with no caller.
  [[nodiscard]] inline char* UpcastIntegerLane(
    gpg::RRef& ref,
    char*
  )
  {
    return ref.TryUpcastChar();
  }

  [[nodiscard]] inline signed char* UpcastIntegerLane(
    gpg::RRef& ref,
    signed char*
  )
  {
    return ref.TryUpcastSignedChar();
  }

  [[nodiscard]] inline unsigned char* UpcastIntegerLane(
    gpg::RRef& ref,
    unsigned char*
  )
  {
    return ref.TryUpcastUnsignedChar();
  }

  [[nodiscard]] inline short* UpcastIntegerLane(
    gpg::RRef& ref,
    short*
  )
  {
    return ref.TryUpcastShort();
  }

  [[nodiscard]] inline unsigned short* UpcastIntegerLane(
    gpg::RRef& ref,
    unsigned short*
  )
  {
    return ref.TryUpcastUnsignedShort();
  }

  [[nodiscard]] inline int* UpcastIntegerLane(
    gpg::RRef& ref,
    int*
  )
  {
    return ref.TryUpcastInt();
  }

  [[nodiscard]] inline unsigned int* UpcastIntegerLane(
    gpg::RRef& ref,
    unsigned int*
  )
  {
    return ref.TryUpcastUnsignedInt();
  }

  [[nodiscard]] inline long* UpcastIntegerLane(
    gpg::RRef& ref,
    long*
  )
  {
    return ref.TryUpcastLong();
  }

  [[nodiscard]] inline unsigned long* UpcastIntegerLane(
    gpg::RRef& ref,
    unsigned long*
  )
  {
    return ref.TryUpcastUnsignedLong();
  }

  template <class TValue>
  [[nodiscard]] TValue* TryUpcastIntegerValue(
    gpg::RRef* const sourceRef
  )
  {
    return UpcastIntegerLane(*sourceRef, static_cast<TValue*>(nullptr));
  }

  template <class TValue>
  [[nodiscard]] gpg::RRef CopyIntegerValueRef(
    gpg::RRef* const sourceRef
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

    return gpg::MakeRRef<TValue>(valueCopy);
  }

  template <class TValue>
  [[nodiscard]] gpg::RRef MoveIntegerValueRef(
    void* const slotObject,
    gpg::RRef* const sourceRef
  )
  {
    TValue* slot = static_cast<TValue*>(slotObject);
    if (slot != nullptr) {
      *slot = *TryUpcastIntegerValue<TValue>(sourceRef);
    }

    return gpg::MakeRRef<TValue>(slot);
  }

  template <class TValue>
  [[nodiscard]] gpg::RRef ConstructIntegerValueRef(
    void* const slotObject
  )
  {
    return gpg::MakeRRef<TValue>(static_cast<TValue*>(slotObject));
  }

  template <class TValue>
  [[nodiscard]] gpg::RRef NewIntegerValueRef()
  {
    return gpg::MakeRRef<TValue>(static_cast<TValue*>(::operator new(sizeof(TValue))));
  }

  template <class TValue>
  void DeleteIntegerValue(
    void* const slotObject
  )
  {
    static_cast<void>(sizeof(TValue));
    ::operator delete(slotObject);
  }

  template <class TValue>
  void DestructIntegerValue(
    void* const slotObject
  )
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
        static_cast<UnsignedValue>(value * static_cast<UnsignedValue>(radix)) + static_cast<UnsignedValue>(digit)
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
   * Every reflected integer type binds the same six value-ref callbacks; the
   * binary emits one copy per type:
   *   0x008E1D00 RIntType_char::NewRef
   *   0x008E1DC0 RIntType_char::CtrRef
   *   0x008E1D30 RIntType_char::CpyRef
   *   0x008E1DF0 RIntType_char::MovRef
   *   0x008DDA40 RIntType_char::Delete
   *   0x008DDA50 RIntType_char::Destruct
   *   0x008E1E70 RIntType_short::NewRef
   *   0x008E1F30 RIntType_short::CtrRef
   *   0x008E1EA0 RIntType_short::CpyRef
   *   0x008E1F60 RIntType_short::MovRef
   *   0x008DDC90 RIntType_short::Delete
   *   0x008DDCA0 RIntType_short::Destruct
   *   0x008E1FE0 RIntType_int::NewRef
   *   0x008E20A0 RIntType_int::CtrRef
   *   0x008E2010 RIntType_int::CpyRef
   *   0x008E20D0 RIntType_int::MovRef
   *   0x008DDF00 RIntType_int::Delete
   *   0x008DDF10 RIntType_int::Destruct
   *   0x008E2150 RIntType_long::NewRef
   *   0x008E2210 RIntType_long::CtrRef
   *   0x008E2180 RIntType_long::CpyRef
   *   0x008E2240 RIntType_long::MovRef
   *   0x008DE0B0 RIntType_long::Delete
   *   0x008DE0C0 RIntType_long::Destruct
   *   0x008E22C0 RIntType_schar::NewRef
   *   0x008E2380 RIntType_schar::CtrRef
   *   0x008E22F0 RIntType_schar::CpyRef
   *   0x008E23B0 RIntType_schar::MovRef
   *   0x008DE310 RIntType_schar::Delete
   *   0x008DE320 RIntType_schar::Destruct
   *   0x008E2430 RIntType_uchar::NewRef
   *   0x008E24F0 RIntType_uchar::CtrRef
   *   0x008E2460 RIntType_uchar::CpyRef
   *   0x008E2520 RIntType_uchar::MovRef
   *   0x008DE570 RIntType_uchar::Delete
   *   0x008DE580 RIntType_uchar::Destruct
   *   0x008E25A0 RIntType_ushort::NewRef
   *   0x008E2660 RIntType_ushort::CtrRef
   *   0x008E25D0 RIntType_ushort::CpyRef
   *   0x008E2690 RIntType_ushort::MovRef
   *   0x008DE7C0 RIntType_ushort::Delete
   *   0x008DE7D0 RIntType_ushort::Destruct
   *   0x008E2710 RIntType_uint::NewRef
   *   0x008E27D0 RIntType_uint::CtrRef
   *   0x008E2740 RIntType_uint::CpyRef
   *   0x008E2800 RIntType_uint::MovRef
   *   0x008DEA30 RIntType_uint::Delete
   *   0x008DEA40 RIntType_uint::Destruct
   *   0x008E2880 RIntType_ulong::NewRef
   *   0x008E2940 RIntType_ulong::CtrRef
   *   0x008E28B0 RIntType_ulong::CpyRef
   *   0x008E2970 RIntType_ulong::MovRef
   *   0x008DEC80 RIntType_ulong::Delete
   *   0x008DEC90 RIntType_ulong::Destruct
   *   0x008E2C30 (binds one callback subset)
   *   0x008E2C60 (binds one callback subset)
   *   0x008E2C90 (binds one callback subset)
   *   0x008E2CC0 (binds one callback subset)
   *   0x008E2CF0 (binds one callback subset)
   *   0x008E2D20 (binds one callback subset)
   *   0x008E2D50 (binds one callback subset)
   *   0x008E2D80 (binds one callback subset)
   *   0x008E2DB0 (binds one callback subset)
   *   0x008E2DE0 (binds one callback subset)
   *   0x008E2E10 (binds one callback subset)
   *   0x008E2E40 (binds one callback subset)
   *   0x008E2E70 (binds one callback subset)
   *   0x008E2EA0 (binds one callback subset)
   *   0x008E2ED0 (binds one callback subset)
   *   0x008E2F00 (binds one callback subset)
   *   0x008E2F30 (binds one callback subset)
   *   0x008E2F60 (binds one callback subset)
   */
  template <class T>
  void BindIntegerRefCallbacks(
    gpg::RType* const typeInfo
  )
  {
    typeInfo->newRefFunc_ = &NewIntegerValueRef<T>;
    typeInfo->ctorRefFunc_ = &ConstructIntegerValueRef<T>;
    typeInfo->cpyRefFunc_ = &CopyIntegerValueRef<T>;
    typeInfo->movRefFunc_ = &MoveIntegerValueRef<T>;
    typeInfo->deleteFunc_ = &DeleteIntegerValue<T>;
    typeInfo->dtrFunc_ = &DestructIntegerValue<T>;
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
 * Formats the integer at `ref.mObj` as decimal into a 30-char fa::string
 * and truncates to the actual written length. The binary writes per-type
 * bodies with the matching printf width specifier; this template
 * consolidates all nine into one via `%lld` and explicit instantiation.
 */
template <class T>
fa::string RIntType<T>::GetLexical(
  const gpg::RRef& ref
) const
{
  const T value = *static_cast<const T*>(ref.mObj);
  fa::string result;
  result.resize(30, '\0');
  const int n = std::sprintf(result.raw_data_mut_unsafe(), "%lld", static_cast<long long>(value));
  result.resize(static_cast<std::size_t>(n));
  return result;
}

template <class T>
bool RIntType<T>::SetLexical(
  const gpg::RRef& ref,
  const char* const str
) const
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
 * Binds the value-ref callbacks for `T` (addresses per type on the
 * declaration in RIntegerTypes.h).
 */
template <class T>
void RIntType<T>::Init()
{
  BindIntegerRefCallbacks<T>(this);
}

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

#define IMPLEMENT_INT_TYPE_INFO(                                                                                       \
  NAME, T, NAME_STR, NEW_REF_FUNC, CPY_REF_FUNC, CTR_REF_FUNC, MOV_REF_FUNC, DEL_REF_FUNC, DTR_REF_FUNC                \
)                                                                                                                      \
  namespace                                                                                                            \
  {                                                                                                                    \
    [[nodiscard]] NAME& Acquire_##NAME()                                                                               \
    {                                                                                                                  \
      static NAME sInstance;                                                                                           \
      return sInstance;                                                                                                \
    }                                                                                                                  \
    struct Bootstrap_##NAME                                                                                            \
    {                                                                                                                  \
      Bootstrap_##NAME()                                                                                               \
      {                                                                                                                \
        register_##NAME##Startup();                                                                                    \
      }                                                                                                                \
    };                                                                                                                 \
    Bootstrap_##NAME gBootstrap_##NAME;                                                                                \
  }                                                                                                                    \
  NAME::NAME()                                                                                                         \
  {                                                                                                                    \
    gpg::PreRegisterRType(typeid(T), this);                                                                            \
  }                                                                                                                    \
  NAME::~NAME() = default;                                                                                             \
  const char* NAME::GetName() const                                                                                    \
  {                                                                                                                    \
    return NAME_STR;                                                                                                   \
  }                                                                                                                    \
  void NAME::Init()                                                                                                    \
  {                                                                                                                    \
    size_ = static_cast<int>(sizeof(T));                                                                               \
    newRefFunc_ = NEW_REF_FUNC;                                                                                        \
    cpyRefFunc_ = CPY_REF_FUNC;                                                                                        \
    deleteFunc_ = DEL_REF_FUNC;                                                                                        \
    ctorRefFunc_ = CTR_REF_FUNC;                                                                                       \
    movRefFunc_ = MOV_REF_FUNC;                                                                                        \
    dtrFunc_ = DTR_REF_FUNC;                                                                                           \
    Finish();                                                                                                          \
  }                                                                                                                    \
  void register_##NAME##Startup()                                                                                      \
  {                                                                                                                    \
    (void)Acquire_##NAME();                                                                                            \
  }

/**
 * Address: 0x008DFAD0 (FUN_008DFAD0, charTypeInfo::charTypeInfo)
 * Address: 0x008E3140 (FUN_008E3140, charTypeInfo::Init)
 * Address: 0x00BE9800 (FUN_00BE9800, register_charTypeInfoStartup)
 * Address: 0x00C09010 (FUN_00C09010, atexit destructor of the charTypeInfo object)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `char`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  charTypeInfo,
  char,
  "char",
  &NewIntegerValueRef<char>,
  &CopyIntegerValueRef<char>,
  &ConstructIntegerValueRef<char>,
  &MoveIntegerValueRef<char>,
  &DeleteIntegerValue<char>,
  &DestructIntegerValue<char>
)
/**
 * Address: 0x008DFE50 (FUN_008DFE50, signedcharTypeInfo::signedcharTypeInfo)
 * Address: 0x008E3240 (FUN_008E3240, signedcharTypeInfo::Init)
 * Address: 0x00BE9880 (FUN_00BE9880, register_signedcharTypeInfoStartup)
 * Address: 0x00C09190 (FUN_00C09190, atexit destructor of the signedcharTypeInfo object)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `signed char`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  signedcharTypeInfo,
  signed char,
  "signed char",
  &NewIntegerValueRef<signed char>,
  &CopyIntegerValueRef<signed char>,
  &ConstructIntegerValueRef<signed char>,
  &MoveIntegerValueRef<signed char>,
  &DeleteIntegerValue<signed char>,
  &DestructIntegerValue<signed char>
)
/**
 * Address: 0x008DFF30 (FUN_008DFF30, unsignedcharTypeInfo::unsignedcharTypeInfo)
 * Address: 0x008E3280 (FUN_008E3280, unsignedcharTypeInfo::Init)
 * Address: 0x00BE98A0 (FUN_00BE98A0, register_unsignedcharTypeInfoStartup)
 * Address: 0x00C091F0 (FUN_00C091F0, atexit destructor of the unsignedcharTypeInfo object)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `unsigned char`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  unsignedcharTypeInfo,
  unsigned char,
  "unsigned char",
  &NewIntegerValueRef<unsigned char>,
  &CopyIntegerValueRef<unsigned char>,
  &ConstructIntegerValueRef<unsigned char>,
  &MoveIntegerValueRef<unsigned char>,
  &DeleteIntegerValue<unsigned char>,
  &DestructIntegerValue<unsigned char>
)
/**
 * Address: 0x008DFBB0 (FUN_008DFBB0, shortTypeInfo::shortTypeInfo)
 * Address: 0x008E3180 (FUN_008E3180, shortTypeInfo::Init)
 * Address: 0x00BE9820 (FUN_00BE9820, register_shortTypeInfoStartup)
 * Address: 0x00C09070 (FUN_00C09070, atexit destructor of the shortTypeInfo object)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `short`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  shortTypeInfo,
  short,
  "short",
  &NewIntegerValueRef<short>,
  &CopyIntegerValueRef<short>,
  &ConstructIntegerValueRef<short>,
  &MoveIntegerValueRef<short>,
  &DeleteIntegerValue<short>,
  &DestructIntegerValue<short>
)
/**
 * Address: 0x008E0010 (FUN_008E0010, unsignedshortTypeInfo::unsignedshortTypeInfo)
 * Address: 0x008E32C0 (FUN_008E32C0, unsignedshortTypeInfo::Init)
 * Address: 0x00BE98C0 (FUN_00BE98C0, register_unsignedshortTypeInfoStartup)
 * Address: 0x00C09250 (FUN_00C09250, atexit destructor of the unsignedshortTypeInfo object)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `unsigned short`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  unsignedshortTypeInfo,
  unsigned short,
  "unsigned short",
  &NewIntegerValueRef<unsigned short>,
  &CopyIntegerValueRef<unsigned short>,
  &ConstructIntegerValueRef<unsigned short>,
  &MoveIntegerValueRef<unsigned short>,
  &DeleteIntegerValue<unsigned short>,
  &DestructIntegerValue<unsigned short>
)
/**
 * Address: 0x008DFC90 (FUN_008DFC90, intTypeInfo::intTypeInfo)
 * Address: 0x008E31C0 (FUN_008E31C0, intTypeInfo::Init)
 * Address: 0x00BE9840 (FUN_00BE9840, register_intTypeInfoStartup)
 * Address: 0x00C090D0 (FUN_00C090D0, atexit destructor of the intTypeInfo object)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `int`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  intTypeInfo,
  int,
  "int",
  &NewIntegerValueRef<int>,
  &CopyIntegerValueRef<int>,
  &ConstructIntegerValueRef<int>,
  &MoveIntegerValueRef<int>,
  &DeleteIntegerValue<int>,
  &DestructIntegerValue<int>
)
/**
 * Address: 0x008E00F0 (FUN_008E00F0, unsignedintTypeInfo::unsignedintTypeInfo)
 * Address: 0x008E3300 (FUN_008E3300, unsignedintTypeInfo::Init)
 * Address: 0x00BE98E0 (FUN_00BE98E0, register_unsignedintTypeInfoStartup)
 * Address: 0x00C092B0 (FUN_00C092B0, atexit destructor of the unsignedintTypeInfo object)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `unsigned int`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  unsignedintTypeInfo,
  unsigned int,
  "unsigned int",
  &NewIntegerValueRef<unsigned int>,
  &CopyIntegerValueRef<unsigned int>,
  &ConstructIntegerValueRef<unsigned int>,
  &MoveIntegerValueRef<unsigned int>,
  &DeleteIntegerValue<unsigned int>,
  &DestructIntegerValue<unsigned int>
)
/**
 * Address: 0x008DFD70 (FUN_008DFD70, longTypeInfo::longTypeInfo)
 * Address: 0x008E3200 (FUN_008E3200, longTypeInfo::Init)
 * Address: 0x00BE9860 (FUN_00BE9860, register_longTypeInfoStartup)
 * Address: 0x00C09130 (FUN_00C09130, atexit destructor of the longTypeInfo object)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `long`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  longTypeInfo,
  long,
  "long",
  &NewIntegerValueRef<long>,
  &CopyIntegerValueRef<long>,
  &ConstructIntegerValueRef<long>,
  &MoveIntegerValueRef<long>,
  &DeleteIntegerValue<long>,
  &DestructIntegerValue<long>
)
/**
 * Address: 0x008E01D0 (FUN_008E01D0, unsignedlongTypeInfo::unsignedlongTypeInfo)
 * Address: 0x008E3340 (FUN_008E3340, unsignedlongTypeInfo::Init)
 * Address: 0x00BE9900 (FUN_00BE9900, register_unsignedlongTypeInfoStartup)
 * Address: 0x00C09310 (FUN_00C09310, atexit destructor of the unsignedlongTypeInfo object)
 *
 * What it does:
 * Constructs and preregisters reflected integer-type metadata for `unsigned long`,
 * then initializes the descriptor with size/callback lanes and finalizes it.
 */
IMPLEMENT_INT_TYPE_INFO(
  unsignedlongTypeInfo,
  unsigned long,
  "unsigned long",
  &NewIntegerValueRef<unsigned long>,
  &CopyIntegerValueRef<unsigned long>,
  &ConstructIntegerValueRef<unsigned long>,
  &MoveIntegerValueRef<unsigned long>,
  &DeleteIntegerValue<unsigned long>,
  &DestructIntegerValue<unsigned long>
)

#undef IMPLEMENT_INT_TYPE_INFO
