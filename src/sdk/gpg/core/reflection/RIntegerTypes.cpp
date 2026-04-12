#include "gpg/core/reflection/RIntegerTypes.h"

#include <cstdio>
#include <cstdlib>
#include <new>
#include <typeinfo>

// ---------------------------------------------------------------------------
// RIntType<T> template impls
// ---------------------------------------------------------------------------

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

#define IMPLEMENT_INT_TYPE_INFO(NAME, T, NAME_STR)                                           \
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
    Finish();                                                                                \
  }                                                                                          \
  void register_##NAME##Startup()                                                            \
  {                                                                                          \
    (void)Acquire_##NAME();                                                                  \
    (void)std::atexit(&cleanup_##NAME);                                                      \
  }

IMPLEMENT_INT_TYPE_INFO(charTypeInfo, char, "char")
IMPLEMENT_INT_TYPE_INFO(signedcharTypeInfo, signed char, "signed char")
IMPLEMENT_INT_TYPE_INFO(unsignedcharTypeInfo, unsigned char, "unsigned char")
IMPLEMENT_INT_TYPE_INFO(shortTypeInfo, short, "short")
IMPLEMENT_INT_TYPE_INFO(unsignedshortTypeInfo, unsigned short, "unsigned short")
IMPLEMENT_INT_TYPE_INFO(intTypeInfo, int, "int")
IMPLEMENT_INT_TYPE_INFO(unsignedintTypeInfo, unsigned int, "unsigned int")
IMPLEMENT_INT_TYPE_INFO(longTypeInfo, long, "long")
IMPLEMENT_INT_TYPE_INFO(unsignedlongTypeInfo, unsigned long, "unsigned long")

#undef IMPLEMENT_INT_TYPE_INFO
