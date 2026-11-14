#include "moho/ui/UiRuntimeTypes.h"

#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"

namespace
{
  template <typename T>
  [[nodiscard]] gpg::RType* CachedUpcastTypeFromTypeInfo()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(T));
    }
    return cached;
  }

  /**
   * Address: 0x007A29B0 (FUN_007A29B0)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `CMauiText`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedCMauiTextType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::CMauiText));
    }
    return cached;
  }

  /**
   * Address: 0x008512F0 (FUN_008512F0)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `CUIMapPreview`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedCUIMapPreviewType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::CUIMapPreview));
    }
    return cached;
  }

} // namespace
