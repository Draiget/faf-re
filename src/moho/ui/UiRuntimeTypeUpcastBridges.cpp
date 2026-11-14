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

} // namespace
