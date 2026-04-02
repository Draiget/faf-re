#include "moho/net/INetNATTraversalProvider.h"

#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  gpg::RType* INetNATTraversalProvider::sType = nullptr;

  gpg::RType* INetNATTraversalProvider::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(INetNATTraversalProvider));
    }
    return sType;
  }
} // namespace moho
