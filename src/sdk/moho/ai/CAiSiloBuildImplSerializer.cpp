#include "moho/ai/CAiSiloBuildImplSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "moho/ai/CAiSiloBuildImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedSSiloBuildInfoType()
  {
    gpg::RType* type = SSiloBuildInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(SSiloBuildInfo));
      SSiloBuildInfo::sType = type;
    }
    return type;
  }

} // namespace

/**
 * Address: 0x00BCE0B0 caller lane (`CAiSiloBuildImplTypeInfo.cpp`'s
 * reflection bootstrap sequence)
 *
 * What it does:
 * Historically forced construction of the (then lazily-constructed)
 * `SSiloBuildInfoSerializer` singleton from an explicit registration
 * sequence. `gSSiloBuildInfoSerializer` is now a genuine namespace-scope
 * global, so its constructor already runs unconditionally at static-init
 * time; this call is kept only so `CAiSiloBuildImplTypeInfo.cpp`'s existing
 * bootstrap sequence does not need editing.
 */
int moho::register_SSiloBuildInfoSerializer()
{
  return 0;
}

/**
 * Address: 0x00BCE150 caller lane (`CAiSiloBuildImplTypeInfo.cpp`'s
 * reflection bootstrap sequence)
 *
 * What it does:
 * Historically forced construction of the (then lazily-constructed)
 * `CAiSiloBuildImplSerializer` singleton from an explicit registration
 * sequence. `gCAiSiloBuildImplSerializer` is now a genuine namespace-scope
 * global, so its constructor already runs unconditionally at static-init
 * time; this call is kept only so `CAiSiloBuildImplTypeInfo.cpp`'s existing
 * bootstrap sequence does not need editing.
 */
int moho::register_CAiSiloBuildImplSerializer()
{
  return 0;
}
