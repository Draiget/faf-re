
#include <cstddef>
#include "gpg/core/reflection/Reflection.h"
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/sim/CMersenneTwister.h"
#include "moho/sim/CMersenneTwisterTypeInfo.h"

// Make CMersenneTwister registration run before default-segment bootstrap
// objects that query RTTI during static initialization.
namespace
{
  moho::CMersenneTwisterTypeInfo gCMersenneTwisterTypeInfo;

  /**
   * Address: 0x00BC3300 (FUN_00BC3300, register_CMersenneTwisterTypeInfo)
   *
   * What it does:
   * Materializes the global reflection descriptor for `CMersenneTwister`.
   */
  struct CMersenneTwisterTypeInfoRegistration
  {
    CMersenneTwisterTypeInfoRegistration()
    {
      (void)gCMersenneTwisterTypeInfo;
    }
  };

  CMersenneTwisterTypeInfoRegistration gCMersenneTwisterTypeInfoRegistration;
} // namespace

namespace moho
{
} // namespace moho

namespace
{
} // namespace
