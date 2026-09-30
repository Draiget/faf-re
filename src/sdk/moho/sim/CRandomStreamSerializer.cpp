#include "moho/sim/CRandomStreamSerializer.h"

#include <cstddef>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/CRandomStreamTypeInfo.h"
#include "gpg/core/reflection/StaticInitPhase.h"

// Make CRandomStream type-info registration run before default-segment
// bootstrap objects that query RTTI during static initialization. This is
// orthogonal to CRandomStreamSerializer below: CRandomStreamTypeInfo derives
// from gpg::RType directly (not gpg::SerHelperBase) and its own real ctor
// (0x00BC3360) is independently __xc_a-reachable.
namespace
{
  /**
   * Address: 0x00BEE720 (FUN_00BEE720, atexit destructor of the CRandomStreamTypeInfo object)
   */
  [[nodiscard]] moho::CRandomStreamTypeInfo* AcquireCRandomStreamTypeInfo()
  {
    static moho::CRandomStreamTypeInfo sInstance;
    return &sInstance;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BC3360 (FUN_00BC3360, register_CRandomStreamTypeInfo)
   *
   * What it does:
   * Startup thunk that constructs the CRandomStream type-info object.
   */
  void register_CRandomStreamTypeInfo()
  {
    (void)AcquireCRandomStreamTypeInfo();
  }

} // namespace moho

namespace
{
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CRandomStreamTypeInfo_f08a86, moho::register_CRandomStreamTypeInfo)
