#include "moho/containers/BVIntSetSerializer.h"

#include <cstdlib>

#include "gpg/core/utils/Global.h"
#include "moho/containers/BVIntSet.h"
#include "moho/containers/BVIntSetTypeInfo.h"
#include "gpg/core/reflection/StaticInitPhase.h"

// Make BVIntSet registration run before default-segment bootstrap objects that
// query BVIntSet RTTI during static initialization.
namespace moho
{
  void register_BVIntSetTypeInfo();
  void register_BVIntSetSerializer();
}

namespace
{
  moho::BVIntSetTypeInfo gBVIntSetTypeInfo;

  // Address: 0x00BC2D00 (FUN_00BC2D00, register_BVIntSetSerializer) -- MSVC's
  // own compiler-generated dynamic initializer for this global runs the real
  // `gpg::SerSaveLoadHelper<BVIntSet>` ctor (self-links into `sNewHelpers`,
  // binds `mLoadCallback`/`mSaveCallback` to the template's `Deserialize`/
  // `Serialize`, installs the vtable) and registers the real mangled
  // destructor (`??1BVIntSetSerializer@Moho@@QAE@@Z`, 0x00BEDEE0) via
  // `atexit`. There is no hand-written "register" function for this in the
  // original source -- matches `gpg::PrimitiveSerHelper<T,IntType>`'s
  // already-established modeling.
  moho::BVIntSetSerializer gBVIntSetSerializer;

  /**
   * Address: 0x00BEDE80 (FUN_00BEDE80, ??1BVIntSetTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Process-exit cleanup for global `BVIntSetTypeInfo` dynamic field/base lanes.
   */
  void cleanup_BVIntSetTypeInfo()
  {
    gBVIntSetTypeInfo.fields_.clear();
    gBVIntSetTypeInfo.bases_.clear();
  }

  struct BVIntSetReflectionRegistration
  {
    BVIntSetReflectionRegistration()
    {
      moho::register_BVIntSetTypeInfo();
      moho::register_BVIntSetSerializer();
    }
  };

  BVIntSetReflectionRegistration gBVIntSetReflectionRegistration;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BC2CE0 (FUN_00BC2CE0, register_BVIntSetTypeInfo)
   *
   * What it does:
   * Materializes startup `BVIntSetTypeInfo` storage and registers process-exit
   * teardown.
   */
  void register_BVIntSetTypeInfo()
  {
    (void)gBVIntSetTypeInfo;
    (void)std::atexit(&cleanup_BVIntSetTypeInfo);
  }

  /**
   * Address: 0x00BC2D00 (FUN_00BC2D00, register_BVIntSetSerializer)
   *
   * What it does:
   * Forces this translation unit's global `BVIntSetSerializer` instance to
   * link into the reflection bootstrap sequence ahead of default-segment
   * consumers that query BVIntSet RTTI. See the Doxygen comment on the
   * declaration (BVIntSetSerializer.h) and on `gBVIntSetSerializer` above for
   * why this function's body has no field-setting logic of its own.
   */
  void register_BVIntSetSerializer()
  {
    (void)gBVIntSetSerializer;
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_BVIntSetTypeInfo_180679, moho::register_BVIntSetTypeInfo)
