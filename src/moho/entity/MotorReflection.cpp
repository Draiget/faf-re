#include "moho/entity/MotorReflection.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  // Address: 0x00BD5930 (FUN_00BD5930, register_MotorSerializer) -- MSVC's
  // own compiler-generated dynamic initializer for this global runs the real
  // `gpg::SerSaveLoadHelper<Motor>` ctor (self-links into `sNewHelpers`,
  // binds `mLoadCallback`/`mSaveCallback` to the template's `Deserialize`/
  // `Serialize`, installs the vtable) and registers the real destructor
  // (0x00BFCF60, no recovered mangled name; body confirmed via raw asm to
  // just call `ResetLinks()`) via `atexit`. Dead zero-xref COMDAT duplicate
  // ctor: 0x006949F0.
  moho::MotorSerializer gMotorSerializer;

  /**
   * Address: 0x00BFCF00 (FUN_00BFCF00, atexit destructor of the MotorTypeInfo object)
   */
  [[nodiscard]] moho::MotorTypeInfo& GetMotorTypeInfo()
  {
    static moho::MotorTypeInfo sInstance;
    return sInstance;
  }

} // namespace

namespace moho
{
  gpg::RType* Motor::sType = nullptr;

  /**
   * Address: 0x00694800 (FUN_00694800, Moho::MotorTypeInfo::MotorTypeInfo)
   */
  MotorTypeInfo::MotorTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(Motor), this);
  }

  /**
   * Address: 0x006948F0 (FUN_006948F0, MotorTypeInfo non-deleting destructor
   * body; zero callers)
   *
   * What it does:
   * Releases reflected base/field vectors through the `gpg::RType` base.
   */
  MotorTypeInfo::~MotorTypeInfo() = default;

  /**
   * Address: 0x00694880 (FUN_00694880, Moho::MotorTypeInfo::GetName)
   */
  const char* MotorTypeInfo::GetName() const
  {
    return "Motor";
  }

  /**
   * Address: 0x00694860 (FUN_00694860, Moho::MotorTypeInfo::Init)
   */
  void MotorTypeInfo::Init()
  {
    size_ = sizeof(Motor);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BD5910 (FUN_00BD5910, register_MotorTypeInfo)
   */
  void register_MotorTypeInfo()
  {
    (void)GetMotorTypeInfo();
  }

  /**
   * Address: 0x00BD5930 (FUN_00BD5930, register_MotorSerializer)
   *
   * What it does:
   * Forces this translation unit's global `MotorSerializer` instance to link
   * into the reflection bootstrap sequence. See the Doxygen comment on the
   * declaration (MotorReflection.h) and on `gMotorSerializer` above for
   * why this function's body has no field-setting logic of its own.
   */
  void register_MotorSerializer()
  {
    (void)gMotorSerializer;
  }
} // namespace moho

namespace
{
  struct MotorReflectionBootstrap
  {
    MotorReflectionBootstrap()
    {
      moho::register_MotorTypeInfo();
      moho::register_MotorSerializer();
    }
  };

  [[maybe_unused]] MotorReflectionBootstrap gMotorReflectionBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_MotorTypeInfo_5e60b9, moho::register_MotorTypeInfo)
