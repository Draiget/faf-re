#include "moho/entity/EntityMotorReflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::MotorTypeInfo;

  alignas(TypeInfo) unsigned char gMotorTypeInfoStorage[sizeof(TypeInfo)];
  bool gMotorTypeInfoConstructed = false;

  // Address: 0x00BD5930 (FUN_00BD5930, register_MotorSerializer) -- MSVC's
  // own compiler-generated dynamic initializer for this global runs the real
  // `gpg::SerSaveLoadHelper<EntityMotor>` ctor (self-links into `sNewHelpers`,
  // binds `mLoadCallback`/`mSaveCallback` to the template's `Deserialize`/
  // `Serialize`, installs the vtable) and registers the real destructor
  // (0x00BFCF60, no recovered mangled name; body confirmed via raw asm to
  // just call `ResetLinks()`) via `atexit`. Dead zero-xref COMDAT duplicate
  // ctor: 0x006949F0.
  moho::MotorSerializer gMotorSerializer;

  [[nodiscard]] TypeInfo& GetMotorTypeInfo() noexcept
  {
    if (!gMotorTypeInfoConstructed) {
      new (gMotorTypeInfoStorage) TypeInfo();
      gMotorTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gMotorTypeInfoStorage);
  }

  /**
   * Address: 0x006831D0 (FUN_006831D0)
   *
   * What it does:
   * Resolves and caches RTTI for the legacy `Moho::Motor` alias lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveLegacyMotorAliasType()
  {
    gpg::RType* type = moho::EntityMotor::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::Motor));
      moho::EntityMotor::sType = type;
    }
    return type;
  }

  void cleanup_MotorTypeInfo_Atexit()
  {
    if (!gMotorTypeInfoConstructed) {
      return;
    }

    GetMotorTypeInfo().~MotorTypeInfo();
    gMotorTypeInfoConstructed = false;
    moho::EntityMotor::sType = nullptr;
  }
} // namespace

namespace moho
{
  gpg::RType* EntityMotor::sType = nullptr;

  /**
   * Address: 0x00694800 (FUN_00694800, Moho::MotorTypeInfo::MotorTypeInfo)
   */
  MotorTypeInfo::MotorTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(EntityMotor), this);
  }

  /**
   * Address: 0x006948F0 (FUN_006948F0, MotorTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Clears reflected base/field vector lanes for one `MotorTypeInfo`
   * instance while preserving outer storage ownership.
   */
  void DestroyMotorTypeInfoBody(MotorTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  /**
   * Address: 0x00BFCF00 (FUN_00BFCF00, Moho::MotorTypeInfo::~MotorTypeInfo)
   */
  MotorTypeInfo::~MotorTypeInfo()
  {
    DestroyMotorTypeInfoBody(this);
  }

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
    size_ = sizeof(EntityMotor);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BD5910 (FUN_00BD5910, register_MotorTypeInfo)
   */
  void register_MotorTypeInfo()
  {
    (void)GetMotorTypeInfo();
    (void)std::atexit(&cleanup_MotorTypeInfo_Atexit);
  }

  /**
   * Address: 0x00BD5930 (FUN_00BD5930, register_MotorSerializer)
   *
   * What it does:
   * Forces this translation unit's global `MotorSerializer` instance to link
   * into the reflection bootstrap sequence. See the Doxygen comment on the
   * declaration (EntityMotorReflection.h) and on `gMotorSerializer` above for
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
