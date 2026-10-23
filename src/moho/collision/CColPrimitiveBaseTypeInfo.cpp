#include "moho/collision/CColPrimitiveBaseTypeInfo.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "moho/collision/ECollisionShape.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  bool gECollisionShapeTypeInfoPreregistered = false;
} // namespace

namespace moho
{
  /**
   * Address: 0x004FE590 (FUN_004FE590, Moho::CColPrimitiveBaseTypeInfo::dtr)
   */
  CColPrimitiveBaseTypeInfo::~CColPrimitiveBaseTypeInfo() = default;

  /**
   * Address: 0x004FE580 (FUN_004FE580, Moho::CColPrimitiveBaseTypeInfo::GetName)
   */
  const char* CColPrimitiveBaseTypeInfo::GetName() const
  {
    return "CColPrimitiveBase";
  }

  /**
   * Address: 0x004FE560 (FUN_004FE560, Moho::CColPrimitiveBaseTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::CColPrimitiveBaseTypeInfo::Init(gpg::RType *this);
   */
  void CColPrimitiveBaseTypeInfo::Init()
  {
    size_ = sizeof(CColPrimitiveBase);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x004FE500 (FUN_004FE500, preregister_CColPrimitiveBaseTypeInfo)
   * Address: 0x00BF19E0 (FUN_00BF19E0, atexit destructor of the CColPrimitiveBaseTypeInfo object)
   *
   * What it does:
   * Constructs/preregisters the startup-owned `CColPrimitiveBaseTypeInfo`
   * instance for `typeid(CColPrimitiveBase)`.
   */
  [[nodiscard]] gpg::RType* preregister_CColPrimitiveBaseTypeInfo()
  {
    static CColPrimitiveBaseTypeInfo sInstance;
    gpg::PreRegisterRType(typeid(CColPrimitiveBase), &sInstance);
    return &sInstance;
  }

  /**
   * Address: 0x00BC7530 (FUN_00BC7530, register_CColPrimitiveBaseTypeInfo)
   *
   * What it does:
   * Installs the startup-owned `CColPrimitiveBaseTypeInfo` instance.
   */
  void register_CColPrimitiveBaseTypeInfo()
  {
    (void)preregister_CColPrimitiveBaseTypeInfo();
  }

  /**
   * Address: 0x004FE480 (FUN_004FE480, Moho::ECollisionShapeTypeInfo::dtr)
   */
  ECollisionShapeTypeInfo::~ECollisionShapeTypeInfo() = default;

  /**
   * Address: 0x004FE470 (FUN_004FE470, Moho::ECollisionShapeTypeInfo::GetName)
   */
  const char* ECollisionShapeTypeInfo::GetName() const
  {
    return "ECollisionShape";
  }

  /**
   * Address: 0x004FE450 (FUN_004FE450, Moho::ECollisionShapeTypeInfo::Init)
   */
  void ECollisionShapeTypeInfo::Init()
  {
    size_ = sizeof(ECollisionShape);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x004FE4B0 (FUN_004FE4B0, Moho::ECollisionShapeTypeInfo::AddEnums)
   */
  void ECollisionShapeTypeInfo::AddEnums()
  {
    mPrefix = "COLSHAPE_";
    AddEnum(StripPrefix("COLSHAPE_None"), static_cast<int>(COLSHAPE_None));
    AddEnum(StripPrefix("COLSHAPE_Box"), static_cast<int>(COLSHAPE_Box));
    AddEnum(StripPrefix("COLSHAPE_Sphere"), static_cast<int>(COLSHAPE_Sphere));
  }

  /**
   * Address: 0x004FE3F0 (FUN_004FE3F0, preregister_ECollisionShapeTypeInfo)
   * Address: 0x00BF19D0 (FUN_00BF19D0, atexit destructor of the ECollisionShapeTypeInfo object)
   */
  gpg::REnumType* preregister_ECollisionShapeTypeInfo()
  {
    static ECollisionShapeTypeInfo sInstance;
    if (!gECollisionShapeTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(ECollisionShape), &sInstance);
      gECollisionShapeTypeInfoPreregistered = true;
    }

    return &sInstance;
  }

  /**
   * Address: 0x00BC7510 (FUN_00BC7510, register_ECollisionShapeTypeInfo)
   */
  void register_ECollisionShapeTypeInfo()
  {
    (void)preregister_ECollisionShapeTypeInfo();
  }
} // namespace moho

namespace
{
  struct CColPrimitiveBaseTypeInfoBootstrap
  {
    CColPrimitiveBaseTypeInfoBootstrap()
    {
      (void)moho::register_CColPrimitiveBaseTypeInfo();
      (void)moho::register_ECollisionShapeTypeInfo();
    }
  };

  [[maybe_unused]] CColPrimitiveBaseTypeInfoBootstrap gCColPrimitiveBaseTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CColPrimitiveBaseTypeInfo_58cbdc, moho::register_CColPrimitiveBaseTypeInfo)
GPG_PREREGISTER_INIT(register_ECollisionShapeTypeInfo_58cbdc, moho::register_ECollisionShapeTypeInfo)

GPG_PREREGISTER_INIT(preregister_CColPrimitiveBaseTypeInfo_58cbdc, moho::preregister_CColPrimitiveBaseTypeInfo)
GPG_PREREGISTER_INIT(preregister_ECollisionShapeTypeInfo_58cbdc, moho::preregister_ECollisionShapeTypeInfo)
