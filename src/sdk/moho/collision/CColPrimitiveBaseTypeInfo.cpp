#include "moho/collision/CColPrimitiveBaseTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "moho/collision/ECollisionShape.h"

namespace
{
  alignas(moho::CColPrimitiveBaseTypeInfo)
    unsigned char gCColPrimitiveBaseTypeInfoStorage[sizeof(moho::CColPrimitiveBaseTypeInfo)];
  bool gCColPrimitiveBaseTypeInfoConstructed = false;

  alignas(moho::ECollisionShapeTypeInfo)
    unsigned char gECollisionShapeTypeInfoStorage[sizeof(moho::ECollisionShapeTypeInfo)];
  bool gECollisionShapeTypeInfoConstructed = false;
  bool gECollisionShapeTypeInfoPreregistered = false;

  [[nodiscard]] moho::CColPrimitiveBaseTypeInfo& CColPrimitiveBaseTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::CColPrimitiveBaseTypeInfo*>(gCColPrimitiveBaseTypeInfoStorage);
  }

  [[nodiscard]] moho::ECollisionShapeTypeInfo& ECollisionShapeTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::ECollisionShapeTypeInfo*>(gECollisionShapeTypeInfoStorage);
  }

  void CleanupCColPrimitiveBaseTypeInfoAtExit()
  {
    if (!gCColPrimitiveBaseTypeInfoConstructed) {
      return;
    }

    CColPrimitiveBaseTypeInfoStorageRef().~CColPrimitiveBaseTypeInfo();
    gCColPrimitiveBaseTypeInfoConstructed = false;
  }

  void CleanupECollisionShapeTypeInfoAtExit()
  {
    if (!gECollisionShapeTypeInfoConstructed) {
      return;
    }

    ECollisionShapeTypeInfoStorageRef().~ECollisionShapeTypeInfo();
    gECollisionShapeTypeInfoConstructed = false;
    gECollisionShapeTypeInfoPreregistered = false;
  }
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
   *
   * What it does:
   * Constructs/preregisters the startup-owned `CColPrimitiveBaseTypeInfo`
   * instance for `typeid(CColPrimitiveBase)`.
   */
  [[nodiscard]] gpg::RType* preregister_CColPrimitiveBaseTypeInfo()
  {
    if (!gCColPrimitiveBaseTypeInfoConstructed) {
      new (gCColPrimitiveBaseTypeInfoStorage) CColPrimitiveBaseTypeInfo();
      gCColPrimitiveBaseTypeInfoConstructed = true;
    }

    gpg::PreRegisterRType(typeid(CColPrimitiveBase), &CColPrimitiveBaseTypeInfoStorageRef());
    return &CColPrimitiveBaseTypeInfoStorageRef();
  }

  /**
   * Address: 0x00BC7530 (FUN_00BC7530, register_CColPrimitiveBaseTypeInfo)
   *
   * What it does:
   * Installs the startup-owned `CColPrimitiveBaseTypeInfo` instance and its
   * process-exit cleanup hook.
   */
  int register_CColPrimitiveBaseTypeInfo()
  {
    (void)preregister_CColPrimitiveBaseTypeInfo();
    return std::atexit(&CleanupCColPrimitiveBaseTypeInfoAtExit);
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
   */
  gpg::REnumType* preregister_ECollisionShapeTypeInfo()
  {
    if (!gECollisionShapeTypeInfoConstructed) {
      new (gECollisionShapeTypeInfoStorage) ECollisionShapeTypeInfo();
      gECollisionShapeTypeInfoConstructed = true;
    }

    if (!gECollisionShapeTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(ECollisionShape), &ECollisionShapeTypeInfoStorageRef());
      gECollisionShapeTypeInfoPreregistered = true;
    }

    return &ECollisionShapeTypeInfoStorageRef();
  }

  /**
   * Address: 0x00BC7510 (FUN_00BC7510, register_ECollisionShapeTypeInfo)
   */
  int register_ECollisionShapeTypeInfo()
  {
    (void)preregister_ECollisionShapeTypeInfo();
    return std::atexit(&CleanupECollisionShapeTypeInfoAtExit);
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
