#include "moho/unit/CUnitCommandTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/script/CScriptObject.h"
#include "moho/unit/Broadcaster.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/ECommandEvent.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CUnitCommandTypeInfo;

  /**
   * Address: 0x00BFEB80 (FUN_00BFEB80, atexit destructor of the TypeInfo object)
   */
  [[nodiscard]] TypeInfo& GetCUnitCommandTypeInfo() noexcept
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  gpg::RType* gLegacyCUnitCommandSecondaryType = nullptr;

  /**
   * Address: 0x006E7CD0 (FUN_006E7CD0)
   *
   * What it does:
   * Resolves and caches one secondary RTTI lane for `CUnitCommand`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveLegacyCUnitCommandSecondaryType()
  {
    gpg::RType* type = gLegacyCUnitCommandSecondaryType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCommand));
      gLegacyCUnitCommandSecondaryType = type;
    }
    return type;
  }

} // namespace

namespace moho
{
  gpg::RType* CUnitCommand::sType = nullptr;
  gpg::RType* CUnitCommand::sPointerType = nullptr;

  gpg::RType* CUnitCommand::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CUnitCommand));
    }
    return sType;
  }

  /**
   * Address: 0x006E7CF0 (FUN_006E7CF0, Moho::CUnitCommand::GetClass)
   *
   * What it does:
   * Returns the cached reflection descriptor for this `CUnitCommand`
   * instance (vtable slot 0).
   */
  gpg::RType* CUnitCommand::GetClass() const
  {
    return StaticGetClass();
  }

  namespace
  {
    /**
     * Address: 0x006E37A0 (FUN_006E37A0)
     * Address: 0x00BFEA30 (FUN_00BFEA30, atexit destructor of the RPointerType<CUnitCommand> object)
     *
     * What it does:
     * Constructs the static `RPointerType<CUnitCommand>` descriptor (the
     * binary's `Moho::CUnitCommand::PointerType`) on first use and
     * pre-registers it under the `CUnitCommand*` type-info key so subsequent
     * `LookupRType` queries from the lazy `GetPointerType` lane resolve to
     * this descriptor.
     */
    void PreregisterCUnitCommandPointerType()
    {
      static gpg::RPointerType<moho::CUnitCommand> sDescriptor;
      gpg::PreRegisterRType(typeid(moho::CUnitCommand*), &sDescriptor);
    }
  } // namespace

  /**
   * Address: 0x006E35F0 (FUN_006E35F0, Moho::CUnitCommand::GetPointerType)
   *
   * What it does:
   * On first call, constructs and pre-registers the static
   * `RPointerType<CUnitCommand>` descriptor. After that, lazily caches the
   * `LookupRType(typeid(CUnitCommand*))` result in `sPointerType` and
   * returns it.
   */
  gpg::RType* CUnitCommand::GetPointerType()
  {
    static const bool sOnceInit = []() {
      PreregisterCUnitCommandPointerType();
      return true;
    }();
    (void)sOnceInit;

    gpg::RType* cached = sPointerType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CUnitCommand*));
      sPointerType = cached;
    }

    return cached;
  }

  /**
   * Address: 0x006E7E90 (FUN_006E7E90, ??0CUnitCommandTypeInfo@Moho@@QAE@@Z)
   */
  CUnitCommandTypeInfo::CUnitCommandTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitCommand), this);
  }

  /**
   * Address: 0x006E7F90 (FUN_006E7F90, CUnitCommandTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Clears reflected base/field vector lanes for one `CUnitCommandTypeInfo`
   * instance while preserving outer storage ownership.
   */
  [[maybe_unused]] void DestroyCUnitCommandTypeInfoBody(CUnitCommandTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  /**
   * Address: 0x006E7F30 (FUN_006E7F30, Moho::CUnitCommandTypeInfo::dtr)
   */
  CUnitCommandTypeInfo::~CUnitCommandTypeInfo()
  {
    DestroyCUnitCommandTypeInfoBody(this);
  }

  /**
   * Address: 0x006E7F20 (FUN_006E7F20, Moho::CUnitCommandTypeInfo::GetName)
   */
  const char* CUnitCommandTypeInfo::GetName() const
  {
    return "CUnitCommand";
  }

  /**
   * Address: 0x006E7FD0 (FUN_006E7FD0, sub_6E7FD0)
   */
  void CUnitCommandTypeInfo::ApplyLegacyBaseVersionLane(gpg::RType* const typeInfo)
  {
    AddBase_CScriptObject(typeInfo);
    AddBase_Broadcaster_ECommandEvent(typeInfo);
    typeInfo->version_ = 2;
  }

  /**
   * Address: 0x006E7EF0 (FUN_006E7EF0, Moho::CUnitCommandTypeInfo::Init)
   */
  void CUnitCommandTypeInfo::Init()
  {
    size_ = sizeof(CUnitCommand);
    gpg::RType::Init();
    ApplyLegacyBaseVersionLane(this);
    Finish();
  }

  /**
   * Address: 0x006EB600 (FUN_006EB600, Moho::CUnitCommandTypeInfo::AddBase_CScriptObject)
   */
  void CUnitCommandTypeInfo::AddBase_CScriptObject(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = CScriptObject::sType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(CScriptObject));
      CScriptObject::sType = baseType;
    }

    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x006EB660 (FUN_006EB660, Moho::CUnitCommandTypeInfo::AddBase_Broadcaster_ECommandEvent)
   */
  void CUnitCommandTypeInfo::AddBase_Broadcaster_ECommandEvent(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = register_Broadcaster_ECommandEvent_RType();
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(Broadcaster<ECommandEvent>));
    }

    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = gpg::BaseSubobjectOffset<CUnitCommand, Broadcaster<ECommandEvent>>();
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00BD8F30 (FUN_00BD8F30, register_CUnitCommandTypeInfo)
   */
  void register_CUnitCommandTypeInfo()
  {
    (void)GetCUnitCommandTypeInfo();
  }
} // namespace moho

namespace
{
  struct CUnitCommandTypeInfoBootstrap
  {
    CUnitCommandTypeInfoBootstrap()
    {
      (void)moho::register_CUnitCommandTypeInfo();
    }
  };

  CUnitCommandTypeInfoBootstrap gCUnitCommandTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitCommandTypeInfo_67e437, moho::register_CUnitCommandTypeInfo)

GPG_PREREGISTER_INIT(PreregisterCUnitCommandPointerType_67e437, moho::PreregisterCUnitCommandPointerType)
