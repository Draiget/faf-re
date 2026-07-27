#include "moho/unit/CUnitCommandTypeInfo.h"

#include <cstdlib>
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

  alignas(TypeInfo) unsigned char gCUnitCommandTypeInfoStorage[sizeof(TypeInfo)];
  bool gCUnitCommandTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& GetCUnitCommandTypeInfo() noexcept
  {
    if (!gCUnitCommandTypeInfoConstructed) {
      new (gCUnitCommandTypeInfoStorage) TypeInfo();
      gCUnitCommandTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCUnitCommandTypeInfoStorage);
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

  /**
   * Address: 0x00BFEB80 (FUN_00BFEB80, ??1CUnitCommandTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Tears down recovered `CUnitCommand` type-info storage at process exit.
   */
  void cleanup_CUnitCommandTypeInfo()
  {
    if (!gCUnitCommandTypeInfoConstructed) {
      return;
    }

    GetCUnitCommandTypeInfo().~CUnitCommandTypeInfo();
    gCUnitCommandTypeInfoConstructed = false;
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

  namespace
  {
    /**
     * Static `RPointerType<CUnitCommand>` descriptor that the binary exposes as
     * `Moho::CUnitCommand::PointerType`. Default static-init runs the
     * RPointerTypeBase → RType → RObject ctor chain and installs the most-
     * derived vftable lane.
     */
    gpg::RPointerType<moho::CUnitCommand> sCUnitCommandPointerTypeStorage{};

    /**
     * Address: 0x006E37A0 (FUN_006E37A0)
     *
     * What it does:
     * Pre-registers the static `RPointerType<CUnitCommand>` descriptor under
     * the `CUnitCommand*` type-info key so subsequent `LookupRType` queries
     * from the lazy `GetPointerType` lane resolve to this descriptor.
     */
    void PreregisterCUnitCommandPointerType()
    {
      gpg::PreRegisterRType(typeid(moho::CUnitCommand*), &sCUnitCommandPointerTypeStorage);
    }

    /**
     * Address: 0x00BFEA30 (FUN_00BFEA30)
     *
     * What it does:
     * Tears down the static `RPointerType<CUnitCommand>` descriptor at process
     * exit: frees heap-backed `bases_`/`fields_` vector storage and resets the
     * RType vftable lane to the `RObject` base. Registered via `atexit` from
     * `GetPointerType`'s once-init path.
     */
    void CleanupCUnitCommandPointerType()
    {
      sCUnitCommandPointerTypeStorage.~RPointerType<moho::CUnitCommand>();
    }
  } // namespace

  /**
   * Address: 0x006E35F0 (FUN_006E35F0, Moho::CUnitCommand::GetPointerType)
   *
   * What it does:
   * On first call, pre-registers the static `RPointerType<CUnitCommand>`
   * descriptor and installs the matching atexit teardown. After that, lazily
   * caches the `LookupRType(typeid(CUnitCommand*))` result in `sPointerType`
   * and returns it.
   */
  gpg::RType* CUnitCommand::GetPointerType()
  {
    static const bool sOnceInit = []() {
      PreregisterCUnitCommandPointerType();
      (void)std::atexit(&CleanupCUnitCommandPointerType);
      return true;
    }();
    (void)sOnceInit;

    if (!sType) {
      sType = gpg::LookupRType(typeid(CUnitCommand));
    }

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
    baseField.v4 = 0;
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
      baseType = gpg::LookupRType(typeid(BroadcasterEventTag<ECommandEvent>));
    }

    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0x34;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00BD8F30 (FUN_00BD8F30, register_CUnitCommandTypeInfo)
   */
  int register_CUnitCommandTypeInfo()
  {
    (void)GetCUnitCommandTypeInfo();
    return std::atexit(&cleanup_CUnitCommandTypeInfo);
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
