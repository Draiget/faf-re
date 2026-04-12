#include "RBlueprint.h"

#include <Windows.h>

#include <cstdlib>
#include <cstring>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaObject.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/resource/RResId.h"
#include "moho/sim/RRuleGameRules.h"

namespace
{
  using TypeInfo = moho::RBlueprintTypeInfo;

  alignas(TypeInfo) unsigned char gRBlueprintTypeInfoStorage[sizeof(TypeInfo)]{};
  bool gRBlueprintTypeInfoConstructed = false;

  [[nodiscard]] gpg::RType* CachedStringType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::string));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedIntType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(int));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedRObjectType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(gpg::RObject));
    }
    return cached;
  }

  [[nodiscard]] TypeInfo& AcquireRBlueprintTypeInfo()
  {
    if (!gRBlueprintTypeInfoConstructed) {
      new (gRBlueprintTypeInfoStorage) TypeInfo();
      gRBlueprintTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRBlueprintTypeInfoStorage);
  }

  void CleanupRBlueprintTypeInfo()
  {
    if (!gRBlueprintTypeInfoConstructed) {
      return;
    }

    AcquireRBlueprintTypeInfo().~TypeInfo();
    gRBlueprintTypeInfoConstructed = false;
  }

  [[nodiscard]] gpg::RField* AddTypedField(
    gpg::RType* const typeInfo,
    const char* const fieldName,
    gpg::RType* const fieldType,
    const int offset
  )
  {
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField(fieldName, fieldType, offset));
    return &typeInfo->fields_.back();
  }

  void AddRBlueprintInstanceCounterDelta(moho::StatItem* const statItem, const long delta)
  {
    if (!statItem) {
      return;
    }
    (void)InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), delta);
  }

  void AddRObjectBase(gpg::RType* const typeInfo)
  {
    gpg::RType* const rObjectType = CachedRObjectType();
    gpg::RField baseField{};
    baseField.mName = rObjectType->GetName();
    baseField.mType = rObjectType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace

namespace moho
{
  gpg::RType* RBlueprint::sPointerType = nullptr;

  /**
   * Address: 0x0050E0C0 (FUN_0050E0C0, Moho::InstanceCounter<Moho::RBlueprint>::GetStatItem)
   *
   * What it does:
   * Lazily resolves and caches the engine stat slot used for
   * `RBlueprint` instance counting.
   */
  template <>
  moho::StatItem* moho::InstanceCounter<moho::RBlueprint>::GetStatItem()
  {
    static moho::StatItem* sStatItem = nullptr;
    if (sStatItem) {
      return sStatItem;
    }

    moho::EngineStats* const engineStats = moho::GetEngineStats();
    if (!engineStats) {
      return nullptr;
    }

    const std::string statPath = BuildInstanceCounterStatPath(typeid(moho::RBlueprint).name());
    sStatItem = engineStats->GetItem(statPath.c_str(), true);
    return sStatItem;
  }

  /**
   * Address: 0x0050DD60 (FUN_0050DD60)
   * Mangled: ??0RBlueprint@Moho@@QAE@PAVRRuleGameRules@1@ABVRResId@1@@Z
   *
   * IDA signature:
   * Moho::RBlueprint *__thiscall Moho::RBlueprint::RBlueprint(
   *         Moho::RBlueprint *this@<ecx>,
   *         Moho::RRuleGameRules *rules,
   *         Moho::RResId const &resId);
   *
   * What it does:
   * Initializes a base `RBlueprint` from `(rules, resId)`: bumps the
   * shared `InstanceCounter<RBlueprint>` slot, captures the owning rules,
   * copies the resource id string into `mBlueprintId` (uses `strlen` of the
   * resource id buffer to honor the original byte-exact behavior),
   * default-initializes `mDescription` and `mSource`, and assigns the next
   * blueprint ordinal from the rules' virtual `AssignNextOrdinal` slot.
   */
  RBlueprint::RBlueprint(RRuleGameRules* const owner, const RResId& resId)
    : mVTable(nullptr)
    , mOwner(owner)
    , mBlueprintId()
    , mDescription()
    , mSource()
    , mBlueprintOrdinal(0)
  {
    AddRBlueprintInstanceCounterDelta(InstanceCounter<RBlueprint>::GetStatItem(), 1L);

    // The original ctor reads the source-id buffer with `strlen`, so a string
    // containing embedded null bytes truncates exactly the same way.
    const char* const sourceData = resId.name.c_str();
    const std::size_t sourceLen = std::strlen(sourceData);
    mBlueprintId.assign(sourceData, sourceLen);

    mBlueprintOrdinal = owner->AssignNextOrdinal();
  }

  /**
   * Address: 0x0050DBA0 (FUN_0050DBA0)
   * Mangled: ?OnInitBlueprint@RBlueprint@Moho@@MAEXXZ
   *
   * What it does:
   * Base blueprint post-load hook; default implementation is empty.
   */
  void RBlueprint::OnInitBlueprint() {}

  /**
   * Address: 0x00556CE0 (FUN_00556CE0, Moho::RBlueprint::GetPointerType)
   *
   * What it does:
   * Lazily resolves and caches the reflection descriptor for `RBlueprint*`.
   */
  gpg::RType* RBlueprint::GetPointerType()
  {
    gpg::RType* cached = sPointerType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(RBlueprint*));
      sPointerType = cached;
    }
    return cached;
  }

  /**
   * Address: 0x0050DBB0 (FUN_0050DBB0, Moho::RBlueprintTypeInfo::RBlueprintTypeInfo)
   *
   * What it does:
   * Preregisters the `RBlueprint` RTTI instance at startup.
   */
  RBlueprintTypeInfo::RBlueprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RBlueprint), this);
  }

  /**
   * Address: 0x0050DC50 (FUN_0050DC50, Moho::RBlueprintTypeInfo::dtr)
   * Address: 0x0050DCB0 (FUN_0050DCB0, core dtor body)
   *
   * What it does:
   * Releases the startup-owned reflection descriptor and restores the base
   * `gpg::RObject` vtable.
   */
  RBlueprintTypeInfo::~RBlueprintTypeInfo() = default;

  /**
   * Address: 0x0050DC40 (FUN_0050DC40, Moho::RBlueprintTypeInfo::GetName)
   *
   * What it does:
   * Returns the RTTI label for `RBlueprint`.
   */
  const char* RBlueprintTypeInfo::GetName() const
  {
    return "RBlueprint";
  }

  /**
   * Address: 0x0050DC10 (FUN_0050DC10, Moho::RBlueprintTypeInfo::Init)
   *
   * What it does:
   * Sets the reflected size, registers the `gpg::RObject` base lane, and
   * publishes the `RBlueprint` field metadata.
   */
  void RBlueprintTypeInfo::Init()
  {
    size_ = sizeof(RBlueprint);
    AddRObjectBase(this);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x0050DF90 (FUN_0050DF90, Moho::RBlueprint::GetLuaBlueprint)
   *
   * What it does:
   * Returns `__blueprints[BlueprintOrdinal]` from the active Lua globals.
   */
  LuaPlus::LuaObject RBlueprint::GetLuaBlueprint(LuaPlus::LuaState* const state) const
  {
    if (!state) {
      return LuaPlus::LuaObject{};
    }

    LuaPlus::LuaObject allBlueprints = state->GetGlobal("__blueprints");
    return allBlueprints[static_cast<int>(mBlueprintOrdinal)];
  }

  /**
   * Address: 0x0050DCF0 (FUN_0050DCF0, Moho::RBlueprintTypeInfo::AddFields)
   *
   * What it does:
   * Registers the base blueprint reflection fields and writes version/description
   * metadata for editor/runtime inspection lanes.
   */
  gpg::RField* RBlueprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    gpg::RField* field = AddTypedField(typeInfo, "BlueprintId", CachedStringType(), 0x08);
    field->v4 = 1;
    field->mDesc = "Blueprint Id";

    field = AddTypedField(typeInfo, "Description", CachedStringType(), 0x24);
    field->v4 = 3;
    field->mDesc = "Generic type of unit (non-display name)";

    field = AddTypedField(typeInfo, "Source", CachedStringType(), 0x40);
    field->v4 = 1;
    field->mDesc = "File this blueprint was defined in";

    return AddTypedField(typeInfo, "BlueprintOrdinal", CachedIntType(), 0x5C);
  }

  /**
   * Address: 0x00BC7FC0 (FUN_00BC7FC0, register_RBlueprintTypeInfo)
   *
   * What it does:
   * Startup thunk that materializes `RBlueprintTypeInfo` and hooks process-exit
   * cleanup.
   */
  void register_RBlueprintTypeInfo()
  {
    (void)AcquireRBlueprintTypeInfo();
    (void)std::atexit(&CleanupRBlueprintTypeInfo);
  }
} // namespace moho

namespace
{
  struct RBlueprintTypeInfoBootstrap
  {
    RBlueprintTypeInfoBootstrap()
    {
      moho::register_RBlueprintTypeInfo();
    }
  };

  RBlueprintTypeInfoBootstrap gRBlueprintTypeInfoBootstrap;
} // namespace
