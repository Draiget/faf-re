#pragma once

// Private to moho/ai: helpers the pieces of the former CAiBrain.cpp share.

#include "moho/ai/CAiBrain.h"
#include "platform/Interlocked.h"
#include "legacy/math/X87Math.h"

#include "legacy/algorithms/Sort.h"
#include "legacy/exceptions/StdExcept.h"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <map>
#include <new>
#include <string>
#include <typeinfo>
#include <vector>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Vector.h"
#include "lua/LuaObject.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/CAiPersonality.h"
#include "moho/ai/EEconResourceTypeInfo.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"

#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "moho/serialization/SBuildReserveInfo.h"
#include "moho/serialization/typeinfo/SBuildReserveInfoTypeInfo.h"
#include "moho/entity/Entity.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CInfluenceMap.h"
#include "moho/sim/SConditionTriggerTypes.h"
#include "moho/sim/CEconStorage.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/CPlatoon.h"
#include "moho/sim/CSquad.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/ResourceDeposit.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDebugCommandRegistrations.h"
#include "moho/sim/STIMap.h"
#include "moho/math/Vector3f.h"
#include "moho/math/Wm3Segment3FafExtras.h"
#include "platform/Platform.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/SUnitConstructionParams.h"
#include "moho/unit/core/Unit.h"

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"


using namespace moho;
namespace moho
{

  int cfunc_CAiBrainCreateUnitNearSpot(lua_State* luaContext);
  int cfunc_CAiBrainCreateUnitNearSpotL(LuaPlus::LuaState* state);
  int cfunc_CAiBrainCreateResourceBuildingNearest(lua_State* luaContext);
  int cfunc_CAiBrainCreateResourceBuildingNearestL(LuaPlus::LuaState* state);
  int cfunc_CAiBrainFindPlaceToBuild(lua_State* luaContext);
  int cfunc_CAiBrainFindPlaceToBuildL(LuaPlus::LuaState* state);

  // Recovered in CUnitCallTeleport.cpp; forward-declared here so the build-order
  // helper below can invoke it by name (matches the binary's cross-TU call).
  //
  // The top-level `const` on every pointer parameter is required, not
  // cosmetic: MSVC encodes a by-value pointer parameter's top-level const
  // into the mangled name (`Q` instead of `P`), and CUnitCallTeleport.cpp's
  // real definition declares every pointer parameter `T* const`. Dropping the
  // `const` here compiles fine (top-level const doesn't affect C++ overload
  // resolution) but mangles to a different symbol the linker can never match
  // against that definition -- confirmed by comparing this TU's requested
  // symbol against `dumpbin /symbols` on CUnitCallTeleport.obj, which showed
  // the `Q`-prefixed definition sitting right there, unmatched.
  [[nodiscard]] bool TryBuildStructureAt(
    SCoordsVec2* const tryPos, const RUnitBlueprint* const blueprint, Sim* const sim,
    const int border, const bool wholeMap, const bool doCoerce, const bool useSkirt);

  /**
   * Address: 0x0057CA20 (FUN_0057CA20, func_ScheduleBuildStructure)
   *
   * What it does:
   * Records one `(builder, command)` weak reservation pair in
   * `brain->mBuildStructureMap` at `where`.
   */
  void func_ScheduleBuildStructure(Unit* builder, CAiBrain* brain, CUnitCommand* command, Wm3::Vector2i where);
}

namespace
{

  struct SAttackVectorGridRow
  {
    std::int32_t mNextColumn = 0;         // +0x00 next cell to record
    fa::vector<int> mOccupancyWords{}; // +0x04 one bit per column
  };
  static_assert(sizeof(SAttackVectorGridRow) == 0x14, "SAttackVectorGridRow size must be 0x14");

  /**
   * Address: 0x0057CAF0 (FUN_0057CAF0, sub_57CAF0)
   *
   * What it does:
   * Drops one reservation out of both owners' weak chains, command lane first
   * and unit lane second, which is the order the binary uses.
   *
   * Each lane is `~WeakPtr<T>`'s own body: splice the node out of the chain its
   * `ownerLinkSlot` names, and leave the node's two words alone because the
   * storage is about to go. `UnlinkFromOwnerChain()` is that splice plus a
   * clear of the node, which is what the callers here want -- the entry either
   * dies with its map node or is a stack temporary the caller reuses.
   *
   * Four hand-written copies of `WeakPtr<T>`'s mechanics used to live here --
   * `UnlinkBuildResourceInfoLinkNoReset`, `UnlinkBuildResourceInfoLink`,
   * `UnlinkBuildResourceInfoLinksNoReset` and
   * `RebindBuildResourceInfoLinkToOwnerSlot`/`RebindBuildResourceInfoLinks` --
   * over an `SBuildResourceInfo` stand-in that every caller reinterpret_cast
   * an `SBuildReserveInfo` into.
   */
  void UnlinkBuildReservation(SBuildReserveInfo& reservation) noexcept
  {
    reservation.mCom.UnlinkFromOwnerChain();
    reservation.mUnit.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x0057CB30 (FUN_0057CB30)
   *
   * What it does:
   * Moves one reservation's two weak lanes onto the owners `source` names,
   * unlinking each from whatever chain it is in first -- `WeakPtr<T>::operator=`
   * on each lane, i.e. `ResetFromOwnerLinkSlot(source-lane's slot)`.
   */
  void RebindBuildReservation(SBuildReserveInfo& destination, const SBuildReserveInfo& source) noexcept
  {
    destination.mUnit = source.mUnit;
    destination.mCom = source.mCom;
  }

  using BuildReserveMapStorage = moho::SBuildStructurePositionMap;

  [[nodiscard]] gpg::RType* ResolveBuildReserveKeyType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Vector2i));
      if (!type) {
        type = gpg::REF_FindFirstTypeNamed({"Wm3::IVector2<int>", "Wm3::Vector2i", "Vector2i"});
      }
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveBuildReserveValueType()
  {
    gpg::RType* type = moho::SBuildReserveInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SBuildReserveInfo));
      if (!type) {
        type = moho::preregister_SBuildReserveInfoTypeInfo();
      }
      moho::SBuildReserveInfo::sType = type;
    }
    return type;
  }

  class BuildReserveMapTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00582830 (FUN_00582830)
     * Demangled: gpg::RMapType_IVector2i_SBuildReserveInfo::dtr (scalar-deleting)
     *
     * What it does:
     * Frees the `RType` base's two `fa::vector<RField>` storage lanes
     * (`bases_._Myfirst` @ +0x2C, `fields_._Myfirst` @ +0x3C), restores the
     * `gpg::RObject` vftable, and conditionally deletes `this`. Defaulted in
     * source: the compiler-generated `~RType()` reproduces this behavior,
     * matching `RVectorType<moho::SimArmy*>::~RVectorType()`'s and
     * `RVectorType<moho::SPointVector>::~RVectorType()`'s identical emission
     * shape (Reflection.h / SPointVector.h) for the same base-layout reason
     * (`sizeof(BuildReserveMapTypeInfo) == 0x64`, same as `gpg::RType` — this
     * descriptor has no `RIndexed` sub-object and adds no data members).
     * Vtable-confirmed: `??_7?$RMapType@V?$IVector2@H@Wm3@@USBuildReserveInfo@Moho@@@gpg@@6B@+0x8`
     * writes this address; that vtable is constructed by `FUN_00582610`
     * (`preregister_BuildReserveMapTypeInfo`, recovered, this file), which
     * constructs the singleton `BuildReserveMapTypeInfo` and so writes its
     * vptr on construction.
     */
    ~BuildReserveMapTypeInfo() override = default;

    /**
     * Address: 0x0057E240 (FUN_0057E240, gpg::RMapType_IVector2i_SBuildReserveInfo::GetName)
     * Address: 0x00BF6320 (FUN_00BF6320, atexit destructor of GetName's cached name)
     *
     * IDA signature:
     * std::string::_Bxty *gpg::RMapType_IVector2i_SBuildReserveInfo::GetName();
     *
     * What it does:
     * Builds `"map<key,value>"` once from the reflected key and value
     * descriptors' own names and returns it. The binary resolves the value
     * descriptor first and the key descriptor second (right-to-left argument
     * evaluation), but formats key-then-value.
     */
    [[nodiscard]] const char* GetName() const override
    {
      static const fa::string sName = gpg::STR_Printf(
        "map<%s,%s>", ResolveBuildReserveKeyType()->GetName(), ResolveBuildReserveValueType()->GetName()
      );
      return sName.c_str();
    }

    /**
     * Address: 0x0057E320 (FUN_0057E320, gpg::RMapType_IVector2i_SBuildReserveInfo::GetLexical)
     *
     * IDA signature:
     * std::string *__thiscall gpg::RMapType_IVector2i_SBuildReserveInfo::GetLexical(
     *     gpg::RType *this, std::string *dest, _DWORD *a3);
     *
     * What it does:
     * Renders the reflected map as `"<base RType lexical>, size=<count>"`. The
     * binary reads the count straight out of the map object's node-count word
     * rather than dispatching a virtual, because this descriptor has no
     * `RIndexed` sub-object; the typed `size()` accessor is that same word.
     */
    [[nodiscard]] fa::string GetLexical(const gpg::RRef& ref) const override
    {
      const fa::string base = gpg::RType::GetLexical(ref);
      const auto* const mapObject = static_cast<const BuildReserveMapStorage*>(ref.mObj);
      const int count = mapObject ? static_cast<int>(mapObject->size()) : 0;
      return gpg::STR_Printf("%s, size=%d", base.c_str(), count);
    }

    /**
     * Address: 0x0057F480 (FUN_0057F480, gpg::RMapType_IVector2i_SBuildReserveInfo::SerLoad)
     *
     * What it does:
     * Clears destination storage, then reads `count` serialized
     * `Wm3::IVector2<int> -> Moho::SBuildReserveInfo` pairs from the archive
     * and inserts them by key. The binary reads each pair's key/value into
     * scratch nodes and then rewires the deserialized value's two intrusive
     * link lanes (`mResourceLink`/`mPlacementLink`) into the map entry
     * in-place rather than copying the raw link fields; `RebindBuildResourceInfoLinks`
     * / `UnlinkBuildResourceInfoLink` reproduce that hand-off.
     */
    static void SerLoad(gpg::ReadArchive* const archive, const std::intptr_t objectPtr, const int, gpg::RRef* const ownerRef)
    {
      auto* const mapObject = reinterpret_cast<BuildReserveMapStorage*>(
        objectPtr
      );
      if (!archive || !mapObject) {
        return;
      }

      unsigned int count = 0u;
      archive->ReadUInt(&count);
      mapObject->clear();

      gpg::RType* const keyType = ResolveBuildReserveKeyType();
      gpg::RType* const valueType = ResolveBuildReserveValueType();
      GPG_ASSERT(keyType != nullptr);
      GPG_ASSERT(valueType != nullptr);
      if (!keyType || !valueType) {
        return;
      }

      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      for (unsigned int i = 0u; i < count; ++i) {
        Wm3::Vector2i key{};
        moho::SBuildReserveInfo value{};
        archive->Read(keyType, &key, owner);
        archive->Read(valueType, &value, owner);

        // The deserialized value's two weak lanes are already linked into their
        // owners' chains, so the map entry takes them over by rebinding rather
        // than by copying the raw link fields - the same hand-off
        // `func_ScheduleBuildStructure` performs from its staging pair.
        RebindBuildReservation((*mapObject)[key], value);
        UnlinkBuildReservation(value);
      }
    }

    /**
     * Address: 0x0057F680 (FUN_0057F680, gpg::RMapType_IVector2i_SBuildReserveInfo::SerSave)
     *
     * What it does:
     * Serializes one `std::map<Wm3::IVector2<int>,Moho::SBuildReserveInfo>` payload
     * by writing each key/value pair through reflected type lanes.
     */
    static void SerSave(gpg::WriteArchive* const archive, const std::intptr_t objectPtr, const int, gpg::RRef* const ownerRef)
    {
      const auto* const mapObject = reinterpret_cast<const BuildReserveMapStorage*>(
        objectPtr
      );
      if (!archive || !mapObject) {
        return;
      }

      archive->WriteUInt(static_cast<unsigned int>(mapObject->size()));

      gpg::RType* const keyType = ResolveBuildReserveKeyType();
      gpg::RType* const valueType = ResolveBuildReserveValueType();
      GPG_ASSERT(keyType != nullptr);
      GPG_ASSERT(valueType != nullptr);
      if (!keyType || !valueType) {
        return;
      }

      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      for (auto it = mapObject->begin(); it != mapObject->end(); ++it) {
        Wm3::Vector2i key = it->first;
        moho::SBuildReserveInfo value = it->second;
        archive->Write(keyType, &key, owner);
        archive->Write(valueType, &value, owner);
      }
    }

    /**
     * Address: 0x0057E300 (FUN_0057E300, gpg::RMapType_IVector2i_SBuildReserveInfo::Init)
     *
     * What it does:
     * Sets reflected size/version metadata (`size_ = 0x0C`, matching every
     * other `RMapType<K,V>` specialization's shared tree control-block size)
     * and binds the key/value pair (de)serialize callbacks.
     */
    void Init() override
    {
      static_assert(sizeof(moho::SBuildStructurePositionMap) == 0x0C, "moho::SBuildStructurePositionMap is 0x0C bytes on x86");
      size_ = sizeof(moho::SBuildStructurePositionMap);
      version_ = 1;
      serLoadFunc_ = &BuildReserveMapTypeInfo::SerLoad;
      serSaveFunc_ = &BuildReserveMapTypeInfo::SerSave;
    }
  };

  static_assert(sizeof(BuildReserveMapTypeInfo) == 0x64, "BuildReserveMapTypeInfo size must be 0x64");

  /**
   * Address: 0x00BF6380 (FUN_00BF6380, atexit destructor of the BuildReserveMapTypeInfo object)
   */
  [[nodiscard]] BuildReserveMapTypeInfo& AcquireBuildReserveMapTypeInfo()
  {
    static BuildReserveMapTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00582610 (FUN_00582610, preregister_BuildReserveMapTypeInfo)
   *
   * What it does:
   * Constructs/preregisters reflection metadata for
   * `std::map<Wm3::IVector2<int>,Moho::SBuildReserveInfo>`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* preregister_BuildReserveMapTypeInfo()
  {
    BuildReserveMapTypeInfo& typeInfo = AcquireBuildReserveMapTypeInfo();
    gpg::PreRegisterRType(typeid(BuildReserveMapStorage), &typeInfo);
    return &typeInfo;
  }

  constexpr int kAiBrainAllianceAnySentinel = 3;
}

