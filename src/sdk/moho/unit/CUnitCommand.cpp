#include "CUnitCommand.h"

#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/IFormationInstanceCountedPtrReflection.h"
#include "moho/command/CCommandDb.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/entity/Entity.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/CountedObject.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/misc/WeakPtr.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/CUnitCommandWeakPtrReflection.h"
#include "moho/unit/ECommandEvent.h"
#include "moho/unit/core/UnitWeakPtrReflection.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

/**
 * Address: 0x006EC9E0 (FUN_006EC9E0)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<CUnitCommand>` and returns that singleton.
 */
[[maybe_unused]] moho::CScrLuaMetatableFactory<moho::CUnitCommand>*
startup_CScrLuaMetatableFactory_CUnitCommand_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CUnitCommand>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  using CommandOwnerSlotNode = WeakPtr<CUnitCommand>;
  using BroadcasterOwnerSlotNode = WeakPtr<Broadcaster>;
  using EntityOwnerSlotNode = WeakPtr<Entity>;

  /**
   * Address: 0x006EB6C0 (FUN_006EB6C0)
   *
   * What it does:
   * Returns cached `CUnitCommand` metatable object from Lua object-factory
   * storage.
   */
  [[maybe_unused]] [[nodiscard]] LuaPlus::LuaObject GetUnitCommandFactory(LuaPlus::LuaState* const state)
  {
    return CScrLuaMetatableFactory<CUnitCommand>::Instance().Get(state);
  }

  [[nodiscard]] bool IsUsableCommandUnitEntry(const CScriptObject* const entry) noexcept
  {
    return SCommandUnitSet::IsUsableEntry(entry);
  }

  static_assert(sizeof(CommandOwnerSlotNode) == sizeof(std::uintptr_t) * 2u, "CommandOwnerSlotNode size");
  static_assert(sizeof(BroadcasterOwnerSlotNode) == sizeof(std::uintptr_t) * 2u, "BroadcasterOwnerSlotNode size");
  static_assert(sizeof(EntityOwnerSlotNode) == sizeof(std::uintptr_t) * 2u, "EntityOwnerSlotNode size");

  constexpr std::uint32_t kNoTargetEntityId = 0xF0000000u;
  constexpr const char* kCommandTypeKey = "CommandType";
  constexpr const char* kXKey = "X";
  constexpr const char* kYKey = "Y";
  constexpr const char* kZKey = "Z";
  constexpr const char* kTargetIdKey = "TargetId";
  constexpr const char* kBlueprintIdKey = "BlueprintId";

  [[nodiscard]] std::string BuildInstanceCounterStatPath(const char* const rawTypeName)
  {
    std::string path("Instance Counts_");
    if (!rawTypeName) {
      return path;
    }

    for (const char* it = rawTypeName; *it != '\0'; ++it) {
      if (*it != '_') {
        path.push_back(*it);
      }
    }
    return path;
  }

  template <class TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(TObject));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveBroadcasterCommandEventType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = register_Broadcaster_ECommandEvent_RType();
      if (!sType) {
        sType = gpg::LookupRType(typeid(BroadcasterEventTag<ECommandEvent>));
      }
    }
    return sType;
  }

  /**
   * Address: 0x006EBFA0 (FUN_006EBFA0)
   *
   * What it does:
   * Resolves and caches RTTI for one `Broadcaster<ECommandEvent>` lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveLegacyBroadcasterCommandEventType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(BroadcasterEventTag<ECommandEvent>));
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveWeakPtrCUnitCommandVectorType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(msvc8::vector<WeakPtr<CUnitCommand>>));
      if (!sType) {
        sType = register_WeakPtr_CUnitCommand_VectorType_00();
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveWeakPtrUnitType()
  {
    gpg::RType* sType = WeakPtr<Unit>::sType;
    if (!sType) {
      sType = gpg::LookupRType(typeid(WeakPtr<Unit>));
      if (!sType) {
        sType = register_WeakPtr_Unit_Type_00();
      }
      WeakPtr<Unit>::sType = sType;
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveLuaObjectType()
  {
    gpg::RType* sType = LuaPlus::LuaObject::sType;
    if (!sType) {
      sType = gpg::LookupRType(typeid(LuaPlus::LuaObject));
      LuaPlus::LuaObject::sType = sType;
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveEntityUnitSetType()
  {
    gpg::RType* sType = EntitySetTemplate<Unit>::sType;
    if (!sType) {
      sType = gpg::LookupRType(typeid(EntitySetTemplate<Unit>));
      EntitySetTemplate<Unit>::sType = sType;
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveCountedPtrIFormationInstanceType()
  {
    gpg::RType* sType = CountedPtr<IFormationInstance>::sType;
    if (!sType) {
      register_IFormationInstanceCountedPtrReflection();
      sType = gpg::LookupRType(typeid(CountedPtr<IFormationInstance>));
      CountedPtr<IFormationInstance>::sType = sType;
    }
    return sType;
  }

  /**
   * Address: 0x006ED340 (FUN_006ED340)
   *
   * What it does:
   * Loads one reflected `Broadcaster<ECommandEvent>` payload through cached
   * RTTI lookup and returns the archive pointer for chaining.
   */
  gpg::ReadArchive* ReadBroadcasterCommandEventArchiveAndReturnArchive(
    gpg::ReadArchive* const archive,
    void* const objectPtr,
    gpg::RRef* const ownerRef
  )
  {
    if (archive != nullptr) {
      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      if (gpg::RType* const type = ResolveBroadcasterCommandEventType()) {
        archive->Read(type, objectPtr, owner);
      }
    }

    return archive;
  }

  /**
   * Address: 0x006ED380 (FUN_006ED380)
   *
   * What it does:
   * Loads one reflected `SSTICommandConstantData` payload through cached RTTI
   * lookup and returns the archive pointer for chaining.
   */
  gpg::ReadArchive* ReadSSTICommandConstantDataArchiveAndReturnArchive(
    gpg::ReadArchive* const archive,
    void* const objectPtr,
    gpg::RRef* const ownerRef
  )
  {
    if (archive != nullptr) {
      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      if (gpg::RType* const type = ResolveCachedType<SSTICommandConstantData>()) {
        archive->Read(type, objectPtr, owner);
      }
    }

    return archive;
  }

  /**
   * Address: 0x006ED3C0 (FUN_006ED3C0)
   *
   * What it does:
   * Loads one reflected `SSTICommandVariableData` payload through cached RTTI
   * lookup and returns the archive pointer for chaining.
   */
  gpg::ReadArchive* ReadSSTICommandVariableDataArchiveAndReturnArchive(
    gpg::ReadArchive* const archive,
    void* const objectPtr,
    gpg::RRef* const ownerRef
  )
  {
    if (archive != nullptr) {
      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      if (gpg::RType* const type = ResolveCachedType<SSTICommandVariableData>()) {
        archive->Read(type, objectPtr, owner);
      }
    }

    return archive;
  }

  /**
   * Address: 0x006ED400 (FUN_006ED400)
   *
   * What it does:
   * Loads one reflected `CountedPtr<IFormationInstance>` payload through
   * cached RTTI lookup and returns the archive pointer for chaining.
   */
  gpg::ReadArchive* ReadCountedPtrIFormationInstanceArchiveAndReturnArchive(
    gpg::ReadArchive* const archive,
    void* const objectPtr,
    gpg::RRef* const ownerRef
  )
  {
    if (archive != nullptr) {
      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      if (gpg::RType* const type = ResolveCountedPtrIFormationInstanceType()) {
        archive->Read(type, objectPtr, owner);
      }
    }

    return archive;
  }

  /**
   * Address: 0x006ED440 (FUN_006ED440)
   *
   * What it does:
   * Saves one reflected `Broadcaster<ECommandEvent>` payload through cached
   * RTTI lookup and returns the archive pointer for chaining.
   */
  gpg::WriteArchive* WriteBroadcasterCommandEventArchiveAndReturnArchive(
    gpg::WriteArchive* const archive,
    void* const objectPtr,
    const gpg::RRef* const ownerRef
  )
  {
    if (archive != nullptr) {
      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      if (gpg::RType* const type = ResolveBroadcasterCommandEventType()) {
        archive->Write(type, objectPtr, owner);
      }
    }

    return archive;
  }

  /**
   * Address: 0x006ED480 (FUN_006ED480)
   *
   * What it does:
   * Saves one reflected `SSTICommandConstantData` payload through cached RTTI
   * lookup and returns the archive pointer for chaining.
   */
  gpg::WriteArchive* WriteSSTICommandConstantDataArchiveAndReturnArchive(
    gpg::WriteArchive* const archive,
    void* const objectPtr,
    const gpg::RRef* const ownerRef
  )
  {
    if (archive != nullptr) {
      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      if (gpg::RType* const type = ResolveCachedType<SSTICommandConstantData>()) {
        archive->Write(type, objectPtr, owner);
      }
    }

    return archive;
  }

  /**
   * Address: 0x006ED4C0 (FUN_006ED4C0)
   *
   * What it does:
   * Saves one reflected `SSTICommandVariableData` payload through cached RTTI
   * lookup and returns the archive pointer for chaining.
   */
  gpg::WriteArchive* WriteSSTICommandVariableDataArchiveAndReturnArchive(
    gpg::WriteArchive* const archive,
    void* const objectPtr,
    const gpg::RRef* const ownerRef
  )
  {
    if (archive != nullptr) {
      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      if (gpg::RType* const type = ResolveCachedType<SSTICommandVariableData>()) {
        archive->Write(type, objectPtr, owner);
      }
    }

    return archive;
  }

  /**
   * Address: 0x006ED500 (FUN_006ED500)
   *
   * What it does:
   * Saves one reflected `CountedPtr<IFormationInstance>` payload through
   * cached RTTI lookup and returns the archive pointer for chaining.
   */
  gpg::WriteArchive* WriteCountedPtrIFormationInstanceArchiveAndReturnArchive(
    gpg::WriteArchive* const archive,
    void* const objectPtr,
    const gpg::RRef* const ownerRef
  )
  {
    if (archive != nullptr) {
      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      if (gpg::RType* const type = ResolveCountedPtrIFormationInstanceType()) {
        archive->Write(type, objectPtr, owner);
      }
    }

    return archive;
  }

  /**
   * Address: 0x006ED5B0 (FUN_006ED5B0)
   *
   * What it does:
   * Read-callback bridge that loads one reflected `Broadcaster<ECommandEvent>`
   * payload through cached RTTI lookup.
   */
  void ReadBroadcasterCommandEventArchiveCallback(
    gpg::ReadArchive* const archive,
    void* const objectPtr,
    gpg::RRef* const ownerRef
  )
  {
    (void)ReadBroadcasterCommandEventArchiveAndReturnArchive(archive, objectPtr, ownerRef);
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeDerivedRef(TObject* const object, gpg::RType* const baseType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<std::uint8_t*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }

  [[nodiscard]] void* BroadcasterSubobjectPtr(CUnitCommand* const command) noexcept
  {
    if (!command) {
      return nullptr;
    }

    // `Broadcaster<ECommandEvent>` is serialized from a secondary base slice
    // at +0x34 in the original binary object layout.
    return reinterpret_cast<void*>(reinterpret_cast<std::uint8_t*>(command) + 0x34u);
  }

  [[nodiscard]] const void* BroadcasterSubobjectPtr(const CUnitCommand* const command) noexcept
  {
    if (!command) {
      return nullptr;
    }

    return reinterpret_cast<const void*>(reinterpret_cast<const std::uint8_t*>(command) + 0x34u);
  }

  void CopyUnitSetFromEntitySet(const EntitySetTemplate<Unit>& source, SCommandUnitSet& destination)
  {
    destination.mVec = gpg::core::FastVector<CScriptObject*>{};
    for (Unit* const* it = source.begin(); it != source.end(); ++it) {
      if (!*it) {
        continue;
      }
      (void)destination.InsertUnitSorted(*it);
    }
  }

  void BuildEntitySetFromCommandUnitSet(const SCommandUnitSet& source, EntitySetTemplate<Unit>& destination)
  {
    destination.Clear();
    for (CScriptObject* const entry : source.mVec) {
      if (!SCommandUnitSet::IsUsableEntry(entry)) {
        continue;
      }

      const Unit* const unit = SCommandUnitSet::UnitFromEntry(entry);
      if (!unit) {
        continue;
      }

      (void)destination.Add(const_cast<Unit*>(unit));
    }
  }

  struct CUnitCommandByteAt110RuntimeView
  {
    std::byte pad0000_010F[0x110];
    std::uint8_t lane110;
  };
  static_assert(offsetof(CUnitCommandByteAt110RuntimeView, lane110) == 0x110, "CUnitCommandByteAt110RuntimeView::lane110");

  struct CUnitCommandByteAt154RuntimeView
  {
    std::byte pad0000_0153[0x154];
    std::uint8_t lane154;
  };
  static_assert(offsetof(CUnitCommandByteAt154RuntimeView, lane154) == 0x154, "CUnitCommandByteAt154RuntimeView::lane154");

  struct CUnitCommandWordAtA0RuntimeView
  {
    std::byte pad0000_009F[0xA0];
    std::uint32_t laneA0;
  };
  static_assert(offsetof(CUnitCommandWordAtA0RuntimeView, laneA0) == 0xA0, "CUnitCommandWordAtA0RuntimeView::laneA0");

  struct CUnitCommandWordAt13CRuntimeView
  {
    std::byte pad0000_013B[0x13C];
    std::uint32_t lane13C;
  };
  static_assert(offsetof(CUnitCommandWordAt13CRuntimeView, lane13C) == 0x13C, "CUnitCommandWordAt13CRuntimeView::lane13C");

  struct SelfLinkPairRuntimeView
  {
    SelfLinkPairRuntimeView* prev;
    SelfLinkPairRuntimeView* next;
  };
  static_assert(sizeof(SelfLinkPairRuntimeView) == 0x08, "SelfLinkPairRuntimeView size");
  static_assert(offsetof(SelfLinkPairRuntimeView, prev) == 0x00, "SelfLinkPairRuntimeView::prev");
  static_assert(offsetof(SelfLinkPairRuntimeView, next) == 0x04, "SelfLinkPairRuntimeView::next");

  /**
   * Address: 0x006E7CC0 (FUN_006E7CC0)
   *
   * What it does:
   * Reads one command-runtime byte lane at offset `+0x110`.
   */
  [[maybe_unused]] std::uint8_t ReadCommandRuntimeByte110(const CUnitCommandByteAt110RuntimeView* const command) noexcept
  {
    return command->lane110;
  }

  /**
   * Address: 0x006E7D30 (FUN_006E7D30)
   *
   * What it does:
   * Reads one command-runtime byte lane at offset `+0x154`.
   */
  [[maybe_unused]] std::uint8_t ReadCommandRuntimeByte154(const CUnitCommandByteAt154RuntimeView* const command) noexcept
  {
    return command->lane154;
  }

  /**
   * Address: 0x006E8160 (FUN_006E8160)
   *
   * What it does:
   * Initializes one two-link intrusive header to singleton self-links.
   */
  [[maybe_unused]] SelfLinkPairRuntimeView* InitializeSelfLinkPairPrimary(SelfLinkPairRuntimeView* const links) noexcept
  {
    links->next = links;
    links->prev = links;
    return links;
  }

  /**
   * Address: 0x006E8AF0 (FUN_006E8AF0)
   *
   * What it does:
   * Returns true for patrol/form-patrol command types and, for attack commands,
   * optionally requires ground-target form.
   */
  [[maybe_unused]] bool IsAttackOrPatrolWithOptionalGroundTarget(
    const CUnitCommand* const command,
    const bool requireGroundTargetForAttack
  ) noexcept
  {
    const EUnitCommandType commandType = command->mVarDat.mCmdType;
    if (commandType == EUnitCommandType::UNITCOMMAND_Attack) {
      if (requireGroundTargetForAttack) {
        return command->mTarget.targetType == EAiTargetType::AITARGET_Ground;
      }
    } else if (
      commandType == EUnitCommandType::UNITCOMMAND_Patrol
      || commandType == EUnitCommandType::UNITCOMMAND_FormPatrol
    ) {
      return true;
    }

    return false;
  }

  /**
   * Address: 0x006E8B30 (FUN_006E8B30)
   *
   * What it does:
   * Returns whether command type equals `UNITCOMMAND_BuildFactory`.
   */
  [[maybe_unused]] bool IsBuildFactoryCommand(const CUnitCommand* const command) noexcept
  {
    return command->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_BuildFactory;
  }

  /**
   * Address: 0x006E9320 (FUN_006E9320)
   *
   * What it does:
   * Returns true when one intrusive two-link header is self-linked.
   */
  [[maybe_unused]] bool IsSelfLinkedPair(const SelfLinkPairRuntimeView* const links) noexcept
  {
    return links->prev == links->next;
  }

  /**
   * Address: 0x006E95A0 (FUN_006E95A0)
   *
   * What it does:
   * Alias lane for initializing one two-link intrusive header to singleton
   * self-links.
   */
  [[maybe_unused]] SelfLinkPairRuntimeView* InitializeSelfLinkPairSecondary(SelfLinkPairRuntimeView* const links) noexcept
  {
    links->next = links;
    links->prev = links;
    return links;
  }

  /**
   * Address: 0x006E95F0 (FUN_006E95F0)
   *
   * What it does:
   * Clears one scalar dword output lane to zero.
   */
  [[maybe_unused]] std::uint32_t* ClearScalarDwordLane(std::uint32_t* const outValue) noexcept
  {
    *outValue = 0u;
    return outValue;
  }

  /**
   * Address: 0x006EC9D0 (FUN_006EC9D0)
   *
   * What it does:
   * Swaps one scalar dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapScalarDwordLane(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    const std::uint32_t value = *right;
    *right = *left;
    *left = value;
    return left;
  }

  /**
   * Address: 0x006ED980 (FUN_006ED980)
   *
   * What it does:
   * Copies one runtime dword lane at offset `+0xA0` into output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyRuntimeWordA0(
    std::uint32_t* const outValue,
    const CUnitCommandWordAtA0RuntimeView* const source
  ) noexcept
  {
    *outValue = source->laneA0;
    return outValue;
  }

  /**
   * Address: 0x006ED990 (FUN_006ED990)
   *
   * What it does:
   * Reads one runtime dword lane at offset `+0x13C`.
   */
  [[maybe_unused]] std::uint32_t ReadRuntimeWord13C(const CUnitCommandWordAt13CRuntimeView* const source) noexcept
  {
    return source->lane13C;
  }

  /**
   * Address: 0x005527C0 (FUN_005527C0, struct_CommandIssueDataHelper::struct_CommandIssueDataHelper)
   *
   * What it does:
   * Initializes one published-command descriptor from issue-data lanes
   * (`nextCommandId`, orientation/aux scalars, blueprint, and Lua-object
   * lexical payload).
   */
  [[maybe_unused]] SSTICommandConstantData* InitializePublishedCommandDescriptorFromIssueData(
    SSTICommandConstantData* const destination,
    const SSTICommandIssueData* const issueData
  )
  {
    destination->cmd = issueData->nextCommandId;
    destination->unk0 = reinterpret_cast<void*>(static_cast<std::uintptr_t>(issueData->unk38));
    destination->origin = issueData->mOri;
    destination->unk1 = issueData->unk4C;
    destination->blueprint = static_cast<REntityBlueprint*>(issueData->mBlueprint);
    destination->unk2 = SCR_ToString(issueData->mObject);
    return destination;
  }

  /**
   * Address: 0x006E7BD0 (FUN_006E7BD0, struct_CommandIssueDataHelper::cpy)
   *
   * What it does:
   * Copies one published-command descriptor lane (`SSTICommandConstantData`)
   * including legacy string payload.
   */
  void CopyPublishedCommandDescriptor(
    SSTICommandConstantData& destination,
    const SSTICommandConstantData& source
  )
  {
    destination.cmd = source.cmd;
    destination.unk0 = source.unk0;
    destination.origin = source.origin;
    destination.unk1 = source.unk1;
    destination.blueprint = source.blueprint;
    destination.unk2 = source.unk2;
  }

  /**
   * Address: 0x006E7BC0 (FUN_006E7BC0)
   *
   * What it does:
   * Adapter that copies one published-command descriptor lane and returns the
   * destination pointer.
   */
  [[maybe_unused]] SSTICommandConstantData* CopyPublishedCommandDescriptorAdapterPrimary(
    SSTICommandConstantData* const destination,
    const SSTICommandConstantData* const source
  )
  {
    CopyPublishedCommandDescriptor(*destination, *source);
    return destination;
  }

  /**
   * Address: 0x006EB470 (FUN_006EB470)
   *
   * What it does:
   * Secondary adapter that copies one published-command descriptor lane and
   * returns the destination pointer.
   */
  [[maybe_unused]] SSTICommandConstantData* CopyPublishedCommandDescriptorAdapterSecondary(
    SSTICommandConstantData* const destination,
    const SSTICommandConstantData* const source
  )
  {
    CopyPublishedCommandDescriptor(*destination, *source);
    return destination;
  }

  /**
   * Address: 0x006E9360 (FUN_006E9360)
   * Address: 0x006EC380 (FUN_006EC380, inlined uninitialized-fill-with-rollback lane)
   *
   * What it does:
   * Appends one command descriptor record into sync publication output.
   *
   * The binary emits one additional helper at `0x006EC380` which drives
   * the grow path of `msvc8::vector<SSTICommandConstantData>::push_back`
   * / `insert_n`: it runs one uninitialized-fill lane (stride
   * `sizeof(SSTICommandConstantData)=0x3C`) that copy-constructs each
   * descriptor by blitting the first `0x20` trivial bytes (cmd/unk0/
   * origin/unk1/blueprint), placement-constructs an empty `msvc8::string`
   * at `+0x20`, and copy-assigns `unk2` from the source. On partial-fill
   * failure (e.g. string allocation throw), its SEH funclet runs the
   * per-lane string-reset helper (`ResetSSTICommandConstantDataStringLane`
   * at `0x006ECB50`) over the already-constructed prefix before
   * re-raising. The same semantic is preserved here via the typed
   * `msvc8::vector::push_back` call.
   */
  void AppendPublishedCommandDescriptor(
    msvc8::vector<SSTICommandConstantData>& descriptors,
    const SSTICommandConstantData& descriptor
  )
  {
    descriptors.push_back(descriptor);
  }

  /**
   * Address: 0x006E7C50 (FUN_006E7C50)
   *
   * What it does:
   * Builds one published-command packet from command id and variable payload.
   */
  [[nodiscard]] SSyncPublishedCommandPacket BuildPublishedCommandPacket(
    const CmdId commandId,
    const SSTICommandVariableData& variableData
  )
  {
    SSyncPublishedCommandPacket packet{};
    packet.commandId = commandId;
    packet.variableData = variableData;
    return packet;
  }

  /**
   * Address: 0x006E93F0 (FUN_006E93F0)
   *
   * What it does:
   * Appends one published-command packet into sync publication output.
   */
  void AppendPublishedCommandPacket(
    msvc8::vector<SSyncPublishedCommandPacket>& packets,
    const SSyncPublishedCommandPacket& packet
  )
  {
    packets.push_back(packet);
  }

  template <typename TValue>
  void SetCommandQueueField(LuaPlus::LuaObject& row, const char* key, const TValue& value);

  template <>
  void SetCommandQueueField<std::int32_t>(LuaPlus::LuaObject& row, const char* const key, const std::int32_t& value)
  {
    row.SetInteger(key, value);
  }

  template <>
  void SetCommandQueueField<float>(LuaPlus::LuaObject& row, const char* const key, const float& value)
  {
    row.SetNumber(key, value);
  }

  template <>
  void SetCommandQueueField<const char*>(LuaPlus::LuaObject& row, const char* const key, const char* const& value)
  {
    row.SetString(key, value ? value : "");
  }

  [[nodiscard]] const char* ResolveBlueprintId(const CUnitCommand& command) noexcept
  {
    const REntityBlueprint* const blueprint = command.mConstDat.blueprint;
    if (!blueprint) {
      return nullptr;
    }

    const char* const blueprintId = blueprint->mBlueprintId.c_str();
    return (blueprintId && blueprintId[0] != '\0') ? blueprintId : nullptr;
  }

  struct CUnitCommandDestroyRuntimeView
  {
    std::uint8_t pad_0000_0034[0x34];
    BroadcasterOwnerSlotNode broadcasterOwnerChainNode;
    std::uint8_t pad_003C_00F0[0xB4];
    CommandOwnerSlotNode unitSetOwnerChainNode;
    std::uint8_t pad_00F8_0118[0x20];
    CountedObject* formationObject;
    std::uint8_t pad_011C_0120[0x04];
    CommandOwnerSlotNode coordinatingOrdersOwnerChainNode;
    std::uint8_t pad_0128_0158[0x30];
    EntityOwnerSlotNode sidecarOwnerChainNode;
  };
  static_assert(
    offsetof(CUnitCommandDestroyRuntimeView, broadcasterOwnerChainNode) == 0x34,
    "CUnitCommandDestroyRuntimeView::broadcasterOwnerChainNode"
  );
  static_assert(
    offsetof(CUnitCommandDestroyRuntimeView, unitSetOwnerChainNode) == 0xF0,
    "CUnitCommandDestroyRuntimeView::unitSetOwnerChainNode"
  );
  static_assert(
    offsetof(CUnitCommandDestroyRuntimeView, formationObject) == 0x118,
    "CUnitCommandDestroyRuntimeView::formationObject"
  );
  static_assert(
    offsetof(CUnitCommandDestroyRuntimeView, coordinatingOrdersOwnerChainNode) == 0x120,
    "CUnitCommandDestroyRuntimeView::coordinatingOrdersOwnerChainNode"
  );
  static_assert(
    offsetof(CUnitCommandDestroyRuntimeView, sidecarOwnerChainNode) == 0x158,
    "CUnitCommandDestroyRuntimeView::sidecarOwnerChainNode"
  );

  void ReleaseIntrusiveRefcountedObject(CountedObject*& object)
  {
    if (!object) {
      return;
    }

    (void)object->ReleaseReference();
    object = nullptr;
  }

  /**
   * Address: 0x006E9650 (FUN_006E9650)
   *
   * What it does:
   * Rebinds one intrusive counted formation pointer slot, releasing previous
   * ownership and add-refing the new pointee when non-null.
   */
  void AssignFormationInstanceRef(CAiFormationInstance*& slot, CAiFormationInstance* const value) noexcept
  {
    if (slot == value) {
      return;
    }

    if (slot != nullptr) {
      auto* const previous = reinterpret_cast<CountedObject*>(slot);
      (void)previous->ReleaseReference();
    }

    slot = value;

    if (slot != nullptr) {
      auto* const current = reinterpret_cast<CountedObject*>(slot);
      current->AddReference();
    }
  }

  void CopyIssueDataToVariablePayload(const SSTICommandIssueData& issueData, SSTICommandVariableData& variableData)
  {
    variableData = SSTICommandVariableData(issueData);
  }

} // namespace

/**
 * Address: 0x006EA340 (FUN_006EA340, Moho::InstanceCounter<Moho::CUnitCommand>::GetStatItem)
 *
 * What it does:
 * Lazily resolves and caches the engine stat slot used for CUnitCommand
 * instance counting (`Instance Counts_<type-name-without-underscores>`).
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::CUnitCommand>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem) {
    return sStatItem;
  }

  const std::string statPath = BuildInstanceCounterStatPath(typeid(moho::CUnitCommand).name());
  moho::EngineStats* const engineStats = moho::GetEngineStats();
  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
}

/**
 * Address: 0x006E95B0 (FUN_006E95B0)
 *
 * What it does:
 * Increments the `CUnitCommand` instance-counter stat lane and returns the
 * pass-through value unchanged.
 */
[[maybe_unused]] int IncrementCUnitCommandInstanceStatAndReturn(const int passthrough)
{
  moho::StatItem* const statItem = moho::InstanceCounter<moho::CUnitCommand>::GetStatItem();
  (void)::InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), 1L);
  return passthrough;
}

CScriptObject* SCommandUnitSet::EntryFromUnit(Unit* const unit) noexcept
{
  if (!unit) {
    return nullptr;
  }

  auto* const raw = reinterpret_cast<std::uint8_t*>(unit);
  return reinterpret_cast<CScriptObject*>(raw + sizeof(IUnit));
}

Unit* SCommandUnitSet::UnitFromEntry(CScriptObject* const entry) noexcept
{
  return const_cast<Unit*>(UnitFromEntry(static_cast<const CScriptObject*>(entry)));
}

const Unit* SCommandUnitSet::UnitFromEntry(const CScriptObject* const entry) noexcept
{
  if (!entry) {
    return nullptr;
  }

  // Command unit-set stores CScriptObject subobject pointers for Unit entries.
  // Unit complete-object base is sizeof(IUnit) bytes before that subobject.
  const auto* const raw = reinterpret_cast<const std::uint8_t*>(entry);
  return reinterpret_cast<const Unit*>(raw - sizeof(IUnit));
}

EntId SCommandUnitSet::EntryEntityId(const CScriptObject* const entry) noexcept
{
  if (!entry || !SCommandUnitSet::IsUsableEntry(entry)) {
    return static_cast<EntId>(0x7FFFFFFF);
  }

  const Unit* const unit = UnitFromEntry(entry);
  return unit ? unit->GetEntityId() : static_cast<EntId>(0x7FFFFFFF);
}

std::size_t SCommandUnitSet::LowerBoundByEntityId(const EntId targetId) const noexcept
{
  std::size_t first = 0;
  std::size_t count = mVec.size();
  while (count != 0) {
    const std::size_t step = count / 2;
    const std::size_t probeIndex = first + step;
    const EntId probeId = EntryEntityId(mVec[probeIndex]);
    if (probeId < targetId) {
      first = probeIndex + 1;
      count -= step + 1;
    } else {
      count = step;
    }
  }

  return first;
}

bool SCommandUnitSet::InsertUnitSorted(Unit* const unit)
{
  if (!unit) {
    return false;
  }

  const EntId unitId = unit->GetEntityId();
  const std::size_t index = LowerBoundByEntityId(unitId);
  CScriptObject* const entry = EntryFromUnit(unit);
  const std::size_t size = mVec.size();

  if (index < size && mVec[index] == entry) {
    return false;
  }

  if (size == mVec.Capacity()) {
    mVec.Reserve(size != 0 ? (size * 2) : 4u);
  }

  CScriptObject** const begin = mVec.start_;
  if (size > index) {
    std::memmove(begin + index + 1, begin + index, (size - index) * sizeof(*begin));
  }

  begin[index] = entry;
  mVec.end_ = begin + size + 1;
  return true;
}

bool SCommandUnitSet::RemoveUnitSorted(Unit* const unit)
{
  const EntId unitId = unit ? unit->GetEntityId() : 0;
  const std::size_t index = LowerBoundByEntityId(unitId);
  const std::size_t size = mVec.size();
  if (index >= size) {
    return false;
  }

  CScriptObject* const expected = EntryFromUnit(unit);
  if (mVec[index] != expected) {
    return false;
  }

  CScriptObject** const begin = mVec.start_;
  if (index + 1 < size) {
    std::memmove(begin + index, begin + index + 1, (size - index - 1) * sizeof(*begin));
  }

  mVec.end_ = begin + size - 1;
  return true;
}

/**
 * Address: 0x006E7FF0 (FUN_006E7FF0, ??0CUnitCommand@Moho@@AAE@XZ)
 *
 * What it does:
 * Default-initializes one command instance used by serializer construct flow.
 */
CUnitCommand::CUnitCommand()
  : unk0(nullptr)
  , mSim(nullptr)
  , mConstDat{}
  , mVarDat{}
  , unk1(nullptr)
  , mUnitSet{}
  , mFormationInstance(nullptr)
  , mTarget{}
  , mInstanceSerial(0)
  , mHasPublishedCommandEvent(false)
  , mNeedsUpdate(true)
  , mUnknownFlag142(false)
  , mUnknownFlag143(false)
  , mCoordinatingOrders{}
  , mUnknownFlag154(false)
  , mUnit()
  , mArgs()
  , mUnknownTailInt(0)
{
  mPrev = this;
  mNext = this;

  mConstDat.cmd = -1;
  mConstDat.unk0 = reinterpret_cast<void*>(static_cast<std::uintptr_t>(0xFFFFFFFFu));
  mConstDat.origin = Wm3::Quatf{1.0f, 0.0f, 0.0f, 0.0f};
  mConstDat.unk1 = 0.0f;
  mConstDat.blueprint = nullptr;
  mConstDat.unk2 = msvc8::string{};

  mVarDat = SSTICommandVariableData{};
  mUnitSet.mVec = gpg::core::FastVector<CScriptObject*>{};

  mTarget.targetType = EAiTargetType::AITARGET_None;
  mTarget.targetEntity.ClearLinkState();
  mTarget.position = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
  mTarget.targetPoint = -1;
  mTarget.targetIsMobile = false;
}

/**
 * Address: 0x006E81B0 (FUN_006E81B0, ??0CUnitCommand@Moho@@QAE@PAVSim@1@ABUSSTICommandIssueData@1@@Z)
 *
 * What it does:
 * Initializes one command from issue payload lanes, updates sim command
 * digest/counter state, and links coordinating-order relationships.
 */
CUnitCommand::CUnitCommand(Sim* const sim, const SSTICommandIssueData& issueData)
  : CUnitCommand(sim, issueData, issueData.nextCommandId)
{
}

/**
    * Alias of FUN_006E81B0 (non-canonical helper lane).
 *
 * What it does:
 * Initializes one command from issue payload lanes, updates sim command
 * digest/counter state, and links coordinating-order relationships, using the
 * resolved command id passed by command-db allocation paths.
 */
CUnitCommand::CUnitCommand(Sim* const sim, const SSTICommandIssueData& issueData, const CmdId resolvedCommandId)
  : unk0(nullptr)
  , mSim(sim)
  , mConstDat{}
  , mVarDat{}
  , unk1(nullptr)
  , mUnitSet{}
  , mFormationInstance(nullptr)
  , mTarget{}
  , mInstanceSerial(0)
  , mHasPublishedCommandEvent(false)
  , mNeedsUpdate(true)
  , mUnknownFlag142(false)
  , mUnknownFlag143(false)
  , mCoordinatingOrders{}
  , mUnknownFlag154(false)
  , mUnit()
  , mArgs(issueData.mObject)
  , mUnknownTailInt(0)
{
  mPrev = this;
  mNext = this;

  (void)InitializePublishedCommandDescriptorFromIssueData(&mConstDat, &issueData);
  mConstDat.cmd = resolvedCommandId;

  CopyIssueDataToVariablePayload(issueData, mVarDat);
  mUnitSet.mVec = gpg::core::FastVector<CScriptObject*>{};
  mTarget.DecodeFromSSTITarget(issueData.mTarget, sim);

  if (!sim) {
    return;
  }

  const std::uint32_t commandSerial = sim->mReserved98C;
  sim->mReserved98C = commandSerial + 1u;
  mInstanceSerial = static_cast<CmdId>(commandSerial);

  sim->Logf("Creating command 0x%08x, type=%d\n", mConstDat.cmd, static_cast<int>(mVarDat.mCmdType));
  sim->mContext.Update(&mConstDat.cmd, sizeof(mConstDat.cmd));
  const std::int32_t commandTypeValue = static_cast<std::int32_t>(mVarDat.mCmdType);
  sim->mContext.Update(&commandTypeValue, sizeof(commandTypeValue));

  if (!sim->mCommandDB || issueData.unk04 == -1) {
    return;
  }

  const auto it = sim->mCommandDB->commands.find(static_cast<CmdId>(issueData.unk04));
  if (it == sim->mCommandDB->commands.end()) {
    return;
  }

  CUnitCommand* const coordinatingCommand = &it->second;
  if (!coordinatingCommand) {
    return;
  }

  const msvc8::vector<WeakPtr<CUnitCommand>> coordinatingPeers = coordinatingCommand->GetCoordinatingOrdersSnapshot();
  for (const WeakPtr<CUnitCommand>& peerWeak : coordinatingPeers) {
    CUnitCommand* const peer = peerWeak.GetObjectPtr();
    if (!peer || peer == this) {
      continue;
    }

    peer->CoordinateWith(this);
    CoordinateWith(peer);
  }

  coordinatingCommand->CoordinateWith(this);
  CoordinateWith(coordinatingCommand);
}

/**
 * Address: 0x006E7D10 (FUN_006E7D10, Moho::CUnitCommand::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef CUnitCommand::GetDerivedObjectRef()
{
  gpg::RRef ref{};
  ref.mObj = this;
  ref.mType = StaticGetClass();
  return ref;
}

/**
 * Address: 0x006E7D40 (FUN_006E7D40, ?GetCoordinateWith@CUnitCommand@Moho@@QBE?AV?$vector@V?$WeakPtr@VCUnitCommand@Moho@@@Moho@@V?$allocator@V?$WeakPtr@VCUnitCommand@Moho@@@Moho@@@std@@@std@@XZ)
 *
 * What it does:
 * Returns a by-value snapshot of this command's coordinating-order weak links.
 */
msvc8::vector<WeakPtr<CUnitCommand>> CUnitCommand::GetCoordinatingOrdersSnapshot() const
{
  return mCoordinatingOrders;
}

/**
 * Address: 0x006E91C0 (FUN_006E91C0, Moho::CUnitCommand::MemberConstruct)
 *
 * What it does:
 * Allocates one command object, runs default constructor lanes, and publishes
 * the result as an unowned construct payload.
 */
void CUnitCommand::MemberConstruct(gpg::SerConstructResult* const result)
{
  if (!result) {
    return;
  }

  CUnitCommand* const command = new (std::nothrow) CUnitCommand();
  gpg::RRef objectRef{};
  objectRef.mObj = command;
  objectRef.mType = CUnitCommand::StaticGetClass();
  result->SetUnowned(objectRef, 0u);
}

/**
 * Address: 0x006ECB80 (FUN_006ECB80, Moho::CUnitCommand::MemberDeserialize)
 * Address: 0x006EC1B0 (FUN_006EC1B0)
 *
 * What it does:
 * Loads reflected base/object lanes and command payload fields, then maps the
 * serialized unit-set lane into command-runtime unit entries.
 */
void CUnitCommand::MemberDeserialize(gpg::ReadArchive* const archive, CUnitCommand* const command, const int version)
{
  if (!archive || !command) {
    return;
  }

  const gpg::RRef ownerRef{};

  if (gpg::RType* const scriptType = ResolveCachedType<CScriptObject>()) {
    archive->Read(scriptType, command, ownerRef);
  }

  if (gpg::RType* const broadcasterType = ResolveBroadcasterCommandEventType()) {
    archive->Read(broadcasterType, BroadcasterSubobjectPtr(command), ownerRef);
  }

  (void)archive->ReadPointer_Sim(&command->mSim, &ownerRef);

  if (gpg::RType* const constDataType = ResolveCachedType<SSTICommandConstantData>()) {
    archive->Read(constDataType, &command->mConstDat, ownerRef);
  }

  if (gpg::RType* const variableDataType = ResolveCachedType<SSTICommandVariableData>()) {
    archive->Read(variableDataType, &command->mVarDat, ownerRef);
  }

  EntitySetTemplate<Unit> loadedUnitSet{};
  if (gpg::RType* const unitSetType = ResolveEntityUnitSetType()) {
    archive->Read(unitSetType, &loadedUnitSet, ownerRef);
    CopyUnitSetFromEntitySet(loadedUnitSet, command->mUnitSet);
  }

  if (gpg::RType* const formationType = ResolveCountedPtrIFormationInstanceType()) {
    CountedPtr<IFormationInstance> formation{};
    archive->Read(formationType, &formation, ownerRef);
    command->mFormationInstance = static_cast<CAiFormationInstance*>(formation.tex);
  }

  if (gpg::RType* const targetType = ResolveCachedType<CAiTarget>()) {
    archive->Read(targetType, &command->mTarget, ownerRef);
  }

  std::uint32_t instanceSerial = 0u;
  archive->ReadUInt(&instanceSerial);
  command->mInstanceSerial = static_cast<CmdId>(instanceSerial);

  archive->ReadBool(&command->mUnknownFlag142);

  if (gpg::RType* const coordinatingOrdersType = ResolveWeakPtrCUnitCommandVectorType()) {
    archive->Read(coordinatingOrdersType, &command->mCoordinatingOrders, ownerRef);
  }

  archive->ReadBool(&command->mUnknownFlag154);

  if (version >= 1) {
    if (gpg::RType* const weakUnitType = ResolveWeakPtrUnitType()) {
      archive->Read(weakUnitType, &command->mUnit, ownerRef);
    }
  }

  if (version >= 2) {
    if (gpg::RType* const luaObjectType = ResolveLuaObjectType()) {
      archive->Read(luaObjectType, &command->mArgs, ownerRef);
    }
  }
}

/**
 * Address: 0x006ECE20 (FUN_006ECE20, Moho::CUnitCommand::MemberSerialize)
 * Address: 0x006EB750 (FUN_006EB750)
 * Address: 0x006EC1C0 (FUN_006EC1C0)
 *
 * What it does:
 * Saves reflected base/object lanes and command payload fields, serializing
 * the command-unit set through legacy `EntitySetTemplate<Unit>` RTTI lanes.
 */
void CUnitCommand::MemberSerialize(CUnitCommand* const command, gpg::WriteArchive* const archive, const int version)
{
  if (!archive || !command) {
    return;
  }

  const gpg::RRef ownerRef{};

  if (gpg::RType* const scriptType = ResolveCachedType<CScriptObject>()) {
    archive->Write(scriptType, command, ownerRef);
  }

  if (gpg::RType* const broadcasterType = ResolveBroadcasterCommandEventType()) {
    archive->Write(broadcasterType, BroadcasterSubobjectPtr(command), ownerRef);
  }

  if (gpg::RType* const simType = ResolveCachedType<Sim>()) {
    const gpg::RRef simRef = MakeDerivedRef(command->mSim, simType);
    gpg::WriteRawPointer(archive, simRef, gpg::TrackedPointerState::Unowned, ownerRef);
  }

  if (gpg::RType* const constDataType = ResolveCachedType<SSTICommandConstantData>()) {
    archive->Write(constDataType, &command->mConstDat, ownerRef);
  }

  if (gpg::RType* const variableDataType = ResolveCachedType<SSTICommandVariableData>()) {
    archive->Write(variableDataType, &command->mVarDat, ownerRef);
  }

  EntitySetTemplate<Unit> serializedUnitSet{};
  BuildEntitySetFromCommandUnitSet(command->mUnitSet, serializedUnitSet);
  if (gpg::RType* const unitSetType = ResolveEntityUnitSetType()) {
    archive->Write(unitSetType, &serializedUnitSet, ownerRef);
  }

  CountedPtr<IFormationInstance> formation{};
  formation.tex = static_cast<IFormationInstance*>(command->mFormationInstance);
  if (gpg::RType* const formationType = ResolveCountedPtrIFormationInstanceType()) {
    archive->Write(formationType, &formation, ownerRef);
  }

  if (gpg::RType* const targetType = ResolveCachedType<CAiTarget>()) {
    archive->Write(targetType, &command->mTarget, ownerRef);
  }

  archive->WriteUInt(static_cast<unsigned int>(command->mInstanceSerial));
  archive->WriteBool(command->mUnknownFlag142);

  if (gpg::RType* const coordinatingOrdersType = ResolveWeakPtrCUnitCommandVectorType()) {
    archive->Write(coordinatingOrdersType, &command->mCoordinatingOrders, ownerRef);
  }

  archive->WriteBool(command->mUnknownFlag154);

  if (version >= 1) {
    if (gpg::RType* const weakUnitType = ResolveWeakPtrUnitType()) {
      archive->Write(weakUnitType, &command->mUnit, ownerRef);
    }
  }

  if (version >= 2) {
    if (gpg::RType* const luaObjectType = ResolveLuaObjectType()) {
      archive->Write(luaObjectType, &command->mArgs, ownerRef);
    }
  }
}

/**
 * Address: 0x006E8B40 (FUN_006E8B40)
 *
 * What it does:
 * Adds `unit` into this command's unit-set and inserts this command weak-ref
 * into `queue` at `index` (negative index inserts relative to queue end).
 */
void CUnitCommand::AddUnit(Unit* const unit, msvc8::vector<WeakPtr<CUnitCommand>>& queue, const int index)
{
  if (!unit || unit->IsDead() || unit->DestroyQueued()) {
    return;
  }

  if (!mUnitSet.InsertUnitSorted(unit)) {
    return;
  }

  mNeedsUpdate = true;
  InsertWeakPtrVectorObjectAt(queue, this, NormalizeWeakPtrVectorInsertIndex(queue, index));

  if (mFormationInstance) {
    mFormationInstance->AddUnit(unit);
  }
}

/**
 * Address: 0x006E8CC0 (FUN_006E8CC0)
 *
 * What it does:
 * Adds one live unit into this command's unit-set and formation lanes without
 * mutating any external command queue.
 */
void CUnitCommand::AddUnit(Unit* const unit)
{
  if (!unit || unit->IsDead() || unit->DestroyQueued()) {
    return;
  }

  if (!mUnitSet.InsertUnitSorted(unit)) {
    return;
  }

  mNeedsUpdate = true;

  if (mFormationInstance) {
    mFormationInstance->AddUnit(unit);
  }
}

/**
 * Address: 0x006E8C20 (FUN_006E8C20)
 *
 * What it does:
 * Removes `unit` from this command's unit-set and removes this command weak-ref
 * from the provided queue.
 */
void CUnitCommand::RemoveUnit(Unit* const unit, msvc8::vector<WeakPtr<CUnitCommand>>& queue)
{
  if (!mUnitSet.RemoveUnitSorted(unit)) {
    return;
  }

  mNeedsUpdate = true;

  if (mFormationInstance) {
    mFormationInstance->RemoveUnit(unit);
    if (mFormationInstance && mFormationInstance->UnitCount() == 0) {
      CountedObject* formationObject = reinterpret_cast<CountedObject*>(mFormationInstance);
      ReleaseIntrusiveRefcountedObject(formationObject);
      mFormationInstance = nullptr;
    }
  }

  (void)RemoveWeakPtrVectorObject(queue, this);
}

/**
 * Address: 0x006E8D10 (FUN_006E8D10)
 *
 * What it does:
 * Removes `unit` from this command's unit-set without touching queue links.
 */
void CUnitCommand::RemoveUnit(Unit* const unit)
{
  if (!mUnitSet.RemoveUnitSorted(unit)) {
    return;
  }

  mNeedsUpdate = true;

  if (mFormationInstance) {
    mFormationInstance->RemoveUnit(unit);
    if (mFormationInstance && mFormationInstance->UnitCount() == 0) {
      CountedObject* formationObject = reinterpret_cast<CountedObject*>(mFormationInstance);
      ReleaseIntrusiveRefcountedObject(formationObject);
      mFormationInstance = nullptr;
    }
  }
}

/**
 * Address: 0x006E8D70 (FUN_006E8D70, Moho::CUnitCommand::FormRemoveUnit)
 *
 * What it does:
 * Removes one unit from the active formation lane and releases the formation
 * instance when that lane becomes empty.
 */
void CUnitCommand::FormRemoveUnit(Unit* const unit, CUnitCommand* const command)
{
  if (!command) {
    return;
  }

  CAiFormationInstance* const formationInstance = command->mFormationInstance;
  if (!formationInstance) {
    return;
  }

  formationInstance->RemoveUnit(unit);
  if (formationInstance->UnitCount() != 0) {
    return;
  }

  CountedObject* formationObject = reinterpret_cast<CountedObject*>(formationInstance);
  ReleaseIntrusiveRefcountedObject(formationObject);
  command->mFormationInstance = nullptr;
}

/**
 * Address: 0x005D5980 (FUN_005D5980, Moho::CUnitCommand::GetFocus)
 *
 * What it does:
 * Returns the current focus entity from the target weak-link lane.
 */
Entity* CUnitCommand::GetFocus(CUnitCommand* const command)
{
  if (!command) {
    return nullptr;
  }

  return command->mTarget.targetEntity.GetObjectPtr();
}

/**
 * Address: 0x005F55F0 (FUN_005F55F0, Moho::CUnitCommand::GetTarget)
 *
 * What it does:
 * Resolves the focused entity to a live unit pointer when available.
 */
Unit* CUnitCommand::GetTarget(CUnitCommand* const command)
{
  Entity* const focus = GetFocus(command);
  return focus ? focus->IsUnit() : nullptr;
}

/**
 * Address: 0x005F24E0 (FUN_005F24E0, Moho::CUnitCommand::IsCoordinating)
 *
 * What it does:
 * Returns true when this command has at least one coordinating-order link.
 */
bool CUnitCommand::IsCoordinating() const
{
  return !mCoordinatingOrders.empty();
}

/**
 * Address: 0x006E90A0 (FUN_006E90A0, Moho::CUnitCommand::IsDone)
 *
 * What it does:
 * Returns true when this command's done flag is set and all resolved
 * coordinating-order peers are done as well.
 */
bool CUnitCommand::IsDone() const
{
  if (mCoordinatingOrders.empty()) {
    return true;
  }

  if (!mUnknownFlag154) {
    return false;
  }

  for (const WeakPtr<CUnitCommand>& commandRef : mCoordinatingOrders) {
    CUnitCommand* const command = commandRef.GetObjectPtr();
    if (command != nullptr && !command->mUnknownFlag154) {
      return false;
    }
  }

  return true;
}

/**
 * Address: 0x006E8A00 (FUN_006E8A00, Moho::CUnitCommand::InFormation)
 *
 * What it does:
 * Returns the active formation instance when `unit` already belongs to it.
 */
CAiFormationInstance* CUnitCommand::InFormation(Unit* const unit, CUnitCommand* const command)
{
  if (!command || !unit) {
    return nullptr;
  }

  CAiFormationInstance* const formationInstance = command->mFormationInstance;
  if (!formationInstance || !formationInstance->Func17(unit, true)) {
    return nullptr;
  }

  return formationInstance;
}

/**
 * Address: 0x006E8A30 (FUN_006E8A30, Moho::CUnitCommand::GetPosition)
 *
 * What it does:
 * Resolves the command position used by formation and non-formation move
 * dispatch paths.
 */
SOCellPos* CUnitCommand::GetPosition(CUnitCommand* const command, Unit* const unit, SOCellPos* const dest)
{
  if (!command || !unit || !dest) {
    return dest;
  }

  CAiFormationInstance* const formationInstance = command->mFormationInstance;
  if (command->mUnitSet.mVec.size() <= 1u || !formationInstance) {
    const Wm3::Vec3f targetPos = command->mTarget.GetTargetPosGun(false);
    const SFootprint& footprint = unit->GetFootprint();
    dest->x = static_cast<std::int32_t>(targetPos.x - (static_cast<float>(footprint.mSizeX) * 0.5f));
    dest->z = static_cast<std::int32_t>(targetPos.z - (static_cast<float>(footprint.mSizeZ) * 0.5f));
    return dest;
  }

  (void)formationInstance->GetAdjustedFormationPosition(dest, unit, nullptr);
  return dest;
}

/**
 * Address: 0x006E88D0 (FUN_006E88D0, Moho::CUnitCommand::Move)
 *
 * What it does:
 * Keeps formation membership in sync for multi-unit commands, adds units to
 * existing formations when appropriate, and creates a new formation instance
 * when the command first needs one.
 */
void CUnitCommand::Move(Unit* const unit, CUnitCommand* const command)
{
  if (!unit || !command) {
    return;
  }

  if (command->mUnitSet.mVec.size() <= 1u || command->mVarDat.v2 < 0) {
    return;
  }

  CAiFormationInstance* const formationInstance = command->mFormationInstance;
  if (formationInstance && !formationInstance->Func17(unit, true) && !unit->IsDead() && !unit->DestroyQueued()) {
    formationInstance->AddUnit(unit);
    return;
  }

  if (command->mFormationInstance != nullptr) {
    return;
  }

  CAiFormationDBImpl* const formationDb = command->mSim ? command->mSim->mFormationDB : nullptr;
  if (!formationDb) {
    return;
  }

  const EFormationType formationType = (unit->mCurrentLayer == LAYER_Air) ? EFormationType::Air : EFormationType::Surface;
  const char* const scriptName = formationDb->GetScriptName(command->mVarDat.v2, formationType);
  if (!scriptName) {
    return;
  }

  const Wm3::Vec3f targetPos = command->mTarget.GetTargetPosGun(false);

  SCoordsVec2 formationCenter{};
  formationCenter.x = targetPos.x;
  formationCenter.z = targetPos.z;
  SFormationUnitWeakRefSet weakSet{};
  weakSet.reserve(command->mUnitSet.mVec.size());
  for (CScriptObject* const entry : command->mUnitSet.mVec) {
    Unit* const queuedUnit = SCommandUnitSet::UnitFromEntry(entry);
    if (!queuedUnit) {
      continue;
    }

    weakSet.push_back(SFormationUnitWeakRef::FromUnit(queuedUnit));
  }

  CAiFormationInstance* const newFormation = formationDb->NewFormation(
    &weakSet,
    scriptName,
    &formationCenter,
    command->mConstDat.origin.x,
    command->mConstDat.origin.y,
    command->mConstDat.origin.z,
    command->mConstDat.origin.w,
    static_cast<int>(command->mVarDat.mCmdType)
  );
  if (!newFormation) {
    return;
  }

  AssignFormationInstanceRef(command->mFormationInstance, newFormation);
  if (command->mFormationInstance != nullptr) {
    command->mFormationInstance->Func22(command->mConstDat.unk1);
  }
}

// 0x006F1650
void CUnitCommand::IncreaseCount(const int amount)
{
  if (amount <= 0 || mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_BuildFactory) {
    return;
  }

  const int newCount = mVarDat.mCount + amount;

  mVarDat.mCount = newCount;
  if (newCount > mVarDat.mMaxCount) {
    mVarDat.mMaxCount = newCount;
  }

  mNeedsUpdate = true;
}

// 0x006F16A0
void CUnitCommand::DecreaseCount(const int amount)
{
  if (amount <= 0 || mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_BuildFactory) {
    return;
  }

  int newCount = mVarDat.mCount - amount;
  if (newCount < 0) {
    newCount = 0;
  }

  mVarDat.mCount = newCount;
  mNeedsUpdate = true;
}

/**
 * Address: 0x006E8820 (FUN_006E8820, Moho::CUnitCommand::SetTarget)
 *
 * What it does:
 * Replaces command target payload, republishes serialized target data, emits
 * one command-event broadcast, and marks command state dirty.
 */
void CUnitCommand::SetTarget(const CAiTarget& target)
{
  mTarget = target;
  mTarget.EncodeToSSTITarget(mVarDat.mTarget1);
  BroadcastEvent(static_cast<ECommandEvent>(0));
  mNeedsUpdate = true;
}

/**
  * Alias of FUN_005BF810 (non-canonical helper lane).
 *
 * What it does:
 * Compatibility forwarder for legacy callsites that still dispatch the recon
 * blip refresh slot through `CUnitCommand`.
 */
void CUnitCommand::RefreshBlipState()
{
  auto* const blip = reinterpret_cast<ReconBlip*>(this);
  if (!blip) {
    return;
  }

  blip->Refresh();
}

/**
 * Address: 0x006E8140 (FUN_006E8140, Moho::CUnitCommand::dtr)
 *
 * What it does:
 * Executes `CUnitCommand` teardown and conditionally frees storage when
 * `deleteFlag & 1` is set.
 */
CScriptObject* CUnitCommand::DestroyWithDeleteFlag(CScriptObject* const object, const std::uint8_t deleteFlag)
{
  auto* const command = reinterpret_cast<CUnitCommand*>(object);
  if (!command) {
    return object;
  }

  command->DestroyInternal();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(command);
  }
  return object;
}

/**
 * Address: 0x006E8500 (FUN_006E8500)
 *
 * What it does:
 * Performs CUnitCommand teardown: unlinks intrusive nodes, releases
 * coordinating-order/formation references, clears command-unit vectors, and
 * resets command-owned transient payload storage.
 */
void CUnitCommand::DestroyInternal()
{
  auto& runtime = *reinterpret_cast<CUnitCommandDestroyRuntimeView*>(this);

  // +0x158/+0x15C: intrusive weak-owner link pair used by command sidecar ownership.
  auto& sidecarLink = runtime.sidecarOwnerChainNode;
  Entity* const sidecarEntity = sidecarLink.GetObjectPtr();
  if (sidecarEntity) {
    sidecarEntity->Destroy();
    sidecarLink.UnlinkFromOwnerChain();
    sidecarLink.ClearLinkState();
  }

  mArgs = LuaPlus::LuaObject{};

  // +0x148..+0x154: coordinating-order vector storage (8-byte owner-link elements).
  mCoordinatingOrders = msvc8::vector<WeakPtr<CUnitCommand>>{};

  // +0x120 list node mirrors binary helper 0x0057D490 unlink shape.
  runtime.coordinatingOrdersOwnerChainNode.UnlinkFromOwnerChain();

  // +0x118 intrusive-refcounted formation object.
  ReleaseIntrusiveRefcountedObject(runtime.formationObject);

  // +0x0F8 command unit-set vector payload.
  mUnitSet.mVec = gpg::core::FastVector<CScriptObject*>{};
  runtime.unitSetOwnerChainNode.UnlinkFromOwnerChain();

  // +0x0068 legacy msvc8::string payload in constant command data.
  mConstDat.unk2 = msvc8::string{};

  // +0x0034 broadcaster/list base slice.
  runtime.broadcasterOwnerChainNode.UnlinkFromOwnerChain();
}

/**
 * Address: 0x006E8DC0 (FUN_006E8DC0)
 *
 * What it does:
 * Rebuilds published command-event membership from the live command-unit set
 * and toggles publish state for empty/non-empty results.
 */
void CUnitCommand::RefreshPublishedCommandEvent(const bool forceRefresh, SSyncData* const syncData)
{
  if (!mNeedsUpdate && !forceRefresh) {
    return;
  }

  mNeedsUpdate = false;
  auto& publishedUnitEntityIds = mVarDat.mEntIds;

  if (mUnitSet.mVec.empty()) {
    if (mHasPublishedCommandEvent) {
      if (syncData) {
        syncData->QueuePendingCommandEventRemoval(mConstDat.cmd);
      }
      mHasPublishedCommandEvent = false;
    }

    // Empty live-unit set follows the binary delete-slot path from 0x006E8E39.
    DestroyInternal();
    return;
  }

  publishedUnitEntityIds = msvc8::vector<EntId>{};
  for (CScriptObject* const entry : mUnitSet.mVec) {
    if (!IsUsableCommandUnitEntry(entry)) {
      continue;
    }

    Unit* const unit = SCommandUnitSet::UnitFromEntry(entry);
    if (!unit || unit->mVisibilityState == 0u) {
      continue;
    }

    publishedUnitEntityIds.push_back(unit->id_);
  }

  if (publishedUnitEntityIds.empty()) {
    if (mHasPublishedCommandEvent) {
      if (syncData) {
        syncData->QueuePendingCommandEventRemoval(mConstDat.cmd);
      }
      mHasPublishedCommandEvent = false;
    }
    return;
  }

  if (!mHasPublishedCommandEvent) {
    if (syncData) {
      SSTICommandConstantData descriptor{};
      CopyPublishedCommandDescriptor(descriptor, mConstDat);
      AppendPublishedCommandDescriptor(syncData->mPublishedCommandDescriptors, descriptor);
    }
    mHasPublishedCommandEvent = true;
  }

  if (syncData) {
    const SSyncPublishedCommandPacket packet = BuildPublishedCommandPacket(mConstDat.cmd, mVarDat);
    AppendPublishedCommandPacket(syncData->mPublishedCommandPackets, packet);
  }
}

/**
 * Address: 0x006E9000 (FUN_006E9000)
 *
 * What it does:
 * Adds a one-way coordinating-order link from this command to `other` when
 * command types are compatible.
 */
void CUnitCommand::CoordinateWith(CUnitCommand* const other)
{
  if (!other) {
    return;
  }

  if (other->mVarDat.mCmdType != mVarDat.mCmdType) {
    return;
  }

  auto*& ownerSlotHead = reinterpret_cast<CommandOwnerSlotNode*&>(this->Broadcaster::mNext);
  CommandOwnerSlotNode temp{};
  temp.ownerLinkSlot = &ownerSlotHead;
  temp.nextInOwner = ownerSlotHead;
  ownerSlotHead = &temp;

  auto& coordinatingOrders = other->mCoordinatingOrders;
  coordinatingOrders.push_back(temp);
  temp.UnlinkFromOwnerChain();
}

/**
 * Address: 0x0128E638 (FUN_0128E638, SimGetCommandQueueInsert)
 *
 * What it does:
 * Builds one command-queue Lua row from `command` and appends it to
 * `queueArray`.
 */
void moho::SimGetCommandQueueInsert(LuaPlus::LuaObject& queueArray, const CUnitCommand& command)
{
  LuaPlus::LuaState* const state = queueArray.GetActiveState();
  if (!state) {
    return;
  }

  LuaPlus::LuaObject row(state);
  row.AssignNewTable(state, 0, 0);

  SetCommandQueueField<std::int32_t>(row, kCommandTypeKey, static_cast<std::int32_t>(command.mVarDat.mCmdType));
  SetCommandQueueField<float>(row, kXKey, command.mVarDat.mTarget1.mPos.x);
  SetCommandQueueField<float>(row, kYKey, command.mVarDat.mTarget1.mPos.y);
  SetCommandQueueField<float>(row, kZKey, command.mVarDat.mTarget1.mPos.z);

  const std::uint32_t targetEntityId = command.mVarDat.mTarget1.mEntityId;
  if (targetEntityId != kNoTargetEntityId) {
    char targetIdText[0x10] = {};
    std::snprintf(targetIdText, sizeof(targetIdText), "%d", static_cast<std::int32_t>(targetEntityId));
    SetCommandQueueField<const char*>(row, kTargetIdKey, targetIdText);
  }

  if (const char* const blueprintId = ResolveBlueprintId(command)) {
    SetCommandQueueField<const char*>(row, kBlueprintIdKey, blueprintId);
  }

  queueArray.SetObject(queueArray.GetN() + 1, row);
}
