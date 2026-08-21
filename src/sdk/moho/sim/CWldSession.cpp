#include "CWldSession.h"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/FastVectorInsertLanes.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "moho/audio/IUserSoundManager.h"
#include "moho/containers/BVIntSet.h"
#include "moho/containers/BVSet.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/entity/REntityBlueprintTypeInfo.h"
#include "moho/entity/UserEntity.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/animation/CAniPose.h"
#include "moho/mesh/Mesh.h"
#include "moho/lua/SCR_Color.h"
#include "moho/lua/SCR_String.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/command/CommandManager.h"
#include "moho/command/SSTICommandConstantData.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/IClientManager.h"
#include "moho/net/IClientMgrUIInterface.h"
#include "moho/resource/RResId.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/camera/VTransform.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/IResources.h"
#include "moho/resource/ResourceDeposit.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "gpg/core/streams/BinaryReader.h"
#include "moho/console/CConCommand.h"
#include "lua/LuaTableIterator.h"
#include "moho/sim/CArmyLuaFunctionRegistrations.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/EGenericIconTypeTypeInfo.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/net/CGpgNetInterface.h"
#include "moho/sim/SDesyncInfo.h"
#include "moho/misc/TimeBar.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/render/RCamManager.h"
#include "moho/terrain/splat/CWldSplat.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/CFormation.h"
#include "moho/sim/CWldSessionLoaderImpl.h"
#include "moho/client/Localization.h"
#include "moho/misc/SessionStartup.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/ui/EMauiKeyCodeTypeInfo.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/ESTITargetTypeTypeInfo.h"
#include "moho/sim/UserArmy.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "moho/ui/CUIManager.h"
#include "moho/unit/core/EFireStateTypeInfo.h"
#include "moho/unit/core/IUnit.h"
#include "moho/ui/IUIManager.h"
#include "moho/unit/core/UserUnit.h"
#include "moho/command/CommandIssueHelper.h"
#include "moho/task/CTask.h"
#include "moho/task/CTaskThread.h"
#include "moho/task/ScrDiskWatcherTask.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  static_assert(sizeof(moho::WeakObject::WeakLinkNodeView) == 0x8, "WeakLinkNodeView size must be 0x8");

  struct FormationPreviewSharedPairRuntimeView
  {
    boost::shared_ptr<void> primaryRuntime;
    boost::shared_ptr<void> secondaryRuntime;
  };
  static_assert(
    sizeof(FormationPreviewSharedPairRuntimeView) == 0x10,
    "FormationPreviewSharedPairRuntimeView size must be 0x10"
  );

  FormationPreviewSharedPairRuntimeView* gFormationPreviewSharedPairsBegin = nullptr;
  FormationPreviewSharedPairRuntimeView* gFormationPreviewSharedPairsEnd = nullptr;
  std::uintptr_t gFormationPreviewSharedPairsOwnerLane = 0u;

  // `StrategicIconAuxView` (the real type) and `gStrategicIconAuxiliary`
  // live in the `moho`-scoped anonymous namespace alongside the type's
  // definition (see `CWldSession::RenderStrategicIcons`'s callee cluster) -
  // a plain forward declaration here would name an unrelated, permanently
  // incomplete type in *this* (global-scope) anonymous namespace instead.

  std::uintptr_t gStrategicIconScratchOwnerLane = 0u;
  std::uint32_t* gStrategicIconScratchDataLane = nullptr;
  std::uint32_t gStrategicIconScratchCountLane = 0u;

  struct StrategicIconScratchTreeNodeRuntimeView
  {
    StrategicIconScratchTreeNodeRuntimeView* mLeft;   // +0x0000
    StrategicIconScratchTreeNodeRuntimeView* mParent; // +0x0004
    StrategicIconScratchTreeNodeRuntimeView* mRight;  // +0x0008
    std::byte mPayload[0x0C3C];                       // +0x000C
    std::uint8_t mColor;                              // +0x0C48
    std::uint8_t mIsSentinel;                         // +0x0C49
  };
  static_assert(
    offsetof(StrategicIconScratchTreeNodeRuntimeView, mColor) == 0x0C48,
    "StrategicIconScratchTreeNodeRuntimeView::mColor offset must be 0x0C48"
  );
  static_assert(
    offsetof(StrategicIconScratchTreeNodeRuntimeView, mIsSentinel) == 0x0C49,
    "StrategicIconScratchTreeNodeRuntimeView::mIsSentinel offset must be 0x0C49"
  );

  template <typename TNode>
  [[nodiscard]] TNode* RotateRuntimeTreeLeft(TNode* const pivot, TNode* const treeHead) noexcept
  {
    TNode* const promoted = pivot->mRight;
    pivot->mRight = promoted->mLeft;
    if (pivot->mRight->mIsSentinel == 0u) {
      pivot->mRight->mParent = pivot;
    }

    promoted->mParent = pivot->mParent;
    if (pivot == treeHead->mParent) {
      treeHead->mParent = promoted;
    } else {
      TNode* const parent = pivot->mParent;
      if (pivot == parent->mLeft) {
        parent->mLeft = promoted;
      } else {
        parent->mRight = promoted;
      }
    }

    promoted->mLeft = pivot;
    pivot->mParent = promoted;
    return promoted;
  }

  template <typename TNode>
  [[nodiscard]] TNode* RotateRuntimeTreeRight(TNode* const pivot, TNode* const treeHead) noexcept
  {
    TNode* const promoted = pivot->mLeft;
    pivot->mLeft = promoted->mRight;
    if (pivot->mLeft->mIsSentinel == 0u) {
      pivot->mLeft->mParent = pivot;
    }

    promoted->mParent = pivot->mParent;
    if (pivot == treeHead->mParent) {
      treeHead->mParent = promoted;
    } else {
      TNode* const parent = pivot->mParent;
      if (pivot == parent->mRight) {
        parent->mRight = promoted;
      } else {
        parent->mLeft = promoted;
      }
    }

    promoted->mRight = pivot;
    pivot->mParent = promoted;
    return promoted;
  }

  struct ListenerLinkRuntimeView final
  {
    ListenerLinkRuntimeView* mPrev; // +0x00
    ListenerLinkRuntimeView* mNext; // +0x04
  };
  static_assert(sizeof(ListenerLinkRuntimeView) == 0x08, "ListenerLinkRuntimeView size must be 0x08");

  class SelectionEventListenerRuntimeLane final
  {
  public:
    SelectionEventListenerRuntimeLane() noexcept
      : mLink{&mLink, &mLink}
    {}

    virtual ~SelectionEventListenerRuntimeLane() = default;
    virtual void OnEvent() noexcept {}

  public:
    ListenerLinkRuntimeView mLink; // +0x04
  };
  static_assert(sizeof(SelectionEventListenerRuntimeLane) == 0x0C, "SelectionEventListenerRuntimeLane size must be 0x0C");

  class PauseEventListenerRuntimeLane final
  {
  public:
    PauseEventListenerRuntimeLane() noexcept
      : mLink{&mLink, &mLink}
    {}

    virtual ~PauseEventListenerRuntimeLane() = default;
    virtual void OnEvent() noexcept {}

  public:
    ListenerLinkRuntimeView mLink; // +0x04
  };
  static_assert(sizeof(PauseEventListenerRuntimeLane) == 0x0C, "PauseEventListenerRuntimeLane size must be 0x0C");

  /**
   * Address: 0x0085A070 (FUN_0085A070)
   *
   * What it does:
   * Stores the current formation-preview shared-pair begin pointer lane into
   * `outValue` and returns that output slot.
   */
  [[nodiscard]] std::uintptr_t* StoreFormationPreviewSharedPairsBeginLane(
    std::uintptr_t* const outValue
  ) noexcept
  {
    *outValue = reinterpret_cast<std::uintptr_t>(gFormationPreviewSharedPairsBegin);
    return outValue;
  }

  /**
   * Address: 0x0085A080 (FUN_0085A080)
   *
   * What it does:
   * Stores the current formation-preview shared-pair end pointer lane into
   * `outValue` and returns that output slot.
   */
  [[nodiscard]] std::uintptr_t* StoreFormationPreviewSharedPairsEndLane(
    std::uintptr_t* const outValue
  ) noexcept
  {
    *outValue = reinterpret_cast<std::uintptr_t>(gFormationPreviewSharedPairsEnd);
    return outValue;
  }

  /**
   * Address: 0x0085A090 (FUN_0085A090)
   *
   * What it does:
   * Returns the active element count in the formation-preview shared-pair lane
   * (`end - begin`), or zero when storage has not been allocated.
   */
  [[nodiscard]] std::int32_t GetFormationPreviewSharedPairCountLane() noexcept
  {
    if (gFormationPreviewSharedPairsBegin == nullptr) {
      return 0;
    }

    return static_cast<std::int32_t>(gFormationPreviewSharedPairsEnd - gFormationPreviewSharedPairsBegin);
  }

  /**
   * Address: 0x0085A280 (FUN_0085A280)
   *
   * What it does:
   * Returns the formation-preview shared-pair owner lane slot.
   */
  [[nodiscard]] void* GetFormationPreviewSharedPairsOwnerLanePrimary(const int /*unused*/) noexcept
  {
    return &gFormationPreviewSharedPairsOwnerLane;
  }

  /**
   * Address: 0x0085A630 (FUN_0085A630)
   *
   * What it does:
   * Secondary entrypoint returning the formation-preview shared-pair owner lane.
   */
  [[nodiscard]] void* GetFormationPreviewSharedPairsOwnerLaneSecondary() noexcept
  {
    return &gFormationPreviewSharedPairsOwnerLane;
  }

  /**
   * Address: 0x00860F90 (FUN_00860F90)
   *
   * What it does:
   * Reads one dword through the strategic-icon scratch data-pointer lane and
   * stores it into `outValue`.
   */
  [[nodiscard]] std::uint32_t* StoreStrategicIconScratchValueLane(
    std::uint32_t* const outValue
  ) noexcept
  {
    *outValue = *gStrategicIconScratchDataLane;
    return outValue;
  }

  /**
   * Address: 0x00860FA0 (FUN_00860FA0)
   *
   * What it does:
   * Stores the strategic-icon scratch data-pointer lane itself into `outValue`.
   */
  [[nodiscard]] std::uintptr_t* StoreStrategicIconScratchDataPointerLane(
    std::uintptr_t* const outValue
  ) noexcept
  {
    *outValue = reinterpret_cast<std::uintptr_t>(gStrategicIconScratchDataLane);
    return outValue;
  }

  /**
   * Address: 0x00861650 (FUN_00861650)
   *
   * What it does:
   * Returns the current strategic-icon scratch data-pointer lane.
   */
  [[nodiscard]] std::uintptr_t GetStrategicIconScratchDataPointerLaneValue() noexcept
  {
    return reinterpret_cast<std::uintptr_t>(gStrategicIconScratchDataLane);
  }

  /**
   * Address: 0x00861660 (FUN_00861660, sub_861660)
   *
   * What it does:
   * Performs one left rotation in the strategic-icon scratch red-black tree
   * lane (nil marker at `+0x0C49`).
   */
  [[nodiscard]] StrategicIconScratchTreeNodeRuntimeView* RotateStrategicIconScratchTreeLeft(
    StrategicIconScratchTreeNodeRuntimeView* const pivot
  ) noexcept
  {
    auto* const treeHead = reinterpret_cast<StrategicIconScratchTreeNodeRuntimeView*>(
      GetStrategicIconScratchDataPointerLaneValue()
    );
    return RotateRuntimeTreeLeft(pivot, treeHead);
  }

  /**
   * Address: 0x00861710 (FUN_00861710, sub_861710)
   *
   * What it does:
   * Performs one right rotation in the strategic-icon scratch red-black tree
   * lane (nil marker at `+0x0C49`).
   */
  [[nodiscard]] StrategicIconScratchTreeNodeRuntimeView* RotateStrategicIconScratchTreeRight(
    StrategicIconScratchTreeNodeRuntimeView* const pivot
  ) noexcept
  {
    auto* const treeHead = reinterpret_cast<StrategicIconScratchTreeNodeRuntimeView*>(
      GetStrategicIconScratchDataPointerLaneValue()
    );
    return RotateRuntimeTreeRight(pivot, treeHead);
  }

  /**
   * Address: 0x00861920 (FUN_00861920)
   *
   * What it does:
   * Returns the current strategic-icon scratch count lane.
   */
  [[nodiscard]] std::uint32_t GetStrategicIconScratchCountLaneValue() noexcept
  {
    return gStrategicIconScratchCountLane;
  }

  /**
   * Address: 0x00861CA0 (FUN_00861CA0)
   *
   * What it does:
   * Returns the strategic-icon scratch owner lane slot.
   */
  [[nodiscard]] void* GetStrategicIconScratchOwnerLaneEntryA(const int /*unused*/) noexcept
  {
    return &gStrategicIconScratchOwnerLane;
  }

  /**
   * Address: 0x00861EB0 (FUN_00861EB0)
   *
   * What it does:
   * Secondary entrypoint returning the strategic-icon scratch owner lane slot.
   */
  [[nodiscard]] void* GetStrategicIconScratchOwnerLaneEntryB(const int /*unused*/) noexcept
  {
    return &gStrategicIconScratchOwnerLane;
  }

  /**
   * Address: 0x00861F60 (FUN_00861F60)
   *
   * What it does:
   * Third entrypoint returning the strategic-icon scratch owner lane slot.
   */
  [[nodiscard]] void* GetStrategicIconScratchOwnerLaneEntryC(const int /*unused*/) noexcept
  {
    return &gStrategicIconScratchOwnerLane;
  }

  /**
   * Address: 0x00862080 (FUN_00862080)
   *
   * What it does:
   * Fourth entrypoint returning the strategic-icon scratch owner lane slot.
   */
  [[nodiscard]] void* GetStrategicIconScratchOwnerLaneEntryD(const int /*unused*/) noexcept
  {
    return &gStrategicIconScratchOwnerLane;
  }

  /**
   * Address: 0x00865710 (FUN_00865710)
   *
   * What it does:
   * Initializes one selection-event listener lane by self-linking its
   * intrusive broadcaster node.
   */
  [[nodiscard]] SelectionEventListenerRuntimeLane* InitializeSelectionEventListenerLane(
    SelectionEventListenerRuntimeLane* const listener
  ) noexcept
  {
    return ::new (listener) SelectionEventListenerRuntimeLane();
  }

  /**
   * Address: 0x00869800 (FUN_00869800)
   *
   * What it does:
   * Initializes one pause-event listener lane by self-linking its intrusive
   * broadcaster node.
   */
  [[nodiscard]] PauseEventListenerRuntimeLane* InitializePauseEventListenerLane(
    PauseEventListenerRuntimeLane* const listener
  ) noexcept
  {
    return ::new (listener) PauseEventListenerRuntimeLane();
  }

  struct SessionSaveDataSerializerHelperRuntimeView
  {
    void* mVTable;                          // +0x00
    gpg::SerHelperBase* mHelperNext;        // +0x04
    gpg::SerHelperBase* mHelperPrev;        // +0x08
    gpg::RType::load_func_t mLoadCallback;  // +0x0C
    gpg::RType::save_func_t mSaveCallback;  // +0x10
  };
  static_assert(
    offsetof(SessionSaveDataSerializerHelperRuntimeView, mHelperNext) == 0x04,
    "SessionSaveDataSerializerHelperRuntimeView::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SessionSaveDataSerializerHelperRuntimeView, mHelperPrev) == 0x08,
    "SessionSaveDataSerializerHelperRuntimeView::mHelperPrev offset must be 0x08"
  );
  static_assert(sizeof(SessionSaveDataSerializerHelperRuntimeView) == 0x14, "SessionSaveDataSerializerHelperRuntimeView size must be 0x14");

  SessionSaveDataSerializerHelperRuntimeView gSessionSaveDataSerializer{};

  [[nodiscard]] gpg::SerHelperBase* SessionSaveDataSerializerSelfNode() noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&gSessionSaveDataSerializer.mHelperNext);
  }

  [[nodiscard]] gpg::RType* ResolveSessionSaveNodeMapArchiveType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::SSessionSaveNodeMap));
    }
    return cached;
  }

  void InitializeSessionSaveDataSerializerHelperNode() noexcept
  {
    gpg::SerHelperBase* const self = SessionSaveDataSerializerSelfNode();
    gSessionSaveDataSerializer.mHelperNext = self;
    gSessionSaveDataSerializer.mHelperPrev = self;
    gSessionSaveDataSerializer.mLoadCallback = nullptr;
    gSessionSaveDataSerializer.mSaveCallback = nullptr;
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkSessionSaveDataSerializerHelperNode() noexcept
  {
    gSessionSaveDataSerializer.mHelperNext->mPrev = gSessionSaveDataSerializer.mHelperPrev;
    gSessionSaveDataSerializer.mHelperPrev->mNext = gSessionSaveDataSerializer.mHelperNext;

    gpg::SerHelperBase* const self = SessionSaveDataSerializerSelfNode();
    gSessionSaveDataSerializer.mHelperPrev = self;
    gSessionSaveDataSerializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00897470 (FUN_00897470, Moho::SSessionSaveDataSerializer::Deserialize)
   *
   * What it does:
   * Deserializes one reflected `SSessionSaveNodeMap` lane from archive input.
   */
  void DeserializeSessionSaveDataSerializerCallback(
    gpg::ReadArchive* const archive,
    void* const payload,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || payload == nullptr) {
      return;
    }

    gpg::RType* const mapType = ResolveSessionSaveNodeMapArchiveType();
    if (mapType == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(mapType, payload, ownerRef != nullptr ? *ownerRef : nullOwner);
  }

  /**
   * Address: 0x008974B0 (FUN_008974B0, Moho::SSessionSaveDataSerializer::Serialize)
   *
   * What it does:
   * Serializes one reflected `SSessionSaveNodeMap` lane to archive output.
   */
  void SerializeSessionSaveDataSerializerCallback(
    gpg::WriteArchive* const archive,
    void* const payload,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || payload == nullptr) {
      return;
    }

    gpg::RType* const mapType = ResolveSessionSaveNodeMapArchiveType();
    if (mapType == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(mapType, payload, ownerRef != nullptr ? *ownerRef : nullOwner);
  }

  /**
   * Address: 0x008974F0 (FUN_008974F0)
   *
   * What it does:
   * Initializes startup `SSessionSaveDataSerializer` helper links and binds
   * deserialize/serialize callback lanes.
   */
  [[nodiscard]] SessionSaveDataSerializerHelperRuntimeView* InitializeSessionSaveDataSerializerHelperStorage() noexcept
  {
    InitializeSessionSaveDataSerializerHelperNode();
    gSessionSaveDataSerializer.mLoadCallback =
      reinterpret_cast<gpg::RType::load_func_t>(&DeserializeSessionSaveDataSerializerCallback);
    gSessionSaveDataSerializer.mSaveCallback =
      reinterpret_cast<gpg::RType::save_func_t>(&SerializeSessionSaveDataSerializerCallback);
    return &gSessionSaveDataSerializer;
  }

  struct SessionSaveDataSerializerBootstrap
  {
    SessionSaveDataSerializerBootstrap()
    {
      (void)InitializeSessionSaveDataSerializerHelperStorage();
    }
  };

  SessionSaveDataSerializerBootstrap gSessionSaveDataSerializerBootstrap;

  /**
   * Address: 0x00897520 (FUN_00897520)
   *
   * What it does:
   * Unlinks `SSessionSaveDataSerializer` helper node from the intrusive helper
   * list, rewires self-links, and returns the helper self node.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkSessionSaveDataSerializerHelperPrimary() noexcept
  {
    return UnlinkSessionSaveDataSerializerHelperNode();
  }

  /**
   * Address: 0x00897550 (FUN_00897550)
   *
   * What it does:
   * Secondary entrypoint for `SSessionSaveDataSerializer` helper-node
   * intrusive unlink + self-link reset.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkSessionSaveDataSerializerHelperSecondary() noexcept
  {
    return UnlinkSessionSaveDataSerializerHelperNode();
  }

  /**
   * Address: 0x00859E90 (FUN_00859E90)
   *
   * What it does:
   * Releases one formation-preview shared-pair payload by dropping both
   * retained shared ownership lanes.
   */
  void ReleaseFormationPreviewSharedPairRuntime(
    FormationPreviewSharedPairRuntimeView* const sharedPair
  ) noexcept
  {
    if (sharedPair == nullptr) {
      return;
    }

    sharedPair->secondaryRuntime.~shared_ptr();
    sharedPair->primaryRuntime.~shared_ptr();
  }

  /**
   * Address: 0x0085A1D0 (FUN_0085A1D0)
   *
   * What it does:
   * Releases every formation-preview shared-pair payload in one contiguous
   * range `[beginPair, endPair)`.
   */
  void ReleaseFormationPreviewSharedPairRangeForward(
    FormationPreviewSharedPairRuntimeView* const beginPair,
    FormationPreviewSharedPairRuntimeView* const endPair
  ) noexcept
  {
    for (FormationPreviewSharedPairRuntimeView* cursor = beginPair; cursor != endPair; ++cursor) {
      ReleaseFormationPreviewSharedPairRuntime(cursor);
    }
  }

  /**
   * What it does:
   * Move-assigns one formation-preview shared-pair entry from `src` to `dst`.
   * Inlined from FUN_0085A9F0: copies `primaryRuntime` by bumping its use-count
   * atomically, calls `weak_release` on the previous `dst.secondaryRuntime`
   * slot before overwriting, then byte-copies the vtable and back-pointer lanes
   * that follow the shared-pair header so the destination observes the exact
   * same owner graph as the source.
   */
  void AssignFormationPreviewSharedPairSlotRuntime(
    FormationPreviewSharedPairRuntimeView* const dst,
    FormationPreviewSharedPairRuntimeView* const src
  ) noexcept
  {
    if (dst == nullptr || src == nullptr) {
      return;
    }

    dst->primaryRuntime = src->primaryRuntime;
    dst->secondaryRuntime = src->secondaryRuntime;
  }

  /**
   * Address: 0x0085A130 (FUN_0085A130)
   *
   * IDA signature:
   * int *__stdcall sub_85A130(int *outFirst, int *first, int *last);
   *
   * What it does:
   * Erases the contiguous slice `[first, last)` from the global formation-
   * preview shared-pair vector (`0x010C425C..0x010C4260`) using the classic
   * `std::vector::erase` shape:
   *   1) Slide `[last, gEnd)` forward into `[first, ...)` via per-slot shared
   *      assignment (FUN_0085A9F0), producing a new end at `first + (gEnd - last)`.
   *   2) Destroy each retired entry in `[new_end, old_gEnd)` via the
   *      shared-pair payload teardown helper (FUN_00859E90).
   *   3) Rebind the global end to `new_end` and return the erase origin
   *      through `*outFirst` so callers can resume iteration.
   */
  FormationPreviewSharedPairRuntimeView** EraseFormationPreviewSharedPairRange(
    FormationPreviewSharedPairRuntimeView** const outFirstIterator,
    FormationPreviewSharedPairRuntimeView* const first,
    FormationPreviewSharedPairRuntimeView* const last
  ) noexcept
  {
    if (first != last) {
      FormationPreviewSharedPairRuntimeView* source = last;
      FormationPreviewSharedPairRuntimeView* destination = first;

      // Step 1: shift the tail `[last, gEnd)` down onto `[first, ...)`.
      FormationPreviewSharedPairRuntimeView* originalEnd = gFormationPreviewSharedPairsEnd;
      if (source != originalEnd) {
        do {
          AssignFormationPreviewSharedPairSlotRuntime(destination, source);
          ++source;
          ++destination;
        } while (source != originalEnd);
        originalEnd = gFormationPreviewSharedPairsEnd;
      }

      // Step 2: destroy retired entries `[new_end, old_gEnd)`.
      FormationPreviewSharedPairRuntimeView* const newEnd = destination;
      for (FormationPreviewSharedPairRuntimeView* cursor = newEnd; cursor != originalEnd; ++cursor) {
        ReleaseFormationPreviewSharedPairRuntime(cursor);
      }

      // Step 3: rebind the global end to the new end.
      gFormationPreviewSharedPairsEnd = newEnd;
    }

    if (outFirstIterator != nullptr) {
      *outFirstIterator = first;
    }
    return outFirstIterator;
  }

  /**
   * Address: 0x00859FE0 (FUN_00859FE0)
   *
   * What it does:
   * Releases one tail entry from the formation-preview shared-pair container
   * (`0x010C425C..0x010C4260`) and rewinds the active end pointer.
   */
  std::uintptr_t ReleaseOneFormationPreviewSharedPairFromTailRuntime() noexcept
  {
    std::uintptr_t result = 0u;
    if (gFormationPreviewSharedPairsBegin == nullptr) {
      return result;
    }

    result = reinterpret_cast<std::uintptr_t>(gFormationPreviewSharedPairsEnd);
    if (gFormationPreviewSharedPairsEnd > gFormationPreviewSharedPairsBegin) {
      FormationPreviewSharedPairRuntimeView* const tailEntry = gFormationPreviewSharedPairsEnd - 1;
      ReleaseFormationPreviewSharedPairRuntime(tailEntry);
      gFormationPreviewSharedPairsEnd = tailEntry;
      result = reinterpret_cast<std::uintptr_t>(tailEntry);
    }
    return result;
  }

  void LinkCursorInfoWeakOwnerRef(moho::MouseInfo& info) noexcept
  {
    moho::WeakObject::WeakLinkNodeView* const self =
      reinterpret_cast<moho::WeakObject::WeakLinkNodeView*>(&info.mUnitHover);
    if (self->ownerLinkSlot == nullptr) {
      self->nextInOwner = nullptr;
      return;
    }

    auto** const ownerLinkSlot = reinterpret_cast<moho::WeakObject::WeakLinkNodeView**>(self->ownerLinkSlot);
    self->nextInOwner = *ownerLinkSlot;
    *ownerLinkSlot = self;
  }

  void UnlinkCursorInfoWeakOwnerRef(moho::MouseInfo& info) noexcept
  {
    moho::WeakObject::WeakLinkNodeView* const self =
      reinterpret_cast<moho::WeakObject::WeakLinkNodeView*>(&info.mUnitHover);
    moho::WeakObject::WeakLinkNodeView** cursor =
      reinterpret_cast<moho::WeakObject::WeakLinkNodeView**>(self->ownerLinkSlot);
    if (cursor == nullptr) {
      return;
    }

    while (*cursor != nullptr && *cursor != self) {
      cursor = &((*cursor)->nextInOwner);
    }

    if (*cursor == self) {
      *cursor = self->nextInOwner;
    }
  }

} // namespace

// Defined at file scope (global namespace, external linkage) in
// CrtRuntimeHelpers.cpp - shared by every legacy VC8 "<container> too long"
// throw lane in that file. Forward-declared here rather than duplicated so
// UICommandGraph's own hash-table growth guard (CheckedIncrementListSize) can
// reuse the identical message/exception construction instead of re-emitting it
// inline a second time. The bucket vector's own overflow lane (FUN_00830620)
// is msvc8::vector<void*>::throw_too_long and is cited there.
[[noreturn]] void RuntimeThrowContainerTooLong(const char* message);

namespace moho
{
  // Beat-scoped console toggles, defined in `moho/misc/RuntimeTuningGlobals.cpp`.
  extern bool ren_FogOfWar;
  extern bool dbg_Metronome;
  extern bool wld_RunWithTheWind;

  /// Lazily-bound engine-stat handles. `DoBeat` publishes how many units it
  /// ticked; `SessionFrame` publishes how many beats the drain consumed.
  StatItem* sEngineStat_UserSync_SessionTick_NumTickers = nullptr;
  StatItem* sEngineStat_Sync_Count = nullptr;

  /**
   * Address: 0x0089AEC0 (FUN_0089AEC0, boost::shared_ptr_SSessionSaveData::shared_ptr_SSessionSaveData)
   *
   * What it does:
   * Constructs one `shared_ptr<SSessionSaveData>` from one raw save-data
   * pointer lane.
   */
  boost::shared_ptr<SSessionSaveData>* ConstructSharedSessionSaveDataFromRaw(
    boost::shared_ptr<SSessionSaveData>* const outSaveData,
    SSessionSaveData* const saveData
  )
  {
    return ::new (outSaveData) boost::shared_ptr<SSessionSaveData>(saveData);
  }

  MouseInfo::MouseInfo()
    : mHitValid(0u)
    , pad_01{0u, 0u, 0u}
    , mMouseWorldPos(0.0f, 0.0f, 0.0f)
    , mUnitHover(nullptr)
    , mPrevious(nullptr)
    , mIsDragger(-1)
    , mMouseScreenPos(0.0f, 0.0f)
  {}

  /**
   * Address: 0x0081CF00 (FUN_0081CF00, ??0UICursorInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Copy-constructs cursor info and relinks weak hovered-unit ownership to this instance.
   */
  MouseInfo::MouseInfo(const MouseInfo& other)
  {
    mHitValid = other.mHitValid;
    mMouseWorldPos = other.mMouseWorldPos;
    mUnitHover = other.mUnitHover;
    LinkCursorInfoWeakOwnerRef(*this);

    mIsDragger = other.mIsDragger;
    mMouseScreenPos = other.mMouseScreenPos;
  }

  /**
   * Address: 0x00893140 (FUN_00893140, ??1UICursorInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Unlinks this cursor info from the hovered-unit weak-owner chain.
   */
  MouseInfo::~MouseInfo()
  {
    UnlinkCursorInfoWeakOwnerRef(*this);
  }

  /**
   * Address: 0x0082B270 (FUN_0082B270, Moho::UICursorInfo::Copy)
   *
   * What it does:
   * Assigns cursor info and updates hovered-unit weak-owner chain links.
   */
  MouseInfo& MouseInfo::operator=(const MouseInfo& other)
  {
    mHitValid = other.mHitValid;
    mMouseWorldPos = other.mMouseWorldPos;

    if (other.mUnitHover != mUnitHover) {
      if (mUnitHover != nullptr) {
        UnlinkCursorInfoWeakOwnerRef(*this);
      }

      mUnitHover = other.mUnitHover;
      LinkCursorInfoWeakOwnerRef(*this);
      if (mUnitHover != nullptr) {
        mIsDragger = other.mIsDragger;
        mMouseScreenPos = other.mMouseScreenPos;
        return *this;
      }
    }

    mIsDragger = other.mIsDragger;
    mMouseScreenPos = other.mMouseScreenPos;
    return *this;
  }

  /**
   * Address: 0x0081F6C0 (FUN_0081F6C0, ??0SCommandModeData@Moho@@QAE@@Z)
   *
   * What it does:
   * Copy-constructs command mode state, including both cursor snapshots.
   */
  CommandModeData::CommandModeData(const CommandModeData& other)
    : mMode(other.mMode)
    , mCommandCaps(other.mCommandCaps)
    , mBlueprint(other.mBlueprint)
    , mMouseDragStart(other.mMouseDragStart)
    , mMouseDragEnd(other.mMouseDragEnd)
    , mModifiers(other.mModifiers)
    , mIsDragged(other.mIsDragged)
    , mReserved5C(other.mReserved5C)
  {}

  /**
   * Address: 0x0081CEA0 (FUN_0081CEA0)
   * Address: 0x0081F760 (FUN_0081F760, sub_81F760)
   * Address: 0x0081FC80 (FUN_0081FC80, sub_81FC80)
   *
   * What it does:
   * Initializes command mode from one cursor snapshot and one modifier lane:
   * clears mode/caps/blueprint, copy-constructs drag-start, resets drag-end,
   * and sets both trailing sentinel lanes to `-1`.
   *
   * All three addresses are the same constructor. Byte-comparing the three
   * `.asm` bodies shows one identical instruction sequence - same field order,
   * same `xorps`/`or eax,-1` idioms, same `MouseInfo` copy-ctor call at
   * `this+0x0C` - differing only in the relative displacement of that call and
   * in the epilogue (`retn` at 0x0081F760, `retn 4` at 0x0081CEA0 and
   * 0x0081FC80, i.e. whether the call site or the callee pops the single
   * `modifiers` word). 0x0081F760 and 0x0081FC80 are the two call-site-
   * specialised emissions `Moho::CUIWorldView::HandleEvent` uses: 0x0081FC80
   * from its wheel-rotation arm (0x008708CD) and 0x0081F760 from its
   * middle-button-press arm (0x00870B29). Those two natural `CommandModeData
   * mode(cursorInfo, eventData.mModifiers);` declarations in
   * moho/ui/UiRuntimeTypes.cpp are the recovery of both.
   */
  CommandModeData::CommandModeData(const MouseInfo& mouseInfo, const int modifiers)
    : mMode(COMMOD_None)
    , mCommandCaps(RULEUCC_None)
    , mBlueprint(nullptr)
    , mMouseDragStart(mouseInfo)
    , mMouseDragEnd()
    , mModifiers(modifiers)
    , mIsDragged(-1)
    , mReserved5C(-1)
  {
    mMouseDragEnd.mHitValid = 0u;
    mMouseDragEnd.mMouseWorldPos = Wm3::Vector3f(0.0f, 0.0f, 0.0f);
    mMouseDragEnd.mUnitHover = nullptr;
    mMouseDragEnd.mPrevious = nullptr;
    mMouseDragEnd.mIsDragger = -1;
    mMouseDragEnd.mMouseScreenPos = Wm3::Vector2f(0.0f, 0.0f);
  }

  /**
   * Address: 0x007EF070 (FUN_007EF070, ??1SCommandModeData@Moho@@QAE@XZ)
   *
   * What it does:
   * Destroys command-mode cursor snapshots and unlinks both hovered-unit
   * weak-owner lanes.
   */
  CommandModeData::~CommandModeData() = default;

  /**
   * Address: 0x0082B230 (FUN_0082B230, ??0SCommandModeData@Moho@@QAE@@Z_0)
   *
   * What it does:
   * Assigns command mode state from another value and copies both cursor-info
   * lanes via `MouseInfo::operator=`.
   */
  CommandModeData& CommandModeData::operator=(const CommandModeData& other)
  {
    mMode = other.mMode;
    mCommandCaps = other.mCommandCaps;
    mBlueprint = other.mBlueprint;
    mMouseDragStart = other.mMouseDragStart;
    mMouseDragEnd = other.mMouseDragEnd;
    mModifiers = other.mModifiers;
    mIsDragged = other.mIsDragged;
    mReserved5C = other.mReserved5C;
    return *this;
  }
} // namespace moho

namespace gpg
{
  class RMultiMapType_EntId_string : public RType
  {
  public:
    /**
     * Address: 0x0089B4C0 (FUN_0089B4C0, gpg::RMultiMapType_EntId_string::dtr)
     */
    ~RMultiMapType_EntId_string() override = default;

    /**
     * Address: 0x00899120 (FUN_00899120, gpg::RMultiMapType_EntId_string::Init)
     *
     * What it does:
     * Sets multimap size/version metadata and binds load/save serializers for
     * `multimap<EntId,std::string>`.
     */
    void Init() override;

    /**
     * Address: 0x00899060 (FUN_00899060, gpg::RMultiMapType_EntId_string::GetName)
     *
     * What it does:
     * Returns the cached lexical label for the reflected
     * `multimap<EntId,std::string>` lane.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00899140 (FUN_00899140, gpg::RMultiMapType_EntId_string::GetLexical)
     *
     * What it does:
     * Formats inherited lexical text and appends current multimap element count.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
  };
} // namespace gpg

namespace
{
  msvc8::string gEntIdStringMultiMapTypeName;
  std::uint32_t gEntIdStringMultiMapTypeNameInitGuard = 0;
  gpg::RType* gEntIdStringMultiMapKeyType = nullptr;
  gpg::RType* gEntIdStringMultiMapValueType = nullptr;
  using EntIdStringMultiMap = std::multimap<moho::EntId, msvc8::string>;

  [[nodiscard]] gpg::RType* ResolveEntIdTypeForMultiMapName()
  {
    if (gEntIdStringMultiMapKeyType == nullptr) {
      constexpr const char* kTypeNames[] = {
        "EntId",
        "Moho::EntId",
        "int",
        "signed int",
      };

      for (const char* const typeName : kTypeNames) {
        if (gpg::RType* const resolved = gpg::REF_FindTypeNamed(typeName); resolved != nullptr) {
          gEntIdStringMultiMapKeyType = resolved;
          break;
        }
      }

      if (gEntIdStringMultiMapKeyType == nullptr) {
        gEntIdStringMultiMapKeyType = gpg::LookupRType(typeid(std::int32_t));
      }
    }

    return gEntIdStringMultiMapKeyType;
  }

  [[nodiscard]] gpg::RType* ResolveStringTypeForMultiMapName()
  {
    if (gEntIdStringMultiMapValueType == nullptr) {
      constexpr const char* kTypeNames[] = {
        "std::string",
        "msvc8::string",
        "string",
      };

      for (const char* const typeName : kTypeNames) {
        if (gpg::RType* const resolved = gpg::REF_FindTypeNamed(typeName); resolved != nullptr) {
          gEntIdStringMultiMapValueType = resolved;
          break;
        }
      }

      if (gEntIdStringMultiMapValueType == nullptr) {
        gEntIdStringMultiMapValueType = gpg::LookupRType(typeid(msvc8::string));
      }
    }

    return gEntIdStringMultiMapValueType;
  }

  [[nodiscard]] gpg::RType* ResolveEntIdArchiveType()
  {
    gpg::RType* const resolved = ResolveEntIdTypeForMultiMapName();
    if (resolved != nullptr) {
      return resolved;
    }
    return gpg::LookupRType(typeid(moho::EntId));
  }

  /**
   * Address: 0x008999A0 (FUN_008999A0)
   *
   * What it does:
   * Clears destination multimap storage and then loads serialized
   * `(EntId, string)` pairs in archive order.
   */
  void DeserializeEntIdStringMultiMap(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    auto* const destination = reinterpret_cast<EntIdStringMultiMap*>(static_cast<std::uintptr_t>(objectPtr));
    unsigned int count = 0u;
    archive->ReadUInt(&count);

    destination->clear();
    gpg::RType* const entIdType = ResolveEntIdArchiveType();

    for (unsigned int index = 0u; index < count; ++index) {
      moho::EntId key = 0;
      archive->Read(entIdType, &key, *ownerRef);

      msvc8::string value{};
      archive->ReadString(&value);

      destination->insert(std::make_pair(key, value));
    }
  }

  /**
   * Address: 0x00899B20 (FUN_00899B20)
   *
   * What it does:
   * Writes multimap element count and serializes each `(EntId, string)` pair
   * in key-order.
   */
  void SerializeEntIdStringMultiMap(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr) {
      return;
    }

    const auto* const source = reinterpret_cast<const EntIdStringMultiMap*>(static_cast<std::uintptr_t>(objectPtr));
    const unsigned int count = source != nullptr ? static_cast<unsigned int>(source->size()) : 0u;
    archive->WriteUInt(count);
    if (source == nullptr) {
      return;
    }

    gpg::RType* const entIdType = ResolveEntIdArchiveType();

    for (const auto& entry : *source) {
      archive->Write(entIdType, &entry.first, *ownerRef);
      msvc8::string value = entry.second;
      archive->WriteString(&value);
    }
  }

  /**
   * Address: 0x00C082E0 (FUN_00C082E0, cleanup_RMultiMapType_EntId_string_Name)
   *
   * What it does:
   * Releases cached lexical storage for
   * `gpg::RMultiMapType_EntId_string::GetName`.
   */
  void cleanup_RMultiMapType_EntId_string_Name()
  {
    gEntIdStringMultiMapTypeName.clear();
    gEntIdStringMultiMapTypeNameInitGuard = 0;
  }
} // namespace

/**
 * Address: 0x00899120 (FUN_00899120, gpg::RMultiMapType_EntId_string::Init)
 *
 * What it does:
 * Sets multimap size/version metadata and binds load/save serializers for
 * `multimap<EntId,std::string>`.
 */
void gpg::RMultiMapType_EntId_string::Init()
{
  size_ = 0x0C;
  version_ = 1;
  serSaveFunc_ = &SerializeEntIdStringMultiMap;
  serLoadFunc_ = &DeserializeEntIdStringMultiMap;
}

/**
 * Address: 0x00899060 (FUN_00899060, gpg::RMultiMapType_EntId_string::GetName)
 *
 * What it does:
 * Lazily builds and caches one reflection label for the
 * `multimap<EntId,std::string>` lane.
 */
const char* gpg::RMultiMapType_EntId_string::GetName() const
{
  if ((gEntIdStringMultiMapTypeNameInitGuard & 1u) == 0u) {
    gEntIdStringMultiMapTypeNameInitGuard |= 1u;

    const gpg::RType* const keyType = ResolveEntIdTypeForMultiMapName();
    const gpg::RType* const valueType = ResolveStringTypeForMultiMapName();
    const char* const keyName = keyType != nullptr ? keyType->GetName() : "EntId";
    const char* const valueName = valueType != nullptr ? valueType->GetName() : "std::string";

    gEntIdStringMultiMapTypeName = gpg::STR_Printf("multimap<%s,%s>", keyName, valueName);
    (void)std::atexit(&cleanup_RMultiMapType_EntId_string_Name);
  }

  return gEntIdStringMultiMapTypeName.c_str();
}

/**
 * Address: 0x00899140 (FUN_00899140, gpg::RMultiMapType_EntId_string::GetLexical)
 *
 * What it does:
 * Formats inherited lexical text and appends current multimap element count.
 */
msvc8::string gpg::RMultiMapType_EntId_string::GetLexical(const gpg::RRef& ref) const
{
  struct MultiMapRuntimeView
  {
    void* allocProxy;
    void* head;
    std::uint32_t size;
  };

  const msvc8::string base = gpg::RType::GetLexical(ref);
  const auto* const map = static_cast<const MultiMapRuntimeView*>(ref.mObj);
  const int size = map ? static_cast<int>(map->size) : 0;
  return gpg::STR_Printf("%s, size=%d", base.c_str(), size);
}

/**
 * Address: 0x0089B460 (FUN_0089B460, preregister_RMultiMapType_EntId_string)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for
 * `std::multimap<moho::EntId,msvc8::string>`.
 */
[[nodiscard]] gpg::RType* preregister_RMultiMapType_EntId_string()
{
  static gpg::RMultiMapType_EntId_string typeInfo;
  gpg::PreRegisterRType(typeid(EntIdStringMultiMap), &typeInfo);
  return &typeInfo;
}

// Forward declaration: this symbol is referenced by the linker at global
// scope (not inside namespace moho), so its definition stays at global scope
// near the end of this file - but `DrawPathPreview` (namespace moho, below)
// needs to call it ahead of that point.
moho::CommandModeData* func_GetRightMouseButtonAction(
  moho::CommandModeData* out, moho::MouseInfo* mouseInfo, int modifiers, moho::CWldSession* wldSession);

namespace moho
{
  // Address lanes:
  // - 0x010A645D (`ui_DebugAltClick`)
  // - 0x010A645E (`UI_SelectAnything`)
  // Recovered as process-global convar-backed toggles used by selection paths.
  bool ui_DebugAltClick = false;
  bool UI_SelectAnything = false;

  // Command-waypoint drawing parameters; see the declarations in CWldSession.h
  // for the per-symbol addresses. All seven are zero at image load and stay so
  // until `UICommandGraph::LoadWaypointParams` imports them.
  std::int32_t ui_CurveSegments = 0;           // 0x00F57CC0

  // Projectile strategic-icon CVars. None of these existed in the tree; the
  // addresses come from the store/compare operands in FUN_008621B0.
  float UI_StrategicProjectileLOD = 0.0f;   // 0x00F57B20
  // 0x00F57A8E holds 0x01 in bin/2025.7.1/ForgedAlliance.exe's .data, so the
  // resource splats are on unless a console command turns them off.
  bool UI_RenResources = true;              // 0x00F57A8E
  bool UI_RenProjectileIcons = false;       // 0x00F57A8F
  bool UI_RenProjectileGlow = false;        // 0x00F57B24
  bool UI_forceWeaponsToYellow = false;     // 0x00F57B25
  float UI_RenProjectileGlowMin = 0.0f;     // 0x00F57B28
  float UI_RenProjectileGlowMax = 0.0f;     // 0x00F57B2C
  float UI_RenProjectileGlowPeriod = 0.0f;  // 0x00F57B30
  float UI_CurGlowTime = 0.0f;              // 0x010A6460

  // Read once per deposit by `CWldSession::RenderResources` (0x00862E68). The
  // 75 is the shipped value: `bin/2025.7.1/ForgedAlliance.exe` holds
  // 0x42960000 at 0x00F57B08, and `func_UI_ResourceLODCutoff_ConVarDef`
  // (0x00BE6010) only binds the console variable to this same storage.
  float UI_ResourceLODCutoff = 75.0f;       // 0x00F57B08

  // Strategic-icon and unit-bar console variables. None of these existed in
  // the tree; every address below is the absolute operand of the instruction
  // that reads it, taken from the `.asm` of the five functions that make up
  // the strategic-icon pass (0x0085B6E0, 0x0085CD40, 0x0085D9A0, 0x0085E0A0,
  // 0x0085E3A0). All ship zeroed - the console/UI layer writes them.
  bool ui_RenderUnitBars = false;                 // 0x00F57B26 (0x0085BFDB)
  bool ui_RenderIcons = false;                    // 0x00F57B27 (0x0085C0B1)
  float ui_lifebarHeight = 0.0f;                  // 0x00F57B6C (0x0085CDCB)
  float ui_LifebarWidth = 0.0f;                   // 0x00F57B70 (0x0085CDB6)
  float ui_LifebarLOD = 0.0f;                     // 0x00F57B74 (0x0085BFE8)
  float ui_LifebarOffset = 0.0f;                  // 0x00F57B78 (0x0085CECE)
  bool ui_NisRenderIcons = false;                 // 0x00F57B7C (0x0085C0A4)
  bool ui_RenderCustomNames = false;              // 0x00F57B7D (0x0085E0BE)
  bool ui_RenderSelectionSetNames = false;        // 0x00F57B7E (0x0085E3BE)
  std::uint32_t ui_CustomNameColor = 0u;          // 0x00F57B80 (0x0085E2ED)
  std::int32_t ui_CustomNameFontSize = 0;         // 0x00F57B84 (0x0085E145)
  std::uint32_t ui_SelectionSetNamesColor = 0u;   // 0x00F57B88 (0x0085E72A)
  float ui_StrategicIconBlinkRate = 0.0f;         // 0x00F57B8C (0x0085DC44)
  float ui_FuelEmptyBlinkRate = 0.0f;             // 0x00F57B90 (0x0085D113)
  float ui_StrategicIconBlinkDuration = 0.0f;     // 0x00F57B94 (0x0085DC22)
  std::uint32_t ui_LifeBarGoodColor = 0u;         // 0x00F57B98 (0x0085D070)
  std::uint32_t ui_LifeBarMedColor = 0u;          // 0x00F57B9C (0x0085D085)
  std::uint32_t ui_LifeBarBadColor = 0u;          // 0x00F57BA0 (0x0085D065)
  float ui_LifeBarGoodCutoff = 0.0f;              // 0x00F57BA4 (0x0085D05E)
  float ui_LifeBarBadCutoff = 0.0f;               // 0x00F57BA8 (0x0085D07C)
  std::uint32_t ui_FuelBarColor = 0u;             // 0x00F57BAC (0x0085D0EE)
  std::uint32_t ui_FuelWarningColor = 0u;         // 0x00F57BB0 (0x0085D135)
  std::uint32_t ui_ShieldBarColor = 0u;           // 0x00F57BB4 (0x0085D0DA)
  std::uint32_t ui_ProgressBarColor = 0u;         // 0x00F57BB8 (0x0085D14B)
  msvc8::string ui_CustomNameFont{};              // 0x00F5B300 (0x0085E124)
  bool ui_ForceLifbarsOnEnemy = false;            // 0x010A644A (0x0085C031)
  bool ui_AlwaysRenderStrategicIcons = false;     // 0x010A644B (0x0085C148)
  // 0x010A6443 lies past ForgedAlliance.exe's raw .data (zero-filled BSS tail),
  // so the path-preview overlay ships off.
  bool ui_DrawPathPreview = false;          // 0x010A6443
  bool ui_PathPreview = false;              // 0x010A6448

  // Entity ids carry their family in the top nibble; 0x1_______ is a projectile.
  constexpr std::uint32_t kEntityFamilyMask = 0xF0000000u;
  constexpr std::uint32_t kEntityFamilyProjectile = 0x10000000u;
  constexpr std::uint32_t kProjectileIconColor = 0xFFFFFFFFu;
  constexpr std::uint32_t kProjectileForcedColor = 0xFFFFFF00u;
  constexpr const char* kProjectileIconTechnique = "TAlphaBlendLinearSampleNoDepth";
  // 0x008624F2 masks the layer with 6 - seabed | sub - to pick the recon grid.
  constexpr std::int32_t kLayerUnderwaterMask = LAYER_Seabed | LAYER_Sub;


  float ui_CurveSmoothness = 0.0f;             // 0x00F57CC4
  float ui_PathSmoothness = 0.0f;              // 0x00F57CC8
  float ui_MaxTextLOD = 0.0f;                  // 0x00F57CCC
  std::int32_t ui_CommandGraphMaxNodeUnits = 0; // 0x00F57CD0
  float ui_MinWaypointSize = 0.0f;             // 0x00F57CD4
  float ui_MaxWaypointSize = 0.0f;             // 0x00F57CD8
  float ui_WaypointLineScale = 0.0f;           // 0x00F57CDC

  struct UICommandGraphNode
  {
    boost::SharedPtrRaw<void> mOrderlineTexture{}; // +0x00 (shared `(px,pi)` pair)
    float mOrderlineAspectRatio = 0.0f;            // +0x08
    float mOrderlineAnimRate = 0.0f;               // +0x0C
    std::uint32_t mOrderlineColor = 0;             // +0x10
    std::uint32_t mOrderlineSelectedColor = 0;     // +0x14
    std::uint32_t mOrderlineHighlightColor = 0;    // +0x18
    float mOrderlineGlow = 0.0f;                   // +0x1C
    float mOrderlineSelectedGlow = 0.0f;           // +0x20
    float mOrderlineHighlightGlow = 0.0f;          // +0x24
    std::uint32_t mWaypointColor = 0;              // +0x28
    std::uint32_t mWaypointSelectedColor = 0;      // +0x2C
    std::uint32_t mWaypointHighlightColor = 0;     // +0x30
    float mWaypointScale = 0.0f;                   // +0x34
    float mWaypointSelectedScale = 0.0f;           // +0x38
    float mWaypointHighlightScale = 0.0f;          // +0x3C
    float mArrowheadCapOffset = 0.0f;              // +0x40
    boost::SharedPtrRaw<void> mWaypointTexture{};  // +0x44 (shared `(px,pi)` pair)
    boost::SharedPtrRaw<void> mArrowheadTexture{}; // +0x4C (shared `(px,pi)` pair)

    /**
     * Address: 0x008243F0 (FUN_008243F0, ??0UICommandGraphNode@Moho@@QAE@@Z)
     * Mangled: ??0UICommandGraphNode@Moho@@QAE@@Z
     *
     * What it does:
     * Initializes one command-graph node style payload with default
     * orderline/waypoint scales and cleared texture shared pointers.
     */
    UICommandGraphNode();

    /**
     * Address: 0x008249B0 (FUN_008249B0, ??1UICommandGraphNode@Moho@@QAE@@Z)
     * Mangled: ??1UICommandGraphNode@Moho@@QAE@@Z
     *
     * What it does:
     * Releases command-graph texture shared-control lanes in arrowhead,
     * waypoint, then orderline teardown order.
     */
    ~UICommandGraphNode();

    /**
     * Address: 0x00825060 (FUN_00825060, Moho::UICommandGraphNode::cpy)
     *
     * What it does:
     * Copies one command-graph style node payload, including shared-texture
     * control lanes for orderline/waypoint/arrowhead textures. Each lane is a
     * strong retain-then-release rebind through FUN_004229B0
     * (`sp_counted_base::release()`, see BoostWrappers.h) - see the definition
     * for the 2026-08-20 audit note.
     */
    UICommandGraphNode* CopyFrom(const UICommandGraphNode& other);

    /**
     * Address: 0x00825570 (FUN_00825570)
     * Mangled: ?LoadTextures@UICommandGraphNode@Moho@@QAEXPAVLuaObject@LuaPlus@@PBDPAVLuaState@3@@Z
     *
     * What it does:
     * Loads command-graph texture/style lanes from one Lua table entry, honoring
     * `inherit_from` recursion before overriding local orderline/waypoint/
     * arrowhead keys.
     */
    void LoadTextures(LuaPlus::LuaObject rootTable, const char* key, LuaPlus::LuaState* state);
  };

  static_assert(sizeof(UICommandGraphNode) == 0x54, "UICommandGraphNode size must be 0x54");
  static_assert(offsetof(UICommandGraphNode, mWaypointTexture) == 0x44, "UICommandGraphNode::mWaypointTexture offset must be 0x44");
  static_assert(offsetof(UICommandGraphNode, mArrowheadTexture) == 0x4C, "UICommandGraphNode::mArrowheadTexture offset must be 0x4C");

  class UICommandGraph
  {
  public:
    friend class CWldSession;

    /**
     * Its real caller (`sub_829190`) always passes `this` explicitly - see
     * `DrawPathPreview`'s own doc comment in CWldSession.h for why the IDA
     * decompile's declared first parameter is misleading here.
     */
    friend void DrawPathPreview(
      UICommandGraph& graph, const GeomCamera3& camera, CD3DPrimBatcher& batcher, std::int32_t tick,
      float tickFraction
    );

    /**
     * `func_ProcessCommandDrag` (0x00829B40, `UICommandDragger::DragMove`/
     * `DragRelease`'s worker in UiRuntimeTypes.cpp) needs `mSession` and
     * `mMapAB0` plus the hash primitives below.
     */
    friend void ProcessCommandDrag(
      const Wm3::Vector3f& mouse, UICommandGraph& graph, CmdId cmdId, bool released
    );

    /**
     * Address: 0x00824810 (FUN_00824810, ??0UICommandGraph@Moho@@QAE@@Z)
     *
     * What it does:
     * Builds command-graph caches, map/index containers, debug font handle,
     * and synchronizes command-graph UI visibility in Lua.
     */
    explicit UICommandGraph(CWldSession* session);

    /**
     * Address: 0x00824B80 (FUN_00824B80, ??1UICommandGraph@Moho@@QAE@XZ) cleanup chain.
     */
    ~UICommandGraph();

  public:
    using CommandGraphNode = UICommandGraphNode;

    template <std::size_t kNodeSize>
    struct HashListNode
    {
      HashListNode* mNext;
      HashListNode* mPrev;
      std::uint8_t mPayload[kNodeSize - 8];
    };

    using HashListNode2C = HashListNode<0x2C>;
    using HashListNode10 = HashListNode<0x10>;

    /**
     * Head of the intrusive chain of graph nodes that reference one command.
     * This is a view onto the first field of the engine's per-command issue
     * helper: 0x00826140 stores `&node.mHelperLink` straight into the helper's
     * leading pointer, and every walk of the chain starts by dereferencing it.
     */
    struct CommandGraphHelperHead;

    /**
     * One node's membership in a command's chain. The chain is threaded
     * pointer-to-pointer: the helper's head points at a link, and each link's
     * `mNext` points at the following link, so unlinking only ever needs the
     * slot that currently refers to this link.
     */
    struct CommandGraphHelperLink
    {
      CommandGraphHelperHead* mHead; // +0x00
      CommandGraphHelperLink* mNext; // +0x04
    };

    struct CommandGraphHelperHead
    {
      CommandGraphHelperLink* mFirst; // +0x00
    };

    /**
     * One dword lane in the engine's four-pointer `gpg::fastvector` shape, with
     * inline storage for a single element.
     *
     * `mCapacity` points one past `mInline[0]` while the lane is inline. When
     * the grow helper spills the lane to the heap it stashes that inline
     * capacity-end *into* `mInline[0]` before overwriting `mBegin`
     * (0x0082E708: `if (begin == inlineOrigin) *inlineOrigin = capacity;`),
     * which is exactly what lets `ReleaseToInline` below restore the capacity
     * with one indirect load rather than recomputing it. `mInline[1]` is
     * reserved storage the constructor deliberately keeps outside the capacity.
     */
    struct CommandGraphDwordLane
    {
      std::uint32_t* mBegin;        // +0x00
      std::uint32_t* mEnd;          // +0x04
      std::uint32_t* mCapacity;     // +0x08
      std::uint32_t* mInlineOrigin; // +0x0C
      std::uint32_t mInline[2];     // +0x10

      void ReleaseToInline() noexcept
      {
        if (mBegin != mInlineOrigin) {
          ::operator delete[](mBegin);
          mBegin = mInlineOrigin;
          mCapacity = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(*mInlineOrigin));
        }
        mEnd = mBegin;
      }
    };

    /**
     * Payload of one command-graph hash node — the drawable record for a single
     * command. `mMapAB0` keys these by the issuing command, `mMapAB1` by the
     * head command of a queue, in which case `mPositionSum`/`mWeight` accumulate
     * across every unit sharing that queue so the graph can draw one node at
     * their centroid.
     *
     * This payload is *not* trivially destructible: it owns two heap-capable
     * dword lanes and one weak reference, which is why the binary's map-erase
     * paths call the destructor below before freeing the node.
     */
    struct UICommandGraphDrawNode
    {
      CmdId mCommandId;                    // +0x00
      CommandGraphHelperLink mHelperLink;  // +0x04
      Wm3::Vector3f mPositionSum;          // +0x0C
      float mWeight;                       // +0x18
      std::uint8_t mHasResolvedPosition;   // +0x1C
      std::uint8_t mIsChainBoundary;       // +0x1D
      std::uint8_t mIsVisible;             // +0x1E
      std::uint8_t pad_1F;                 // +0x1F
      /**
       * The node's drawable mesh, owned strongly. `sub_826550` decrements the
       * control block's *use* count at +0x04 and calls vtable slot 1 (dispose)
       * on last release, which is `release()` and not `weak_release()` — the
       * two differ by which counter they touch, so getting it wrong either
       * leaks the mesh or frees it early. 0x008282B0 / 0x00828DD0 read the same
       * lane back as a `MeshInstance*` to stance it at the node's anchor.
       */
      boost::SharedPtrRaw<MeshInstance> mMeshInstance; // +0x20
      /**
       * Orderline tangent override: 0x008288D0 reads this as one `Vector3f`
       * (previously mis-split as `field_0x28`(uint32)/`field_0x2C`/
       * `field_0x30`, three separate scalars - it is one 12-byte vector) and
       * uses it in place of the computed from/to tangent whenever it's
       * non-zero.
       */
      Wm3::Vector3f mOrientationHint;      // +0x28
      Wm3::Vector3f mPreviousCentroid;     // +0x34
      float field_0x40;                    // +0x40
      std::uint32_t field_0x44;            // +0x44
      CommandGraphDwordLane mLaneA;        // +0x48
      CommandGraphDwordLane mLaneB;        // +0x60

      /**
       * Address: 0x00826550 (FUN_00826550, sub_826550)
       *
       * What it does:
       * Releases both dword lanes back to inline storage (freeing any spilled
       * heap block), drops the weak owner reference, and unlinks the node from
       * its command's intrusive chain.
       */
      ~UICommandGraphDrawNode();
    };

    /**
     * The AB tables' node. Unlike the 0x2C and 0x10 tables this one carries a
     * non-trivial payload, so `ClearHashListNodes` runs `DestroyPayload` before
     * releasing the allocation — mirroring the binary's list-erase helper at
     * 0x0082EF80, which calls the payload destructor on `node + 0x10` and only
     * then frees the node.
     */
    struct HashListNode88
    {
      HashListNode88* mNext;          // +0x00
      HashListNode88* mPrev;          // +0x04
      std::uint32_t mKey;             // +0x08
      std::uint32_t mKeyHigh;         // +0x0C
      UICommandGraphDrawNode mDraw;   // +0x10

      static void DestroyPayload(HashListNode88* const node) noexcept
      {
        node->mDraw.~UICommandGraphDrawNode();
      }
    };

    // {_Alproxy, _Myfirst, _Mylast, _Myend} at +0x00/04/08/0C, 0x10 bytes --
    // this is msvc8::vector<void*>, not a distinct type.
    using HashBucketVector = msvc8::vector<void*>;

    template <typename TNode>
    struct HashTable
    {
      std::uint8_t mOwnerByte; // +0x00
      std::uint8_t pad_01[7];
      TNode* mListHead;           // +0x08
      std::uint32_t mListSize;    // +0x0C
      HashBucketVector mBuckets;  // +0x10
      std::uint32_t mBucketMask;  // +0x20
      std::uint32_t mBucketCount; // +0x24
    };

    struct CommandGraphTreeNode
    {
      CommandGraphTreeNode* mLeft;    // +0x00
      CommandGraphTreeNode* mParent;  // +0x04
      CommandGraphTreeNode* mRight;   // +0x08
      std::uint8_t mPayload[0x18];    // +0x0C
      std::uint8_t mColorOrAllocated; // +0x24
      std::uint8_t mIsSentinel;       // +0x25
      std::uint8_t pad_26[2];
    };

    struct CommandGraphTree
    {
      void* mAllocProxy;           // +0x00
      CommandGraphTreeNode* mHead; // +0x04
      std::uint32_t mSize;         // +0x08
    };

    /**
     * One drawn segment of a queued-order "orderline" - the ribbon connecting
     * two command-graph draw nodes. `mGraphRuntimeTree` buckets these by
     * texture: each tree node's `mPayload` holds a
     * `{boost::SharedPtrRaw<CD3DBatchTexture>, msvc8::vector<CommandGraphEdge*>}`
     * pair, and the render pass walks the bucket's vector once per texture.
     *
     * `mEdge` sits at offset +0x10 of the 0x2C-byte `HashListNode2C` that
     * owns it (`mNext@0/mPrev@4/mKeyLow@8/mKeyHigh@0xC/mEdge@0x10`), which
     * pins this struct's size at exactly 0x1C (0x2C - 0x10).
     */
    struct CommandGraphEdge
    {
      /**
       * Touch/visit refcount: 0x00826960 increments this by one every time
       * a queued order resolves to this (fromNode,toNode) edge, and reads
       * it back (clamped to `ui_CommandGraphMaxNodeUnits`) as the edge's
       * apparent unit weight in 0x008275B0's orientation-hint accumulation.
       */
      std::uint32_t mTouchCount{};          // +0x00, confirmed by FUN_00826960/FUN_008275B0
      float mBaseWidth{};                   // +0x04, confirmed by FUN_008288D0.c:85 and FUN_00826960
      UICommandGraphDrawNode* mFromNode{};  // +0x08
      UICommandGraphDrawNode* mToNode{};    // +0x0C
      /**
       * Per-lane bundle-spacing index, both written by 0x008275B0 as
       * `(loopIndex / max(laneCount - 1, 1)) - 0.5`: `mLaneBDistribution`
       * while walking `mFromNode->mLaneB` (this edge seen from its "from"
       * endpoint), `mLaneADistribution` while walking `mToNode->mLaneA`
       * (this edge seen from its "to" endpoint).
       */
      float mLaneBDistribution{};           // +0x10, confirmed by FUN_008275B0
      float mLaneADistribution{};           // +0x14, confirmed by FUN_008275B0
      /**
       * When set, 0x008288D0 skips `ResolveDrawNodeHighlightState` entirely
       * and draws this edge with the owning `CommandGraphNode`'s
       * mOrderlineHighlightColor/mOrderlineHighlightGlow directly - i.e. this
       * forces the "highlighted" style, it does not carry a per-edge custom
       * color (an earlier read of this struct assumed `+0x1C`/`+0x28` held a
       * per-edge override color/alpha; neither offset is actually read
       * anywhere in 0x008288D0, so that guess has been dropped).
       */
      bool mForceHighlightStyle{};           // +0x18
      std::uint8_t mUnknown19_1B[0x03]{};    // +0x19, unconfirmed - not touched by FUN_00826960/FUN_008275B0
    };

    static_assert(sizeof(CommandGraphEdge) == 0x1C, "CommandGraphEdge size must be 0x1C");
    static_assert(offsetof(CommandGraphEdge, mBaseWidth) == 0x04, "CommandGraphEdge::mBaseWidth offset must be 0x04");
    static_assert(offsetof(CommandGraphEdge, mFromNode) == 0x08, "CommandGraphEdge::mFromNode offset must be 0x08");
    static_assert(offsetof(CommandGraphEdge, mToNode) == 0x0C, "CommandGraphEdge::mToNode offset must be 0x0C");
    static_assert(offsetof(CommandGraphEdge, mLaneBDistribution) == 0x10, "CommandGraphEdge::mLaneBDistribution offset must be 0x10");
    static_assert(offsetof(CommandGraphEdge, mLaneADistribution) == 0x14, "CommandGraphEdge::mLaneADistribution offset must be 0x14");
    static_assert(offsetof(CommandGraphEdge, mForceHighlightStyle) == 0x18, "CommandGraphEdge::mForceHighlightStyle offset must be 0x18");

    /**
     * Typed view over `CommandGraphTreeNode::mPayload` - a texture-keyed
     * bucket of orderline edges. `mGraphRuntimeTree` is a real msvc8-shaped
     * red-black tree (matching `mColorOrAllocated`/`mIsSentinel` at the same
     * offsets a real `_Tree` node uses), so this reinterprets the 24-byte
     * payload rather than modeling the tree as a distinct container type.
     */
    struct CommandGraphTreeBucket
    {
      boost::SharedPtrRaw<CD3DBatchTexture> mTexture;   // +0x00
      msvc8::vector<CommandGraphEdge*> mEdges;          // +0x08
    };
    static_assert(sizeof(CommandGraphTreeBucket) == 0x18, "CommandGraphTreeBucket size must be 0x18");

    [[nodiscard]] static CommandGraphTreeBucket& BucketOf(CommandGraphTreeNode& node) noexcept
    {
      return *reinterpret_cast<CommandGraphTreeBucket*>(node.mPayload);
    }

    /**
     * Tri-state highlight the render pass picks a waypoint/orderline style
     * color and scale from - see `ResolveDrawNodeHighlightState`.
     */
    enum class ECommandNodeHighlightState : std::int32_t
    {
      Normal = 0,
      Highlighted = 1,
      Selected = 2,
    };

    /**
     * Address: 0x00828280 (FUN_00828280, sub_828280)
     *
     * IDA signature:
     * bool __userpurge sub_828280@<al>(int a1@<eax>, int a2);
     *
     * What it does:
     * The "selected" test `ResolveDrawNodeHighlightState` ends on: resolves the
     * draw node's owning command-issue helper, asks that helper for the entity
     * set the command is aimed at, and reports whether that set shares any live
     * entity with the session's current selection. A node with no owning helper
     * is never selected.
     *
     * Its own null-helper guard is kept even though the only caller has already
     * checked the same field - the binary re-tests it here.
     */
    [[nodiscard]] bool DrawNodeSharesLiveEntityWithSelection(const UICommandGraphDrawNode& drawNode) const;

    /**
     * Address: 0x008281E0 (FUN_008281E0, sub_8281E0)
     * Address: 0x00831110 (FUN_00831110, sub_831110) - now
     * `SSelectionSetUserEntity::HasCommonLiveEntityWith`
     *
     * What it does:
     * Picks the style state a command-graph draw node renders with this
     * frame: `Highlighted` when the cursor is hovering a unit the node's
     * command affects, or when the node's command is the session's
     * currently-interacting one; `Selected` when the node's affected-entity
     * set shares any live entity with the current selection; `Normal`
     * otherwise, and always `Normal` for a node with no owning command.
     *
     * The binary's `mIsDragger` comparison (0x00828249: `cmp ebx,[esi+18h]`)
     * reads `MouseInfo::mIsDragger` as a `CmdId`, not a boolean "currently
     * dragging" flag - it is genuinely the id of whichever command the
     * session is presently interacting with. Preserved as a raw field read
     * with this comment rather than renaming the widely-shared `MouseInfo`
     * field.
     */
    [[nodiscard]] ECommandNodeHighlightState
      ResolveDrawNodeHighlightState(const UICommandGraphDrawNode& drawNode) const;

  private:
    static void ReleaseIntrusive(CD3DFont*& font);
    static void AssignIntrusive(CD3DFont*& dst, CD3DFont* src);

    /**
     * Address: 0x0082F030 (FUN_0082F030)
     */
    static HashListNode88* AllocateMapABListSentinel();

    /**
     * Address: 0x0082F5B0 (FUN_0082F5B0)
     */
    static HashListNode2C* AllocateMapCListSentinel();

    /**
     * Address: 0x0082FAF0 (FUN_0082FAF0)
     */
    static HashListNode10* AllocateMapDListSentinel();

    /**
     * Address: 0x0082BF40 (FUN_0082BF40)
     */
    static void InitMapAB(HashTable<HashListNode88>& table, const UICommandGraph* owner);

    /**
     * Address: 0x0082C400 (FUN_0082C400)
     */
    static void InitMapC(HashTable<HashListNode2C>& table, const UICommandGraph* owner);

    /**
     * Address: 0x0082C8D0 (FUN_0082C8D0)
     */
    static void InitMapD(HashTable<HashListNode10>& table, const UICommandGraph* owner);

    /**
     * Address: 0x0082FAB0 (FUN_0082FAB0, MSVC8 std::list<T>::clear inline expansion)
     * Address: 0x0082C840 (FUN_0082C840, the HashListNode2C instantiation)
     *
     * What it does:
     * Clears one sentinel-headed hash-list in place without freeing the
     * sentinel head. Payload nodes are trivially destructible.
     */
    template <typename TNode>
    static void ClearHashListNodes(HashTable<TNode>& table) noexcept;

    template <typename TNode>
    static void DestroyMap(HashTable<TNode>& table);

    /**
     * The value portion of one HashListNode88 - everything after the
     * intrusive mNext/mPrev link header. ConstructHashListNode88
     * copy-constructs a new node's mKey/mDraw from one of these; the source
     * may be a real existing node's tail (during rehash relocation,
     * `&oldNode->mKey` overlays this exactly - the ctor-arg evidence at
     * 0x00830523) or a freestanding stack composite built for a fresh
     * insert (mMapAB0's insert-if-missing path, sub_82B300 at 0x0082B35C).
     *
     * mUnused04 mirrors HashListNode88::mKeyHigh's position but is never
     * read by any of mMapAB0's find/insert primitives recovered below -
     * only the low key dword participates in hashing/comparison, so this
     * field is left exactly as uninitialized as the binary leaves it
     * (0x00831D80 copies just the leading dword before delegating the tail
     * to the draw-node relocate at 0x0082D530).
     */
    struct HashListNode88Value
    {
      std::uint32_t mKey;             // +0x00
      std::uint32_t mUnused04;        // +0x04
      UICommandGraphDrawNode mDraw;   // +0x08
    };

    /**
     * Address: 0x0082D530 (FUN_0082D530, sub_82D530)
     * Address: 0x00826620 (FUN_00826620, the no-EH emission of this same body)
     *
     * What it does:
     * Relocate-copies one command-graph draw node's full payload: command
     * id, the intrusive command-issue helper chain link (re-publishing the
     * helper's head to point at `destination` in place of `source`),
     * position/weight/flag scalars, the owned mesh instance (retaining a
     * new strong reference on the shared control block rather than
     * transferring it, since `source` keeps its own reference until
     * destroyed separately), the orientation hint/previous-centroid/
     * reserved scalars, and both dword lanes. Used by the hash node
     * constructor below whenever a node is built from an existing node's
     * payload (rehash relocation) or a fresh stack value.
     */
    static UICommandGraphDrawNode* RelocateDrawNode(UICommandGraphDrawNode* destination, UICommandGraphDrawNode& source);

    /**
     * Address: 0x00831AB0 (FUN_00831AB0, sub_831AB0)
     *
     * What it does:
     * Overflow-checked `operator new` for `count` HashListNode88 (0x88-byte)
     * slots; throws `std::bad_alloc` when `count` would overflow the byte
     * count. Matches the legacy VC8 `std::_Allocate<T>` shape already used
     * throughout legacy/containers/Vector.h for other element sizes.
     */
    [[nodiscard]] static void* AllocateHashListNode88Storage(std::size_t count);

    /**
     * Address: 0x00831D80 (FUN_00831D80, sub_831D80)
     *
     * What it does:
     * Constructs one HashListNode88Value in place: copies the key dword,
     * then relocate-copies the draw-node payload via RelocateDrawNode.
     * `mUnused04` is left untouched, matching the binary exactly.
     */
    static HashListNode88Value* ConstructHashListNode88Value(HashListNode88Value* destination, HashListNode88Value& source);

    /**
     * Address: 0x008304D0 (FUN_008304D0, sub_8304D0)
     *
     * What it does:
     * Allocates one HashListNode88, links it explicitly via the caller-
     * supplied `next`/`prev` (the classic Dinkumware `_Buynode(_Next, _Prev,
     * _Val)` shape), then constructs its value portion from `valueSource`.
     * If construction throws, the raw node is freed before the exception
     * propagates (matches the binary's SEH cleanup funclet at 0x00830540).
     */
    [[nodiscard]] static HashListNode88* ConstructHashListNode88(
      HashListNode88* next, HashListNode88* prev, HashListNode88Value& valueSource
    );

    /**
     * Not a distinct binary function: the Park-Miller "minimal standard"
     * integer scramble (`ldiv(key ^ 0xDEADBEEF, 127773)` then
     * `16807*rem - 2836*quot`, wrapping negative results by `+0x7FFFFFFF`)
     * is inlined independently at every hash-table site below
     * (0x0082C240, 0x0082C2E0, 0x0082BFB0 x2) rather than shared in the
     * binary. Lifted into one named helper here per the intent-first
     * helper contract instead of duplicating the scramble four times.
     */
    [[nodiscard]] static std::uint32_t HashKeyToBucketIndex(const HashTable<HashListNode88>& table, std::uint32_t key) noexcept;

    /**
     * Address: 0x0082C240 (FUN_0082C240, sub_82C240)
     *
     * What it does:
     * Finds the node whose key exactly matches `key` within its hash
     * bucket, or returns the table's list sentinel (`mListHead`) when no
     * exact match exists - the same "not found" convention
     * InsertOrFindHashListNode88/FindOrInsertCommandGraphDrawNode use to
     * detect a miss.
     */
    [[nodiscard]] static HashListNode88* FindHashListNode88(HashTable<HashListNode88>& table, std::uint32_t key) noexcept;

    /**
     * Address: 0x0082C2E0 (FUN_0082C2E0, sub_82C2E0)
     *
     * What it does:
     * Returns the `[first, last)` equal-range of nodes matching `key`
     * within their hash bucket. An empty range collapses both ends to the
     * table's list sentinel (`mListHead`), matching the binary's fallback
     * (it reuses the sentinel rather than the bucket's own end pointer once
     * no match is found).
     */
    [[nodiscard]] static std::pair<HashListNode88*, HashListNode88*>
      EqualRangeHashListNode88(HashTable<HashListNode88>& table, std::uint32_t key) noexcept;

    /**
     * Address: 0x0082B450 (FUN_0082B450, sub_82B450)
     *
     * What it does:
     * Counts nodes matching `key` by walking EqualRangeHashListNode88's
     * `[first, last)` range one `mNext` step at a time.
     */
    [[nodiscard]] static std::uint32_t CountHashListNode88(HashTable<HashListNode88>& table, std::uint32_t key) noexcept;

    /**
     * Address: 0x0082F050 (FUN_0082F050, sub_82F050)
     *
     * What it does:
     * Adds `count` to `sizeField` after an overflow guard against the
     * legacy VC8 list max-size (0x1FFFFFF), throwing
     * `std::length_error("list<T> too long")` on overflow. Calls the same
     * shared throw lane as msvc8::vector<T>::throw_too_long.
     */
    static std::uint32_t CheckedIncrementListSize(std::uint32_t count, std::uint32_t& sizeField);

    /**
     * Address: 0x0082BFB0 (FUN_0082BFB0, sub_82BFB0)
     *
     * What it does:
     * `mMapAB0`'s hash-bucket insert lane: grows/rehashes one bucket at a
     * time when the load factor is exceeded, then finds-or-inserts `key`,
     * returning the existing node when found (`outInserted=false`) or a
     * freshly constructed node linked into its bucket and the table's
     * global list (`outInserted=true`, `mListSize` bumped via
     * CheckedIncrementListSize).
     */
    static HashListNode88*
      InsertOrFindHashListNode88(HashTable<HashListNode88>& table, HashListNode88Value& valueSource, bool& outInserted);

    /**
     * Address: 0x0082B300 (FUN_0082B300, sub_82B300)
     *
     * What it does:
     * `mMapAB0`'s public find-or-insert entry point: looks `key` up via
     * FindHashListNode88 first; on a miss, default-constructs a temporary
     * draw node payload (0x00824600), relocate-copies it into a second
     * temporary, and inserts a real node built from `{key, temporary}` via
     * InsertOrFindHashListNode88. Always returns a pointer to the resolved
     * node's draw-node payload (`&node->mDraw`).
     */
    [[nodiscard]] static UICommandGraphDrawNode*
      FindOrInsertCommandGraphDrawNode(std::uint32_t key, HashTable<HashListNode88>& table);

    /**
     * Address: 0x008300D0 (FUN_008300D0)
     */
    static CommandGraphTreeNode* AllocateTreeSentinelNode();

    static void InitTree(CommandGraphTree& tree);

    /**
     * Address: 0x0082BEE0 (FUN_0082BEE0, sub_82BEE0)
     *
     * What it does:
     * Frees one command-graph tree bucket's edge-pointer vector storage (if
     * spilled off the vector's inline/proxy state to a heap buffer) and
     * releases its owned batch-texture control block. Does not free the
     * owning tree node - callers do that immediately afterward. Before this
     * recovery pass, `DestroyTree`'s node-delete walk never called this,
     * leaking `mEdges`' heap buffer and the texture refcount on every
     * teardown (including the class destructor) - see the fix in
     * `DestroyTree` below.
     */
    static void ReleaseCommandGraphTreeBucket(CommandGraphTreeBucket& bucket) noexcept;

    /**
     * Not a distinct binary function - the post-order (right subtree, this
     * node, left subtree) node-destroy walk that 0x00824B50 (`DestroyTree`)
     * inlines in the binary (0x0082CDE0 is that copy; a second copy at
     * 0x00826000/`sub_826000` feeds the same release step into a
     * rebuild-reset path that is not yet recovered - see
     * `decomp/recovery/reports/by-source/src/sdk/moho/sim/CWldSession.cpp.reconstruction.md`).
     * Lifted into one shared helper here per the intent-first helper
     * contract instead of duplicating the walk.
     */
    static void DestroyCommandGraphTreeSubtree(CommandGraphTreeNode* sentinelHead, CommandGraphTreeNode* node);

    /**
     * Address: 0x00824B50 (FUN_00824B50, sub_824B50)
     *
     * What it does:
     * Destroys one command-graph runtime tree (nodes + head sentinel) and
     * clears head/size lanes. Releases each node's bucket resources
     * (texture refcount + edge-vector heap buffer) via
     * `ReleaseCommandGraphTreeBucket` before freeing the node.
     */
    static void DestroyTree(CommandGraphTree& tree);

    /**
     * Address: 0x00824740 (FUN_00824740, func_OnCommandGraphShow)
     */
    static void OnCommandGraphShow(LuaPlus::LuaState* state, bool visible);

    /**
     * Address: 0x00824D50 (FUN_00824D50, Moho::UICommandGraph::LoadPathParams)
     */
    void LoadPathParams();

    /**
     * Address: 0x00825150 (FUN_00825150, func_LoadCommandGraphWaypointParams)
     */
    static void LoadWaypointParams();

    /**
     * Address: 0x00828FB0 (FUN_00828FB0, Moho::UICommandGraph::CreateMeshes)
     */
    void CreateMeshes();

    void MarkDirty() noexcept
    {
      mNeedsRebuild = 1u;
    }

    /**
     * Address: 0x008282B0 (FUN_008282B0, sub_8282B0)
     *
     * What it does:
     * Draws one command node's waypoint marker quad: a flat square centered
     * on the node's averaged position, sized to a roughly-constant apparent
     * screen size via the camera's viewport perspective-width row, colored
     * and scaled by `ResolveDrawNodeHighlightState`.
     */
    void DrawWaypointMarker(const GeomCamera3& camera, CD3DPrimBatcher& batcher, UICommandGraphDrawNode& drawNode) const;

    /**
     * Address: 0x00828DD0 (FUN_00828DD0, sub_828DD0)
     *
     * What it does:
     * Poses the node's owned mesh instance at its resolved (or history-
     * resolved fallback) anchor and, when that anchor came from a real unit
     * blueprint, draws the unit's footprint skirt there too.
     */
    void DrawPositionNodeMesh(UICommandGraphDrawNode& drawNode, CD3DPrimBatcher& batcher) const;

    /**
     * Address: 0x00828610 (FUN_00828610, Moho::DisplayCommandNode)
     *
     * What it does:
     * Draws the "ETA: mm:ss" text label above one command-graph draw node.
     */
    void DisplayCommandNode(const GeomCamera3& camera, const UICommandGraphDrawNode& drawNode, CD3DPrimBatcher& batcher) const;

    /**
     * Address: 0x008288D0 (FUN_008288D0, sub_8288D0)
     *
     * What it does:
     * Draws one command-graph "orderline" ribbon segment between two draw
     * nodes' averaged positions.
     */
    void DrawCommandOrderline(
      const GeomCamera3& camera, CD3DPrimBatcher& batcher, std::int32_t tick, float tickFraction,
      const CommandGraphEdge& edge, bool isGlow
    ) const;

  public:
    /**
     * Address: 0x00829190 (FUN_00829190, sub_829190)
     *
     * What it does:
     * The per-frame command-graph render pass: draws every queued-order
     * orderline (opaque then glow, grouped by texture), every waypoint
     * marker, positions each node's anchored mesh/skirt, the path-preview
     * overlay, then switches to a screen-space projection and draws every
     * node's ETA text label.
     *
     * The `__userpurge` signature carries two more register arguments
     * (`CRenderWorldView*`, `boost::shared_ptr<UICommandGraph>&`) that its
     * caller (`sub_85AF40`) always supplies, but this function's own body
     * never dereferences either - confirmed against every callsite in its
     * disassembly. Dropped from this signature rather than kept unused.
     *
     * Public (unlike its `DrawWaypointMarker`/`DrawCommandOrderline`/etc.
     * siblings above, which are only ever called from here): its real caller
     * is `sub_85AF40`, outside this class - reached via
     * `DrawCommandGraphMeshIfPresent` (CWldSession.h) from
     * `CRenderWorldView::RenderCommandGraph`.
     */
    void DrawCommandGraphMesh(const GeomCamera3& camera, CD3DPrimBatcher& batcher, std::int32_t tick, float tickFraction);

    /**
     * Address: 0x00829800 (FUN_00829800, sub_829800)
     *
     * IDA signature:
     * float *__userpurge sub_829800@<eax>(Moho::GeomCamera3 *a1@<esi>,
     *   Moho::UICommandGraph *a2, _DWORD *a3, float *a4);
     *
     * What it does:
     * Per-frame cursor/waypoint hit test for the command graph: walks every
     * draw node in `mMapAB0`'s hash list, frustum-culls its averaged anchor
     * (`mPositionSum / mWeight`) against the camera's view solid, and for
     * every surviving node compares its projected screen position against
     * `cursorScreenPos` within a depth-scaled, `ui_MinWaypointSize`/
     * `ui_MaxWaypointSize`-clamped tolerance (`ui_WaypointLineScale` applied
     * on top - the decompiled read shows as `ui_CommandClickScale`, which is
     * not a real symbol; see `UICommandGraph::LoadPathParams`'s doc comment
     * on why both Lua keys resolve to `ui_WaypointLineScale`), the same
     * style knobs `DrawWaypointMarker` uses for the visible marker size).
     * Ferry-command nodes get a small (0.1) tolerance bonus,
     * matching the binary's dedicated `UNITCOMMAND_Ferry` branch. Among the
     * nodes within tolerance, the closest wins unless a farther node's
     * cursor-entity set already shares a live entity with the current
     * session selection, in which case that node preempts distance.
     *
     * Returns the winning node's command id, or -1 when none qualifies.
     */
    [[nodiscard]] CmdId ResolveCursorHighlightCommandId(
      const GeomCamera3& camera, const Wm3::Vector2f& cursorScreenPos
    ) const;

  private:
    std::uint8_t mNeedsRebuild; // +0x0000
    std::uint8_t pad_0001[3];
    CommandGraphNode mNodes[40];        // +0x0004
    CWldSession* mSession;              // +0x0D24
    void* mSessionRes1;                 // +0x0D28
    CD3DFont* mDebugFont;               // +0x0D2C
    HashTable<HashListNode88> mMapAB0;  // +0x0D30
    HashTable<HashListNode88> mMapAB1;  // +0x0D58
    HashTable<HashListNode2C> mMapC;    // +0x0D80
    HashTable<HashListNode10> mMapD;    // +0x0DA8
    CommandGraphTree mGraphRuntimeTree; // +0x0DD0
  };

  static_assert(sizeof(UICommandGraph::CommandGraphNode) == 0x54, "UICommandGraph::CommandGraphNode size must be 0x54");
  static_assert(sizeof(UICommandGraph::HashListNode88) == 0x88, "UICommandGraph::HashListNode88 size must be 0x88");
  static_assert(
    sizeof(UICommandGraph::CommandGraphDwordLane) == 0x18,
    "UICommandGraph::CommandGraphDwordLane size must be 0x18"
  );
  static_assert(
    sizeof(UICommandGraph::UICommandGraphDrawNode) == 0x78,
    "UICommandGraph::UICommandGraphDrawNode size must be 0x78"
  );
  static_assert(
    offsetof(UICommandGraph::HashListNode88, mDraw) == 0x10,
    "UICommandGraph::HashListNode88::mDraw offset must be 0x10"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mHelperLink) == 0x04,
    "UICommandGraphDrawNode::mHelperLink offset must be 0x04"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mPositionSum) == 0x0C,
    "UICommandGraphDrawNode::mPositionSum offset must be 0x0C"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mWeight) == 0x18,
    "UICommandGraphDrawNode::mWeight offset must be 0x18"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mMeshInstance) == 0x20,
    "UICommandGraphDrawNode::mMeshInstance offset must be 0x20"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mOrientationHint) == 0x28,
    "UICommandGraphDrawNode::mOrientationHint offset must be 0x28"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mPreviousCentroid) == 0x34,
    "UICommandGraphDrawNode::mPreviousCentroid offset must be 0x34"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mLaneA) == 0x48,
    "UICommandGraphDrawNode::mLaneA offset must be 0x48"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mLaneB) == 0x60,
    "UICommandGraphDrawNode::mLaneB offset must be 0x60"
  );
  static_assert(sizeof(UICommandGraph::HashListNode2C) == 0x2C, "UICommandGraph::HashListNode2C size must be 0x2C");
  static_assert(sizeof(UICommandGraph::HashListNode10) == 0x10, "UICommandGraph::HashListNode10 size must be 0x10");
  static_assert(sizeof(UICommandGraph::HashBucketVector) == 0x10, "UICommandGraph::HashBucketVector size must be 0x10");
  static_assert(
    sizeof(UICommandGraph::HashTable<UICommandGraph::HashListNode88>) == 0x28,
    "UICommandGraph::HashTable size must be 0x28"
  );
  static_assert(
    sizeof(UICommandGraph::CommandGraphTreeNode) == 0x28, "UICommandGraph::CommandGraphTreeNode size must be 0x28"
  );
  static_assert(sizeof(UICommandGraph::CommandGraphTree) == 0x0C, "UICommandGraph::CommandGraphTree size must be 0x0C");
  static_assert(sizeof(UICommandGraph) == 0xDDC, "UICommandGraph size must be 0xDDC");

  /**
   * Address: 0x008243F0 (FUN_008243F0, ??0UICommandGraphNode@Moho@@QAE@@Z)
   * Mangled: ??0UICommandGraphNode@Moho@@QAE@@Z
   *
   * What it does:
   * Seeds one command-graph style node with default animation/scaling lanes
   * and clears orderline/waypoint/arrowhead texture shared pointers.
   */
  UICommandGraphNode::UICommandGraphNode()
  {
    mOrderlineTexture.px = nullptr;
    mOrderlineTexture.pi = nullptr;
    mOrderlineAnimRate = 0.1f;
    mOrderlineAspectRatio = 1.0f;
    mOrderlineColor = 0u;
    mOrderlineSelectedColor = 0u;
    mOrderlineHighlightColor = 0u;
    mOrderlineGlow = 0.0f;
    mOrderlineSelectedGlow = 0.0f;
    mOrderlineHighlightGlow = 0.0f;
    mWaypointColor = 0u;
    mWaypointSelectedColor = 0u;
    mWaypointHighlightColor = 0u;
    mWaypointScale = 1.0f;
    mWaypointSelectedScale = 1.0f;
    mWaypointHighlightScale = 1.0f;
    mWaypointTexture.px = nullptr;
    mWaypointTexture.pi = nullptr;
    mArrowheadTexture.px = nullptr;
    mArrowheadTexture.pi = nullptr;
  }

  /**
   * Address: 0x008249B0 (FUN_008249B0, ??1UICommandGraphNode@Moho@@QAE@@Z)
   * Mangled: ??1UICommandGraphNode@Moho@@QAE@@Z
   *
   * What it does:
   * Releases command-graph texture shared-control lanes in arrowhead, waypoint,
   * then orderline teardown order.
   */
  UICommandGraphNode::~UICommandGraphNode()
  {
    mArrowheadTexture.release();
    mWaypointTexture.release();
    mOrderlineTexture.release();
  }

  /**
   * Address: 0x00825060 (FUN_00825060, Moho::UICommandGraphNode::cpy)
   *
   * NOTE (2026-08-20 audit): all three texture-lane releases below previously
   * called `.weak_release()`. FUN_00825060 confirms all three inline copies of
   * the retain/release pattern call FUN_004229B0 for the release step
   * (verified by manual displacement calculation at 0x00825087, 0x0082510E,
   * 0x0082513B), which is `sp_counted_base::release()`, not `weak_release()`
   * (see BoostWrappers.h). The acquire side (`add_ref_copy()`) was already
   * correct. Corrected to `.release()` to match.
   *
   * What it does:
   * Copies one command-graph style node payload, including shared-texture
   * control lanes for orderline/waypoint/arrowhead textures.
   */
  UICommandGraphNode* UICommandGraphNode::CopyFrom(const UICommandGraphNode& other)
  {
    mOrderlineTexture.px = other.mOrderlineTexture.px;
    boost::detail::sp_counted_base* incomingControl = other.mOrderlineTexture.pi;
    if (incomingControl != mOrderlineTexture.pi) {
      if (incomingControl != nullptr) {
        incomingControl->add_ref_copy();
      }
      if (mOrderlineTexture.pi != nullptr) {
        mOrderlineTexture.pi->release();
      }
      mOrderlineTexture.pi = incomingControl;
    }

    mOrderlineAspectRatio = other.mOrderlineAspectRatio;
    mOrderlineAnimRate = other.mOrderlineAnimRate;
    mOrderlineColor = other.mOrderlineColor;
    mOrderlineSelectedColor = other.mOrderlineSelectedColor;
    mOrderlineHighlightColor = other.mOrderlineHighlightColor;
    mOrderlineGlow = other.mOrderlineGlow;
    mOrderlineSelectedGlow = other.mOrderlineSelectedGlow;
    mOrderlineHighlightGlow = other.mOrderlineHighlightGlow;
    mWaypointColor = other.mWaypointColor;
    mWaypointSelectedColor = other.mWaypointSelectedColor;
    mWaypointHighlightColor = other.mWaypointHighlightColor;
    mWaypointScale = other.mWaypointScale;
    mWaypointSelectedScale = other.mWaypointSelectedScale;
    mWaypointHighlightScale = other.mWaypointHighlightScale;
    mArrowheadCapOffset = other.mArrowheadCapOffset;

    mWaypointTexture.px = other.mWaypointTexture.px;
    incomingControl = other.mWaypointTexture.pi;
    if (incomingControl != mWaypointTexture.pi) {
      if (incomingControl != nullptr) {
        incomingControl->add_ref_copy();
      }
      if (mWaypointTexture.pi != nullptr) {
        mWaypointTexture.pi->release();
      }
      mWaypointTexture.pi = incomingControl;
    }

    mArrowheadTexture.px = other.mArrowheadTexture.px;
    incomingControl = other.mArrowheadTexture.pi;
    if (incomingControl != mArrowheadTexture.pi) {
      if (incomingControl != nullptr) {
        incomingControl->add_ref_copy();
      }
      if (mArrowheadTexture.pi != nullptr) {
        mArrowheadTexture.pi->release();
      }
      mArrowheadTexture.pi = incomingControl;
    }

    return this;
  }

  /**
   * Address: 0x00825570 (FUN_00825570)
   * Mangled: ?LoadTextures@UICommandGraphNode@Moho@@QAEXPAVLuaObject@LuaPlus@@PBDPAVLuaState@3@@Z
   *
   * NOTE (2026-08-20 audit): all three texture-lane assignments below
   * (orderline/waypoint/arrowhead) previously called `.weak_release()` in the
   * shared `assignSharedLane` lambda. FUN_00825570 confirms all three call
   * sites (0x008256E4, 0x00825B26, 0x00825EF9, xref-verified) target
   * FUN_004229B0, i.e. `sp_counted_base::release()`, not `weak_release()`
   * (see BoostWrappers.h). The acquire side (`add_ref_copy()`) was already
   * correct. Corrected to `.release()`; the lambda was renamed from
   * `assignWeakSharedLane` to match (function-local, no external callers).
   *
   * What it does:
   * Loads command-graph texture/style lanes from one Lua table entry, honoring
   * `inherit_from` recursion before overriding local orderline/waypoint/
   * arrowhead keys.
   */
  void UICommandGraphNode::LoadTextures(LuaPlus::LuaObject rootTable, const char* const key, LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject nodeTable = rootTable[key];
    if (nodeTable.IsNil()) {
      return;
    }

    LuaPlus::LuaObject inheritFrom = nodeTable["inherit_from"];
    if (!inheritFrom.IsNil()) {
      LoadTextures(LuaPlus::LuaObject(rootTable), inheritFrom.GetString(), state);
    }

    const auto hasKey = [&nodeTable](const char* const fieldName) -> bool {
      LuaPlus::LuaObject probe = nodeTable[fieldName];
      return !probe.IsNil();
    };

    const auto assignSharedLane = [](
                                    boost::SharedPtrRaw<void>& destination,
                                    void* const sourcePx,
                                    boost::detail::sp_counted_base* const sourceControl
                                  ) {
      destination.px = sourcePx;
      if (sourceControl != destination.pi) {
        if (sourceControl != nullptr) {
          sourceControl->add_ref_copy();
        }
        if (destination.pi != nullptr) {
          destination.pi->release();
        }
        destination.pi = sourceControl;
      }
    };

    if (hasKey("orderline_texture")) {
      if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
        if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
          LuaPlus::LuaObject textureValue = nodeTable["orderline_texture"];
          ID3DDeviceResources::TextureResourceHandle loadedTexture{};
          resources->GetTexture(loadedTexture, textureValue.GetString(), 0, true);

          const boost::SharedPtrRaw<RD3DTextureResource> loadedRaw = boost::SharedPtrRawFromSharedBorrow(loadedTexture);
          assignSharedLane(mOrderlineTexture, loadedRaw.px, loadedRaw.pi);
        }
      }
    }

    if (hasKey("orderline_uv_aspect_ratio")) {
      mOrderlineAspectRatio = static_cast<float>(nodeTable["orderline_uv_aspect_ratio"].GetNumber());
    }

    if (hasKey("orderline_anim_rate")) {
      mOrderlineAnimRate = static_cast<float>(nodeTable["orderline_anim_rate"].GetNumber());
    }

    if (hasKey("orderline_color")) {
      mOrderlineColor = SCR_DecodeColor(state, nodeTable["orderline_color"]);
    }

    if (hasKey("orderline_selected_color")) {
      mOrderlineSelectedColor = SCR_DecodeColor(state, nodeTable["orderline_selected_color"]);
    }

    if (hasKey("orderline_highlight_color")) {
      mOrderlineHighlightColor = SCR_DecodeColor(state, nodeTable["orderline_highlight_color"]);
    }

    if (hasKey("orderline_glow")) {
      mOrderlineGlow = static_cast<float>(nodeTable["orderline_glow"].GetNumber());
    }

    if (hasKey("orderline_selected_glow")) {
      mOrderlineSelectedGlow = static_cast<float>(nodeTable["orderline_selected_glow"].GetNumber());
    }

    if (hasKey("orderline_highlight_glow")) {
      mOrderlineHighlightGlow = static_cast<float>(nodeTable["orderline_highlight_glow"].GetNumber());
    }

    if (hasKey("waypoint_texture")) {
      LuaPlus::LuaObject textureValue = nodeTable["waypoint_texture"];
      const boost::shared_ptr<CD3DBatchTexture> loadedTexture = CD3DBatchTexture::FromFile(textureValue.GetString(), 1u);
      const boost::SharedPtrRaw<CD3DBatchTexture> loadedRaw = boost::SharedPtrRawFromSharedBorrow(loadedTexture);
      assignSharedLane(mWaypointTexture, loadedRaw.px, loadedRaw.pi);
    }

    if (hasKey("waypoint_color")) {
      mWaypointColor = SCR_DecodeColor(state, nodeTable["waypoint_color"]);
    }

    if (hasKey("waypoint_selected_color")) {
      mWaypointSelectedColor = SCR_DecodeColor(state, nodeTable["waypoint_selected_color"]);
    }

    if (hasKey("waypoint_highlight_color")) {
      mWaypointHighlightColor = SCR_DecodeColor(state, nodeTable["waypoint_highlight_color"]);
    }

    if (hasKey("waypoint_scale")) {
      mWaypointScale = static_cast<float>(nodeTable["waypoint_scale"].GetNumber());
    }

    if (hasKey("waypoint_selected_scale")) {
      mWaypointSelectedScale = static_cast<float>(nodeTable["waypoint_selected_scale"].GetNumber());
    }

    if (hasKey("waypoint_highlight_scale")) {
      mWaypointHighlightScale = static_cast<float>(nodeTable["waypoint_highlight_scale"].GetNumber());
    }

    if (hasKey("arrowhead_cap_offset")) {
      mArrowheadCapOffset = static_cast<float>(nodeTable["arrowhead_cap_offset"].GetNumber());
    }

    if (hasKey("arrowhead_texture")) {
      LuaPlus::LuaObject textureValue = nodeTable["arrowhead_texture"];
      const boost::shared_ptr<CD3DBatchTexture> loadedTexture = CD3DBatchTexture::FromFile(textureValue.GetString(), 1u);
      const boost::SharedPtrRaw<CD3DBatchTexture> loadedRaw = boost::SharedPtrRawFromSharedBorrow(loadedTexture);
      assignSharedLane(mArrowheadTexture, loadedRaw.px, loadedRaw.pi);
    }
  }

  namespace
  {
    struct CommandGraphLane64RuntimeView
    {
      std::uint8_t mPad00_63[0x64];
      std::uint32_t mValue; // +0x64
    };

    static_assert(
      offsetof(CommandGraphLane64RuntimeView, mValue) == 0x64,
      "CommandGraphLane64RuntimeView::mValue offset must be 0x64"
    );

    struct CommandGraphLane458RuntimeView
    {
      std::uint8_t mPad00_457[0x458];
      std::uint32_t mValue; // +0x458
    };

    static_assert(
      offsetof(CommandGraphLane458RuntimeView, mValue) == 0x458,
      "CommandGraphLane458RuntimeView::mValue offset must be 0x458"
    );

    struct WeakOwnerLinkHeadRuntimeView
    {
      std::uint8_t mPad00_07[0x8];
      void* mHead; // +0x08
    };

    static_assert(
      offsetof(WeakOwnerLinkHeadRuntimeView, mHead) == 0x08,
      "WeakOwnerLinkHeadRuntimeView::mHead offset must be 0x08"
    );

    struct WeakOwnerLinkNodeRuntimeView
    {
      std::int32_t mState;      // +0x00
      void** mOwnerLinkSlot;    // +0x04
      void* mNextInOwner;       // +0x08
    };

    static_assert(sizeof(WeakOwnerLinkNodeRuntimeView) == 0x0C, "WeakOwnerLinkNodeRuntimeView size must be 0x0C");
    static_assert(
      offsetof(WeakOwnerLinkNodeRuntimeView, mOwnerLinkSlot) == 0x04,
      "WeakOwnerLinkNodeRuntimeView::mOwnerLinkSlot offset must be 0x04"
    );

    struct DwordPairRuntimeView
    {
      std::uint32_t mFirst;   // +0x00
      std::uint32_t mSecond;  // +0x04
    };

    struct PointerTripletLaneRuntimeView
    {
      void* mBegin;       // +0x00
      void* mEnd;         // +0x04
      void* mCapacityEnd; // +0x08
      void* mMeta;        // +0x0C
    };

    static_assert(sizeof(PointerTripletLaneRuntimeView) == 0x10, "PointerTripletLaneRuntimeView size must be 0x10");

    struct CommandGraphIssueRuntimeView
    {
      std::int32_t mCommandId;                   // +0x00
      void* mOwnerLinkSlot;                      // +0x04
      void* mOwnerNextLink;                      // +0x08
      Wm3::Vector3f mAnchorPosition;             // +0x0C
      float mLaneWidth;                          // +0x18
      std::uint8_t mFlag1;                       // +0x1C
      std::uint8_t mFlag2;                       // +0x1D
      std::uint8_t mIsEnabled;                   // +0x1E
      std::uint8_t pad_1F;                       // +0x1F
      std::uint32_t mUnknown20;                  // +0x20
      std::uint32_t mUnknown24;                  // +0x24
      float mUnknown28;                          // +0x28
      float mUnknown2C;                          // +0x2C
      float mUnknown30;                          // +0x30
      float mUnknown34;                          // +0x34
      float mUnknown38;                          // +0x38
      float mUnknown3C;                          // +0x3C
      float mUnknown40;                          // +0x40
      std::uint32_t mUnknown44;                  // +0x44
      PointerTripletLaneRuntimeView mPrimaryRefLane;   // +0x48
      std::uint32_t mPrimaryInline0;             // +0x58
      std::uint32_t mPrimaryInline1;             // +0x5C
      PointerTripletLaneRuntimeView mSecondaryRefLane; // +0x60
      std::uint32_t mSecondaryInline0;           // +0x70
      std::uint32_t mSecondaryInline1;           // +0x74
    };

    static_assert(sizeof(CommandGraphIssueRuntimeView) == 0x78, "CommandGraphIssueRuntimeView size must be 0x78");
    static_assert(
      offsetof(CommandGraphIssueRuntimeView, mPrimaryRefLane) == 0x48,
      "CommandGraphIssueRuntimeView::mPrimaryRefLane offset must be 0x48"
    );
    static_assert(
      offsetof(CommandGraphIssueRuntimeView, mSecondaryRefLane) == 0x60,
      "CommandGraphIssueRuntimeView::mSecondaryRefLane offset must be 0x60"
    );

    /**
     * Address: 0x00824330 (FUN_00824330, sub_824330)
     *
     * What it does:
     * Returns one first-dword lane from one command-graph helper payload.
     */
    [[nodiscard]] std::uint32_t ReadCommandGraphHelperLane0(const void* const value) noexcept
    {
      if (value == nullptr) {
        return 0u;
      }
      return *static_cast<const std::uint32_t*>(value);
    }

    /**
     * Address: 0x00824380 (FUN_00824380, sub_824380)
     *
     * What it does:
     * Returns one dword lane at `+0x64` from one command-graph runtime payload.
     */
    [[nodiscard]] std::uint32_t ReadCommandGraphHelperLane64(const void* const value) noexcept
    {
      if (value == nullptr) {
        return 0u;
      }
      return static_cast<const CommandGraphLane64RuntimeView*>(value)->mValue;
    }

    /**
     * Address: 0x00824470 (FUN_00824470, sub_824470)
     *
     * What it does:
     * Returns one dword lane at `+0x458` from one command-graph runtime payload.
     */
    [[nodiscard]] std::uint32_t ReadCommandGraphHelperLane458(const void* const value) noexcept
    {
      if (value == nullptr) {
        return 0u;
      }
      return static_cast<const CommandGraphLane458RuntimeView*>(value)->mValue;
    }

    /**
     * Address: 0x00824480 (FUN_00824480, sub_824480)
     *
     * What it does:
     * Initializes one weak-owner link node and inserts its owner-slot lane into
     * one owner link-head lane at `+0x08`.
     */
    [[nodiscard]] WeakOwnerLinkNodeRuntimeView* InitWeakOwnerLinkNodeFromHead(
      WeakOwnerLinkNodeRuntimeView* const node,
      void* const owner
    ) noexcept
    {
      if (node == nullptr) {
        return nullptr;
      }

      node->mState = 1;
      auto* const ownerSlot = (owner != nullptr)
        ? reinterpret_cast<void**>(&static_cast<WeakOwnerLinkHeadRuntimeView*>(owner)->mHead)
        : nullptr;
      node->mOwnerLinkSlot = ownerSlot;

      if (ownerSlot != nullptr) {
        node->mNextInOwner = *ownerSlot;
        *ownerSlot = &node->mOwnerLinkSlot;
      } else {
        node->mNextInOwner = nullptr;
      }

      return node;
    }

    /**
     * Address: 0x008244D0 (FUN_008244D0, sub_8244D0)
     *
     * What it does:
     * Returns one first-dword lane from one command-graph helper payload.
     */
    [[nodiscard]] std::uint32_t ReadCommandGraphHelperLane0Alt(const void* const value) noexcept
    {
      if (value == nullptr) {
        return 0u;
      }
      return *static_cast<const std::uint32_t*>(value);
    }

    /**
     * Address: 0x00824540 (FUN_00824540, sub_824540)
     *
     * What it does:
     * Copies one second-dword lane from source payload into destination dword.
     */
    [[nodiscard]] std::uint32_t* CopyRuntimeLane4ToDword(
      std::uint32_t* const destination,
      const void* const source
    ) noexcept
    {
      if (destination == nullptr) {
        return nullptr;
      }
      if (source == nullptr) {
        *destination = 0u;
      } else {
        *destination = *(reinterpret_cast<const std::uint32_t*>(source) + 1);
      }
      return destination;
    }

    /**
     * Address: 0x008245D0 (FUN_008245D0, sub_8245D0)
     *
     * What it does:
     * Writes one two-dword pair payload (`first`,`second`) to destination.
     */
    [[nodiscard]] DwordPairRuntimeView* InitDwordPairRuntimeLane(
      DwordPairRuntimeView* const destination,
      const std::uint32_t second,
      const std::uint32_t first
    ) noexcept
    {
      if (destination == nullptr) {
        return nullptr;
      }
      destination->mFirst = first;
      destination->mSecond = second;
      return destination;
    }

    /**
     * Address: 0x00824600 (FUN_00824600, sub_824600)
     *
     * What it does:
     * Initializes one command-graph issue runtime lane with cleared scalar state
     * and two inline-backed pointer-triplet reference lanes.
     */
    [[nodiscard]] CommandGraphIssueRuntimeView*
    InitCommandGraphIssueRuntimeLane(CommandGraphIssueRuntimeView* const lane) noexcept
    {
      if (lane == nullptr) {
        return nullptr;
      }

      lane->mCommandId = -1;
      lane->mOwnerLinkSlot = nullptr;
      lane->mOwnerNextLink = nullptr;
      lane->mAnchorPosition = Wm3::Vector3f(0.0f, 0.0f, 0.0f);
      lane->mLaneWidth = 0.0f;
      lane->mFlag1 = 0u;
      lane->mFlag2 = 0u;
      lane->mIsEnabled = 1u;
      lane->pad_1F = 0u;
      lane->mUnknown20 = 0u;
      lane->mUnknown24 = 0u;
      lane->mUnknown28 = 0.0f;
      lane->mUnknown2C = 0.0f;
      lane->mUnknown30 = 0.0f;
      lane->mUnknown34 = 0.0f;
      lane->mUnknown38 = 0.0f;
      lane->mUnknown3C = 0.0f;
      lane->mUnknown40 = 0.0f;
      lane->mUnknown44 = 0u;

      lane->mPrimaryInline0 = 0u;
      lane->mPrimaryInline1 = 0u;
      lane->mPrimaryRefLane.mBegin = &lane->mPrimaryInline0;
      lane->mPrimaryRefLane.mEnd = &lane->mPrimaryInline0;
      lane->mPrimaryRefLane.mCapacityEnd = &lane->mPrimaryInline1;
      lane->mPrimaryRefLane.mMeta = &lane->mPrimaryInline0;

      lane->mSecondaryInline0 = 0u;
      lane->mSecondaryInline1 = 0u;
      lane->mSecondaryRefLane.mBegin = &lane->mSecondaryInline0;
      lane->mSecondaryRefLane.mEnd = &lane->mSecondaryInline0;
      lane->mSecondaryRefLane.mCapacityEnd = &lane->mSecondaryInline1;
      lane->mSecondaryRefLane.mMeta = &lane->mSecondaryInline0;
      return lane;
    }

    /**
     * Address: 0x00825FF0 (FUN_00825FF0, sub_825FF0)
     *
     * What it does:
     * Sets one byte lane to `1` and returns destination.
     */
    [[nodiscard]] std::uint8_t* SetByteLaneTrue(std::uint8_t* const destination) noexcept
    {
      if (destination == nullptr) {
        return nullptr;
      }
      *destination = 1u;
      return destination;
    }
  } // namespace

  /**
   * Address: 0x00823B40 (FUN_00823B40, struct_BuildTemplate::struct_BuildTemplate)
   *
   * What it does:
   * Copy-constructs one build-template entry (position, heading, blueprint id).
   */
  SBuildTemplateInfo::SBuildTemplateInfo(const SBuildTemplateInfo& other)
    : mPos(other.mPos)
    , mBuildOrder(other.mBuildOrder)
    , mBlueprintId(other.mBlueprintId)
  {}

  namespace
  {
    [[nodiscard]] IWldUIProvider* ResolveWldUIProvider() noexcept
    {
      if (sWldUIProvider == nullptr) {
        return nullptr;
      }

      return dynamic_cast<IWldUIProvider*>(sWldUIProvider);
    }

    // Forward-declared here (rather than defined) because the process-global
    // singleton lane below only ever holds a pointer; `StrategicIconAuxView`
    // itself is defined later in this same `moho`-scoped anonymous
    // namespace, next to `CWldSession::RenderStrategicIcons`'s callee
    // cluster (0x0085B6E0's lazy-init target, address 0x010C4300).
    struct StrategicIconAuxView;
    StrategicIconAuxView* gStrategicIconAuxiliary = nullptr;

    /**
     * Address: 0x0085EFE0 (FUN_0085EFE0)
     *
     * What it does:
     * Returns the global strategic-icon auxiliary object lane.
     */
    [[nodiscard]] StrategicIconAuxView* GetStrategicIconAuxiliaryLaneA() noexcept
    {
      return gStrategicIconAuxiliary;
    }

    /**
     * Address: 0x0085EFF0 (FUN_0085EFF0)
     *
     * What it does:
     * Secondary entrypoint returning the strategic-icon auxiliary object lane.
     */
    [[nodiscard]] StrategicIconAuxView* GetStrategicIconAuxiliaryLaneB() noexcept
    {
      return gStrategicIconAuxiliary;
    }

    /**
     * Address: 0x0085F000 (FUN_0085F000)
     *
     * What it does:
     * Third entrypoint returning the strategic-icon auxiliary object lane.
     */
    [[nodiscard]] StrategicIconAuxView* GetStrategicIconAuxiliaryLaneC() noexcept
    {
      return gStrategicIconAuxiliary;
    }

    CWldSession* gActiveWldSession = nullptr;
    SWldSessionInfo* gPendingWldSessionInfo = nullptr;
    EWldFrameAction gWldFrameAction = EWldFrameAction::Inactive;
    WldTeardownCallbackVector gWldTeardownCallbacks{};
    std::uint32_t gWldTeardownCallbacksInitMask = 0;

    /**
     * Address: 0x0088E900 (FUN_0088E900, pending session-info ownership rebind helper)
     *
     * What it does:
     * Moves one released `SWldSessionInfo*` payload into the process-global
     * pending-session slot, deleting the previous payload when ownership
     * changes, and returns the global slot address.
     */
    [[nodiscard]] SWldSessionInfo** RebindPendingWldSessionInfoFromReleasedSlot(
      SWldSessionInfo** const releasedSlot
    ) noexcept
    {
      SWldSessionInfo* const nextSessionInfo = *releasedSlot;
      *releasedSlot = nullptr;

      if (nextSessionInfo != gPendingWldSessionInfo) {
        SWldSessionInfo* const previousSessionInfo = gPendingWldSessionInfo;
        if (previousSessionInfo != nullptr) {
          previousSessionInfo->~SWldSessionInfo();
          ::operator delete(previousSessionInfo);
        }
      }

      gPendingWldSessionInfo = nextSessionInfo;
      return &gPendingWldSessionInfo;
    }

    void CleanupWldTeardownCallbacks()
    {
      gWldTeardownCallbacks.clear();
      gWldTeardownCallbacksInitMask &= ~1u;
    }

    /**
     * Address: 0x00869870 (FUN_00869870, teardown callback dispatch core)
     *
     * What it does:
     * Iterates every registered world-session teardown callback and invokes it
     * with the current active world-session pointer.
     */
    void DispatchTeardownCallbacksCore(WldTeardownCallbackVector* const callbacks)
    {
      const std::size_t callbackCount = callbacks->size();
      for (std::size_t i = 0; i < callbackCount; ++i) {
        IWldTeardownCallback* const callback = (*callbacks)[i];
        (void)callback->OnWldSessionTeardown(gActiveWldSession);
      }
    }

    [[nodiscard]] std::intptr_t DispatchTeardownCallbacksCoreAndReturnLastResult(
      WldTeardownCallbackVector* const callbacks
    )
    {
      if (callbacks == nullptr) {
        return 0;
      }

      // The binary's return register still holds `_Myfirst` when the callback
      // list is empty, so that is the seed value here.
      std::intptr_t result = reinterpret_cast<std::intptr_t>(callbacks->data());

      const std::size_t callbackCount = callbacks->size();
      for (std::size_t i = 0; i < callbackCount; ++i) {
        IWldTeardownCallback* const callback = (*callbacks)[i];
        result = static_cast<std::intptr_t>(callback->OnWldSessionTeardown(gActiveWldSession));
      }

      return result;
    }

    /**
     * Address: 0x008698B0 (FUN_008698B0, func_DoTeardownCallbacks)
     *
     * What it does:
     * Invokes every registered world-session teardown callback with the current
     * global active-session pointer and returns the last callback result lane.
     */
    [[nodiscard]] std::intptr_t DoTeardownCallbacks(WldTeardownCallbackVector* const callbacks)
    {
      if (callbacks == nullptr) {
        return 0;
      }

      return DispatchTeardownCallbacksCoreAndReturnLastResult(callbacks);
    }

    struct VizUpdateNode
    {
      VizUpdateNode* left;          // +0x00
      VizUpdateNode* parent;        // +0x04
      VizUpdateNode* right;         // +0x08
      std::uintptr_t key;           // +0x0C
      std::uintptr_t ownerLinkHead; // +0x10
      std::uintptr_t ownerNextLink; // +0x14
      std::uint8_t color;           // +0x18 (0=red, 1=black)
      std::uint8_t isSentinel;      // +0x19
      std::uint8_t pad_1A[2];
    };

    static_assert(sizeof(VizUpdateNode) == 0x1C, "VizUpdateNode size must be 0x1C");

    struct VizUpdateTree
    {
      void* debugProxy;    // +0x00
      VizUpdateNode* head; // +0x04
      std::uint32_t size;  // +0x08
    };

    static_assert(sizeof(VizUpdateTree) == 0x0C, "VizUpdateTree size must be 0x0C");

    [[nodiscard]] VizUpdateTree* GetVizUpdateTree(CWldSession* session)
    {
      return reinterpret_cast<VizUpdateTree*>(&session->mVizUpdateRoot);
    }

    [[nodiscard]] const VizUpdateTree* GetVizUpdateTree(const CWldSession* session)
    {
      return reinterpret_cast<const VizUpdateTree*>(&session->mVizUpdateRoot);
    }

    struct SessionPauseCallbackLink
    {
      SessionPauseCallbackLink* prev;
      SessionPauseCallbackLink* next;
    };

    class ISessionPauseCallback
    {
    public:
      virtual void OnSessionPauseStateChanged(bool isPaused) = 0;
    };

    struct SessionPauseCallbackOwnerLayout
    {
      void* vftable;
      SessionPauseCallbackLink link;
    };

    static_assert(sizeof(SessionPauseCallbackLink) == 0x8, "SessionPauseCallbackLink size must be 0x8");
    static_assert(
      offsetof(SessionPauseCallbackOwnerLayout, link) == sizeof(void*),
      "SessionPauseCallbackOwnerLayout::link offset must follow vftable lane"
    );

    [[nodiscard]] SessionPauseCallbackLink* AsSessionPauseCallbackLink(gpg::core::IntrusiveLink<CWldSession*>* link) noexcept
    {
      return reinterpret_cast<SessionPauseCallbackLink*>(link);
    }

    [[nodiscard]] ISessionPauseCallback* AsSessionPauseCallbackOwner(SessionPauseCallbackLink* const link) noexcept
    {
      constexpr std::size_t kCallbackLinkOffset = offsetof(SessionPauseCallbackOwnerLayout, link);
      auto* const raw = reinterpret_cast<std::uint8_t*>(link) - kCallbackLinkOffset;
      return reinterpret_cast<ISessionPauseCallback*>(raw);
    }

    void InitSessionPauseCallbackHead(gpg::core::IntrusiveLink<CWldSession*>& head) noexcept
    {
      auto* const link = AsSessionPauseCallbackLink(&head);
      link->prev = link;
      link->next = link;
    }

    [[nodiscard]] bool IsSessionPauseCallbackHeadEmpty(const gpg::core::IntrusiveLink<CWldSession*>& head) noexcept
    {
      const SessionPauseCallbackLink* const link =
        reinterpret_cast<const SessionPauseCallbackLink*>(&head);
      return link->next == link;
    }

    void UnlinkSessionPauseCallbackNode(SessionPauseCallbackLink* const link) noexcept
    {
      link->prev->next = link->next;
      link->next->prev = link->prev;
      link->prev = link;
      link->next = link;
    }

    void LinkSessionPauseCallbackNodeBefore(
      SessionPauseCallbackLink* const anchor,
      SessionPauseCallbackLink* const link
    ) noexcept
    {
      link->prev = anchor->prev;
      link->next = anchor;
      anchor->prev->next = link;
      anchor->prev = link;
    }

    struct SelectionEventBroadcasterOwnerLayout
    {
      void** vftable;
      ListenerLinkRuntimeView link;
    };

    using SelectionEventDispatchFn = void(__thiscall*)(
      SelectionEventBroadcasterOwnerLayout* owner,
      std::uint32_t lane0,
      std::uint32_t lane1,
      std::uint32_t lane2,
      std::uint32_t lane3
    );

    [[nodiscard]] SelectionEventBroadcasterOwnerLayout* AsSelectionEventBroadcasterOwner(
      ListenerLinkRuntimeView* const link
    ) noexcept
    {
      constexpr std::size_t kLinkOffset = offsetof(SelectionEventBroadcasterOwnerLayout, link);
      auto* const raw = reinterpret_cast<std::uint8_t*>(link) - kLinkOffset;
      return reinterpret_cast<SelectionEventBroadcasterOwnerLayout*>(raw);
    }

    /**
     * Address: 0x008986F0 (FUN_008986F0, ?BroadcastEvent@?$Broadcaster@USSelectionEvent@Moho@@@Moho@@IAEXUSSelectionEvent@2@@Z)
     *
     * What it does:
     * Stages one selection-event listener list into a temporary sentinel lane,
     * reinserts each listener back into the owner list, and dispatches one
     * 4-lane selection-event payload through the listener vtable.
     */
    void BroadcastSelectionEventListeners(
      ListenerLinkRuntimeView& head,
      const std::uint32_t lane0,
      const std::uint32_t lane1,
      const std::uint32_t lane2,
      const std::uint32_t lane3
    )
    {
      if (head.mNext == &head) {
        return;
      }

      ListenerLinkRuntimeView staging{};
      staging.mPrev = &staging;
      staging.mNext = &staging;

      staging.mPrev = head.mPrev;
      staging.mNext = head.mNext;
      staging.mPrev->mNext = &staging;
      staging.mNext->mPrev = &staging;
      head.mPrev = &head;
      head.mNext = &head;

      while (staging.mNext != &staging) {
        ListenerLinkRuntimeView* const listenerLink = staging.mNext;
        listenerLink->mPrev->mNext = listenerLink->mNext;
        listenerLink->mNext->mPrev = listenerLink->mPrev;
        listenerLink->mPrev = listenerLink;
        listenerLink->mNext = listenerLink;

        listenerLink->mPrev = head.mPrev;
        listenerLink->mNext = &head;
        head.mPrev->mNext = listenerLink;
        head.mPrev = listenerLink;

        SelectionEventBroadcasterOwnerLayout* const owner = AsSelectionEventBroadcasterOwner(listenerLink);
        if (owner->vftable != nullptr && owner->vftable[0] != nullptr) {
          auto* const dispatch = reinterpret_cast<SelectionEventDispatchFn>(owner->vftable[0]);
          dispatch(owner, lane0, lane1, lane2, lane3);
        }
      }
    }

    /**
     * `Broadcaster<SSelectionEvent>` is a base subobject of `CWldSession`, so
     * its listener-list head is the session's own first intrusive link at
     * +0x00 - `SetSelection` (0x00896140) loads `arg_0`, the session pointer,
     * straight into `esi` as `BroadcastEvent`'s `this`.
     */
    [[nodiscard]] ListenerLinkRuntimeView& SelectionEventHead(CWldSession& session) noexcept
    {
      return *reinterpret_cast<ListenerLinkRuntimeView*>(&session.head0);
    }

    [[nodiscard]] std::uint32_t SelectionEventLaneFromPointer(const void* const pointer) noexcept
    {
      return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(pointer));
    }

    /**
     * Address: 0x00898820 (FUN_00898820)
     *
     * What it does:
     * Stages the pause-callback intrusive list into a temporary sentinel lane,
     * reinserts each callback back into the owner list, and dispatches pause
     * state notifications in original iteration order.
     */
    void DispatchSessionPauseCallbacks(gpg::core::IntrusiveLink<CWldSession*>& head, const bool isPaused)
    {
      if (IsSessionPauseCallbackHeadEmpty(head)) {
        return;
      }

      SessionPauseCallbackLink staging{};
      staging.prev = &staging;
      staging.next = &staging;

      SessionPauseCallbackLink* const headLink = AsSessionPauseCallbackLink(&head);
      staging.prev = headLink->prev;
      staging.next = headLink->next;
      staging.prev->next = &staging;
      staging.next->prev = &staging;
      headLink->prev = headLink;
      headLink->next = headLink;

      while (staging.next != &staging) {
        SessionPauseCallbackLink* const callbackLink = staging.next;
        UnlinkSessionPauseCallbackNode(callbackLink);
        LinkSessionPauseCallbackNodeBefore(headLink, callbackLink);
        AsSessionPauseCallbackOwner(callbackLink)->OnSessionPauseStateChanged(isPaused);
      }
    }

    /**
     * Address: 0x00823E10 (FUN_00823E10, sub_823E10)
     *
     * What it does:
     * Releases one build-template blueprint-id string lane and restores
     * SSO-empty string state in-place.
     */
    [[nodiscard]] SBuildTemplateInfo* DestroyBuildTemplateInfo(SBuildTemplateInfo* const info)
    {
      if (info->mBlueprintId.myRes >= 0x10u) {
        ::operator delete(info->mBlueprintId.bx.ptr);
      }

      info->mBlueprintId.mySize = 0;
      info->mBlueprintId.myRes = 15;
      info->mBlueprintId.bx.buf[0] = '\0';
      return info;
    }

    /**
     * Address: 0x00823DD0 (FUN_00823DD0, sub_823DD0)
     *
     * What it does:
     * Releases one half-open build-template range `[first,last)` by destroying
     * each blueprint-id string lane in 0x2C-byte record strides.
     */
    void DestroyBuildTemplateRange(SBuildTemplateInfo* first, SBuildTemplateInfo* last)
    {
      while (first != last) {
        (void)DestroyBuildTemplateInfo(first);
        ++first;
      }
    }

    void EnsureBuildTemplateCapacityForAppend(SBuildTemplateBuffer& buffer)
    {
      if (buffer.mFinish != buffer.mCapacity) {
        return;
      }

      const std::size_t currentSize = static_cast<std::size_t>(buffer.mFinish - buffer.mStart);
      const std::size_t currentCapacity = static_cast<std::size_t>(buffer.mCapacity - buffer.mStart);
      std::size_t nextCapacity = currentCapacity + (currentCapacity >> 1u);
      if (nextCapacity < currentSize + 1u) {
        nextCapacity = currentSize + 1u;
      }
      if (nextCapacity == 0u) {
        nextCapacity = 1u;
      }

      auto* const nextStorage = static_cast<SBuildTemplateInfo*>(::operator new[](nextCapacity * sizeof(SBuildTemplateInfo)));
      SBuildTemplateInfo* writeCursor = nextStorage;

      try {
        for (std::size_t i = 0; i < currentSize; ++i) {
          new (writeCursor) SBuildTemplateInfo(buffer.mStart[i]);
          ++writeCursor;
        }
      } catch (...) {
        DestroyBuildTemplateRange(nextStorage, writeCursor);
        ::operator delete[](nextStorage);
        throw;
      }

      DestroyBuildTemplateRange(buffer.mStart, buffer.mFinish);
      if (buffer.mStart != buffer.mOriginalStart) {
        ::operator delete[](buffer.mStart);
      }

      buffer.mStart = nextStorage;
      buffer.mFinish = writeCursor;
      buffer.mCapacity = nextStorage + nextCapacity;
    }

    void AppendBuildTemplateEntry(SBuildTemplateBuffer& buffer, const SBuildTemplateInfo& info)
    {
      EnsureBuildTemplateCapacityForAppend(buffer);
      new (buffer.mFinish) SBuildTemplateInfo(info);
      ++buffer.mFinish;
    }

    void SortBuildTemplateRangeByOrder(SBuildTemplateInfo* const begin, SBuildTemplateInfo* const end)
    {
      if (begin == nullptr || end == nullptr || begin == end || begin + 1 == end) {
        return;
      }

      std::sort(
        begin,
        end,
        [](const SBuildTemplateInfo& lhs, const SBuildTemplateInfo& rhs) noexcept { return lhs.mBuildOrder < rhs.mBuildOrder; }
      );
    }

    /**
     * Address: 0x00898E50 (FUN_00898E50, sub_898E50)
     *
     * What it does:
     * Rebinds one build-template fastvector lane to inline storage and copies
     * source entries in-order, allocating spill storage when source size
     * exceeds inline capacity.
     */
    SBuildTemplateBuffer* RebindAndCopyBuildTemplateBufferInline(
      SBuildTemplateBuffer* const destination,
      const SBuildTemplateBuffer& source
    )
    {
      if (destination == nullptr) {
        return nullptr;
      }

      constexpr std::size_t kInlineCount = 16u;
      auto* const inlineStart = reinterpret_cast<SBuildTemplateInfo*>(&destination->mInlineStorage[0]);
      destination->mStart = inlineStart;
      destination->mFinish = inlineStart;
      destination->mCapacity = inlineStart + kInlineCount;
      destination->mOriginalStart = inlineStart;

      const SBuildTemplateInfo* const sourceStart = source.mStart;
      const SBuildTemplateInfo* const sourceFinish = source.mFinish;
      if (sourceStart == nullptr || sourceFinish == nullptr || sourceFinish <= sourceStart) {
        return destination;
      }

      const std::size_t sourceCount = static_cast<std::size_t>(sourceFinish - sourceStart);
      SBuildTemplateInfo* writeStart = destination->mStart;
      if (sourceCount > kInlineCount) {
        writeStart = static_cast<SBuildTemplateInfo*>(::operator new[](sourceCount * sizeof(SBuildTemplateInfo)));
        destination->mStart = writeStart;
        destination->mFinish = writeStart;
        destination->mCapacity = writeStart + sourceCount;
      }

      try {
        for (std::size_t i = 0; i < sourceCount; ++i) {
          new (destination->mFinish) SBuildTemplateInfo(sourceStart[i]);
          ++destination->mFinish;
        }
      } catch (...) {
        DestroyBuildTemplateRange(destination->mStart, destination->mFinish);
        if (destination->mStart != inlineStart) {
          ::operator delete[](destination->mStart);
        }
        destination->mStart = inlineStart;
        destination->mFinish = inlineStart;
        destination->mCapacity = inlineStart + kInlineCount;
        destination->mOriginalStart = inlineStart;
        throw;
      }

      return destination;
    }

    /**
     * Address: 0x00823D30 (FUN_00823D30, sub_823D30)
     *
     * What it does:
     * Returns one first-dword lane from one build-template helper payload.
     */
    [[nodiscard]] std::uint32_t ReadBuildTemplateHelperLane0(const void* const value) noexcept
    {
      if (value == nullptr) {
        return 0u;
      }
      return *static_cast<const std::uint32_t*>(value);
    }

    /**
     * Address: 0x00823D40 (FUN_00823D40, sub_823D40)
     *
     * What it does:
     * Returns one second-dword lane from one build-template helper payload.
     */
    [[nodiscard]] std::uint32_t ReadBuildTemplateHelperLane4(const void* const value) noexcept
    {
      if (value == nullptr) {
        return 0u;
      }
      return *(reinterpret_cast<const std::uint32_t*>(value) + 1);
    }

    constexpr std::uint32_t kBuildPreviewValidColor = 0xD800D800u;
    constexpr std::uint32_t kBuildPreviewInvalidColor = 0xD8D80000u;

    [[nodiscard]] SCoordsVec2 BuildPreviewCoordsFromWorldPosition(const Wm3::Vector3f& worldPosition) noexcept
    {
      return SCoordsVec2{worldPosition.x, worldPosition.z};
    }

    [[nodiscard]] std::uint32_t SelectBuildPreviewColor(
      const CWldSession& session,
      const bool placementAccepted
    ) noexcept
    {
      if (placementAccepted || !session.mShowInvalidBuildPlacementPreview) {
        return kBuildPreviewValidColor;
      }

      return kBuildPreviewInvalidColor;
    }

    void CopyOccupationPositionToPreviewTransform(
      const SOccupationResult& occupation,
      VTransform& previewTransform
    ) noexcept
    {
      previewTransform.pos_ = occupation.pos;
    }

    /**
     * Address: 0x00854930 (FUN_00854930, sub_854930)
     *
     * Wm3::Vector3f const &, Moho::RUnitBlueprint const *, Moho::VTransform &, Moho::CWldSession &, std::uint32_t &
     *
     * IDA signature:
     * int __userpurge sub_854930@<eax>(float *a1@<eax>, Moho::RUnitBlueprint *a2@<edx>, float *a3@<edi>, int esi0@<esi>, int *a5);
     *
     * What it does:
     * Evaluates build placement for one template-entry preview position, writes
     * the preview color, and snaps the preview transform to the occupation result.
     */
    [[nodiscard]] std::uint32_t ApplyBuildTemplatePlacementPreviewStatus(
      const Wm3::Vector3f& worldPosition,
      const RUnitBlueprint* const buildBlueprint,
      VTransform& previewTransform,
      CWldSession& session,
      std::uint32_t& outPreviewColor
    )
    {
      SOccupationResult occupation{};
      const SCoordsVec2 buildPosition = BuildPreviewCoordsFromWorldPosition(worldPosition);
      const bool canBuild = USERUNIT_CanBeBuiltAt(session, buildBlueprint, buildPosition, false, &occupation, nullptr);

      outPreviewColor = SelectBuildPreviewColor(session, canBuild);
      CopyOccupationPositionToPreviewTransform(occupation, previewTransform);
      return outPreviewColor;
    }

    /**
     * Address: 0x00854860 (FUN_00854860, sub_854860)
     *
     * Moho::CommandModeData const &, Wm3::Vector3f const &, Moho::CWldSession &, Moho::VTransform &, std::uint32_t &
     *
     * IDA signature:
     * float *__userpurge sub_854860@<eax>(_DWORD *a1@<edi>, float *a2@<esi>, int a3, float *arg4, int *a5);
     *
     * What it does:
     * Evaluates single-blueprint build preview placement, including anchored
     * build-distance validation, then writes preview color and snapped transform.
     */
    [[nodiscard]] VTransform* ApplyCommandModeBuildPlacementPreviewStatus(
      const CommandModeData& commandMode,
      const Wm3::Vector3f& worldPosition,
      CWldSession& session,
      VTransform& previewTransform,
      std::uint32_t& outPreviewColor
    )
    {
      const auto* const buildBlueprint = static_cast<const RUnitBlueprint*>(commandMode.mBlueprint);
      const SCoordsVec2 buildPosition = BuildPreviewCoordsFromWorldPosition(worldPosition);

      bool withinBuildDistance = true;
      if (commandMode.mMode == COMMOD_BuildAnchored) {
        withinBuildDistance = USERUNIT_WithinBuildDistance(session, buildBlueprint, buildPosition);
      }

      SOccupationResult occupation{};
      const bool canBuild = USERUNIT_CanBeBuiltAt(session, buildBlueprint, buildPosition, false, &occupation, nullptr);

      outPreviewColor = SelectBuildPreviewColor(session, withinBuildDistance && canBuild);
      CopyOccupationPositionToPreviewTransform(occupation, previewTransform);
      return &previewTransform;
    }

    /**
     * One classified entity in the strategic-icon pass - `struct_UnitIconData`
     * in the IDB. `CWldSession::RenderStrategicIcons` fills one of these per
     * visible entity, files it into one of the five runs on
     * `StrategicIconAuxView` below, and the emitters read it back.
     *
     * Layout evidence, all from the binary:
     *  - the copy-assignment at 0x0085CB00 walks every lane in order: two
     *    dwords at `+0`/`+4`, three floats at `+8`/`+12`/`+16`, three
     *    shared-pointer pairs at `+20`/`+24`, `+28`/`+32` and `+36`/`+40`
     *    (each re-seated through the `use_count_`/`weak_release` pair, so each
     *    is a `boost::shared_ptr`), then five single bytes at `+44`..`+48`;
     *  - the destructor at 0x0085CA20 releases exactly the control blocks held
     *    at `+0x18` (`mov esi, [edi+18h]`), `+0x20` and `+0x28`, which pins the
     *    three shared pointers to `+0x14`, `+0x1C` and `+0x24`;
     *  - the element stride is 0x34 in both the vector grow lane
     *    (`add esi, 34h` @ 0x0085EF3A) and the lifebar loop
     *    (`add edi, 34h` @ 0x0085C9C5), and every size computation in the
     *    family divides the byte span by 52.
     *
     * Flag roles come from `RenderUnitIcon` (0x0085D9A0), which is the only
     * reader: `+0x2C` gates the newly-created blink (0x0085DBF6), `+0x2D` the
     * pause overlay quad (0x0085DCD5), `+0x2E` the stunned overlay quad
     * (0x0085DD3C), `+0x2F` suppresses the base icon quad (0x0085DC90) and
     * `+0x30` marks the formation-preview ghost, whose colour is alpha-halved
     * instead of team-coloured (0x0085DBE1).
     *
     * The binary's per-type container and special-member emissions for this
     * struct are all covered by code that already exists, so none of them get
     * a hand-written copy here:
     *  - 0x0085CA20 is the compiler-generated `~UnitIconData` (three
     *    `shared_ptr` releases in reverse declaration order);
     *  - 0x0085CB00 is the compiler-generated `operator=`;
     *  - 0x0085ED70 / 0x0085EED0 / 0x0085F1B0 / 0x0085F290 are
     *    `msvc8::vector<UnitIconData>`'s `reserve` / `push_back` /
     *    `erase(first,last)` / destructor, and 0x0085F140, 0x0085F930,
     *    0x0085FDB0, 0x0085FFB0 and 0x0085F310 are that same instantiation's
     *    grow, allocate, copy-construct, uninitialised-copy and length-error
     *    lanes. They belong on `msvc8::vector<T>` in
     *    src/sdk/legacy/containers/Vector.h next to the other per-type
     *    emissions listed there, not as a second set of container primitives.
     */
    struct UnitIconData
    {
      UserEntity* mUnit = nullptr;                       // +0x00
      const REntityBlueprint* mBlueprint = nullptr;      // +0x04
      float mWorldX = 0.0f;                              // +0x08
      float mWorldY = 0.0f;                              // +0x0C
      float mWorldZ = 0.0f;                              // +0x10
      boost::shared_ptr<CD3DBatchTexture> mIconTexture;    // +0x14
      boost::shared_ptr<CD3DBatchTexture> mPausedTexture;  // +0x1C
      boost::shared_ptr<CD3DBatchTexture> mStunnedTexture; // +0x24
      /// Own or allied unit: the only ones whose icon blinks while fresh.
      bool mIsFriendly = false;        // +0x2C
      /// Draw the pause/toggle-off overlay over the icon.
      bool mShowPausedOverlay = false; // +0x2D
      /// Draw the stunned overlay over the icon.
      bool mShowStunnedOverlay = false; // +0x2E
      /// The unit's mesh is already on screen, so only the overlays are drawn.
      bool mSuppressBaseIcon = false;  // +0x2F
      /// Formation-preview ghost rather than a live unit.
      bool mIsFormationGhost = false;  // +0x30
      std::uint8_t pad_0031_0033[0x03]{};
    };

    static_assert(sizeof(UnitIconData) == 0x34, "UnitIconData size must be 0x34");
    static_assert(offsetof(UnitIconData, mBlueprint) == 0x04, "UnitIconData::mBlueprint offset must be 0x04");
    static_assert(offsetof(UnitIconData, mWorldX) == 0x08, "UnitIconData::mWorldX offset must be 0x08");
    static_assert(offsetof(UnitIconData, mWorldZ) == 0x10, "UnitIconData::mWorldZ offset must be 0x10");
    static_assert(offsetof(UnitIconData, mIconTexture) == 0x14, "UnitIconData::mIconTexture offset must be 0x14");
    static_assert(offsetof(UnitIconData, mPausedTexture) == 0x1C, "UnitIconData::mPausedTexture offset must be 0x1C");
    static_assert(
      offsetof(UnitIconData, mStunnedTexture) == 0x24, "UnitIconData::mStunnedTexture offset must be 0x24"
    );
    static_assert(offsetof(UnitIconData, mIsFriendly) == 0x2C, "UnitIconData::mIsFriendly offset must be 0x2C");
    static_assert(
      offsetof(UnitIconData, mIsFormationGhost) == 0x30, "UnitIconData::mIsFormationGhost offset must be 0x30"
    );

    /**
     * The strategic-icon pass's per-frame scratch object - `struct_IconAux` in
     * the IDB. `CWldSession::RenderStrategicIcons` lazily allocates exactly one
     * of these into a process-global lane (0x010C4300) on its first frame and
     * reuses it forever after, clearing the five icon runs at the top of each
     * frame rather than reallocating them.
     *
     * Size evidence: the single allocation site pushes 0xACh
     * (`push 0ACh` @ 0x0085B72D) into `operator new` before running the
     * constructor at 0x0085B2A0.
     *
     * Field evidence (constructor 0x0085B2A0 unless noted):
     *  - `+0x00..0x0F` is the camera's viewport rect, copied a float at a time
     *    from `GeomCamera3::viewport.r[3]` (`fld [eax+2B4h]` ->
     *    `fstp [ebp+0]` .. `fld [eax+2C0h]` -> `fstp [ebp+0Ch]`,
     *    0x0085B864..0x0085B88B). It is the one region the constructor leaves
     *    alone, because the render entry rewrites it every frame.
     *  - `+0x10` session (`mov [ebp+10h], edi` @ 0x0085B861), `+0x14` batcher
     *    (`mov [ebp+14h], ebx` @ 0x0085B7C6), `+0x18` camera view
     *    (`mov [ebp+18h], eax` @ 0x0085B7C0).
     *  - `+0x1C` is a float, not the `CWldMap*` the mangled name types into
     *    that argument slot: the render entry stores the incoming slot with
     *    `movss dword ptr [ebp+1Ch], xmm0` (0x0085B85C) after loading it with
     *    `movss xmm0, [esp+argC]`, and the constructor zeroes it with
     *    `movss dword ptr [esi+1Ch], xmm0` (0x0085B2D0) rather than a `mov`.
     *    The lifebar emitter reads it back as the sub-tick interpolant that
     *    drives the fuel-empty blink (`*(float *)(aux+28)` at 0x0085D103).
     *  - `+0x20` the 0xFFFFFFFF solid-colour texture the bar quads are drawn
     *    with (`CD3DBatchTexture::FromSolidColor` @ 0x0085B349, stored at
     *    0x0085B35B/0x0085B38A).
     *  - `+0x28` the generic-icon table: `GetGenericIcons` is handed `aux+0x28`
     *    (`add eax, 28h` @ 0x0085B788) and indexes it as 8-byte elements
     *    (`&_Myfirst[2 * iconType]`), and 0x0085F020 sizes it to exactly 8.
     *  - `+0x38`/`+0x40` the pause and stunned rest textures.
     *  - `+0x48`, `+0x58`, `+0x68`, `+0x78`, `+0x88` the five icon runs, each
     *    a 0x10-byte `msvc8::vector` header the frame entry clears in turn
     *    (`lea eax, [ebp+48h]` .. `lea eax, [ebp+88h]`,
     *    0x0085B7C3..0x0085B82D) and the constructor reserves at
     *    0x200/0x200/0x40/0x80/0x80 elements.
     *  - `+0x98`, `+0x9C`, `+0xA0`, `+0xA4` the four `GameColors.TeamColorMode`
     *    entries, decoded in source order Self/Ally/Enemy/Neutral but stored
     *    Self/Neutral/Ally/Enemy (`mov [esi+98h], eax` 0x0085B4B1,
     *    `[esi+0A0h]` 0x0085B54C, `[esi+0A4h]` 0x0085B5DF, `[esi+9Ch]`
     *    0x0085B672), and `+0xA8` the unidentified-blip colour
     *    (`mov [esi+0A8h], eax` @ 0x0085B6AD).
     *
     * The five runs are drawn in declaration order, which is why the split
     * matters: ground icons, then air icons on top of them (the classifier
     * picks the second run when `RUnitBlueprint::Air.CanFly`, blueprint+0x368,
     * is set - 0x0085C2E8), then the high-sort-priority icons whose blueprint
     * carries its own texture, then the selected units, and finally the
     * lifebars under their own `TLifeBar` technique.
     */
    struct StrategicIconAuxView
    {
      float mViewportX = 0.0f;              // +0x00
      float mViewportY = 0.0f;              // +0x04
      float mViewportWidth = 0.0f;          // +0x08
      float mViewportHeight = 0.0f;         // +0x0C
      CWldSession* mSession = nullptr;      // +0x10
      CD3DPrimBatcher* mBatcher = nullptr;  // +0x14
      const GeomCamera3* mCamera = nullptr; // +0x18
      /// Sub-tick interpolant for this frame; see the `+0x1C` note above.
      float mTickFraction = 0.0f;                                       // +0x1C
      boost::shared_ptr<CD3DBatchTexture> mWhiteTexture;                // +0x20
      msvc8::vector<boost::shared_ptr<CD3DBatchTexture>> mGenericIcons; // +0x28
      boost::shared_ptr<CD3DBatchTexture> mPauseRestTexture;            // +0x38
      boost::shared_ptr<CD3DBatchTexture> mStunnedRestTexture;          // +0x40
      msvc8::vector<UnitIconData> mGroundIcons;       // +0x48
      msvc8::vector<UnitIconData> mAirIcons;          // +0x58
      msvc8::vector<UnitIconData> mHighPriorityIcons; // +0x68
      msvc8::vector<UnitIconData> mSelectedIcons;     // +0x78
      msvc8::vector<UnitIconData> mLifebarIcons;      // +0x88
      std::uint32_t mSelfColor = 0u;         // +0x98
      std::uint32_t mNeutralColor = 0u;      // +0x9C
      std::uint32_t mAllyColor = 0u;         // +0xA0
      std::uint32_t mEnemyColor = 0u;        // +0xA4
      std::uint32_t mUnidentifiedColor = 0u; // +0xA8

      /**
       * Address: 0x0085B2A0 (FUN_0085B2A0, struct_TeamColors::struct_TeamColors)
       * Mangled: struct_IconAux *__stdcall struct_TeamColors::struct_TeamColors(struct_IconAux *this)
       *
       * What it does:
       * Builds the white solid-colour texture, reserves the five icon runs to
       * their binary-observed capacities (0x200/0x200/0x40/0x80/0x80 for
       * ground/air/high-priority/selected/lifebar), and decodes the four
       * `GameColors.TeamColorMode` entries plus the unidentified-blip colour.
       * `mGenericIcons`/`mPauseRestTexture`/`mStunnedRestTexture` are left
       * empty here - the binary fills them from separate calls
       * (`LoadGenericIcons`/`LoadPauseAndStunnedRestTextures`) right after
       * construction, not from this constructor.
       */
      StrategicIconAuxView();

      /**
       * Address: 0x0085E7F0 (FUN_0085E7F0, struct_IconAux::GetGenericIcons)
       * Mangled: LuaPlus::LuaObject *__cdecl struct_IconAux::GetGenericIcons(Moho::CWldSession *session, std::vector *target)
       *
       * What it does:
       * Loads `/lua/ui/game/strategicIcons.lua`'s `GenericIcons` table and
       * fills one `mGenericIcons` slot per `EGenericIconType` key with the
       * named batch texture. `mGenericIcons` is sized to exactly 8 first
       * (0x0085F020, the `msvc8::vector<boost::shared_ptr<CD3DBatchTexture>>`
       * resize lane for this instantiation - a per-type container emission
       * already covered generically by `msvc8::vector<T>::resize`, the same
       * way the sibling `UnitIconData` instantiation's reserve/push_back/erase
       * lanes are documented above rather than hand-recovered).
       */
      void LoadGenericIcons(CWldSession* session);

      /**
       * Address: 0x0085EA60 (FUN_0085EA60, struct_IconAux::GetStunIcons)
       *
       * What it does:
       * Imports strategic icon Lua tables and refreshes pause/stunned overlay
       * rest textures for one icon-aux runtime object.
       */
      void LoadPauseAndStunnedRestTextures(CWldSession* session);
    };

    static_assert(sizeof(StrategicIconAuxView) == 0xAC, "StrategicIconAuxView size must be 0xAC");
    static_assert(
      offsetof(StrategicIconAuxView, mViewportWidth) == 0x08, "StrategicIconAuxView::mViewportWidth offset must be 0x08"
    );
    static_assert(
      offsetof(StrategicIconAuxView, mSession) == 0x10, "StrategicIconAuxView::mSession offset must be 0x10"
    );
    static_assert(
      offsetof(StrategicIconAuxView, mBatcher) == 0x14, "StrategicIconAuxView::mBatcher offset must be 0x14"
    );
    static_assert(offsetof(StrategicIconAuxView, mCamera) == 0x18, "StrategicIconAuxView::mCamera offset must be 0x18");
    static_assert(
      offsetof(StrategicIconAuxView, mTickFraction) == 0x1C, "StrategicIconAuxView::mTickFraction offset must be 0x1C"
    );
    static_assert(
      offsetof(StrategicIconAuxView, mWhiteTexture) == 0x20, "StrategicIconAuxView::mWhiteTexture offset must be 0x20"
    );
    static_assert(
      offsetof(StrategicIconAuxView, mGenericIcons) == 0x28, "StrategicIconAuxView::mGenericIcons offset must be 0x28"
    );
    static_assert(
      offsetof(StrategicIconAuxView, mPauseRestTexture) == 0x38,
      "StrategicIconAuxView::mPauseRestTexture offset must be 0x38"
    );
    static_assert(
      offsetof(StrategicIconAuxView, mStunnedRestTexture) == 0x40,
      "StrategicIconAuxView::mStunnedRestTexture offset must be 0x40"
    );
    static_assert(
      offsetof(StrategicIconAuxView, mGroundIcons) == 0x48, "StrategicIconAuxView::mGroundIcons offset must be 0x48"
    );
    static_assert(
      offsetof(StrategicIconAuxView, mAirIcons) == 0x58, "StrategicIconAuxView::mAirIcons offset must be 0x58"
    );
    static_assert(
      offsetof(StrategicIconAuxView, mHighPriorityIcons) == 0x68,
      "StrategicIconAuxView::mHighPriorityIcons offset must be 0x68"
    );
    static_assert(
      offsetof(StrategicIconAuxView, mSelectedIcons) == 0x78, "StrategicIconAuxView::mSelectedIcons offset must be 0x78"
    );
    static_assert(
      offsetof(StrategicIconAuxView, mLifebarIcons) == 0x88, "StrategicIconAuxView::mLifebarIcons offset must be 0x88"
    );
    static_assert(
      offsetof(StrategicIconAuxView, mSelfColor) == 0x98, "StrategicIconAuxView::mSelfColor offset must be 0x98"
    );
    static_assert(
      offsetof(StrategicIconAuxView, mUnidentifiedColor) == 0xA8,
      "StrategicIconAuxView::mUnidentifiedColor offset must be 0xA8"
    );

    /**
     * Address: 0x0085B2A0 (FUN_0085B2A0, struct_TeamColors::struct_TeamColors)
     *
     * What it does:
     * Builds the white solid-colour texture, reserves the five icon runs to
     * their binary-observed capacities, and decodes the team-color palette.
     * See the class comment above for the full field-by-field evidence.
     */
    StrategicIconAuxView::StrategicIconAuxView()
    {
      mWhiteTexture = CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu);

      mGroundIcons.reserve(0x200);
      mAirIcons.reserve(0x200);
      mHighPriorityIcons.reserve(0x40);
      mSelectedIcons.reserve(0x80);
      mLifebarIcons.reserve(0x80);

      LuaPlus::LuaObject* const colors = moho::GetColors();
      const LuaPlus::LuaObject gameColors = (*colors)["GameColors"];
      const LuaPlus::LuaObject teamColorMode = gameColors["TeamColorMode"];

      // Decoded in the binary's source order (Self/Ally/Enemy/Neutral); the
      // storage order (Self/Neutral/Ally/Enemy) is just field layout, not a
      // reordering of which key feeds which member.
      mSelfColor = SCR_DecodeColor(msvc8::string(teamColorMode["Self"].GetString()));
      mAllyColor = SCR_DecodeColor(msvc8::string(teamColorMode["Ally"].GetString()));
      mEnemyColor = SCR_DecodeColor(msvc8::string(teamColorMode["Enemy"].GetString()));
      mNeutralColor = SCR_DecodeColor(msvc8::string(teamColorMode["Neutral"].GetString()));

      mUnidentifiedColor = moho::GetUnidentifiedColor();
    }

    /**
     * Address: 0x0085E7F0 (FUN_0085E7F0, struct_IconAux::GetGenericIcons)
     *
     * What it does:
     * Loads `/lua/ui/game/strategicIcons.lua`'s `GenericIcons` table and
     * fills one `mGenericIcons` slot per `EGenericIconType` key with the
     * named batch texture.
     */
    void StrategicIconAuxView::LoadGenericIcons(CWldSession* const session)
    {
      mGenericIcons.resize(8);

      const LuaPlus::LuaObject iconTable = SCR_Import(session->mState, "/lua/ui/game/strategicIcons.lua");
      const LuaPlus::LuaObject genericIcons = iconTable.GetByName("GenericIcons");

      for (LuaPlus::LuaTableIterator iter(genericIcons, 1); iter.IsValid(); iter.Next()) {
        EGenericIconType iconType{};
        gpg::RRef enumRef{};
        gpg::RRef_EGenericIconType(&enumRef, &iconType);
        SCR_GetEnum(session->mState, iter.GetKey().GetString(), enumRef);

        mGenericIcons[static_cast<std::size_t>(iconType)] = CD3DBatchTexture::FromFile(iter.GetValue().GetString(), 0u);
      }
    }

    /**
     * Address: 0x0085EA60 (FUN_0085EA60, struct_IconAux::GetStunIcons)
     *
     * What it does:
     * Imports strategic icon Lua tables and refreshes pause/stunned overlay
     * rest textures for one icon-aux runtime object.
     */
    void StrategicIconAuxView::LoadPauseAndStunnedRestTextures(CWldSession* const session)
    {
      LuaPlus::LuaObject iconTable = SCR_Import(session->mState, "/lua/ui/game/strategicIcons.lua");
      LuaPlus::LuaObject pauseIcons = iconTable.GetByName("PauseIcons");
      LuaPlus::LuaObject pauseRest = pauseIcons.GetByName("PauseRest");
      if (pauseRest.IsString()) {
        mPauseRestTexture = CD3DBatchTexture::FromFile(pauseRest.GetString(), 0u);
      }

      iconTable = SCR_Import(session->mState, "/lua/ui/game/strategicIcons.lua");
      LuaPlus::LuaObject stunnedIcons = iconTable.GetByName("StunnedIcons");
      LuaPlus::LuaObject stunnedRest = stunnedIcons.GetByName("StunnedRest");
      if (stunnedRest.IsString()) {
        mStunnedRestTexture = CD3DBatchTexture::FromFile(stunnedRest.GetString(), 0u);
      }
    }

    /**
     * Address: 0x0085CBD0 (FUN_0085CBD0, sub_85CBD0)
     *
     * IDA signature:
     * _DWORD *callcnv_F3 sub_85CBD0@<eax>(_DWORD *a1@<eax>, _DWORD **a2@<ebx>, int a3@<edi>, _DWORD *a4@<esi>, char a5);
     *
     * What it does:
     * Picks the shared "no specific blueprint icon" texture for one unit:
     * a fixed structure icon for immobile blueprints, or a land/naval/air
     * icon looked up by the unit's movement layer for mobile ones, or the
     * plain white texture when the layer doesn't match any of those three.
     * `wantHighlightVariant` selects the `*HL` (highlight) icon set over the
     * plain set - the caller (`PickUnitStrategicIconTexture` below) passes
     * `true` for the mouse-over case and `false` otherwise.
     *
     * Evidence: `iconData->mBlueprint->IsMobile()` is the vtable-slot-4
     * dispatch at 0x0085CBD9/0x0085CBDC (`REntityBlueprint` vftable slot 4,
     * byte-verified against `bin/2025.7.1/ForgedAlliance.exe` at 0x00E0F604
     * == 0x00511B60 == `REntityBlueprint::IsMobile`). The category switch
     * reads `iconData->mUnit->mVariableData.mLayerMask` (UserEntity+0xF0,
     * `cmp .. 0F0h` @ 0x0085CC20/0x0085CC87) and its case labels (1 / 2,4,8 /
     * 16) match `ELayer`'s `LAYER_Land` / `LAYER_Seabed|LAYER_Sub|LAYER_Water`
     * / `LAYER_Air` exactly. Every branch is a plain `boost::shared_ptr`
     * copy (`sub_428340`, itself just `*dst = *src; if (src.pn)
     * ++src.pn->use_count_`) from one of `aux->mGenericIcons`'s eight slots
     * or `aux->mWhiteTexture` - never a weak-to-shared promotion.
     */
    [[nodiscard]] boost::shared_ptr<CD3DBatchTexture> PickGenericStrategicIconTexture(
      const StrategicIconAuxView& aux, const UnitIconData& iconData, const bool wantHighlightVariant
    )
    {
      if (!iconData.mBlueprint->IsMobile()) {
        return aux.mGenericIcons[wantHighlightVariant ? GIT_StructureHL : GIT_Structure];
      }

      switch (static_cast<ELayer>(iconData.mUnit->mVariableData.mLayerMask)) {
        case LAYER_Land:
          return aux.mGenericIcons[wantHighlightVariant ? GIT_LandHL : GIT_Land];
        case LAYER_Seabed:
        case LAYER_Sub:
        case LAYER_Water:
          return aux.mGenericIcons[wantHighlightVariant ? GIT_NavalHL : GIT_Naval];
        case LAYER_Air:
          return aux.mGenericIcons[wantHighlightVariant ? GIT_AirHL : GIT_Air];
        default:
          return aux.mWhiteTexture;
      }
    }

    /**
     * Address: 0x0085D880 (FUN_0085D880, sub_85D880)
     *
     * IDA signature:
     * Moho::CAniPose **__usercall sub_85D880@<eax>(Moho::UserEntity **eax0@<eax>,
     *   Moho::CAniPose **a2@<edx>, char a3@<cl>, int a4, char a5, _DWORD *a1);
     *
     * What it does:
     * Picks the strategic-icon texture for one classified unit. A unit that
     * qualifies for a per-blueprint icon (is a real `UserUnit` and its
     * `mIntelStateFlags` "has real blueprint data" bit is set - the same bit
     * `UserEntity.cpp` already names `kSelectionBracketEnemyVisibleMask`) picks
     * one of the blueprint's four cached textures by `(isHovered, isSelected
     * && selectedVariantEligible)`: Rest / Over / Selected / SelectedOver.
     * Everything else (recon blips, wrecks, props, or a unit whose intel
     * doesn't carry full blueprint data) falls back to
     * `PickGenericStrategicIconTexture`.
     *
     * Evidence, all byte-verified in `FUN_0085D880.asm`:
     *  - `mov edx, [eax+0Ch]; call edx` (0x0085D893/0x0085D89E) is vtable
     *    slot 3 on `iconData.mUnit`, i.e. `UserEntity::IsUserUnit()`
     *    (Hex-Rays' "IsUserUnit2" is its own disambiguation of the
     *    const/non-const overload pair, not a distinct virtual).
     *  - `test byte ptr [eax+3E0h], 10h` (0x0085D8AB/0x0085D954) reads bit
     *    0x10 of `UserUnit::mIntelStateFlags` (already documented on that
     *    field: "0x10=has-data").
     *  - The four cached-texture fetches are inlined `boost::shared_ptr`
     *    copies (unconditional `lock xadd`, no expiry check) from
     *    `iconData.mBlueprint`+0x15C/0x164/0x16C/0x174 -
     *    `mStrategicIconRest/Selected/Over/SelectedOver` exactly (see the
     *    retype note on those fields in `REntityBlueprint.h`).
     */
    [[nodiscard]] boost::shared_ptr<CD3DBatchTexture> PickUnitStrategicIconTexture(
      const StrategicIconAuxView& aux,
      const UnitIconData& iconData,
      const bool isSelected,
      const bool selectedVariantEligible,
      const bool isHovered
    )
    {
      UserUnit* const asUnit = iconData.mUnit->IsUserUnit();
      // Same bit UserEntity.cpp's kSelectionBracketEnemyVisibleMask names on
      // mIntelStateFlags; re-declared locally because that constant is
      // file-private there.
      constexpr std::uint32_t kHasBlueprintIconDataMask = 0x10u;
      const bool usesGenericIcon =
        asUnit == nullptr || (asUnit->mIntelStateFlags & kHasBlueprintIconDataMask) == 0u;

      if (isHovered) {
        if (usesGenericIcon) {
          return PickGenericStrategicIconTexture(aux, iconData, /*wantHighlightVariant=*/true);
        }
        return (isSelected && selectedVariantEligible) ? iconData.mBlueprint->mStrategicIconSelectedOver
                                                         : iconData.mBlueprint->mStrategicIconOver;
      }

      if (isSelected && selectedVariantEligible) {
        return iconData.mBlueprint->mStrategicIconSelected;
      }
      if (usesGenericIcon) {
        return PickGenericStrategicIconTexture(aux, iconData, /*wantHighlightVariant=*/false);
      }
      return iconData.mBlueprint->mStrategicIconRest;
    }

    template <typename TPointee>
    struct SpCountedImplOwnedPointeeStorage
    {
      void* mVftable;
      std::int32_t mUseCount;
      std::int32_t mWeakCount;
      TPointee* mPointee;
    };

    /**
     * Address: 0x0089B860 (FUN_0089B860)
     *
     * What it does:
     * Disposes one `sp_counted_impl_p<SSessionSaveData>` payload by running
     * non-deleting `SSessionSaveData` teardown and releasing owned storage.
     */
    void DisposeCountedSessionSaveDataStorage(
      SpCountedImplOwnedPointeeStorage<SSessionSaveData>* const countedStorage
    ) noexcept
    {
      SSessionSaveData* const saveData = countedStorage->mPointee;
      if (saveData != nullptr) {
        saveData->~SSessionSaveData();
        ::operator delete(static_cast<void*>(saveData));
      }
    }

    /**
     * Address: 0x0089BCF0 (FUN_0089BCF0)
     *
     * What it does:
     * Destroys one `UICommandGraph` instance and releases its owned storage.
     */
    void DestroyUICommandGraphOwned(UICommandGraph* const graph) noexcept
    {
      if (graph == nullptr) {
        return;
      }

      graph->~UICommandGraph();
      ::operator delete(graph);
    }

    /**
     * Address: 0x0089BC90 (FUN_0089BC90)
     *
     * What it does:
     * Disposes one `sp_counted_impl_p<UICommandGraph>` payload by running
     * non-deleting `UICommandGraph` teardown and releasing owned storage.
     */
    void DisposeCountedUICommandGraphStorage(
      SpCountedImplOwnedPointeeStorage<UICommandGraph>* const countedStorage
    ) noexcept
    {
      DestroyUICommandGraphOwned(countedStorage->mPointee);
    }

    [[nodiscard]] boost::detail::sp_counted_base* CreateBoostControlForUICommandGraph(UICommandGraph* const graph)
    {
      if (!graph) {
        return nullptr;
      }

      auto* const control = new (std::nothrow) boost::detail::sp_counted_impl_p<UICommandGraph>(graph);
      if (!control) {
        DestroyUICommandGraphOwned(graph);
        return nullptr;
      }
      return control;
    }

    /**
     * Address: 0x00898F70 (FUN_00898F70, ??0WeakPtr_UICommandGraph@Moho@@QAE@@Z_0)
     *
     * What it does:
     * Performs one weak-lock operation for the session command-graph lane:
     * if the control block still has live shared owners, returns one retained
     * shared handle using the current payload pointer; otherwise returns empty.
     */
    [[nodiscard]] boost::SharedPtrRaw<UICommandGraph>
    LockWeakCommandGraph(UICommandGraph* px, boost::detail::sp_counted_base* control)
    {
      if (!control) {
        return {};
      }

      boost::SharedPtrRaw<UICommandGraph> out{};
      out.px = px;
      out.pi = control;
      if (!out.add_ref_lock()) {
        return {};
      }
      return out;
    }

    void AssignSharedCommandGraph(boost::SharedPtrRaw<UICommandGraph>& out, UICommandGraph* const graph)
    {
      boost::detail::sp_counted_base* const newControl = CreateBoostControlForUICommandGraph(graph);
      UICommandGraph* const ownedGraph = newControl ? graph : nullptr;

      out.release();

      out.px = ownedGraph;
      out.pi = newControl;
    }

    /**
     * Address: 0x0086EDD0 (FUN_0086EDD0, ??0WeakPtr_UICommandGraph@Moho@@QAE@@Z)
     *
     * NOTE (2026-08-20 audit): despite the `WeakPtr_UICommandGraph` mangled
     * name, FUN_0086EDD0's own body proves this member is strong-owning, not
     * weak-observing - exactly the same "WeakPtr_X is really a shared_ptr"
     * situation already fixed for `WeakPtr_CD3DBatchTexture` in
     * CD3DPrimBatcher.cpp. Disassembly: the acquire step is
     * `lock xadd [pi+4],1` (`use_count_` at +0x04, i.e. `add_ref_copy()`, not
     * `weak_add_ref()`) and the release step calls FUN_004229B0 (manually
     * verified by displacement calculation: rel32 -0x0044C449 from 0x0086EDF4
     * resolves to exactly 0x004229B0), which is `sp_counted_base::release()`
     * (see BoostWrappers.h), not `weak_release()`. `CWldSession`'s
     * `mUICommandGraphPx`/`mUICommandGraphControl` fields (declared in
     * CWldSession.h, out of scope for this pass) are therefore a STRONG
     * owning reference to the session's command graph, not a weak observer -
     * their header comment ("weak control block for mUICommandGraphPx") is
     * now known to be wrong and needs a follow-up fix in CWldSession.h. Names
     * here are kept stable (function-local to this TU either way, but the
     * fields they mutate are declared externally) and documented instead.
     *
     * What it does:
     * Copies one shared command-graph payload into `CWldSession`'s owning
     * command-graph lane, rebinding control ownership only when the incoming
     * control block changes.
     */
    void CopySharedToWeakCommandGraph(
      const boost::SharedPtrRaw<UICommandGraph>& shared,
      UICommandGraph*& weakPx,
      boost::detail::sp_counted_base*& weakControl
    )
    {
      weakPx = shared.px;
      boost::detail::sp_counted_base* const incomingControl = shared.pi;

      if (incomingControl != weakControl) {
        if (incomingControl != nullptr) {
          incomingControl->add_ref_copy();
        }

        if (weakControl != nullptr) {
          weakControl->release();
        }

        weakControl = incomingControl;
      }
    }

    /**
     * Address: 0x00824060 (FUN_00824060, Moho::WeakPtr_UICommandGraph::Release)
     *
     * NOTE (2026-08-20 audit): FUN_00824060 is byte-shape-identical to
     * FUN_004229B0 (decrements `use_count_` at +0x04, calls dispose() via
     * vtable slot +0x04, then decrements `weak_count_` at +0x08 and calls
     * destroy() via vtable slot +0x08) - it is release(), already cited under
     * `SharedPtrRaw<T>::release()`'s evidence list in BoostWrappers.h. Session
     * teardown must release the strong reference `CopySharedToWeakCommandGraph`
     * establishes (see its note above), not weak-release it.
     *
     * What it does:
     * Releases `CWldSession`'s owning reference to its command graph on
     * session teardown.
     */
    void ReleaseWeakCommandGraph(UICommandGraph*& px, boost::detail::sp_counted_base*& control)
    {
      if (control) {
        control->release();
      }
      px = nullptr;
      control = nullptr;
    }

    template <typename TNode>
    [[nodiscard]] TNode* AllocateSelfLinkedNode()
    {
      auto* const node = static_cast<TNode*>(::operator new(sizeof(TNode)));
      std::memset(node, 0, sizeof(TNode));
      node->mNext = node;
      node->mPrev = node;
      return node;
    }

  } // namespace

  void UICommandGraph::ReleaseIntrusive(CD3DFont*& font)
  {
    if (!font) {
      return;
    }

    --font->mRefCount;
    if (font->mRefCount == 0) {
      font->Release(1);
    }
    font = nullptr;
  }

  void UICommandGraph::AssignIntrusive(CD3DFont*& dst, CD3DFont* const src)
  {
    if (dst == src) {
      return;
    }

    ReleaseIntrusive(dst);
    dst = src;
    if (dst) {
      ++dst->mRefCount;
    }
  }

  /**
   * Address: 0x00826550 (FUN_00826550, sub_826550)
   *
   * IDA signature:
   * _DWORD *__stdcall sub_826550(int a1);
   *
   * What it does:
   * Tears one draw node down: both dword lanes are released back to their
   * inline storage (freeing the spilled heap block if there is one), the weak
   * owner reference is dropped, and the node is spliced out of its command's
   * intrusive chain.
   *
   * The binary releases lane B before lane A; the order is preserved because
   * `operator delete[]` is observable.
   */
  UICommandGraph::UICommandGraphDrawNode::~UICommandGraphDrawNode()
  {
    mLaneB.ReleaseToInline();
    mLaneA.ReleaseToInline();

    mMeshInstance.release();

    if (mHelperLink.mHead == nullptr) {
      return;
    }

    // Pointer-to-pointer walk: start at the command's chain head and advance
    // through each link's `mNext` until the slot that refers to this link is
    // found, then splice this link out of it.
    CommandGraphHelperLink** slot = &mHelperLink.mHead->mFirst;
    while (*slot != &mHelperLink) {
      slot = &(*slot)->mNext;
    }
    *slot = mHelperLink.mNext;
  }

  /**
   * Address: 0x0082F030 (FUN_0082F030)
   */
  UICommandGraph::HashListNode88* UICommandGraph::AllocateMapABListSentinel()
  {
    return AllocateSelfLinkedNode<HashListNode88>();
  }

  /**
   * Address: 0x0082F5B0 (FUN_0082F5B0)
   */
  UICommandGraph::HashListNode2C* UICommandGraph::AllocateMapCListSentinel()
  {
    return AllocateSelfLinkedNode<HashListNode2C>();
  }

  /**
   * Address: 0x0082FAF0 (FUN_0082FAF0)
   */
  UICommandGraph::HashListNode10* UICommandGraph::AllocateMapDListSentinel()
  {
    return AllocateSelfLinkedNode<HashListNode10>();
  }

  /**
   * Address: 0x0082BF40 (FUN_0082BF40)
   */
  void UICommandGraph::InitMapAB(HashTable<HashListNode88>& table, const UICommandGraph* const owner)
  {
    table.mOwnerByte = static_cast<std::uint8_t>(reinterpret_cast<std::uintptr_t>(owner) & 0xFFu);
    table.mListHead = AllocateMapABListSentinel();
    table.mListSize = 0u;
    table.mBuckets.assign(9u, table.mListHead);
    table.mBucketMask = 1u;
    table.mBucketCount = 1u;
  }

  /**
   * Address: 0x0082C400 (FUN_0082C400)
   */
  void UICommandGraph::InitMapC(HashTable<HashListNode2C>& table, const UICommandGraph* const owner)
  {
    table.mOwnerByte = static_cast<std::uint8_t>(reinterpret_cast<std::uintptr_t>(owner) & 0xFFu);
    table.mListHead = AllocateMapCListSentinel();
    table.mListSize = 0u;
    table.mBuckets.assign(9u, table.mListHead);
    table.mBucketMask = 1u;
    table.mBucketCount = 1u;
  }

  /**
   * Address: 0x0082C8D0 (FUN_0082C8D0)
   */
  void UICommandGraph::InitMapD(HashTable<HashListNode10>& table, const UICommandGraph* const owner)
  {
    table.mOwnerByte = static_cast<std::uint8_t>(reinterpret_cast<std::uintptr_t>(owner) & 0xFFu);
    table.mListHead = AllocateMapDListSentinel();
    table.mListSize = 0u;
    table.mBuckets.assign(9u, table.mListHead);
    table.mBucketMask = 1u;
    table.mBucketCount = 1u;
  }

  /**
   * Address: 0x0082FAB0 (FUN_0082FAB0, MSVC8 `std::list<T>::clear` inline expansion for
   *                      trivial-destructor hash-list nodes)
   * Address: 0x0082C840 (FUN_0082C840, the `HashListNode2C` instantiation of this same
   *                      template, reached from mMapC's teardown. Verified as the same
   *                      body rather than assumed: both are 19 instructions with an
   *                      identical mnemonic sequence, and the sole `call rel32` in each
   *                      resolves to the same target, 0x00957A60 `operator delete`. The
   *                      two node types compile to identical code because neither
   *                      payload needs destroying, so only the link teardown remains.)
   *
   * IDA signature:
   * _DWORD *__usercall sub_82FAB0@<eax>(int a1@<esi>);
   *
   * What it does:
   * Clears one sentinel-headed doubly-linked list in place. Resets the sentinel
   * head's next/prev to itself, zeroes the size lane, then walks each former
   * payload node, destroys its payload and frees its allocation.
   *
   * 0x0082FAB0 is the 0x10-node table's clear and frees without destroying,
   * because that table's payload really is trivially destructible. The AB
   * tables are not: their list-erase helper at 0x0082EF80 calls the draw-node
   * destructor on `node + 0x10` before `operator delete(node)`, so `TNode`
   * opts in through `DestroyPayload`. Without that call each cleared node
   * leaks both spilled dword lanes and one weak reference.
   */
  template <typename TNode>
  void UICommandGraph::ClearHashListNodes(HashTable<TNode>& table) noexcept
  {
    TNode* const head = table.mListHead;
    if (head == nullptr) {
      return;
    }

    // Detach circular list: sentinel becomes empty before node frees so any
    // re-entrancy during ::operator delete cannot observe stale next/prev links.
    TNode* current = head->mNext;
    head->mNext = head;
    head->mPrev = head;
    table.mListSize = 0u;

    while (current != head) {
      TNode* const next = current->mNext;
      // The sentinel head is deliberately excluded from this walk: the binary
      // never constructs its payload, and neither does AllocateSelfLinkedNode.
      if constexpr (requires(TNode* node) { TNode::DestroyPayload(node); }) {
        TNode::DestroyPayload(current);
      }
      ::operator delete(current);
      current = next;
    }
  }

  template <typename TNode>
  void UICommandGraph::DestroyMap(HashTable<TNode>& table)
  {
    ClearHashListNodes(table);

    if (table.mListHead) {
      ::operator delete(table.mListHead);
      table.mListHead = nullptr;
    }

    table.mBuckets = HashBucketVector{};  // VC8 _Tidy(): destroy + free + null the lanes
    table.mBucketMask = 1u;
    table.mBucketCount = 1u;
  }

  /**
   * Address: 0x0082D530 (FUN_0082D530, sub_82D530 -- the SEH-wrapped emission:
   *                      it installs SEH_82D530, carries unwind funclets at
   *                      0x00B843xx and ends in ___CxxFrameHandler3_0)
   * Address: 0x00826620 (FUN_00826620, the same source body emitted without EH
   *                      scaffolding, 86 instructions vs 128)
   *
   * NOTE: these two are NOT ICF twins, despite an earlier note in the progress
   * DB saying so - ICF folds byte-identical COMDATs and these differ in size
   * and at the very first instruction (`push ebx` vs `mov eax, large fs:0`).
   * They are one source function emitted twice, once in a context needing
   * exception scaffolding and once not; the field-by-field copy order is
   * identical in both (mCommandId, helper-link relink, the +0x0C..+0x18 float
   * quad, the three +0x1C..+0x1E bytes, +0x20, the +0x24 weak_release/
   * lock-xadd add_ref pair, the +0x28..+0x40 float run, +0x44, then the two
   * dword-lane copies).
   */
  UICommandGraph::UICommandGraphDrawNode* UICommandGraph::RelocateDrawNode(
    UICommandGraphDrawNode* const destination, UICommandGraphDrawNode& source
  )
  {
    destination->mCommandId = source.mCommandId;

    destination->mHelperLink.mHead = source.mHelperLink.mHead;
    if (source.mHelperLink.mHead != nullptr) {
      destination->mHelperLink.mNext = source.mHelperLink.mHead->mFirst;
      source.mHelperLink.mHead->mFirst = &destination->mHelperLink;
    } else {
      destination->mHelperLink.mNext = nullptr;
    }

    destination->mPositionSum = source.mPositionSum;
    destination->mWeight = source.mWeight;
    destination->mHasResolvedPosition = source.mHasResolvedPosition;
    destination->mIsChainBoundary = source.mIsChainBoundary;
    destination->mIsVisible = source.mIsVisible;

    // Retain a new strong reference on the shared control block rather than
    // transferring ownership - `source` keeps its own reference and is torn
    // down separately by its caller.
    destination->mMeshInstance = source.mMeshInstance.clone_retained();

    destination->mOrientationHint = source.mOrientationHint;
    destination->mPreviousCentroid = source.mPreviousCentroid;
    destination->field_0x40 = source.field_0x40;
    destination->field_0x44 = source.field_0x44;

    const auto relocateLane = [](CommandGraphDwordLane& dstLane, const CommandGraphDwordLane& srcLane) {
      const gpg::core::legacy::FastVectorInsertRuntimeView sourceView{
        reinterpret_cast<std::byte*>(srcLane.mBegin), reinterpret_cast<std::byte*>(srcLane.mEnd),
        reinterpret_cast<std::byte*>(srcLane.mCapacity), reinterpret_cast<std::byte*>(srcLane.mInlineOrigin)
      };
      (void)gpg::core::legacy::InitializeDwordInlineScratchFromView(
        reinterpret_cast<gpg::core::legacy::DwordVectorInlineScratch*>(&dstLane), sourceView
      );
    };
    relocateLane(destination->mLaneA, source.mLaneA);
    relocateLane(destination->mLaneB, source.mLaneB);

    return destination;
  }

  /**
   * Address: 0x00831AB0 (FUN_00831AB0, sub_831AB0)
   */
  void* UICommandGraph::AllocateHashListNode88Storage(const std::size_t count)
  {
    if ((0xFFFFFFFFu / static_cast<std::uint32_t>(count)) < sizeof(HashListNode88)) {
      throw std::bad_alloc();
    }
    return ::operator new(sizeof(HashListNode88) * count);
  }

  /**
   * Address: 0x00831D80 (FUN_00831D80, sub_831D80)
   */
  UICommandGraph::HashListNode88Value* UICommandGraph::ConstructHashListNode88Value(
    HashListNode88Value* const destination, HashListNode88Value& source
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }
    destination->mKey = source.mKey;
    RelocateDrawNode(&destination->mDraw, source.mDraw);
    return destination;
  }

  /**
   * Address: 0x008304D0 (FUN_008304D0, sub_8304D0)
   */
  UICommandGraph::HashListNode88* UICommandGraph::ConstructHashListNode88(
    HashListNode88* const next, HashListNode88* const prev, HashListNode88Value& valueSource
  )
  {
    auto* const node = static_cast<HashListNode88*>(AllocateHashListNode88Storage(1));
    node->mNext = next;
    node->mPrev = prev;
    try {
      ConstructHashListNode88Value(reinterpret_cast<HashListNode88Value*>(&node->mKey), valueSource);
    } catch (...) {
      ::operator delete(node);
      throw;
    }
    return node;
  }

  /**
   * Not a distinct binary function - see the declaration's doc comment.
   */
  std::uint32_t UICommandGraph::HashKeyToBucketIndex(const HashTable<HashListNode88>& table, const std::uint32_t key) noexcept
  {
    const std::ldiv_t split = std::ldiv(static_cast<long>(key ^ 0xDEADBEEFu), 127773L);
    long scrambled = 16807L * split.rem - 2836L * split.quot;
    if (scrambled < 0) {
      scrambled += 0x7FFFFFFFL;
    }
    std::uint32_t bucketIndex = static_cast<std::uint32_t>(scrambled) & table.mBucketMask;
    if (table.mBucketCount <= bucketIndex) {
      bucketIndex += static_cast<std::uint32_t>(-1) - (table.mBucketMask >> 1u);
    }
    return bucketIndex;
  }

  /**
   * Address: 0x0082C240 (FUN_0082C240, sub_82C240)
   *
   * The hash bucket vector stores one boundary pointer per bucket index
   * plus one trailing sentinel-adjacent boundary (N+1 slots for N buckets):
   * bucket[i]'s range is `[mBuckets.mStart[i], mBuckets.mStart[i+1])`, so
   * adjacent buckets share a slot (bucket i's end is bucket i+1's begin).
   * Confirmed directly from this function's own disassembly
   * (`lea ecx,[ecx+eax*4]` - single dword stride per bucket index, not
   * doubled).
   */
  UICommandGraph::HashListNode88* UICommandGraph::FindHashListNode88(
    HashTable<HashListNode88>& table, const std::uint32_t key
  ) noexcept
  {
    const std::uint32_t bucketIndex = HashKeyToBucketIndex(table, key);
    auto* const bucketSlots = reinterpret_cast<HashListNode88**>(table.mBuckets.data());
    HashListNode88* node = bucketSlots[bucketIndex];
    HashListNode88* const bucketEnd = bucketSlots[bucketIndex + 1u];

    if (node == bucketEnd) {
      return table.mListHead;
    }
    while (node->mKey < key) {
      node = node->mNext;
      if (node == bucketEnd) {
        return table.mListHead;
      }
    }
    return (key >= node->mKey) ? node : table.mListHead;
  }

  /**
   * Address: 0x0082C2E0 (FUN_0082C2E0, sub_82C2E0)
   */
  std::pair<UICommandGraph::HashListNode88*, UICommandGraph::HashListNode88*> UICommandGraph::EqualRangeHashListNode88(
    HashTable<HashListNode88>& table, const std::uint32_t key
  ) noexcept
  {
    const std::uint32_t bucketIndex = HashKeyToBucketIndex(table, key);
    auto* const bucketSlots = reinterpret_cast<HashListNode88**>(table.mBuckets.data());
    HashListNode88* node = bucketSlots[bucketIndex];
    HashListNode88* const bucketEnd = bucketSlots[bucketIndex + 1u];

    if (node != bucketEnd) {
      while (node->mKey < key) {
        node = node->mNext;
        if (node == bucketEnd) {
          break;
        }
      }
    }

    if (node == bucketEnd) {
      return {table.mListHead, table.mListHead};
    }

    HashListNode88* const first = node;
    do {
      if (key < node->mKey) {
        break;
      }
      node = node->mNext;
    } while (node != bucketEnd);

    if (first == node) {
      return {table.mListHead, table.mListHead};
    }
    return {first, node};
  }

  /**
   * Address: 0x0082B450 (FUN_0082B450, sub_82B450)
   */
  std::uint32_t UICommandGraph::CountHashListNode88(HashTable<HashListNode88>& table, const std::uint32_t key) noexcept
  {
    const auto [first, last] = EqualRangeHashListNode88(table, key);
    std::uint32_t count = 0u;
    for (HashListNode88* node = first; node != last; node = node->mNext) {
      ++count;
    }
    return count;
  }

  /**
   * Address: 0x0082F050 (FUN_0082F050, sub_82F050)
   */
  std::uint32_t UICommandGraph::CheckedIncrementListSize(const std::uint32_t count, std::uint32_t& sizeField)
  {
    if ((0x1FFFFFFu - sizeField) < count) {
      RuntimeThrowContainerTooLong("list<T> too long");
    }
    sizeField += count;
    return sizeField;
  }

  /**
   * Address: 0x0082BFB0 (FUN_0082BFB0, sub_82BFB0)
   */
  UICommandGraph::HashListNode88* UICommandGraph::InsertOrFindHashListNode88(
    HashTable<HashListNode88>& table, HashListNode88Value& valueSource, bool& outInserted
  )
  {
    if (table.mBucketCount <= (table.mListSize >> 2u)) {
      // Load factor exceeded: grow the bucket boundary array (or just the
      // mask, when slack already covers it) and redistribute exactly one
      // old bucket's nodes between it and the newly-available bucket - the
      // binary's incremental (split-one-bucket-per-insert) rehash, not a
      // full rebuild.
      const auto bucketVectorLength = static_cast<std::uint32_t>(table.mBuckets.size());

      if ((bucketVectorLength - 1u) > table.mBucketCount) {
        if (table.mBucketMask < table.mBucketCount) {
          table.mBucketMask = 2u * table.mBucketMask + 1u;
        }
      } else {
        const std::uint32_t newMask = 2u * bucketVectorLength - 3u;
        table.mBucketMask = newMask;
        table.mBuckets.resize(newMask + 2u, table.mListHead);
      }

      auto* const rehashBucketSlots = reinterpret_cast<HashListNode88**>(table.mBuckets.data());
      const std::uint32_t splitBucketIndex = table.mBucketCount - (table.mBucketMask >> 1u) - 1u;
      HashListNode88* node = rehashBucketSlots[splitBucketIndex];
      HashListNode88* const splitBucketEnd = rehashBucketSlots[splitBucketIndex + 1u];

      if (splitBucketEnd != node) {
        for (;;) {
          // Raw masked hash WITHOUT the wraparound adjustment
          // HashKeyToBucketIndex applies elsewhere: the binary compares
          // this directly against splitBucketIndex, which by construction
          // is always already within [0, mask] on this path.
          const std::ldiv_t split = std::ldiv(static_cast<long>(node->mKey ^ 0xDEADBEEFu), 127773L);
          long scrambled = 16807L * split.rem - 2836L * split.quot;
          if (scrambled < 0) {
            scrambled += 0x7FFFFFFFL;
          }
          const std::uint32_t rehashedIndex = static_cast<std::uint32_t>(scrambled) & table.mBucketMask;

          if (rehashedIndex == splitBucketIndex) {
            node = node->mNext;
          } else {
            HashListNode88* const next = node->mNext;
            if (next != table.mListHead) {
              if (rehashBucketSlots[splitBucketIndex] == node) {
                std::uint32_t walkIndex = splitBucketIndex;
                for (;;) {
                  rehashBucketSlots[walkIndex] = next;
                  if (walkIndex == 0u) {
                    break;
                  }
                  --walkIndex;
                  if (rehashBucketSlots[walkIndex] != node) {
                    break;
                  }
                }
              }

              // Splice `node` out of its current position and onto the
              // tail of the table's global list, immediately before the
              // sentinel - exactly where the newly-available bucket's
              // range belongs.
              HashListNode88* const sentinel = table.mListHead;
              HashListNode88* const oldTail = sentinel->mPrev;
              node->mPrev->mNext = next;
              next->mPrev = node->mPrev;
              node->mNext = sentinel;
              node->mPrev = oldTail;
              oldTail->mNext = node;
              sentinel->mPrev = node;
            }

            // Cascade: any bucket boundary between the split point and the
            // new bucket that still holds the sentinel as its own begin
            // (hasn't been individually established yet) is retargeted to
            // this node's new tail position too.
            std::uint32_t cascadeIndex = table.mBucketCount;
            while (cascadeIndex > splitBucketIndex && rehashBucketSlots[cascadeIndex] == table.mListHead) {
              rehashBucketSlots[cascadeIndex] = node;
              --cascadeIndex;
            }

            if (next == table.mListHead) {
              break;
            }
            node = next;
          }
        }
      }

      ++table.mBucketCount;
    }

    const std::uint32_t bucketIndex = HashKeyToBucketIndex(table, valueSource.mKey);
    auto* const bucketSlots = reinterpret_cast<HashListNode88**>(table.mBuckets.data());
    HashListNode88* insertionPoint = bucketSlots[bucketIndex + 1u];

    if (bucketSlots[bucketIndex] != insertionPoint) {
      bool reachedBegin = false;
      for (;;) {
        insertionPoint = insertionPoint->mPrev;
        if (insertionPoint->mKey <= valueSource.mKey) {
          break;
        }
        if (bucketSlots[bucketIndex] == insertionPoint) {
          reachedBegin = true;
          break;
        }
      }

      if (!reachedBegin) {
        if (insertionPoint->mKey >= valueSource.mKey) {
          outInserted = false;
          return insertionPoint;
        }
        insertionPoint = insertionPoint->mNext;
      }
    }

    HashListNode88* const newNode = ConstructHashListNode88(insertionPoint, insertionPoint->mPrev, valueSource);
    CheckedIncrementListSize(1u, table.mListSize);

    HashListNode88* const oldPrev = newNode->mPrev;
    insertionPoint->mPrev = newNode;
    oldPrev->mNext = newNode;

    if (bucketSlots[bucketIndex] == insertionPoint) {
      std::uint32_t cascadeIndex = bucketIndex;
      for (;;) {
        bucketSlots[cascadeIndex] = newNode;
        if (cascadeIndex == 0u) {
          break;
        }
        --cascadeIndex;
        if (bucketSlots[cascadeIndex] != insertionPoint) {
          break;
        }
      }
    }

    outInserted = true;
    return newNode;
  }

  /**
   * Address: 0x0082B300 (FUN_0082B300, sub_82B300)
   */
  UICommandGraph::UICommandGraphDrawNode* UICommandGraph::FindOrInsertCommandGraphDrawNode(
    const std::uint32_t key, HashTable<HashListNode88>& table
  )
  {
    HashListNode88* const found = FindHashListNode88(table, key);
    if (found != table.mListHead) {
      return &found->mDraw;
    }

    // Miss: build a default-valued draw node payload (0x00824600 -
    // InitCommandGraphIssueRuntimeLane, shared with the command-issue
    // helper's own runtime lane below: identical 0x78-byte shape, see
    // CommandGraphIssueRuntimeView), relocate-copy it into a second
    // temporary, and insert a real node built from `{key, temporary}`.
    CommandGraphIssueRuntimeView tempDefault{};
    (void)InitCommandGraphIssueRuntimeLane(&tempDefault);
    auto* const tempDefaultAsDrawNode = reinterpret_cast<UICommandGraphDrawNode*>(&tempDefault);

    UICommandGraphDrawNode tempRelocated{};
    RelocateDrawNode(&tempRelocated, *tempDefaultAsDrawNode);

    HashListNode88Value insertValue{};
    insertValue.mKey = key;
    RelocateDrawNode(&insertValue.mDraw, tempRelocated);

    bool inserted = false;
    HashListNode88* const resultNode = InsertOrFindHashListNode88(table, insertValue, inserted);

    tempRelocated.~UICommandGraphDrawNode();
    tempDefaultAsDrawNode->~UICommandGraphDrawNode();

    return &resultNode->mDraw;
  }

  /**
   * Address: 0x008300D0 (FUN_008300D0)
   */
  UICommandGraph::CommandGraphTreeNode* UICommandGraph::AllocateTreeSentinelNode()
  {
    auto* const node = static_cast<CommandGraphTreeNode*>(::operator new(sizeof(CommandGraphTreeNode)));
    std::memset(node, 0, sizeof(CommandGraphTreeNode));
    node->mColorOrAllocated = 1u;
    node->mIsSentinel = 0u;
    return node;
  }

  void UICommandGraph::InitTree(CommandGraphTree& tree)
  {
    tree.mAllocProxy = nullptr;
    tree.mHead = AllocateTreeSentinelNode();
    tree.mHead->mIsSentinel = 1u;
    tree.mHead->mLeft = tree.mHead;
    tree.mHead->mParent = tree.mHead;
    tree.mHead->mRight = tree.mHead;
    tree.mSize = 0u;
  }

  /**
   * Address: 0x0082BEE0 (FUN_0082BEE0, sub_82BEE0)
   */
  void UICommandGraph::ReleaseCommandGraphTreeBucket(CommandGraphTreeBucket& bucket) noexcept
  {
    if (bucket.mEdges.data() != nullptr) {
      ::operator delete(bucket.mEdges.data());
    }
    bucket.mEdges.reset_range_lanes_preserve_proxy();
    bucket.mTexture.release();
  }

  /**
   * Address: 0x0082CDE0 (FUN_0082CDE0, sub_82CDE0, `DestroyTree`'s copy of this walk)
   */
  void UICommandGraph::DestroyCommandGraphTreeSubtree(CommandGraphTreeNode* const sentinelHead, CommandGraphTreeNode* node)
  {
    if (node == nullptr || node == sentinelHead || node->mIsSentinel != 0u) {
      return;
    }

    DestroyCommandGraphTreeSubtree(sentinelHead, node->mRight);
    CommandGraphTreeNode* const left = node->mLeft;
    ReleaseCommandGraphTreeBucket(BucketOf(*node));
    ::operator delete(node);
    DestroyCommandGraphTreeSubtree(sentinelHead, left);
  }

  /**
   * Address: 0x00824B50 (FUN_00824B50, sub_824B50)
   *
   * What it does:
   * Destroys command-graph runtime tree nodes rooted at `mHead->mParent`,
   * releasing each node's bucket resources first, then releases the head
   * sentinel and clears head/size lanes.
   */
  void UICommandGraph::DestroyTree(CommandGraphTree& tree)
  {
    if (tree.mHead) {
      DestroyCommandGraphTreeSubtree(tree.mHead, tree.mHead->mParent);
      ::operator delete(tree.mHead);
    }

    tree.mHead = nullptr;
    tree.mSize = 0u;
    tree.mAllocProxy = nullptr;
  }

  /**
   * Address: 0x00824740 (FUN_00824740, func_OnCommandGraphShow)
   */
  void UICommandGraph::OnCommandGraphShow(LuaPlus::LuaState* const state, const bool visible)
  {
    if (!state) {
      return;
    }

    lua_State* const cstate = state->GetCState();
    if (!cstate) {
      return;
    }

    const int savedTop = lua_gettop(cstate);
    lua_getglobal(cstate, "import");
    if (!lua_isfunction(cstate, -1)) {
      lua_settop(cstate, savedTop);
      return;
    }

    lua_pushstring(cstate, "/lua/ui/game/commandgraph.lua");
    if (lua_call(cstate, 1, 1) != 0) {
      lua_settop(cstate, savedTop);
      return;
    }

    if (!lua_istable(cstate, -1)) {
      lua_settop(cstate, savedTop);
      return;
    }

    // Lua 5.0-era ABI: use push+gettable instead of lua_getfield.
    lua_pushstring(cstate, "OnCommandGraphShow");
    lua_gettable(cstate, -2);
    if (!lua_isfunction(cstate, -1)) {
      lua_settop(cstate, savedTop);
      return;
    }

    lua_pushboolean(cstate, visible ? 1 : 0);
    lua_call(cstate, 1, 0);
    lua_settop(cstate, savedTop);
  }

  /**
   * Address: 0x00824D50 (FUN_00824D50, Moho::UICommandGraph::LoadPathParams)
   *
   * IDA signature:
   * void __stdcall Moho::UICommandGraph::LoadPathParams(Moho::UICommandGraph *a1);
   *
   * What it does:
   * Imports `/lua/ui/game/commandgraphparams.lua` on the UI Lua state, builds
   * one node from its `default` entry, then gives every command type its own
   * node: the default is copied in first, and the per-type entry (keyed
   * `<enum prefix><lexical name>`, e.g. `UNITCOMMAND_Attack`) is layered over
   * it. A command type with no entry in the table keeps the default.
   */
  void UICommandGraph::LoadPathParams()
  {
    LuaPlus::LuaState* const state = g_UIManager != nullptr ? g_UIManager->mLuaState : nullptr;
    const LuaPlus::LuaObject module = SCR_Import(state, "/lua/ui/game/commandgraphparams.lua");
    if (module.IsNil()) {
      return;
    }

    const LuaPlus::LuaObject params = module["CommandGraphParams"];
    if (!params.IsTable()) {
      return;
    }

    // 0x00824DE9 open-codes the node constructor here rather than calling it.
    UICommandGraphNode defaults{};
    defaults.LoadTextures(params, "default", state);

    for (std::int32_t index = 0; index < static_cast<std::int32_t>(std::size(mNodes)); ++index) {
      (void)mNodes[index].CopyFrom(defaults);

      auto commandType = static_cast<EUnitCommandType>(index);
      gpg::RRef commandTypeRef{};
      (void)gpg::RRef_EUnitCommandType(&commandTypeRef, &commandType);

      // The reflected type is always the EUnitCommandType enum descriptor, so
      // the binary reads `mPrefix` straight off it at 0x00824F3E rather than
      // going through the IsEnumType() virtual.
      const auto* const enumType = static_cast<const gpg::REnumType*>(commandTypeRef.mType);
      const msvc8::string lexicalName = commandTypeRef.GetLexical();
      const msvc8::string key = gpg::STR_Printf("%s%s", enumType->mPrefix, lexicalName.c_str());

      mNodes[index].LoadTextures(params, key.c_str(), state);
    }
  }

  /**
   * Address: 0x00825150 (FUN_00825150, func_LoadCommandGraphWaypointParams)
   *
   * IDA signature:
   * LuaPlus::LuaObject *sub_825150();
   *
   * What it does:
   * Imports `/lua/ui/game/commandwaypoint.lua` on the UI Lua state and copies
   * its `CommandWaypointParams` table into the seven command-waypoint globals.
   * Each key is optional: a missing or nil entry leaves the global at whatever
   * the previous import (or image load) left there.
   */
  void UICommandGraph::LoadWaypointParams()
  {
    LuaPlus::LuaState* const state = g_UIManager != nullptr ? g_UIManager->mLuaState : nullptr;
    const LuaPlus::LuaObject module = SCR_Import(state, "/lua/ui/game/commandwaypoint.lua");
    if (module.IsNil()) {
      return;
    }

    const LuaPlus::LuaObject params = module["CommandWaypointParams"];
    if (!params.IsTable()) {
      return;
    }

    // The binary re-reads each key after the nil test rather than reusing the
    // probe object, and tests every key even once one is missing.
    if (!params["ui_CurveSegments"].IsNil()) {
      ui_CurveSegments = static_cast<std::int32_t>(params["ui_CurveSegments"].GetNumber());
    }
    if (!params["ui_CurveSmoothness"].IsNil()) {
      ui_CurveSmoothness = static_cast<float>(params["ui_CurveSmoothness"].GetNumber());
    }
    if (!params["ui_PathSmoothness"].IsNil()) {
      ui_PathSmoothness = static_cast<float>(params["ui_PathSmoothness"].GetNumber());
    }
    if (!params["ui_CommandGraphMaxNodeUnits"].IsNil()) {
      ui_CommandGraphMaxNodeUnits =
        static_cast<std::int32_t>(params["ui_CommandGraphMaxNodeUnits"].GetNumber());
    }
    if (!params["ui_MinWaypointSize"].IsNil()) {
      ui_MinWaypointSize = static_cast<float>(params["ui_MinWaypointSize"].GetNumber());
    }
    if (!params["ui_MaxWaypointSize"].IsNil()) {
      ui_MaxWaypointSize = static_cast<float>(params["ui_MaxWaypointSize"].GetNumber());
    }
    if (!params["ui_WaypointLineScale"].IsNil()) {
      ui_WaypointLineScale = static_cast<float>(params["ui_WaypointLineScale"].GetNumber());
    }

    // Not a transcription slip: 0x00825524 stores the `ui_CommandClickScale`
    // value into `ui_WaypointLineScale` (0x00F57CDC), the same global the
    // block above writes. There is no `ui_CommandClickScale` symbol in the
    // image at all, so whichever of the two keys the Lua table defines last
    // wins the line scale. Preserved because the original does it.
    if (!params["ui_CommandClickScale"].IsNil()) {
      ui_WaypointLineScale = static_cast<float>(params["ui_CommandClickScale"].GetNumber());
    }
  }

  /**
   * Address: 0x00828FB0 (FUN_00828FB0, Moho::UICommandGraph::CreateMeshes)
   */
  void UICommandGraph::CreateMeshes()
  {
    // Remaining command-graph mesh build pass (0x00829190 chain) is pending deep lift.
  }

  /**
   * What it does: see the header.
   */
  UICommandGraph::ECommandNodeHighlightState UICommandGraph::ResolveDrawNodeHighlightState(
    const UICommandGraphDrawNode& drawNode
  ) const
  {
    auto* const ownerHelper = reinterpret_cast<UserCommandIssueHelper*>(drawNode.mHelperLink.mHead);
    if (ownerHelper == nullptr) {
      return ECommandNodeHighlightState::Normal;
    }

    if (UserEntity* const hoveredEntity = mSession->GetHoveredUserEntity(); hoveredEntity != nullptr) {
      if (UserUnit* const hoveredUnit = hoveredEntity->IsUserUnit(); hoveredUnit != nullptr) {
        SSelectionSetUserEntity* const cursorEntities = ResolveCommandIssueCursorEntities(*ownerHelper);
        SSelectionSetUserEntity::FindResult found{};
        (void)SSelectionSetUserEntity::Find(&found, cursorEntities, hoveredUnit);
        if (found.mRes != cursorEntities->mHead) {
          return ECommandNodeHighlightState::Highlighted;
        }
      }
    }

    if (ownerHelper->mConstantData.cmd == mSession->GetCursorInfo().mIsDragger) {
      return ECommandNodeHighlightState::Highlighted;
    }

    if (DrawNodeSharesLiveEntityWithSelection(drawNode)) {
      return ECommandNodeHighlightState::Selected;
    }

    return ECommandNodeHighlightState::Normal;
  }

  /**
   * Address: 0x00828280 (FUN_00828280, sub_828280)
   *
   * IDA signature:
   * bool __userpurge sub_828280@<al>(int a1@<eax>, int a2);
   *
   * What it does:
   * Reports whether the draw node's command is aimed at anything the player
   * currently has selected. See the declaration for why the null-helper guard
   * is repeated here.
   */
  bool UICommandGraph::DrawNodeSharesLiveEntityWithSelection(
    const UICommandGraphDrawNode& drawNode
  ) const
  {
    auto* const ownerHelper = reinterpret_cast<UserCommandIssueHelper*>(drawNode.mHelperLink.mHead);
    if (ownerHelper == nullptr) {
      return false;
    }

    SSelectionSetUserEntity* const cursorEntities = ResolveCommandIssueCursorEntities(*ownerHelper);
    return cursorEntities->HasCommonLiveEntityWith(mSession->GetSelection());
  }

  /**
   * Address: 0x008282B0 (FUN_008282B0, sub_8282B0)
   *
   * IDA signature:
   * void __thiscall sub_8282B0(UICommandGraph *this, GeomCamera3 *camera,
   *   CD3DPrimBatcher *batcher, UICommandGraphDrawNode *drawNode);
   *
   * What it does:
   * Draws one command node's waypoint marker: a flat quad centered on the
   * node's averaged position, colored/scaled by
   * `ResolveDrawNodeHighlightState`, sized to a roughly-constant apparent
   * screen size via the camera viewport's perspective-width row
   * (`ProjectViewportWidthRow2`, the same shape as the already-recovered
   * `ProjectViewportDepthRow1`, one row over) and clamped to
   * `[ui_MinWaypointSize, ui_MaxWaypointSize]`.
   */
  void UICommandGraph::DrawWaypointMarker(
    const GeomCamera3& camera, CD3DPrimBatcher& batcher, UICommandGraphDrawNode& drawNode
  ) const
  {
    auto* const helper = reinterpret_cast<UserCommandIssueHelper*>(drawNode.mHelperLink.mHead);
    if (helper == nullptr) {
      return;
    }

    const auto commandType = ResolveCommandIssueHelperCommandType(*helper);
    const CommandGraphNode& node = mNodes[static_cast<std::size_t>(commandType)];

    boost::shared_ptr<CD3DBatchTexture> texture = boost::SharedPtrFromRawRetained(
      reinterpret_cast<const boost::SharedPtrRaw<CD3DBatchTexture>&>(node.mWaypointTexture)
    );

    std::uint32_t color = 0;
    float styleScale = 0.0f;
    switch (ResolveDrawNodeHighlightState(drawNode)) {
    case ECommandNodeHighlightState::Normal:
      color = node.mWaypointColor;
      styleScale = node.mWaypointScale;
      break;
    case ECommandNodeHighlightState::Highlighted:
      color = node.mWaypointHighlightColor;
      styleScale = node.mWaypointHighlightScale;
      break;
    case ECommandNodeHighlightState::Selected:
      color = node.mWaypointSelectedColor;
      styleScale = node.mWaypointSelectedScale;
      break;
    }

    if (!texture) {
      texture = CD3DBatchTexture::FromSolidColor(0xFF30F030u);
    }

    const float invWeight = 1.0f / drawNode.mWeight;
    const Wm3::Vector3f avg{
      drawNode.mPositionSum.x * invWeight, drawNode.mPositionSum.y * invWeight, drawNode.mPositionSum.z * invWeight
    };

    const float depthW = camera.viewport.ProjectViewportWidthRow2(avg);

    float size = (drawNode.field_0x40 * styleScale) / depthW;
    size = std::clamp(size, ui_MinWaypointSize, ui_MaxWaypointSize);

    batcher.SetTexture(texture);

    const CD3DPrimBatcher::Vertex topLeft{avg.x - size, avg.y, avg.z + size, color, 0.0f, 1.0f};
    const CD3DPrimBatcher::Vertex topRight{avg.x - size, avg.y, avg.z - size, color, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex bottomRight{avg.x + size, avg.y, avg.z - size, color, 1.0f, 0.0f};
    const CD3DPrimBatcher::Vertex bottomLeft{avg.x + size, avg.y, avg.z + size, color, 1.0f, 1.0f};
    batcher.DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  /**
   * Address: 0x00829800 (FUN_00829800, sub_829800)
   *
   * IDA signature:
   * float *__userpurge sub_829800@<eax>(Moho::GeomCamera3 *a1@<esi>,
   *   Moho::UICommandGraph *a2, _DWORD *a3, float *a4);
   *
   * What it does: see the declaration.
   */
  CmdId UICommandGraph::ResolveCursorHighlightCommandId(
    const GeomCamera3& camera, const Wm3::Vector2f& cursorScreenPos
  ) const
  {
    if (mMapAB0.mListHead->mNext == mMapAB0.mListHead) {
      return -1;
    }

    float bestScaledDistance = std::numeric_limits<float>::infinity();
    CmdId bestCommandId = -1;

    for (HashListNode88* node = mMapAB0.mListHead->mNext; node != mMapAB0.mListHead; node = node->mNext) {
      const UICommandGraphDrawNode& drawNode = node->mDraw;

      const float invWeight = 1.0f / drawNode.mWeight;
      const Wm3::Vector3f avg{
        drawNode.mPositionSum.x * invWeight, drawNode.mPositionSum.y * invWeight, drawNode.mPositionSum.z * invWeight
      };

      // Frustum-cull the averaged anchor against the camera's view solid
      // before spending a projection + hit test on it.
      bool culledByFrustum = false;
      for (const Wm3::Plane3f& plane : camera.solid2.planes_) {
        const float signedDistance =
          ((plane.Normal.x * avg.x) + (plane.Normal.y * avg.y) + (plane.Normal.z * avg.z)) - plane.Constant;
        if (signedDistance <= 0.0f) {
          culledByFrustum = true;
          break;
        }
      }
      if (culledByFrustum) {
        continue;
      }

      const Wm3::Vector2f screenPos = camera.Project(avg);
      const float dx = screenPos.x - cursorScreenPos.x;
      const float dy = screenPos.y - cursorScreenPos.y;
      const float pixelDistance = std::sqrt((dx * dx) + (dy * dy));

      const float depthW = camera.viewport.ProjectViewportWidthRow2(avg);
      float worldTolerance = drawNode.field_0x40 / depthW;
      worldTolerance = std::clamp(worldTolerance, ui_MinWaypointSize, ui_MaxWaypointSize);

      const float scaledTolerance = worldTolerance * depthW;
      float scaledDistance = depthW * pixelDistance;

      auto* const helper = reinterpret_cast<UserCommandIssueHelper*>(drawNode.mHelperLink.mHead);
      if (helper != nullptr && ResolveCommandIssueHelperCommandType(*helper) == EUnitCommandType::UNITCOMMAND_Ferry) {
        // Ferry waypoints get a small extra tolerance bonus so a ferry order's
        // markers are easier to pick back up under the cursor.
        scaledDistance -= 0.1f;
      }

      // `ui_CommandClickScale` (the decompiled global name at this read) is
      // not a real symbol - see the `ui_WaypointLineScale` doc comment in
      // `UICommandGraph::LoadPathParams` above: both the `ui_WaypointLineScale`
      // and `ui_CommandClickScale` Lua keys write the same global
      // (0x00F57CDC), and that is what this address reads.
      if ((ui_WaypointLineScale * scaledTolerance) < scaledDistance) {
        continue;
      }

      bool preemptsByLiveSelection = false;
      if (helper != nullptr) {
        SSelectionSetUserEntity* const cursorEntities = ResolveCommandIssueCursorEntities(*helper);
        preemptsByLiveSelection = cursorEntities->HasCommonLiveEntityWith(mSession->GetSelection());
      }

      if (bestScaledDistance > scaledDistance || preemptsByLiveSelection) {
        bestScaledDistance = scaledDistance;
        bestCommandId = drawNode.mCommandId;
      }
    }

    return bestCommandId;
  }

  /**
   * Address: 0x00828DD0 (FUN_00828DD0, sub_828DD0)
   *
   * IDA signature:
   * void __usercall sub_828DD0(UICommandGraphDrawNode *drawNode@<?>,
   *   UICommandGraph *graph, CD3DPrimBatcher *batcher);
   *
   * What it does:
   * Poses the node's owned mesh instance at its resolved position (the
   * averaged `mPositionSum/mWeight` anchor when `mHasResolvedPosition`,
   * otherwise the anchor `ResolveCommandGraphAnchorWorldPosition` resolves
   * from the owning command's history) with identity orientation (a snap,
   * not an interpolated move - `SetStance` is called with the same
   * transform as both its start and end). When the anchor came from a real
   * unit blueprint, additionally draws that unit's footprint skirt there.
   *
   * The decompile carries the documented "positive sp value has been
   * detected" reliability warning; the temporary `VTransform` construction
   * it mis-attributes to a stack slot 24 bytes off was re-derived from the
   * raw x86 (0x00828E19..0x00828E3A) instead. The observable geometry
   * (position = averaged anchor, orientation = identity,
   * `SetStance(anchor, anchor)`) matches for both branches regardless.
   */
  void UICommandGraph::DrawPositionNodeMesh(UICommandGraphDrawNode& drawNode, CD3DPrimBatcher& batcher) const
  {
    if (!drawNode.mMeshInstance.px) {
      return;
    }
    auto* const helper = reinterpret_cast<UserCommandIssueHelper*>(drawNode.mHelperLink.mHead);
    if (helper == nullptr) {
      return;
    }

    Wm3::Vector3f anchor{};
    const RUnitBlueprint* unitBlueprint = nullptr;

    if (drawNode.mHasResolvedPosition) {
      const REntityBlueprint* const blueprint = helper->mConstantData.blueprint;
      if (blueprint == nullptr || !blueprint->IsUnitBlueprint()) {
        return;
      }
      unitBlueprint = static_cast<const RUnitBlueprint*>(blueprint);

      const float invWeight = 1.0f / drawNode.mWeight;
      anchor = {
        drawNode.mPositionSum.x * invWeight, drawNode.mPositionSum.y * invWeight, drawNode.mPositionSum.z * invWeight
      };
    } else {
      anchor = ResolveCommandGraphAnchorWorldPosition(*helper);
    }

    const VTransform transform{anchor, Wm3::Quatf{1.0f, 0.0f, 0.0f, 0.0f}};
    drawNode.mMeshInstance.px->SetStance(transform, transform);

    if (unitBlueprint == nullptr) {
      return;
    }

    CHeightField* const heightField = mSession->mWldMap->mTerrainRes->GetHeightField();
    CameraImpl* const camera = CAM_GetCamera(gpg::StrArg("WorldCamera"));
    const std::uint32_t color = drawNode.mIsVisible ? 0xD8000000u : 0xD8280000u;
    DrawUnitSkirt(heightField, unitBlueprint, camera->CameraGetView(), anchor, mSession, &batcher, color);
  }

  /**
   * Address: 0x00828610 (FUN_00828610, Moho::DisplayCommandNode)
   *
   * IDA signature:
   * void __userpurge Moho::DisplayCommandNode(UICommandGraph *this@<ecx>,
   *   GeomCamera3 *camera@<ebx>, UICommandGraphDrawNode *drawNode@<esi>,
   *   CD3DPrimBatcher *batcher);
   *
   * What it does:
   * Draws the "ETA: mm:ss" text label above one command-graph draw node,
   * gated by the "display_eta" option, the command not yet being due
   * (`drawNode.field_0x44 - mSession->mGameTick < 0` skips), and - only for
   * the non-highlighted/non-selected state - an LOD distance test against
   * `ui_MaxTextLOD` using the camera viewport's depth row (the same
   * `ProjectViewportDepthRow1` shape used throughout this file).
   *
   * Glyph size is `field_0x40 * (style scale for the resolved highlight
   * state)`; the label anchors at the node's averaged position offset by
   * that glyph size in X/-Z, then is projected to screen space and nudged
   * by `mDebugFont->mDescent + 1` pixels vertically.
   */
  void UICommandGraph::DisplayCommandNode(
    const GeomCamera3& camera, const UICommandGraphDrawNode& drawNode, CD3DPrimBatcher& batcher
  ) const
  {
    if (drawNode.mHelperLink.mHead == nullptr) {
      return;
    }

    const std::int32_t beatsUntilDue = static_cast<std::int32_t>(drawNode.field_0x44) - mSession->mGameTick;
    if (beatsUntilDue < 0) {
      return;
    }

    auto* const helper = reinterpret_cast<UserCommandIssueHelper*>(drawNode.mHelperLink.mHead);
    const auto commandType = ResolveCommandIssueHelperCommandType(*helper);
    const CommandGraphNode& node = mNodes[static_cast<std::size_t>(commandType)];

    const float invWeight = 1.0f / drawNode.mWeight;
    const Wm3::Vector3f avg{
      drawNode.mPositionSum.x * invWeight, drawNode.mPositionSum.y * invWeight, drawNode.mPositionSum.z * invWeight
    };

    float styleScale = 0.0f;
    switch (ResolveDrawNodeHighlightState(const_cast<UICommandGraphDrawNode&>(drawNode))) {
    case ECommandNodeHighlightState::Normal:
      if (camera.viewport.ProjectViewportDepthRow1(avg) >= ui_MaxTextLOD) {
        return;
      }
      styleScale = node.mWaypointScale;
      break;
    case ECommandNodeHighlightState::Highlighted:
      styleScale = node.mWaypointHighlightScale;
      break;
    case ECommandNodeHighlightState::Selected:
      styleScale = node.mWaypointSelectedScale;
      break;
    }

    const float glyphScale = drawNode.field_0x40 * styleScale;

    if (!OPTIONS_GetBool("display_eta")) {
      return;
    }

    const float seconds = static_cast<float>(beatsUntilDue) * 0.1f;
    const auto truncSeconds = static_cast<std::int32_t>(std::trunc(seconds));
    const msvc8::string label = gpg::STR_Printf("ETA: %d.%02d", truncSeconds / 60, truncSeconds % 60);

    const Wm3::Vector3f textAnchor{avg.x + glyphScale, avg.y, avg.z - glyphScale};
    const Wm3::Vector2f projected = camera.Project(textAnchor);
    const Wm3::Vector2f screenPos{
      static_cast<float>(static_cast<std::int32_t>(projected.x + 1.0f)),
      static_cast<float>(static_cast<std::int32_t>(projected.y - (mDebugFont->mDescent + 1.0f)))
    };

    // Color/scale/maxAdvance are elided register args at this callsite the
    // decompile doesn't show explicitly; `NAN` for maxAdvance is the one
    // value the raw decompile states literally, preserved as-is (an
    // unclipped label). Color/scale use this file's other text-draw
    // defaults (opaque white, unscaled) pending a dedicated re-verification.
    mDebugFont->Render2D(gpg::StrArg(label.c_str()), &batcher, screenPos, 0xFFFFFFFFu, 1.0f, std::numeric_limits<float>::quiet_NaN());
  }

  /**
   * Address: 0x008288D0 (FUN_008288D0, sub_8288D0)
   *
   * IDA signature:
   * void __thiscall sub_8288D0(GeomCamera3 *this, UICommandGraph *graph,
   *   CD3DPrimBatcher *batcher, int tick, float tickFraction,
   *   CommandGraphEdge *edge, char isGlow);
   *
   * What it does:
   * Draws one command-graph "orderline" ribbon segment between two draw
   * nodes' averaged positions via `EmitHermiteRibbonSegments`.
   *
   * Verified against the raw x86 (every `*0.0` term in the endpoint-offset
   * block resolves to a hardware-confirmed zero, exactly the pattern
   * already documented on `EmitHermiteRibbonSegments`): the spline's two
   * control points are the *unmodified* averaged from/to positions, and the
   * two tangents fed to the Hermite blend are each endpoint's own tangent
   * (its `mOrientationHint` when non-zero, else the normalized from-to
   * direction) scaled by a smoothness radius
   * (`min(segmentLength * 0.25, ui_CurveSmoothness * width)`).
   *
   * Color/glow selection: when `edge.mForceHighlightStyle` is set, this
   * skips `ResolveDrawNodeHighlightState` entirely and uses the owning
   * node's `mOrderlineHighlightColor`/`mOrderlineHighlightGlow` directly -
   * i.e. the flag forces the "highlighted" appearance, it does not carry a
   * per-edge custom color (see the field's own doc comment). Otherwise the
   * usual 0/1/2 dispatch picks Normal/Highlighted/Selected colors. For the
   * glow pass (`isGlow`), the color's alpha byte is replaced by the style's
   * glow scalar.
   */
  void UICommandGraph::DrawCommandOrderline(
    const GeomCamera3& camera, CD3DPrimBatcher& batcher, const std::int32_t tick, const float tickFraction,
    const CommandGraphEdge& edge, const bool isGlow
  ) const
  {
    UICommandGraphDrawNode* const fromNode = edge.mFromNode;
    if (fromNode == nullptr) {
      return;
    }
    UICommandGraphDrawNode* const toNode = edge.mToNode;
    if (toNode == nullptr) {
      return;
    }
    auto* const ownerHelper = reinterpret_cast<UserCommandIssueHelper*>(toNode->mHelperLink.mHead);
    if (ownerHelper == nullptr) {
      return;
    }

    const float fromInvWeight = 1.0f / fromNode->mWeight;
    const Wm3::Vector3f fromPos{
      fromNode->mPositionSum.x * fromInvWeight, fromNode->mPositionSum.y * fromInvWeight,
      fromNode->mPositionSum.z * fromInvWeight
    };
    const float toInvWeight = 1.0f / toNode->mWeight;
    const Wm3::Vector3f toPos{
      toNode->mPositionSum.x * toInvWeight, toNode->mPositionSum.y * toInvWeight, toNode->mPositionSum.z * toInvWeight
    };

    const float widthFromDepth = camera.viewport.ProjectViewportWidthRow2(fromPos) * 2.0f;
    const float widthToDepth = camera.viewport.ProjectViewportWidthRow2(toPos) * 2.0f;
    const float width = (edge.mBaseWidth + std::max(widthFromDepth, widthToDepth)) * ui_WaypointLineScale;

    Wm3::Vector3f direction{toPos.x - fromPos.x, toPos.y - fromPos.y, toPos.z - fromPos.z};
    direction.Normalize();

    Wm3::Vector3f fromTangent = direction;
    if (fromNode->mOrientationHint.x != 0.0f || fromNode->mOrientationHint.y != 0.0f
        || fromNode->mOrientationHint.z != 0.0f) {
      fromTangent = fromNode->mOrientationHint;
    }
    Wm3::Vector3f toTangent = direction;
    if (toNode->mOrientationHint.x != 0.0f || toNode->mOrientationHint.y != 0.0f
        || toNode->mOrientationHint.z != 0.0f) {
      toTangent = toNode->mOrientationHint;
    }

    const float segmentLength = std::sqrt(
      ((toPos.x - fromPos.x) * (toPos.x - fromPos.x) + (toPos.y - fromPos.y) * (toPos.y - fromPos.y))
      + (toPos.z - fromPos.z) * (toPos.z - fromPos.z)
    );
    const float smoothRadius = std::min(segmentLength * 0.25f, ui_CurveSmoothness * width);

    const auto commandType = ResolveCommandIssueHelperCommandType(*ownerHelper);
    const CommandGraphNode& node = mNodes[static_cast<std::size_t>(commandType)];

    std::uint32_t color;
    float glow;
    if (edge.mForceHighlightStyle) {
      color = node.mOrderlineHighlightColor;
      glow = node.mOrderlineHighlightGlow;
    } else {
      switch (ResolveDrawNodeHighlightState(*toNode)) {
      case ECommandNodeHighlightState::Selected:
        color = node.mOrderlineSelectedColor;
        glow = node.mOrderlineSelectedGlow;
        break;
      case ECommandNodeHighlightState::Highlighted:
        color = node.mOrderlineHighlightColor;
        glow = node.mOrderlineHighlightGlow;
        break;
      case ECommandNodeHighlightState::Normal:
      default:
        color = node.mOrderlineColor;
        glow = node.mOrderlineGlow;
        break;
      }
    }
    if (isGlow) {
      color &= static_cast<std::uint32_t>(static_cast<std::uint8_t>(glow * 255.0f)) << 24;
    }

    const float uStart = 1.0f - std::fmod((static_cast<double>(tick) + tickFraction) * node.mOrderlineAnimRate, 1.0);

    EmitHermiteRibbonSegments(
      batcher, fromPos, toPos, Wm3::Vector3f{fromTangent.x * smoothRadius, fromTangent.y * smoothRadius, fromTangent.z * smoothRadius},
      Wm3::Vector3f{toTangent.x * smoothRadius, toTangent.y * smoothRadius, toTangent.z * smoothRadius}, width, color,
      uStart, node.mOrderlineAspectRatio
    );
  }

  // Forward declarations: reopens the same file-scope anonymous namespace
  // that defines these two sentinel-headed RB-tree walkers further below (by
  // the selection/save-tree helpers), so `DrawCommandGraphMesh` below - the
  // only command-graph draw method that needs them - can call them here,
  // ahead of their point of definition.
  namespace
  {
    template <typename TNode>
    [[nodiscard]] bool IsSentinelNode(const TNode* node);
    template <typename TNode>
    [[nodiscard]] TNode* NextTreeNode(TNode* node);
  }

  /**
   * Address: 0x00829190 (FUN_00829190, sub_829190)
   *
   * What it does:
   * The per-frame command-graph render pass. Six sub-passes, each under its
   * own primbatcher technique:
   *   A) "TCommand"        - opaque orderlines, walking `mGraphRuntimeTree`
   *      (a texture-bucketed red-black tree; each node's payload is a
   *      `{texture, msvc8::vector<CommandGraphEdge*>}` pair) and drawing
   *      every edge in every bucket with `isGlow=false`.
   *   B) "TCommandGlow"    - the same tree walk again with `isGlow=true`.
   *   C) "TAlphaBlendLinearSampleNoDepth" - waypoint marker billboards,
   *      walking `mMapAB0` (the sentinel-headed draw-node list).
   *   D) "TAlphaBlendLinearSample" - position-node meshes/skirts, same
   *      `mMapAB0` walk, with a flat white texture bound first.
   *   E) "TCommandOther"   - the optional path-preview overlay (gated on
   *      `ui_DrawPathPreview`), then a screen-space pixel projection.
   *   F) (still under TCommandOther) - per-node ETA text labels, a third
   *      `mMapAB0` walk.
   *
   * The two tree walks and three list walks are the decompiler's
   * `boost::shared_ptr`-shaped traversal of `mGraphRuntimeTree`/`mMapAB0`
   * respectively (IDA mistyped both containers as chains of
   * `boost::detail::sp_counted_base_vtbl`/`CD3DBatchTexture` because their
   * node layouts happen to alias those types' field shapes at the read
   * offsets) - recovered here as the same typed RB-tree/list walks every
   * sibling command-graph function already uses.
   *
   * The `__userpurge` signature carries two more register arguments
   * (`CRenderWorldView*`, `boost::shared_ptr<UICommandGraph>&`) that its
   * caller (`sub_85AF40`) always supplies, but this function's own body
   * never dereferences either - confirmed against every callsite in its
   * disassembly. Dropped from this signature rather than kept unused.
   */
  void UICommandGraph::DrawCommandGraphMesh(
    const GeomCamera3& camera, CD3DPrimBatcher& batcher, const std::int32_t tick, const float tickFraction
  )
  {
    batcher.Flush();

    // Pass A: opaque orderlines, bucketed by texture.
    (void)batcher.Setup("TCommand");
    batcher.SetViewProjMatrix(camera);
    for (CommandGraphTreeNode* node = mGraphRuntimeTree.mHead->mLeft;
         node != nullptr && node != mGraphRuntimeTree.mHead; node = NextTreeNode(node)) {
      CommandGraphTreeBucket& bucket = BucketOf(*node);
      batcher.SetTexture(boost::SharedPtrFromRawRetained(bucket.mTexture));
      for (CommandGraphEdge* const edge : bucket.mEdges) {
        DrawCommandOrderline(camera, batcher, tick, tickFraction, *edge, /*isGlow=*/false);
      }
    }
    batcher.Flush();

    // Pass B: glow overlay for the same orderlines.
    (void)batcher.Setup("TCommandGlow");
    batcher.SetViewProjMatrix(camera);
    for (CommandGraphTreeNode* node = mGraphRuntimeTree.mHead->mLeft;
         node != nullptr && node != mGraphRuntimeTree.mHead; node = NextTreeNode(node)) {
      CommandGraphTreeBucket& bucket = BucketOf(*node);
      batcher.SetTexture(boost::SharedPtrFromRawRetained(bucket.mTexture));
      for (CommandGraphEdge* const edge : bucket.mEdges) {
        DrawCommandOrderline(camera, batcher, tick, tickFraction, *edge, /*isGlow=*/true);
      }
    }
    batcher.Flush();

    // Pass C: waypoint marker billboards.
    (void)batcher.Setup("TAlphaBlendLinearSampleNoDepth");
    for (HashListNode88* node = mMapAB0.mListHead->mNext; node != mMapAB0.mListHead; node = node->mNext) {
      DrawWaypointMarker(camera, batcher, node->mDraw);
    }
    batcher.Flush();

    // Pass D: position-node meshes/skirts, over a flat white texture.
    (void)batcher.Setup("TAlphaBlendLinearSample");
    batcher.SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));
    for (HashListNode88* node = mMapAB0.mListHead->mNext; node != mMapAB0.mListHead; node = node->mNext) {
      DrawPositionNodeMesh(node->mDraw, batcher);
    }
    batcher.Flush();

    // Pass E: optional path-preview overlay, then switch to a screen-space
    // pixel projection for the ETA text pass below.
    (void)batcher.Setup("TCommandOther");
    if (ui_DrawPathPreview) {
      DrawPathPreview(*this, camera, batcher, tick, tickFraction);
    }

    batcher.SetProjectionMatrix(MakeViewportPixelProjection(camera));
    batcher.SetViewMatrix(VMatrix4::Identity());

    // Pass F: per-node ETA text labels, in the screen-space projection just set.
    for (HashListNode88* node = mMapAB0.mListHead->mNext; node != mMapAB0.mListHead; node = node->mNext) {
      DisplayCommandNode(camera, node->mDraw, batcher);
    }
    batcher.Flush();
  }

  void DrawCommandGraphMeshIfPresent(
    UICommandGraph* const graph, const GeomCamera3& camera, CD3DPrimBatcher& batcher, const std::int32_t tick,
    const float tickFraction
  )
  {
    if (graph != nullptr) {
      graph->DrawCommandGraphMesh(camera, batcher, tick, tickFraction);
    }
  }

  /**
   * Not a distinct binary function - see `DrawCommandGraphMeshIfPresent`
   * above for why `UICommandGraph::ResolveCursorHighlightCommandId` needs a
   * wrapper here. `Moho::CUIWorldView::UpdateSelection` (UiRuntimeTypes.cpp)
   * calls this through the bare `UICommandGraph*` its `mComGraph` holds.
   * Returns -1 (no highlighted command) when `graph` is null.
   */
  CmdId ResolveCommandGraphCursorHighlightIfPresent(
    UICommandGraph* const graph, const GeomCamera3& camera, const Wm3::Vector2f& cursorScreenPos
  )
  {
    if (graph == nullptr) {
      return -1;
    }
    return graph->ResolveCursorHighlightCommandId(camera, cursorScreenPos);
  }

  // Forward declarations for functions `DrawPathPreview` below needs whose
  // own out-of-line definitions live later in this TU (`func_
  // GetRightMouseButtonAction`, at global scope, is referenced by the linker
  // at global scope so its definition stays there) or that this codebase
  // conventionally forward-declares per-TU rather than sharing a header for
  // (`MultQuadVec`, matching the same one-line declaration already repeated
  // in a dozen other .cpp files that call it).
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);

  /**
   * Address: 0x00821F50 (FUN_00821F50, Moho::UnitCommandCapToCommandType)
   *
   * Defined in Sim.cpp; declared here rather than pulling in Sim.h for one
   * symbol.
   */
  [[nodiscard]] EUnitCommandType UnitCommandCapToCommandType(ERuleBPUnitCommandCaps commandCap);

  /**
   * Address: 0x0082A380 (FUN_0082A380, sub_82A380)
   *
   * What it does:
   * Draws the active move-command's path-preview ribbon: either the
   * Ramer-Douglas-Peucker-simplified world-space path sampled from the
   * previewed army's runtime cell-position scratch buffer
   * (`ui_PathPreview` on), or a straight two-point line from the cursor to
   * the deepest selected unit's current/queued anchor position
   * (`ui_PathPreview` off). Both converge on the same ribbon-emission walk
   * used by `UICommandGraph::DrawCommandOrderline`, styled from the
   * command-graph node matching the pending right-click command, with an
   * arrowhead billboard capping the last segment when the node has one.
   *
   * `arg0`, the IDA-declared first parameter, is not a real argument - see
   * this function's declaration in CWldSession.h.
   *
   * The runtime cell-position buffer's trailing "meta" dword
   * (`SArmyVectorWithMeta::mMetaWord`, modeled as a plain `uint32_t` because
   * different consumers reuse the same four bytes differently) is read here
   * as a pointer to a 3-byte `{sizeX, sizeZ, layer}` footprint descriptor -
   * confirmed against the raw disassembly, not just the decompile, so the
   * reinterpret is applied at this call site rather than changing the
   * field's canonical type.
   */
  void DrawPathPreview(
    UICommandGraph& graph, const GeomCamera3& camera, CD3DPrimBatcher& batcher, const std::int32_t tick,
    const float tickFraction
  )
  {
    CWldSession* const session = graph.mSession;

    const std::int32_t focusArmy = session->FocusArmy;
    if (focusArmy < 0) {
      return;
    }
    UserArmy* const army = session->userArmies[focusArmy];
    if (army == nullptr) {
      return;
    }

    SArmyVectorWithMeta& scratch = army->mVarDat.mRuntimeWordVectorWithMeta;
    const std::size_t cellCount = scratch.mWords.size();
    // The meta dword is only ever a real descriptor pointer once the army's
    // scratch buffer has been populated for STI/path-preview display; a
    // fresh/never-populated army leaves it null.
    const std::uint8_t* const footprintDescriptor = *reinterpret_cast<const std::uint8_t* const*>(&scratch.mMetaWord);

    msvc8::list<Wm3::Vector3f> simplifiedPath{};
    float capWidthSeed = 0.0f;

    if (ui_PathPreview) {
      if (footprintDescriptor == nullptr || cellCount < 2) {
        return;
      }

      capWidthSeed = static_cast<float>(footprintDescriptor[0]);

      STIMap* const stiMap = session->GetSTIMap();
      const auto* const cellPositions = reinterpret_cast<const SOCellPos*>(scratch.mWords.begin());

      msvc8::vector<Wm3::Vector3f> worldPts(cellCount);
      for (std::size_t i = 0; i < cellCount; ++i) {
        worldPts[i] = COORDS_ToWorldPos(
          stiMap, cellPositions[i], static_cast<ELayer>(footprintDescriptor[2]), footprintDescriptor[0],
          footprintDescriptor[1]
        );
      }

      simplifiedPath.push_back(worldPts.front());
      simplifiedPath.push_back(worldPts.back());
      SimplifyPathSpan(
        worldPts, 0, static_cast<std::int32_t>(cellCount) - 1, simplifiedPath, --simplifiedPath.end(),
        ui_PathSmoothness
      );
    } else {
      if (!session->CursorInfo().mHitValid) {
        return;
      }

      UserUnit* const subject = PickPathPreviewSubject(const_cast<SSelectionSetUserEntity&>(session->GetSelection()));
      if (subject == nullptr) {
        return;
      }

      IUnit* const subjectBridge = GetIUnitBridge(subject);
      // The blueprint byte this reads (its own footprint-size lane, same
      // family as the sizeX byte the ui_PathPreview branch above reads from
      // the descriptor) was not independently re-derived against
      // RUnitBlueprint's layout - kept as a raw byte read rather than
      // guessing a named field.
      capWidthSeed = static_cast<float>(reinterpret_cast<const std::uint8_t*>(subjectBridge->GetBlueprint())[216]);

      Wm3::Vector3f endPos = subjectBridge->GetPosition();
      if (MAUI_KeyIsDown(MKEY_SHIFT)) {
        // `GetLastQueuedUserCommandAnchor` and `ResolveCommandGraphAnchorWorldPosition`
        // both ultimately view the same binary object (the unit's most
        // recently queued command-issue helper) through different recovered
        // type lanes - see the former's doc comment in UserUnit.cpp.
        const auto* const anchorHelper =
          reinterpret_cast<const UserCommandIssueHelper*>(GetLastQueuedUserCommandAnchor(subject));
        if (anchorHelper != nullptr) {
          endPos = ResolveCommandGraphAnchorWorldPosition(const_cast<UserCommandIssueHelper&>(*anchorHelper));
        }
      }

      simplifiedPath.push_back(session->CursorInfo().mMouseWorldPos);
      simplifiedPath.push_back(endPos);
    }

    // Two distinct distance-based scale terms, both read off the camera's
    // world/view-matrix row via the front preview point - confirmed distinct
    // (not the same term reused) by their different scale constants and by
    // `capDivisor` alone folding in `capWidthSeed` as a floor:
    //   capDivisor - denominator for the arrowhead cap offset below.
    //   maxWidthTerm - the ribbon half-width term, maxed against the back
    //     point too (matching `DrawCommandOrderline`'s sibling formula)
    //     rather than the single-point read the raw decompile's redundant
    //     reloads collapse to.
    const float frontProjected = camera.viewport.ProjectViewportWidthRow2(simplifiedPath.front());
    const float capDivisor = std::max(capWidthSeed, frontProjected * 3.0f) * 0.2f;

    float maxWidthTerm = frontProjected * 2.0f;
    const float backProjected = camera.viewport.ProjectViewportWidthRow2(simplifiedPath.back()) * 2.0f;
    if (backProjected > maxWidthTerm) {
      maxWidthTerm = backProjected;
    }

    const LuaPlus::LuaObject waypointModule = SCR_Import(g_UIManager->mLuaState, "/lua/ui/game/commandwaypoint.lua");
    LuaPlus::LuaFunction<float> calculateWaypointLineWidth{waypointModule["CalculateWaypointLineWidth"]};
    const float luaWidth = calculateWaypointLineWidth(static_cast<unsigned int>(session->GetSelection().size()));

    const float finalWidth = (maxWidthTerm + luaWidth) * ui_WaypointLineScale;

    // Side-effect-only: the binary re-fills a scratch SCommandModeData via
    // GetLeftMouseButtonAction, then immediately overwrites it with a copy of
    // the resolved commandData and destroys it - net zero data effect, since
    // neither commandData nor anything outside this scratch's own lifetime is
    // touched. No named ECommandMode value 7 exists (this isn't a real
    // COMMOD_Ping|COMMOD_Order union - plain sequential enum, not flag bits);
    // kept as the raw literal the binary compares against.
    CommandModeData commandData{};
    (void)func_GetRightMouseButtonAction(&commandData, &session->CursorInfo(), 0, session);
    if (commandData.mMode == static_cast<ECommandMode>(7)) {
      CommandModeData scratch{};
      (void)session->GetLeftMouseButtonAction(&scratch, &session->CursorInfo(), 0);
    }

    const ERuleBPUnitCommandCaps caps =
      (commandData.mMode == COMMOD_Order) ? commandData.mCommandCaps : RULEUCC_Move;
    UICommandGraph::CommandGraphNode& node = graph.mNodes[static_cast<std::size_t>(UnitCommandCapToCommandType(caps))];

    if (node.mOrderlineTexture.px != nullptr) {
      batcher.SetTexture(boost::SharedPtrFromRawRetained(reinterpret_cast<const boost::SharedPtrRaw<CD3DBatchTexture>&>(
        node.mOrderlineTexture
      )));
    } else {
      batcher.SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));
    }

    const bool hasArrowhead = node.mArrowheadTexture.px != nullptr;
    const float uStart = 1.0f - std::fmod((static_cast<double>(tick) + tickFraction) * node.mOrderlineAnimRate, 1.0);

    for (auto it = simplifiedPath.begin(); it != simplifiedPath.end(); ++it) {
      auto next = it;
      ++next;
      if (next == simplifiedPath.end()) {
        break;
      }

      Wm3::Vector3f p0 = *it;
      Wm3::Vector3f p1 = *next;
      const bool isLastSegment = [&] {
        auto afterNext = next;
        ++afterNext;
        return afterNext == simplifiedPath.end();
      }();

      if (isLastSegment && hasArrowhead) {
        Wm3::Vector3f direction{p1.x - p0.x, p1.y - p0.y, p1.z - p0.z};
        direction.Normalize();
        p1 = Wm3::Vector3f{p1.x + direction.x * finalWidth, p1.y + direction.y * finalWidth, p1.z + direction.z * finalWidth};
      }

      auto prevOfIt = it;
      const bool hasPrevOfIt = (it != simplifiedPath.begin());
      if (hasPrevOfIt) {
        --prevOfIt;
      }
      auto afterNext = next;
      ++afterNext;
      const bool hasAfterNext = (afterNext != simplifiedPath.end());

      Wm3::Vector3f t0{p1.x - p0.x, p1.y - p0.y, p1.z - p0.z};
      if (hasPrevOfIt) {
        t0 = Wm3::Vector3f{p1.x - prevOfIt->x, p1.y - prevOfIt->y, p1.z - prevOfIt->z};
      }
      const float t0Len = std::sqrt(t0.x * t0.x + t0.y * t0.y + t0.z * t0.z);
      if (t0Len > ui_PathSmoothness && t0Len > 0.0f) {
        const float scale = ui_PathSmoothness / t0Len;
        t0 = Wm3::Vector3f{t0.x * scale, t0.y * scale, t0.z * scale};
      }

      Wm3::Vector3f t1{p1.x - p0.x, p1.y - p0.y, p1.z - p0.z};
      if (hasAfterNext) {
        t1 = Wm3::Vector3f{afterNext->x - p0.x, afterNext->y - p0.y, afterNext->z - p0.z};
      }
      const float t1Len = std::sqrt(t1.x * t1.x + t1.y * t1.y + t1.z * t1.z);
      if (t1Len > ui_PathSmoothness && t1Len > 0.0f) {
        const float scale = ui_PathSmoothness / t1Len;
        t1 = Wm3::Vector3f{t1.x * scale, t1.y * scale, t1.z * scale};
      }

      EmitHermiteRibbonSegments(
        batcher, p0, p1, t0, t1, finalWidth, node.mOrderlineSelectedColor, uStart, node.mOrderlineAspectRatio
      );

      if (isLastSegment && hasArrowhead) {
        const float capOffset = (finalWidth / capDivisor) * node.mArrowheadCapOffset;
        batcher.Flush();
        batcher.SetTexture(boost::SharedPtrFromRawRetained(reinterpret_cast<const boost::SharedPtrRaw<CD3DBatchTexture>&>(
          node.mArrowheadTexture
        )));

        Wm3::Vector3f direction{p1.x - p0.x, p1.y - p0.y, p1.z - p0.z};
        direction.Normalize();
        const Wm3::Vector3f capCenter{
          p1.x + direction.x * capOffset, p1.y + direction.y * capOffset, p1.z + direction.z * capOffset};
        const Wm3::Quaternionf orient = COORDS_Orient(direction);

        Wm3::Vector3f corners[4] = {
          {-finalWidth, 0.0f, -finalWidth}, {-finalWidth, 0.0f, finalWidth}, {finalWidth, 0.0f, finalWidth},
          {finalWidth, 0.0f, -finalWidth}};
        for (Wm3::Vector3f& corner : corners) {
          Wm3::Vector3f rotated{};
          (void)MultQuadVec(&rotated, &corner, &orient);
          corner = Wm3::Vector3f{capCenter.x + rotated.x, capCenter.y + rotated.y, capCenter.z + rotated.z};
        }

        batcher.DrawQuad(
          CD3DPrimBatcher::Vertex{corners[0].x, corners[0].y, corners[0].z, 0xFFFFFFFFu, 0.0f, 1.0f},
          CD3DPrimBatcher::Vertex{corners[1].x, corners[1].y, corners[1].z, 0xFFFFFFFFu, 0.0f, 0.0f},
          CD3DPrimBatcher::Vertex{corners[2].x, corners[2].y, corners[2].z, 0xFFFFFFFFu, 1.0f, 0.0f},
          CD3DPrimBatcher::Vertex{corners[3].x, corners[3].y, corners[3].z, 0xFFFFFFFFu, 1.0f, 1.0f}
        );
      }
    }
  }

  /**
   * Address: 0x00824810 (FUN_00824810, ??0UICommandGraph@Moho@@QAE@@Z)
   */
  UICommandGraph::UICommandGraph(CWldSession* const session)
    : mNeedsRebuild(1u)
    , pad_0001{0, 0, 0}
    , mNodes{}
    , mSession(session)
    , mSessionRes1(session ? session->mCommandManager : nullptr)
    , mDebugFont(nullptr)
    , mMapAB0{}
    , mMapAB1{}
    , mMapC{}
    , mMapD{}
    , mGraphRuntimeTree{}
  {
    InitMapAB(mMapAB0, this);
    InitMapAB(mMapAB1, this);
    InitMapC(mMapC, this);
    InitMapD(mMapD, this);
    InitTree(mGraphRuntimeTree);

    boost::SharedPtrRaw<CD3DFont> createdFont = CD3DFont::Create(10, "Andale Mono");
    AssignIntrusive(mDebugFont, createdFont.px);
    createdFont.release();

    LoadPathParams();
    LoadWaypointParams();
    CreateMeshes();
    OnCommandGraphShow(mSession ? mSession->mState : nullptr, true);
  }

  /**
   * Address: 0x00824B80 (FUN_00824B80, ??1UICommandGraph@Moho@@QAE@XZ) cleanup chain.
   */
  UICommandGraph::~UICommandGraph()
  {
    OnCommandGraphShow(mSession ? mSession->mState : nullptr, false);
    DestroyTree(mGraphRuntimeTree);
    DestroyMap(mMapD);
    DestroyMap(mMapC);
    DestroyMap(mMapAB1);
    DestroyMap(mMapAB0);
    ReleaseIntrusive(mDebugFont);
    mSessionRes1 = nullptr;
    mSession = nullptr;
    mNeedsRebuild = 0u;
  }

  namespace
  {
    struct SessionSaveSourceNode
    {
      SessionSaveSourceNode* mLeft;   // +0x00
      SessionSaveSourceNode* mParent; // +0x04
      SessionSaveSourceNode* mRight;  // +0x08
      std::uint32_t mCommandSourceId; // +0x0C
      void* mProvider;                // +0x10
      std::uint8_t mColor;            // +0x14
      std::uint8_t mIsSentinel;       // +0x15
      std::uint8_t pad_16[2];
    };

    static_assert(sizeof(SessionSaveSourceNode) == 0x18, "SessionSaveSourceNode size must be 0x18");
    static_assert(
      offsetof(SessionSaveSourceNode, mCommandSourceId) == 0x0C,
      "SessionSaveSourceNode::mCommandSourceId offset must be 0x0C"
    );
    static_assert(
      offsetof(SessionSaveSourceNode, mProvider) == 0x10, "SessionSaveSourceNode::mProvider offset must be 0x10"
    );
    static_assert(
      offsetof(SessionSaveSourceNode, mIsSentinel) == 0x15, "SessionSaveSourceNode::mIsSentinel offset must be 0x15"
    );

    struct SessionEntityMapNode
    {
      SessionEntityMapNode* mLeft;   // +0x00
      SessionEntityMapNode* mParent; // +0x04
      SessionEntityMapNode* mRight;  // +0x08
      std::uint32_t mEntityId;       // +0x0C
      UserEntity* mEntity;           // +0x10
      std::uint8_t pad_14_17[4];     // +0x14
      std::uint8_t mColor;           // +0x18
      std::uint8_t mIsSentinel;      // +0x19
      std::uint8_t pad_1A[2];
    };

    static_assert(sizeof(SessionEntityMapNode) == 0x1C, "SessionEntityMapNode size must be 0x1C");
    static_assert(
      offsetof(SessionEntityMapNode, mEntityId) == 0x0C,
      "SessionEntityMapNode::mEntityId offset must be 0x0C"
    );
    static_assert(
      offsetof(SessionEntityMapNode, mEntity) == 0x10,
      "SessionEntityMapNode::mEntity offset must be 0x10"
    );
    static_assert(
      offsetof(SessionEntityMapNode, mIsSentinel) == 0x19,
      "SessionEntityMapNode::mIsSentinel offset must be 0x19"
    );

    struct SessionEntityMap
    {
      void* mAllocProxy;            // +0x00
      SessionEntityMapNode* mHead;  // +0x04
      std::uint32_t mSize;          // +0x08
    };

    static_assert(sizeof(SessionEntityMap) == 0x0C, "SessionEntityMap size must be 0x0C");
    static_assert(offsetof(SessionEntityMap, mHead) == 0x04, "SessionEntityMap::mHead offset must be 0x04");
    static_assert(offsetof(SessionEntityMap, mSize) == 0x08, "SessionEntityMap::mSize offset must be 0x08");

    struct CWldSessionOrphanRuntimeView
    {
      std::uint8_t pad_0000_0043[0x44];
      SessionEntityMap mEntityMap;                // +0x44
      std::uint8_t pad_0050_042B[0x3DC];
      SSelectionSetUserEntity mPendingOrphanSet;  // +0x42C
    };

    static_assert(
      offsetof(CWldSessionOrphanRuntimeView, mEntityMap) == 0x44,
      "CWldSessionOrphanRuntimeView::mEntityMap offset must be 0x44"
    );
    static_assert(
      offsetof(CWldSessionOrphanRuntimeView, mPendingOrphanSet) == 0x42C,
      "CWldSessionOrphanRuntimeView::mPendingOrphanSet offset must be 0x42C"
    );
    /// The visibility lane is the same weak-entity set shape as the orphan
    /// lane, but it starts 12 bytes later - only the shared base is really
    /// there - so it needs its own overlay rather than a second member.
    struct CWldSessionVizUpdateRuntimeView
    {
      std::uint8_t pad_0000_0437[0x438];
      SSelectionSetUserEntity mVizUpdateSet;      // +0x438
    };

    static_assert(
      offsetof(CWldSessionVizUpdateRuntimeView, mVizUpdateSet) == 0x438,
      "CWldSessionVizUpdateRuntimeView::mVizUpdateSet offset must be 0x438"
    );

    struct UserEntityWeakLinkSlotRuntimeView
    {
      void* mOwnerLinkSlot; // +0x00
    };

    static_assert(
      sizeof(UserEntityWeakLinkSlotRuntimeView) == sizeof(void*),
      "UserEntityWeakLinkSlotRuntimeView size must be pointer-sized"
    );

    struct CursorInfoRuntimeView
    {
      std::uint8_t mHitValid; // +0x00
      std::uint8_t pad_01[3];
      Wm3::Vector3f mMouseWorldPos;            // +0x04
      UserEntityWeakLinkSlotRuntimeView mUnitHover; // +0x10
      UserEntityWeakLinkSlotRuntimeView mPrevious;  // +0x14
      std::int32_t mIsDragger;                 // +0x18
      Wm3::Vector2f mMouseScreenPos;           // +0x1C
    };

    static_assert(sizeof(CursorInfoRuntimeView) == 0x24, "CursorInfoRuntimeView size must be 0x24");
    static_assert(offsetof(CursorInfoRuntimeView, mUnitHover) == 0x10, "CursorInfoRuntimeView::mUnitHover offset must be 0x10");
    static_assert(offsetof(CursorInfoRuntimeView, mPrevious) == 0x14, "CursorInfoRuntimeView::mPrevious offset must be 0x14");
    static_assert(
      offsetof(CursorInfoRuntimeView, mIsDragger) == 0x18, "CursorInfoRuntimeView::mIsDragger offset must be 0x18"
    );

    struct CWldSessionCursorRuntimeView
    {
      std::uint8_t pad_0000_04AF[0x4B0];
      CursorInfoRuntimeView mCursorInfo; // +0x4B0
    };

    static_assert(
      offsetof(CWldSessionCursorRuntimeView, mCursorInfo) == 0x4B0,
      "CWldSessionCursorRuntimeView::mCursorInfo offset must be 0x4B0"
    );

    [[nodiscard]] CursorInfoRuntimeView& AccessCursorInfoRuntime(CWldSession& session) noexcept
    {
      return reinterpret_cast<CWldSessionCursorRuntimeView*>(&session)->mCursorInfo;
    }

    [[nodiscard]] const CursorInfoRuntimeView& AccessCursorInfoRuntime(const CWldSession& session) noexcept
    {
      return reinterpret_cast<const CWldSessionCursorRuntimeView*>(&session)->mCursorInfo;
    }

    [[nodiscard]] MouseInfo& AccessCursorInfo(CWldSession& session) noexcept
    {
      return *reinterpret_cast<MouseInfo*>(&AccessCursorInfoRuntime(session));
    }

    [[nodiscard]] const MouseInfo& AccessCursorInfo(const CWldSession& session) noexcept
    {
      return *reinterpret_cast<const MouseInfo*>(&AccessCursorInfoRuntime(session));
    }

    struct SessionSaveTagNode
    {
      SessionSaveTagNode* mLeft;   // +0x00
      SessionSaveTagNode* mParent; // +0x04
      SessionSaveTagNode* mRight;  // +0x08
      msvc8::string mTagName;      // +0x0C
      std::uint8_t mColor;         // +0x28
      std::uint8_t mIsSentinel;    // +0x29
      std::uint8_t pad_2A[2];
    };

    static_assert(sizeof(SessionSaveTagNode) == 0x2C, "SessionSaveTagNode size must be 0x2C");
    static_assert(offsetof(SessionSaveTagNode, mTagName) == 0x0C, "SessionSaveTagNode::mTagName offset must be 0x0C");
    static_assert(
      offsetof(SessionSaveTagNode, mIsSentinel) == 0x29, "SessionSaveTagNode::mIsSentinel offset must be 0x29"
    );

    struct SessionSaveNodeOwnerView
    {
      std::uint8_t pad_0000[0x3D4];
      SessionSaveTagNode* mTagTreeHead; // +0x3D4
    };

    static_assert(
      offsetof(SessionSaveNodeOwnerView, mTagTreeHead) == 0x3D4,
      "SessionSaveNodeOwnerView::mTagTreeHead offset must be 0x3D4"
    );

    class ISessionSaveSourceProvider
    {
    public:
      virtual ~ISessionSaveSourceProvider() = default;
      virtual void* Slot04() = 0;
      virtual void* Slot08() = 0;
      virtual void* GetSaveNodeOwner() = 0; // vtable +0x0C
    };

    template <typename TNode>
    [[nodiscard]] bool IsSentinelNode(const TNode* const node)
    {
      return !node || node->mIsSentinel != 0u;
    }

    template <typename TNode>
    [[nodiscard]] TNode* NextTreeNode(TNode* node)
    {
      if (!node || IsSentinelNode(node)) {
        return node;
      }

      if (!IsSentinelNode(node->mRight)) {
        node = node->mRight;
        while (!IsSentinelNode(node->mLeft)) {
          node = node->mLeft;
        }
        return node;
      }

      TNode* parent = node->mParent;
      while (!IsSentinelNode(parent) && node == parent->mRight) {
        node = parent;
        parent = parent->mParent;
      }
      return parent;
    }

    /**
     * Address: 0x0066A300 (FUN_0066A300)
     *
     * What it does:
     * Resolves one `UserEntity*` from one weak-set index lane by loading the
     * node weak-owner slot and returning `ownerLinkSlot - 8` when linked.
     */
    [[nodiscard]] UserEntity*
      DecodeSelectionIndexOwner(const SSelectionSetUserEntity::Index* const index) noexcept
    {
      constexpr std::uintptr_t kSelectionOwnerLinkOffset = offsetof(UserEntity, mIUnitChainHead);
#if defined(MOHO_ABI_MSVC8_COMPAT)
      static_assert(kSelectionOwnerLinkOffset == 0x08, "UserEntity selection weak-link offset must stay 0x08");
#endif

      void* const ownerLinkSlot = index->mNode->mEnt.mOwnerLinkSlot;
      if (ownerLinkSlot == nullptr) {
        return nullptr;
      }

      return reinterpret_cast<UserEntity*>(static_cast<std::byte*>(ownerLinkSlot) - kSelectionOwnerLinkOffset);
    }

    [[nodiscard]] UserEntity* DecodeSelectedUserEntity(const SSelectionWeakRefUserEntity& weakRef)
    {
      if (!weakRef.mOwnerLinkSlot) {
        return nullptr;
      }

      constexpr std::uintptr_t kSelectionOwnerLinkOffset = offsetof(UserEntity, mIUnitChainHead);
#if defined(MOHO_ABI_MSVC8_COMPAT)
      static_assert(kSelectionOwnerLinkOffset == 0x08, "UserEntity selection weak-link offset must stay 0x08");
#endif

      const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(weakRef.mOwnerLinkSlot);
      if (raw < kSelectionOwnerLinkOffset) {
        return nullptr;
      }

      return reinterpret_cast<UserEntity*>(raw - kSelectionOwnerLinkOffset);
    }

    // DecodeUserEntityWeakRef(const CameraUserEntityWeakRef&) lives in
    // CameraImpl.h/.cpp now - it decodes the same GetArmyUnitsInFrustum()
    // lanes and CRenderWorldView's build-drag adjacency pass needs it too.

    [[nodiscard]] UserEntity* DecodeUserEntityWeakLinkSlot(const UserEntityWeakLinkSlotRuntimeView& weakSlot)
    {
      constexpr std::uintptr_t kUserEntityWeakOwnerOffset = offsetof(UserEntity, mIUnitChainHead);
#if defined(MOHO_ABI_MSVC8_COMPAT)
      static_assert(kUserEntityWeakOwnerOffset == 0x08, "UserEntity weak-link owner offset must stay 0x08");
#endif

      const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(weakSlot.mOwnerLinkSlot);
      if (raw == 0u || raw == kUserEntityWeakOwnerOffset || raw < kUserEntityWeakOwnerOffset) {
        return nullptr;
      }

      return reinterpret_cast<UserEntity*>(raw - kUserEntityWeakOwnerOffset);
    }

    /**
     * Address: 0x0081FD2B..0x0081FD4E (inlined into
     * `Moho::SCommandModeData::HandleEvent`, FUN_0081FCD0)
     *
     * What it does:
     * Resolves the entity a command-mode drag snapshot is hovering.
     * `MouseInfo::mUnitHover` is an intrusive weak-link slot rather than a
     * live pointer (the same lane `CWldSession::GetHoveredUserEntity` decodes
     * for the session's own cursor), and an entity the session has already
     * orphaned (`mMarkedForDeletion`) counts as "nothing hovered".
     */
    [[nodiscard]] UserEntity* DecodeHoveredDragEntity(const MouseInfo& cursor) noexcept
    {
      UserEntity* const entity =
        DecodeUserEntityWeakLinkSlot(reinterpret_cast<const UserEntityWeakLinkSlotRuntimeView&>(cursor.mUnitHover));
      if (entity == nullptr || entity->mMarkedForDeletion != 0u) {
        return nullptr;
      }
      return entity;
    }

    // GetHoveredUserEntity is now CWldSession::GetHoveredUserEntity, a public
    // member (declared near GetCursorInfo() in the header) - promoted so the
    // command-graph render pass in CRenderWorldView.cpp can call it too.

    // ResolveIUnitBridge was a duplicate of UserUnit.h's GetIUnitBridge -
    // callers below now use that instead.

    [[nodiscard]] bool ContainsUnitPtr(const msvc8::vector<UserUnit*>& units, const UserUnit* const unit)
    {
      return std::find(units.begin(), units.end(), unit) != units.end();
    }

    void AppendUnitUnique(msvc8::vector<UserUnit*>& units, UserUnit* const unit)
    {
      if (unit == nullptr || ContainsUnitPtr(units, unit)) {
        return;
      }
      units.push_back(unit);
    }

    void RemoveUnitIfPresent(msvc8::vector<UserUnit*>& units, const UserUnit* const unit)
    {
      msvc8::vector<UserUnit*> filteredUnits{};
      filteredUnits.reserve(units.size());
      for (UserUnit* const candidate : units) {
        if (candidate != unit) {
          filteredUnits.push_back(candidate);
        }
      }
      units = filteredUnits;
    }

    [[nodiscard]] bool ContainsEntityPtr(const msvc8::vector<UserEntity*>& entities, const UserEntity* const entity)
    {
      return std::find(entities.begin(), entities.end(), entity) != entities.end();
    }

    void CollectSelectionEntities(const SSelectionSetUserEntity& selection, msvc8::vector<UserEntity*>& outEntities)
    {
      outEntities.clear();

      const SSelectionNodeUserEntity* const head = selection.mHead;
      if (head == nullptr) {
        return;
      }

      for (const SSelectionNodeUserEntity* node = head->mLeft; node && node != head; node = NextTreeNode(node)) {
        UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
        if (entity == nullptr || ContainsEntityPtr(outEntities, entity)) {
          continue;
        }
        outEntities.push_back(entity);
      }
    }

    /**
     * Address: 0x0081D160 (FUN_0081D160)
     *
     * What it does:
     * Returns true when at least one live entity in the current selection is in
     * the `TELEPORTATION` category.
     */
    [[nodiscard]] bool SelectionContainsTeleportationUnit(SSelectionSetUserEntity& selection)
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      if (head == nullptr) {
        return false;
      }

      msvc8::string teleportationCategory("TELEPORTATION");
      SSelectionNodeUserEntity* node = head->mLeft;
      node = SSelectionSetUserEntity::find(&selection, node, &node);
      while (node != head) {
        UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
        if (entity != nullptr && entity->IsInCategory(teleportationCategory)) {
          return true;
        }

        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&selection, node, &node);
      }

      return false;
    }

    /**
     * Address: 0x0081DB40 (FUN_0081DB40, func_CoordinatedAttack)
     *
     * What it does:
     * Returns true when the dragged command is an attack/form-attack command
     * and no live selected user-unit already has that command helper queued.
     *
     * Invocation: sole caller in the binary is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, 2167 instructions, owned by this file), from the
     * `RULEUCC_Attack` hovered-target arm at 0x0081FEBD - recovered below and
     * calling this by name.
     */
    [[nodiscard]] bool CanStartCoordinatedAttack(CWldSession& session, const CmdId commandId)
    {
      UserCommandIssueHelper* const helper = FindCommandIssueHelperInSession(&session, commandId);
      if (helper == nullptr) {
        return false;
      }

      const EUnitCommandType commandType = ResolveCommandIssueHelperCommandType(*helper);
      if (commandType != EUnitCommandType::UNITCOMMAND_Attack &&
          commandType != EUnitCommandType::UNITCOMMAND_FormAttack) {
        return false;
      }

      SSelectionSetUserEntity& selection = session.mSelection;
      SSelectionNodeUserEntity* const head = selection.mHead;
      if (head == nullptr) {
        return true;
      }

      SSelectionNodeUserEntity* node = head->mLeft;
      node = SSelectionSetUserEntity::find(&selection, node, &node);
      while (node != head) {
        UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;
        IUnit* const iunit = GetIUnitBridge(userUnit);
        if (userUnit != nullptr && iunit != nullptr && !iunit->IsDead() && !iunit->DestroyQueued()) {
          UserCommandQueue* const manager = userUnit->GetCommandQueue();
          if (UserUnitManagerContainsCommandIssueHelper(manager, helper)) {
            return false;
          }
        }

        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&selection, node, &node);
      }

      return true;
    }

    /**
     * Address: 0x0081DD00 (FUN_0081DD00)
     *
     * IDA signature:
     * char __cdecl sub_81DD00(Moho::WeakSet_UserEntity *a1, struct_CommandIssueHelper *a2);
     *
     * What it does:
     * Tests whether a just-issued Move/FormMove drag command (`helper`) may
     * be silently restarted in place as Patrol/FormPatrol instead of being
     * queued as a brand-new order. Returns false when `helper` is null, the
     * selection is empty, or `helper`'s resolved command type is neither
     * Move nor FormMove. Otherwise walks the live selection: any live,
     * non-dead, non-destroy-queued `UserUnit` with a command queue that is
     * in the "POD" category vetoes the restart outright. For every such
     * unit whose queue already contains `helper` at a position other than
     * the last entry (queue depth over 1 and `helper` is not the tail),
     * every queued command in that unit's whole resolved queue must
     * resolve to `helper`'s own command type, or the restart is rejected;
     * units whose queue doesn't meet that depth/position/membership gate
     * are simply skipped. Returns true once every live selected entity has
     * been scanned without a rejection.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, 2167 instructions, owned by this file), from the
     * drag-move patrol-restart arm (0x008207E6) - on success the caller
     * skips issuing a new command and instead calls
     * `RestartMoveCommandAsPatrol` below with the same selection and helper.
     * `HandleEvent` is recovered below and calls this by name.
     */
    [[nodiscard]] bool CanRestartMoveCommandAsPatrol(
      SSelectionSetUserEntity& selection,
      UserCommandIssueHelper* const helper
    )
    {
      if (helper == nullptr) {
        return false;
      }

      SSelectionNodeUserEntity* const head = selection.mHead;
      if (head == nullptr) {
        return false;
      }

      SSelectionNodeUserEntity* node = head->mLeft;
      node = SSelectionSetUserEntity::find(&selection, node, &node);

      const EUnitCommandType commandType = ResolveCommandIssueHelperCommandType(*helper);
      if (node == head ||
          (commandType != EUnitCommandType::UNITCOMMAND_Move &&
           commandType != EUnitCommandType::UNITCOMMAND_FormMove)) {
        return false;
      }

      const msvc8::string podCategory("POD");

      while (node != head) {
        UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;
        IUnit* const iunit = GetIUnitBridge(userUnit);

        if (userUnit != nullptr && iunit != nullptr && !iunit->IsDead() && !iunit->DestroyQueued()) {
          UserCommandQueue* const manager = userUnit->GetCommandQueue();
          if (manager != nullptr) {
            if (userUnit->IsInCategory(podCategory)) {
              return false;
            }

            if (GetUserUnitManagerQueueSize(manager) <= 1
                || GetUserUnitManagerQueueTailHelperRaw(manager) == helper
                || !UserUnitManagerContainsCommandIssueHelper(manager, helper)) {
              return false;
            }

            if (!UserUnitManagerQueueHasUniformCommandType(manager, commandType)) {
              return false;
            }
          }
        }

        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&selection, node, &node);
      }

      return true;
    }

    /**
     * Address: 0x0081DEF0 (FUN_0081DEF0)
     *
     * IDA signature:
     * std::map *__usercall sub_81DEF0@<eax>(Moho::WeakSet_UserEntity *ebx0@<ebx>, struct_CommandIssueHelper *a2);
     *
     * What it does:
     * Companion to `CanRestartMoveCommandAsPatrol`, invoked only once that
     * gate has confirmed the restart is safe. Resolves `helper`'s own
     * command type (Move -> Patrol, FormMove -> FormPatrol) then walks
     * every live selected entity's command queue via
     * `RestartQueuedCommandsFromHelper`, which reissues every queue entry
     * from `helper` onward (inclusive) that still shares its original
     * command type.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below, 0x008207F7), called with the same weak
     * selection set still live in a register from the
     * `CanRestartMoveCommandAsPatrol` call immediately before it.
     */
    void RestartMoveCommandAsPatrol(SSelectionSetUserEntity& selection, UserCommandIssueHelper* const helper)
    {
      const EUnitCommandType originalCommandType = ResolveCommandIssueHelperCommandType(*helper);
      const EUnitCommandType restartCommandType =
        (originalCommandType == EUnitCommandType::UNITCOMMAND_Move)
          ? EUnitCommandType::UNITCOMMAND_Patrol
          : EUnitCommandType::UNITCOMMAND_FormPatrol;

      SSelectionNodeUserEntity* const head = selection.mHead;
      if (head == nullptr) {
        return;
      }

      SSelectionNodeUserEntity* node = head->mLeft;
      node = SSelectionSetUserEntity::find(&selection, node, &node);

      while (node != head) {
        UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;
        IUnit* const iunit = GetIUnitBridge(userUnit);

        if (userUnit != nullptr && iunit != nullptr && !iunit->IsDead() && !iunit->DestroyQueued()) {
          if (UserCommandQueue* const manager = userUnit->GetCommandQueue(); manager != nullptr) {
            RestartQueuedCommandsFromHelper(manager, helper, originalCommandType, restartCommandType);
          }
        }

        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&selection, node, &node);
      }
    }

    /**
     * Address: 0x0081E050 (FUN_0081E050)
     *
     * IDA signature:
     * char __cdecl sub_81E050(Moho::WeakSet_UserEntity *arg0, float *a2, char a3);
     *
     * What it does:
     * Scans the live selection for eligible `UserUnit`s (`IsUserUnit`, has a
     * command queue, not dead, not destroy-queued), accumulating their live
     * `IUnit::GetPosition()` into `outAnchor` for a running average. Unless
     * `skipPatrolCheck` is set, also inspects each eligible unit's
     * most-recently-queued command helper - taken from its factory command
     * queue when the unit is immobile (`IUnit::IsMobile()` false), otherwise
     * its regular command queue - and returns true immediately the moment
     * that command resolves to Patrol/FormPatrol (the caller then reissues
     * the drag command as-is, using the existing target, with no new
     * anchor). Otherwise, when that command's own command-graph anchor
     * position (`ResolveCommandGraphAnchorWorldPosition`, 0x0081CFD0)
     * resolves to a valid (non-NaN) position, `outAnchor` is overwritten
     * with it (last live match wins). After the scan: if `outAnchor` ended
     * up anything other than the zero vector (an anchor override was
     * found), it is kept as-is; otherwise `outAnchor` is replaced by the
     * running position average. Returns false on both of those paths - only
     * the early Patrol/FormPatrol detection returns true.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below), called twice from the `RULEUCC_Patrol`
     * arm (0x00820BD7 and 0x00820CED): once for the plain-selection drag and
     * once for the paired rally-point `ISSUE_FactoryCommand` drag, each time
     * immediately followed by `Moho::STIMap::GetSurface` snapping `outAnchor`
     * to the terrain when this returns false.
     */
    [[nodiscard]] bool ResolveGroupMoveAnchorOrDetectPatrol(
      SSelectionSetUserEntity& selection,
      Wm3::Vector3f& outAnchor,
      const bool skipPatrolCheck
    )
    {
      outAnchor = Wm3::Vector3f::Zero();

      SSelectionNodeUserEntity* const head = selection.mHead;
      if (head == nullptr) {
        return false;
      }

      SSelectionNodeUserEntity* node = head->mLeft;
      node = SSelectionSetUserEntity::find(&selection, node, &node);

      std::int32_t eligibleCount = 0;
      Wm3::Vector3f anchorOverride = Wm3::Vector3f::Zero();

      while (node != head) {
        UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;

        if (userUnit != nullptr) {
          if (UserCommandQueue* const manager = userUnit->GetCommandQueue(); manager != nullptr) {
            IUnit* const iunit = GetIUnitBridge(userUnit);
            if (iunit != nullptr && !iunit->IsDead() && !iunit->DestroyQueued()) {
              ++eligibleCount;
              const Wm3::Vec3f& position = iunit->GetPosition();
              outAnchor.x += position.x;
              outAnchor.y += position.y;
              outAnchor.z += position.z;

              if (!skipPatrolCheck) {
                UserCommandIssueHelper* lastHelper = GetUserUnitManagerLastQueuedHelper(manager);
                if (!iunit->IsMobile()) {
                  if (UserCommandQueue* const factoryManager = userUnit->GetFactoryCommandQueue();
                      factoryManager != nullptr) {
                    lastHelper = GetUserUnitManagerLastQueuedHelper(factoryManager);
                  }
                }

                if (lastHelper != nullptr) {
                  const EUnitCommandType lastCommandType = ResolveCommandIssueHelperCommandType(*lastHelper);
                  if (lastCommandType == EUnitCommandType::UNITCOMMAND_Patrol ||
                      lastCommandType == EUnitCommandType::UNITCOMMAND_FormPatrol) {
                    return true;
                  }

                  if (const Wm3::Vector3f resolvedAnchor = ResolveCommandGraphAnchorWorldPosition(*lastHelper);
                      IsValidVector3f(resolvedAnchor)) {
                    anchorOverride = resolvedAnchor;
                  }
                }
              }
            }
          }
        }

        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&selection, node, &node);
      }

      if (const Wm3::Vector3f zero = Wm3::Vector3f::Zero(); Wm3::Vector3f::Compare(&anchorOverride, &zero)) {
        outAnchor = anchorOverride;
        return false;
      }

      if (eligibleCount > 0) {
        const float invCount = 1.0f / static_cast<float>(eligibleCount);
        outAnchor.x *= invCount;
        outAnchor.y *= invCount;
        outAnchor.z *= invCount;
      }

      return false;
    }

    /**
     * Address: 0x0081E2E0 (FUN_0081E2E0)
     *
     * IDA signature:
     * char __cdecl sub_81E2E0(Moho::WeakSet_UserEntity *a1, float *a2);
     *
     * What it does:
     * Ferry-command sibling of `ResolveGroupMoveAnchorOrDetectPatrol`.
     * Scans the live selection for eligible `UserUnit`s (`IsUserUnit`, has
     * a command queue, not dead, not destroy-queued). For each: resolves
     * its most-recently-queued command helper; when one exists, accumulates
     * that command's own command-graph anchor position
     * (`ResolveCommandGraphAnchorWorldPosition`) into `outAnchor` and clears
     * the "all still ferrying" flag unless that command is itself
     * `UNITCOMMAND_Ferry`; when none exists, accumulates the unit's live
     * `IUnit::GetPosition()` instead and always clears the flag. After the
     * scan, `outAnchor` is divided by the eligible-unit count (left
     * untouched when there were none). Returns true when every eligible
     * unit's queued command was already `UNITCOMMAND_Ferry` (including the
     * vacuous case of no eligible units at all - the caller then reissues
     * the ferry command as-is), false otherwise (`outAnchor` now holds the
     * averaged anchor/position for the caller to snap to the terrain
     * surface).
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below, 0x008216BD), from the `RULEUCC_Ferry`
     * command-capability arm.
     */
    [[nodiscard]] bool ResolveGroupFerryAnchorOrDetectFerry(
      SSelectionSetUserEntity& selection,
      Wm3::Vector3f& outAnchor
    )
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      if (head == nullptr) {
        return true;
      }

      SSelectionNodeUserEntity* node = head->mLeft;
      node = SSelectionSetUserEntity::find(&selection, node, &node);

      std::int32_t eligibleCount = 0;
      bool allFerrying = true;

      while (node != head) {
        UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;

        if (userUnit != nullptr) {
          if (UserCommandQueue* const manager = userUnit->GetCommandQueue(); manager != nullptr) {
            IUnit* const iunit = GetIUnitBridge(userUnit);
            if (iunit != nullptr && !iunit->IsDead() && !iunit->DestroyQueued()) {
              ++eligibleCount;

              UserCommandIssueHelper* const lastHelper = GetUserUnitManagerLastQueuedHelper(manager);
              if (lastHelper != nullptr) {
                const Wm3::Vector3f anchor = ResolveCommandGraphAnchorWorldPosition(*lastHelper);
                outAnchor.x += anchor.x;
                outAnchor.y += anchor.y;
                outAnchor.z += anchor.z;

                if (ResolveCommandIssueHelperCommandType(*lastHelper) != EUnitCommandType::UNITCOMMAND_Ferry) {
                  allFerrying = false;
                }
              } else {
                const Wm3::Vec3f& position = iunit->GetPosition();
                outAnchor.x += position.x;
                outAnchor.y += position.y;
                outAnchor.z += position.z;
                allFerrying = false;
              }
            }
          }
        }

        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&selection, node, &node);
      }

      if (eligibleCount > 0) {
        const float invCount = 1.0f / static_cast<float>(eligibleCount);
        outAnchor.x *= invCount;
        outAnchor.y *= invCount;
        outAnchor.z *= invCount;
      }

      return allFerrying;
    }

    /**
     * Address: 0x0081E4E0 (FUN_0081E4E0)
     *
     * IDA signature:
     * int __usercall sub_81E4E0@<eax>(Moho::WeakSet_UserEntity *eax0@<eax>, Wm3::Vector3f a2, int a3);
     *
     * What it does:
     * Returns the already-queued command-issue helper (if any) whose
     * blueprint pointer exactly matches `candidateBlueprint` AND whose own
     * command-graph anchor world position snaps to the same footprint cell
     * as `dragPosition` - i.e. detects "about to queue a second build order
     * for the same structure at the same spot". Only runs when the
     * selection holds exactly one live, eligible `UserUnit` (`IsUserUnit`,
     * has a command queue, not dead, not destroy-queued); returns null for
     * every other case, including a selection with zero or more than one
     * entity.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below, 0x00821E8A), from the
     * `COMMOD_Build`/`COMMOD_BuildAnchored` arm: when the drag position is
     * not a legal build spot, the existing colocated order is decremented
     * (`ISSUE_DecreaseCommandCount`) instead of a duplicate being stacked.
     */
    [[nodiscard]] UserCommandIssueHelper* FindColocatedQueuedBuildOrder(
      SSelectionSetUserEntity& selection,
      const Wm3::Vector3f& dragPosition,
      const REntityBlueprint* const candidateBlueprint
    )
    {
      if (selection.size() != 1) {
        return nullptr;
      }

      SSelectionNodeUserEntity* node = selection.mHead->mLeft;
      node = SSelectionSetUserEntity::find(&selection, node, &node);

      UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
      UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;
      if (userUnit == nullptr) {
        return nullptr;
      }

      UserCommandQueue* const manager = userUnit->GetCommandQueue();
      if (manager == nullptr) {
        return nullptr;
      }

      IUnit* const iunit = GetIUnitBridge(userUnit);
      if (iunit == nullptr || iunit->IsDead() || iunit->DestroyQueued()) {
        return nullptr;
      }

      return FindColocatedQueuedBuildOrderInManager(manager, dragPosition, candidateBlueprint);
    }

    /**
     * Address: 0x0081E610 (FUN_0081E610)
     *
     * IDA signature:
     * std::map_uint_WeakPtr_UserEntity::_Node *__usercall sub_81E610@<eax>(
     *     int a1@<eax>, Moho::WeakSet_UserEntity *a2, Moho::WeakSet_UserEntity *a3, Moho::WeakSet_UserEntity *a4);
     *
     * What it does:
     * Splits the live entities of `source` into `rallyPointSet` (entities
     * in the "RALLYPOINT" category) and `otherSet` (everything else). The
     * binary inlines the same category-bitset test
     * `Moho::UserEntity::IsInCategory` (0x008B97C0) already performs -
     * verified field-for-field against that recovered body - so this calls
     * it directly per entity rather than re-inlining the raw bitset index
     * math. `a1` (the binary's category-lookup-resolver source) is not a
     * separate parameter here: `IsInCategory` resolves it from the
     * entity's own `mSession`, which is always the same session this
     * selection belongs to. The binary's own return value is raw
     * find-iterator debris from the last loop step; no caller inspects it.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below), called three times - from the
     * `RULEUCC_Move` (0x0082069A), `RULEUCC_Patrol` (0x0082095E) and
     * `RULEUCC_CallTransport` (0x00820F49) arms - to split the current
     * selection ahead of a rally-point-aware factory command.
     */
    void SplitSelectionByRallyPointCategory(
      SSelectionSetUserEntity& source,
      SSelectionSetUserEntity& rallyPointSet,
      SSelectionSetUserEntity& otherSet
    )
    {
      const msvc8::string rallyPointCategory("RALLYPOINT");

      SSelectionNodeUserEntity* const head = source.mHead;
      if (head == nullptr) {
        return;
      }

      SSelectionNodeUserEntity* node = head->mLeft;
      node = SSelectionSetUserEntity::find(&source, node, &node);

      while (node != head) {
        if (UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt); entity != nullptr) {
          SSelectionSetUserEntity::AddResult addResult{};
          if (entity->IsInCategory(rallyPointCategory)) {
            (void)SSelectionSetUserEntity::Add(&addResult, &rallyPointSet, entity);
          } else {
            (void)SSelectionSetUserEntity::Add(&addResult, &otherSet, entity);
          }
        }

        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&source, node, &node);
      }
    }

    /**
     * Address: 0x0081E700 (FUN_0081E700)
     *
     * IDA signature:
     * std::map_uint_WeakPtr_UserEntity::_Node *__cdecl sub_81E700(
     *     Moho::WeakSet_UserEntity *a1, Moho::WeakSet_UserEntity *a2, Moho::WeakSet_UserEntity *a3);
     *
     * What it does:
     * Splits the live, mobile (`IUnit::IsMobile()`), `UserUnit` entities of
     * `source` for a ferry-command drag: units in the "TRANSPORTATION"
     * category that are also "AIR" or "AIRSTAGINGPLATFORM" go into
     * `airTransportSet` (the candidate ferriers); every other mobile unit
     * that is in the "LAND" category goes into `landUnitSet` (the
     * candidate passengers). Non-mobile units, non-`UserUnit` entities, and
     * mobile units that are neither an eligible air transport nor LAND are
     * left out of both sets. The binary's own return value is raw
     * find-iterator debris from the last loop step; no caller inspects it.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below), from the `RULEUCC_Ferry` arm
     * (0x0082162F) - `airTransportSet` becomes the selection fed into
     * `ResolveGroupFerryAnchorOrDetectFerry` immediately afterward - and from
     * the `RULEUCC_Transport` arm's no-extra-selection branch (0x008213D6).
     */
    void SplitSelectionForFerryCommand(
      SSelectionSetUserEntity& source,
      SSelectionSetUserEntity& airTransportSet,
      SSelectionSetUserEntity& landUnitSet
    )
    {
      const msvc8::string transportationCategory("TRANSPORTATION");
      const msvc8::string airCategory("AIR");
      const msvc8::string airStagingCategory("AIRSTAGINGPLATFORM");
      const msvc8::string landCategory("LAND");

      SSelectionNodeUserEntity* const head = source.mHead;
      if (head == nullptr) {
        return;
      }

      SSelectionNodeUserEntity* node = head->mLeft;
      node = SSelectionSetUserEntity::find(&source, node, &node);

      while (node != head) {
        UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;
        IUnit* const iunit = GetIUnitBridge(userUnit);

        if (userUnit != nullptr && iunit != nullptr && iunit->IsMobile()) {
          const bool isAirTransport = entity->IsInCategory(transportationCategory) &&
            (entity->IsInCategory(airCategory) || entity->IsInCategory(airStagingCategory));

          SSelectionSetUserEntity::AddResult addResult{};
          if (isAirTransport) {
            (void)SSelectionSetUserEntity::Add(&addResult, &airTransportSet, entity);
          } else if (entity->IsInCategory(landCategory)) {
            (void)SSelectionSetUserEntity::Add(&addResult, &landUnitSet, entity);
          }
        }

        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&source, node, &node);
      }
    }

    /**
     * Address: 0x0081E9E0 (FUN_0081E9E0)
     *
     * IDA signature:
     * std::map_uint_WeakPtr_UserEntity::_Node *__cdecl sub_81E9E0(
     *     Moho::WeakSet_UserEntity *a1, Moho::WeakSet_UserEntity *a2, Moho::WeakSet_UserEntity *a3);
     *
     * What it does:
     * Splits the live `UserUnit` entities of `source` by the "REBUILDER"
     * category: units in that category go into `rebuilderSet`, every other
     * `UserUnit` goes into `nonRebuilderSet`. Non-`UserUnit` entities are
     * left out of both sets. The binary's own return value is raw
     * find-iterator debris from the last loop step; no caller inspects it.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below, 0x00820222), splitting the selection
     * ahead of issuing a guard-style command at a hovered "STRUCTURE"
     * target - `nonRebuilderSet` is issued the command immediately after
     * with the hovered entity as its direct target, `rebuilderSet` gets the
     * same command aimed at the structure's world position instead.
     */
    void SplitSelectionByRebuilderCategory(
      SSelectionSetUserEntity& source,
      SSelectionSetUserEntity& nonRebuilderSet,
      SSelectionSetUserEntity& rebuilderSet
    )
    {
      const msvc8::string rebuilderCategory("REBUILDER");

      SSelectionNodeUserEntity* const head = source.mHead;
      if (head == nullptr) {
        return;
      }

      SSelectionNodeUserEntity* node = head->mLeft;
      node = SSelectionSetUserEntity::find(&source, node, &node);

      while (node != head) {
        UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;

        if (userUnit != nullptr) {
          SSelectionSetUserEntity::AddResult addResult{};
          if (userUnit->IsInCategory(rebuilderCategory)) {
            (void)SSelectionSetUserEntity::Add(&addResult, &rebuilderSet, entity);
          } else {
            (void)SSelectionSetUserEntity::Add(&addResult, &nonRebuilderSet, entity);
          }
        }

        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&source, node, &node);
      }
    }

    /**
     * Address: 0x0081EB20 (FUN_0081EB20)
     *
     * IDA signature:
     * _Iterator_base **__usercall sub_81EB20@<eax>(
     *     Moho::WeakSet_UserEntity *a1@<ebx>, Moho::WeakSet_UserEntity *a2, Moho::WeakSet_UserEntity *a3);
     *
     * What it does:
     * Splits the live `UserUnit` entities of `source` for an attack-move-
     * to-ground drag: units that are both mobile (`IUnit::IsMobile()`) and
     * set to `FIRESTATE_ReturnFire` go into `aggressiveMoveSet` (eligible
     * for AggressiveMove); every other live `UserUnit` (immobile, or on a
     * different fire state) goes into `otherSet`. Non-`UserUnit` entities
     * are left out of both sets. The binary's own return value is raw
     * find-iterator debris from the last loop step; no caller inspects it.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below, 0x0081FF48), from the `RULEUCC_Attack`
     * no-hover ground-target arm: `aggressiveMoveSet` is issued
     * `UNITCOMMAND_AggressiveMove` immediately afterward when non-empty.
     */
    void SplitSelectionForAggressiveMove(
      SSelectionSetUserEntity& source,
      SSelectionSetUserEntity& aggressiveMoveSet,
      SSelectionSetUserEntity& otherSet
    )
    {
      SSelectionNodeUserEntity* const head = source.mHead;
      if (head == nullptr) {
        return;
      }

      SSelectionNodeUserEntity* node = head->mLeft;
      node = SSelectionSetUserEntity::find(&source, node, &node);

      while (node != head) {
        UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;

        if (userUnit != nullptr) {
          IUnit* const iunit = GetIUnitBridge(userUnit);
          const bool eligible = iunit != nullptr && iunit->IsMobile() &&
            userUnit->mUnitVarDat.mFireState == FIRESTATE_ReturnFire;

          SSelectionSetUserEntity::AddResult addResult{};
          if (eligible) {
            (void)SSelectionSetUserEntity::Add(&addResult, &aggressiveMoveSet, entity);
          } else {
            (void)SSelectionSetUserEntity::Add(&addResult, &otherSet, entity);
          }
        }

        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&source, node, &node);
      }
    }

    [[nodiscard]] bool
    AreEntitySetsEqual(const msvc8::vector<UserEntity*>& lhs, const msvc8::vector<UserEntity*>& rhs)
    {
      if (lhs.size() != rhs.size()) {
        return false;
      }

      for (const UserEntity* const entity : lhs) {
        if (!ContainsEntityPtr(rhs, entity)) {
          return false;
        }
      }

      return true;
    }

    // EraseSelectionNodeAndAdvance is declared in CWldSession.h (hoisted to
    // external linkage below the anonymous namespace at 0x0066A550/0x007B30D0)
    // and is visible here via that include.

    void ClearSelectionSet(SSelectionSetUserEntity& selection)
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      if (head == nullptr) {
        selection.mSize = 0u;
        selection.mSizeMirrorOrUnused = 0u;
        return;
      }

      SSelectionNodeUserEntity* cursor = head->mLeft;
      (void)selection.EraseRange(&cursor, head->mLeft, head);
      selection.mSizeMirrorOrUnused = selection.mSize;
    }

    struct CWldSessionSelectionStatsRuntimeView
    {
      std::uint8_t pad_0000_04AC[0x4AC];
      std::int32_t maxSelectionSize; // +0x4AC
    };
    static_assert(
      offsetof(CWldSessionSelectionStatsRuntimeView, maxSelectionSize) == 0x4AC,
      "CWldSessionSelectionStatsRuntimeView::maxSelectionSize offset must be 0x4AC"
    );

    void BuildSelectionSyncMask(const SSelectionSetUserEntity& selection, SSyncFilterMaskBlock& outMask)
    {
      BVIntSet selectionIds{};
      const SSelectionNodeUserEntity* const head = selection.mHead;
      if (head != nullptr) {
        for (const SSelectionNodeUserEntity* node = head->mLeft; node && node != head; node = NextTreeNode(node)) {
          UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
          if (entity == nullptr || entity->IsUserUnit() == nullptr) {
            continue;
          }
          (void)selectionIds.Add(static_cast<unsigned int>(entity->mParams.mEntityId));
        }
      }

      outMask = selectionIds;
    }

    [[nodiscard]] bool IsSelectionNil(const SSelectionNodeUserEntity* const node)
    {
      return node == nullptr || node->mIsSentinel != 0u;
    }

    [[nodiscard]] SSelectionNodeUserEntity*
    SelectionMin(SSelectionNodeUserEntity* node, SSelectionNodeUserEntity* const head)
    {
      while (!IsSelectionNil(node) && !IsSelectionNil(node->mLeft)) {
        node = node->mLeft;
      }
      return IsSelectionNil(node) ? head : node;
    }

    [[nodiscard]] SSelectionNodeUserEntity*
    SelectionMax(SSelectionNodeUserEntity* node, SSelectionNodeUserEntity* const head)
    {
      while (!IsSelectionNil(node) && !IsSelectionNil(node->mRight)) {
        node = node->mRight;
      }
      return IsSelectionNil(node) ? head : node;
    }

    void RecomputeSelectionExtrema(WeakEntitySetUserEntity& selection)
    {
      if (selection.mHead == nullptr) {
        return;
      }

      SSelectionNodeUserEntity* const head = selection.mHead;
      SSelectionNodeUserEntity* const root = head->mParent;
      if (IsSelectionNil(root)) {
        head->mParent = head;
        head->mLeft = head;
        head->mRight = head;
        return;
      }

      head->mLeft = SelectionMin(root, head);
      head->mRight = SelectionMax(root, head);
    }

    void ReplaceSelectionSubtree(
      WeakEntitySetUserEntity& selection,
      SSelectionNodeUserEntity* const oldNode,
      SSelectionNodeUserEntity* const newNode
    )
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      if (oldNode->mParent == head) {
        head->mParent = newNode;
      } else if (oldNode == oldNode->mParent->mLeft) {
        oldNode->mParent->mLeft = newNode;
      } else {
        oldNode->mParent->mRight = newNode;
      }

      if (!IsSelectionNil(newNode)) {
        newNode->mParent = oldNode->mParent;
      }
    }

    void RotateSelectionLeft(WeakEntitySetUserEntity& selection, SSelectionNodeUserEntity* const node)
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      SSelectionNodeUserEntity* const pivot = node->mRight;
      node->mRight = pivot->mLeft;
      if (!IsSelectionNil(pivot->mLeft)) {
        pivot->mLeft->mParent = node;
      }

      pivot->mParent = node->mParent;
      if (node->mParent == head) {
        head->mParent = pivot;
      } else if (node == node->mParent->mLeft) {
        node->mParent->mLeft = pivot;
      } else {
        node->mParent->mRight = pivot;
      }

      pivot->mLeft = node;
      node->mParent = pivot;
    }

    void RotateSelectionRight(WeakEntitySetUserEntity& selection, SSelectionNodeUserEntity* const node)
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      SSelectionNodeUserEntity* const pivot = node->mLeft;
      node->mLeft = pivot->mRight;
      if (!IsSelectionNil(pivot->mRight)) {
        pivot->mRight->mParent = node;
      }

      pivot->mParent = node->mParent;
      if (node->mParent == head) {
        head->mParent = pivot;
      } else if (node == node->mParent->mRight) {
        node->mParent->mRight = pivot;
      } else {
        node->mParent->mLeft = pivot;
      }

      pivot->mRight = node;
      node->mParent = pivot;
    }

    [[nodiscard]] std::uint32_t SelectionKeyFromEntity(const UserEntity* const entity) noexcept
    {
      return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(entity));
    }

    /**
     * Address: 0x007FDFE0 (FUN_007FDFE0, std::map<unsigned int,WeakPtr<UserEntity>>::find
     * — lower-bound descent by uint key, matching this function's direct
     * equality-during-descent shape to the same effect. Emitted via
     * FindSelectionNodeByKey's real callers: FindSelectionNodeByEntityGuarded
     * (0x00867780, above) and this file's other selection-lookup sites.
     */
    [[nodiscard]] SSelectionNodeUserEntity*
    FindSelectionNodeByKey(const WeakEntitySetUserEntity& selection, const std::uint32_t key)
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      if (head == nullptr) {
        return nullptr;
      }

      SSelectionNodeUserEntity* node = head->mParent;
      while (!IsSelectionNil(node)) {
        if (key < node->mKey) {
          node = node->mLeft;
        } else if (node->mKey < key) {
          node = node->mRight;
        } else {
          return node;
        }
      }

      return head;
    }

    /**
     * Address: 0x007AE140 (FUN_007AE140)
     *
     * What it does:
     * Initializes one selection weak-owner lane and links it into
     * `entity->mIUnitChainHead`.
     */
    void LinkSelectionWeakOwnerRef(UserEntity* const entity, SSelectionWeakRefUserEntity& weakRef)
    {
      weakRef.mOwnerLinkSlot = nullptr;
      weakRef.mNextOwner = nullptr;
      if (entity == nullptr) {
        return;
      }

      auto** ownerLinkSlot = reinterpret_cast<SSelectionWeakRefUserEntity**>(&entity->mIUnitChainHead);
      weakRef.mOwnerLinkSlot = ownerLinkSlot;
      weakRef.mNextOwner = *ownerLinkSlot;
      *ownerLinkSlot = &weakRef;
    }

    class ScopedSelectionOwnerLinkGuard
    {
    public:
      explicit ScopedSelectionOwnerLinkGuard(UserEntity* const entity) noexcept
      {
        mOwnerLinkSlot = entity ? reinterpret_cast<SSelectionWeakRefUserEntity**>(&entity->mIUnitChainHead) : nullptr;
        if (!mOwnerLinkSlot) {
          return;
        }

        mPrev = *mOwnerLinkSlot;
        *mOwnerLinkSlot = MarkerNode();
      }

      ~ScopedSelectionOwnerLinkGuard()
      {
        Restore();
      }

      ScopedSelectionOwnerLinkGuard(const ScopedSelectionOwnerLinkGuard&) = delete;
      ScopedSelectionOwnerLinkGuard& operator=(const ScopedSelectionOwnerLinkGuard&) = delete;

    private:
      [[nodiscard]] SSelectionWeakRefUserEntity* MarkerNode() noexcept
      {
        return reinterpret_cast<SSelectionWeakRefUserEntity*>(&mOwnerLinkSlot);
      }

      void Restore() noexcept
      {
        if (!mOwnerLinkSlot) {
          return;
        }

        auto** cursor = mOwnerLinkSlot;
        const SSelectionWeakRefUserEntity* const marker = MarkerNode();
        while (*cursor != marker) {
          cursor = &((*cursor)->mNextOwner);
        }

        *cursor = mPrev;
        mOwnerLinkSlot = nullptr;
        mPrev = nullptr;
      }

    private:
      SSelectionWeakRefUserEntity** mOwnerLinkSlot = nullptr;
      SSelectionWeakRefUserEntity* mPrev = nullptr;
    };

    /**
     * Address: 0x007B09E0 (FUN_007B09E0, sub_7B09E0)
     *
     * What it does:
     * Initializes one freshly allocated selection node with head/parent links,
     * copies key + owner-link lane from `sourceNode`, relinks that owner chain,
     * and writes color/sentinel flags.
     */
    [[nodiscard]] SSelectionNodeUserEntity* InitializeSelectionCloneNodeFromSource(
      SSelectionNodeUserEntity* const destinationNode,
      SSelectionNodeUserEntity* const headNode,
      const SSelectionNodeUserEntity* const sourceNode,
      SSelectionNodeUserEntity* const parentNode,
      const std::uint8_t color
    ) noexcept
    {
      destinationNode->mLeft = headNode;
      destinationNode->mParent = parentNode;
      destinationNode->mRight = headNode;
      destinationNode->mKey = sourceNode->mKey;

      auto** const ownerHead =
        reinterpret_cast<SSelectionWeakRefUserEntity**>(sourceNode->mEnt.mOwnerLinkSlot);
      destinationNode->mEnt.mOwnerLinkSlot = sourceNode->mEnt.mOwnerLinkSlot;
      if (ownerHead != nullptr) {
        destinationNode->mEnt.mNextOwner = *ownerHead;
        *ownerHead = &destinationNode->mEnt;
      } else {
        destinationNode->mEnt.mNextOwner = nullptr;
      }

      destinationNode->mColor = color;
      destinationNode->mIsSentinel = 0u;
      return destinationNode;
    }

    /**
     * Address: 0x007B06F0 (FUN_007B06F0, sub_7B06F0)
     *
     * What it does:
     * Allocates one selection node and initializes it from one source node
     * via `InitializeSelectionCloneNodeFromSource(...)`.
     */
    [[nodiscard]] SSelectionNodeUserEntity* AllocateSelectionCloneNodeFromSource(
      SSelectionNodeUserEntity* const headNode,
      SSelectionNodeUserEntity* const parentNode,
      const SSelectionNodeUserEntity* const sourceNode,
      const std::uint8_t color
    )
    {
      auto* const destinationNode =
        static_cast<SSelectionNodeUserEntity*>(::operator new(sizeof(SSelectionNodeUserEntity), std::nothrow));
      if (destinationNode != nullptr) {
        (void)InitializeSelectionCloneNodeFromSource(destinationNode, headNode, sourceNode, parentNode, color);
      }
      return destinationNode;
    }

    /**
     * Address: 0x00867EE0 (FUN_00867EE0, sub_867EE0)
     *
     * What it does:
     * Recursively clones one source selection subtree under `parentNode`,
     * preserving key/color and owner-link chain semantics.
     */
    [[nodiscard]] SSelectionNodeUserEntity* CloneSelectionSubtreeIntoSet(
      SSelectionSetUserEntity* const destinationSet,
      const SSelectionNodeUserEntity* const sourceNode,
      SSelectionNodeUserEntity* const parentNode
    )
    {
      SSelectionNodeUserEntity* const headNode = destinationSet->mHead;
      if (sourceNode == nullptr || sourceNode->mIsSentinel != 0u) {
        return headNode;
      }

      SSelectionNodeUserEntity* const clonedNode = AllocateSelectionCloneNodeFromSource(
        headNode,
        parentNode,
        sourceNode,
        sourceNode->mColor
      );
      if (clonedNode == nullptr) {
        return headNode;
      }

      clonedNode->mLeft = CloneSelectionSubtreeIntoSet(destinationSet, sourceNode->mLeft, clonedNode);
      clonedNode->mRight = CloneSelectionSubtreeIntoSet(destinationSet, sourceNode->mRight, clonedNode);
      return clonedNode;
    }

    /**
     * Address: 0x00867B20 (FUN_00867B20, sub_867B20)
     *
     * What it does:
     * Rebuilds one destination selection set from one source set by cloning
     * the source root subtree and then recomputing left/right extrema lanes.
     */
    [[nodiscard]] SSelectionNodeUserEntity* CloneSelectionTreeFromStorage(
      SSelectionSetUserEntity* const destinationSet,
      const SSelectionSetUserEntity* const sourceSet
    )
    {
      SSelectionNodeUserEntity* const destinationHead = destinationSet->mHead;
      destinationHead->mParent =
        CloneSelectionSubtreeIntoSet(destinationSet, sourceSet->mHead->mParent, destinationHead);
      destinationSet->mSize = sourceSet->mSize;

      SSelectionNodeUserEntity* result = destinationHead->mParent;
      if (result->mIsSentinel != 0u) {
        destinationHead->mLeft = destinationHead;
        destinationHead->mRight = destinationHead;
        return result;
      }

      SSelectionNodeUserEntity* leftMost = result;
      while (leftMost->mLeft->mIsSentinel == 0u) {
        leftMost = leftMost->mLeft;
      }
      destinationHead->mLeft = leftMost;

      SSelectionNodeUserEntity* rightMostParent = destinationHead->mParent;
      result = rightMostParent->mRight;
      while (result->mIsSentinel == 0u) {
        rightMostParent = result;
        result = result->mRight;
      }
      destinationHead->mRight = rightMostParent;
      return result;
    }

    /**
     * Address: 0x00867780 (FUN_00867780, sub_867780)
     *
     * What it does:
     * Resolves one weak-set tree node for `entity` using the transient
     * owner-link guard lane, then writes one `{set,node}` cursor pair.
     */
    [[nodiscard]] SSelectionSetUserEntity::FindResult* FindSelectionNodeByEntityGuarded(
      SSelectionSetUserEntity::FindResult* const outResult,
      SSelectionSetUserEntity* const set,
      UserEntity* const entity
    )
    {
      if (outResult == nullptr) {
        return nullptr;
      }

      outResult->mSet = set;
      outResult->mRes = (set != nullptr) ? set->mHead : nullptr;
      if (set == nullptr) {
        return outResult;
      }

      ScopedSelectionOwnerLinkGuard ownerLinkGuard(entity);
      outResult->mRes = FindSelectionNodeByKey(*set, SelectionKeyFromEntity(entity));
      return outResult;
    }

    void FixupAfterSelectionInsert(WeakEntitySetUserEntity& selection, SSelectionNodeUserEntity* node)
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      while (node != head->mParent && node->mParent->mColor == 0u) {
        SSelectionNodeUserEntity* const parent = node->mParent;
        SSelectionNodeUserEntity* const grand = parent->mParent;
        if (parent == grand->mLeft) {
          SSelectionNodeUserEntity* const uncle = grand->mRight;
          if (uncle->mColor == 0u) {
            parent->mColor = 1u;
            uncle->mColor = 1u;
            grand->mColor = 0u;
            node = grand;
          } else {
            if (node == parent->mRight) {
              node = parent;
              RotateSelectionLeft(selection, node);
            }
            node->mParent->mColor = 1u;
            grand->mColor = 0u;
            RotateSelectionRight(selection, grand);
          }
        } else {
          SSelectionNodeUserEntity* const uncle = grand->mLeft;
          if (uncle->mColor == 0u) {
            parent->mColor = 1u;
            uncle->mColor = 1u;
            grand->mColor = 0u;
            node = grand;
          } else {
            if (node == parent->mLeft) {
              node = parent;
              RotateSelectionRight(selection, node);
            }
            node->mParent->mColor = 1u;
            grand->mColor = 0u;
            RotateSelectionLeft(selection, grand);
          }
        }
      }

      head->mParent->mColor = 1u;
    }

    [[nodiscard]] bool InsertSelectionEntity(
      SSelectionSetUserEntity& selection,
      UserEntity* const entity,
      SSelectionNodeUserEntity** const outNode = nullptr
    )
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      if (head == nullptr || entity == nullptr) {
        if (outNode != nullptr) {
          *outNode = head;
        }
        return false;
      }

      const std::uint32_t key = SelectionKeyFromEntity(entity);
      SSelectionNodeUserEntity* parent = head;
      SSelectionNodeUserEntity* probe = head->mParent;
      while (!IsSelectionNil(probe)) {
        parent = probe;
        if (key < probe->mKey) {
          probe = probe->mLeft;
        } else if (probe->mKey < key) {
          probe = probe->mRight;
        } else {
          if (outNode != nullptr) {
            *outNode = probe;
          }
          return false;
        }
      }

      auto* const inserted = static_cast<SSelectionNodeUserEntity*>(::operator new(sizeof(SSelectionNodeUserEntity)));
      inserted->mLeft = head;
      inserted->mRight = head;
      inserted->mParent = parent;
      inserted->mKey = key;
      inserted->mColor = 0u;
      inserted->mIsSentinel = 0u;
      inserted->pad_1A[0] = 0u;
      inserted->pad_1A[1] = 0u;
      LinkSelectionWeakOwnerRef(entity, inserted->mEnt);

      if (parent == head) {
        head->mParent = inserted;
      } else if (key < parent->mKey) {
        parent->mLeft = inserted;
      } else {
        parent->mRight = inserted;
      }

      ++selection.mSize;
      FixupAfterSelectionInsert(selection, inserted);
      RecomputeSelectionExtrema(selection);
      if (outNode != nullptr) {
        *outNode = inserted;
      }
      return true;
    }

    struct SelectionInsertFindResult
    {
      SSelectionNodeUserEntity* node;
      bool inserted;
    };

    /**
     * Address: 0x007B25C0 (FUN_007B25C0)
     *
     * What it does:
     * Initializes one weak-set storage header with a fresh sentinel node and
     * resets its live-node count to zero.
     */
    [[nodiscard]] SSelectionSetUserEntity* InitializeSelectionSetHeadStorage(
      SSelectionSetUserEntity* const set
    )
    {
      SSelectionNodeUserEntity* const head = AllocateWeakEntitySetHead();
      set->mHead = head;
      head->mIsSentinel = 1u;
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      set->mSize = 0u;
      return set;
    }

    /**
     * Address: 0x007B25F0 (FUN_007B25F0)
     *
     * What it does:
     * Starts at the set head's left-most node, prunes tombstones, and writes
     * one `{set,node}` result pair for weak-set iteration callers.
     */
    [[nodiscard]] WeakEntitySetUserEntity::FindResult* BuildSelectionFindResultFromHeadLeft(
      WeakEntitySetUserEntity* const set,
      WeakEntitySetUserEntity::FindResult* const outResult
    )
    {
      SSelectionNodeUserEntity* node = set->mHead->mLeft;
      (void)PruneTombstonesAndFindLive(*set, &node, node);
      outResult->mSet = set;
      outResult->mRes = node;
      return outResult;
    }

    /**
     * Address: 0x008484E0 (FUN_008484E0)
     *
     * What it does:
     * Advances one weak-set cursor by one RB-tree successor and writes the next
     * live-node `{set,node}` result pair after tombstone filtering.
     */
    [[nodiscard]] SSelectionSetUserEntity::FindResult* BuildSelectionFindResultFromNextCursor(
      SSelectionSetUserEntity* const set,
      const SSelectionSetUserEntity::FindResult* const cursor,
      SSelectionSetUserEntity::FindResult* const outResult
    )
    {
      if (outResult == nullptr) {
        return nullptr;
      }

      SSelectionNodeUserEntity* node = (cursor != nullptr) ? cursor->mRes : nullptr;
      if (set != nullptr && node != nullptr) {
        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(set, node, &node);
      }

      outResult->mSet = set;
      outResult->mRes = node;
      return outResult;
    }

    /**
     * Address: 0x00822A50 (FUN_00822A50, sub_822A50)
     *
     * What it does:
     * Decrements one weak-set RB-tree iterator cursor to its predecessor.
     */
    [[nodiscard]] SSelectionNodeUserEntity*
    DecrementSelectionCursor(SSelectionSetUserEntity* const set, SSelectionNodeUserEntity* const cursor)
    {
      if (set == nullptr || set->mHead == nullptr || cursor == nullptr) {
        return nullptr;
      }

      SSelectionNodeUserEntity* const head = set->mHead;
      if (cursor == head) {
        return head->mRight;
      }

      if (!IsSelectionNil(cursor->mLeft)) {
        return SelectionMax(cursor->mLeft, head);
      }

      SSelectionNodeUserEntity* node = cursor;
      SSelectionNodeUserEntity* parent = node->mParent;
      while (parent != nullptr && parent != head && node == parent->mLeft) {
        node = parent;
        parent = parent->mParent;
      }

      return (parent != nullptr) ? parent : head;
    }

    /**
     * Address: 0x00822AB0 (FUN_00822AB0, sub_822AB0)
     *
     * What it does:
     * Initializes one selection-tree node payload from one entity key and links
     * the embedded weak-owner lane into the entity intrusive chain.
     */
    [[nodiscard]] SSelectionNodeUserEntity* InitSelectionNodeValueAndWeakLink(
      SSelectionNodeUserEntity* const node,
      WeakEntitySetUserEntity* const set,
      UserEntity* const entity
    )
    {
      if (node == nullptr || set == nullptr || set->mHead == nullptr) {
        return nullptr;
      }

      SSelectionNodeUserEntity* const head = set->mHead;
      node->mLeft = head;
      node->mRight = head;
      node->mParent = head;
      node->mKey = SelectionKeyFromEntity(entity);
      node->mColor = 0u;
      node->mIsSentinel = 0u;
      node->pad_1A[0] = 0u;
      node->pad_1A[1] = 0u;
      LinkSelectionWeakOwnerRef(entity, node->mEnt);
      return node;
    }

    /**
     * Address: 0x008229E0 (FUN_008229E0, sub_8229E0)
     *
     * What it does:
     * Allocates one selection-tree node and initializes it for one entity key.
     */
    [[nodiscard]] SSelectionNodeUserEntity*
    AllocateAndInitSelectionNode(WeakEntitySetUserEntity* const set, UserEntity* const entity)
    {
      if (set == nullptr || set->mHead == nullptr) {
        return nullptr;
      }

      auto* const node = static_cast<SSelectionNodeUserEntity*>(::operator new(sizeof(SSelectionNodeUserEntity)));
      return InitSelectionNodeValueAndWeakLink(node, set, entity);
    }

    /**
     * Address: 0x00822670 (FUN_00822670, sub_822670)
     *
     * What it does:
     * Inserts one entity key into the selection weak-set RB-tree and returns
     * `{node,inserted}`.
     */
    [[nodiscard]] SelectionInsertFindResult* InsertSelectionNodeAndRebalance(
      SelectionInsertFindResult* const outResult,
      WeakEntitySetUserEntity* const set,
      UserEntity* const entity
    )
    {
      outResult->node = (set != nullptr) ? set->mHead : nullptr;
      outResult->inserted = false;

      if (set == nullptr || set->mHead == nullptr) {
        return outResult;
      }

      if (set->mSize >= 0x15555554u) {
        throw std::length_error("map/set<T> too long");
      }

      SSelectionNodeUserEntity* const head = set->mHead;
      const std::uint32_t key = SelectionKeyFromEntity(entity);
      SSelectionNodeUserEntity* parent = head;
      SSelectionNodeUserEntity* probe = head->mParent;
      while (!IsSelectionNil(probe)) {
        parent = probe;
        if (key < probe->mKey) {
          probe = probe->mLeft;
        } else if (probe->mKey < key) {
          probe = probe->mRight;
        } else {
          outResult->node = probe;
          return outResult;
        }
      }

      SSelectionNodeUserEntity* const inserted = AllocateAndInitSelectionNode(set, entity);
      inserted->mParent = parent;
      if (parent == head) {
        head->mParent = inserted;
      } else if (key < parent->mKey) {
        parent->mLeft = inserted;
      } else {
        parent->mRight = inserted;
      }

      ++set->mSize;
      FixupAfterSelectionInsert(*set, inserted);
      RecomputeSelectionExtrema(*set);
      outResult->node = inserted;
      outResult->inserted = true;
      return outResult;
    }

    /**
     * Address: 0x00822420 (FUN_00822420, sub_822420)
     *
     * What it does:
     * Performs one find-or-insert operation for the selection weak-set key lane
     * and returns `{node,inserted}`.
     *
     * Takes the bare 12-byte header so both weak-set instantiations share it:
     * the binary reads only the head at `[set+4]` (0x0082242A) and the live
     * count at `[set+8]` (0x00822688), never the extra `+0x0C` selection lane,
     * and this body is the one `WeakSet<UserUnit>::Add` (0x00822270) calls
     * directly at 0x008222D2.
     */
    [[nodiscard]] SelectionInsertFindResult* FindOrInsertSelectionNodeByUserEntity(
      SelectionInsertFindResult* const outResult,
      WeakEntitySetUserEntity* const set,
      UserEntity* const entity
    )
    {
      outResult->node = (set != nullptr) ? set->mHead : nullptr;
      outResult->inserted = false;

      if (set == nullptr || set->mHead == nullptr) {
        return outResult;
      }

      SSelectionNodeUserEntity* const found = FindSelectionNodeByKey(*set, SelectionKeyFromEntity(entity));
      if (found != nullptr && found != set->mHead) {
        outResult->node = found;
        return outResult;
      }

      return InsertSelectionNodeAndRebalance(outResult, set, entity);
    }

    [[nodiscard]] std::uint32_t SelectionKeyFromEntityPointerLane(const UserEntity* const* const entityLane) noexcept
    {
      return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(entityLane != nullptr ? *entityLane : nullptr));
    }

    void ResolveSelectionEqualRangeByKey(
      SSelectionSetUserEntity* const set,
      const std::uint32_t key,
      SSelectionNodeUserEntity*& outLowerBound,
      SSelectionNodeUserEntity*& outUpperBound
    ) noexcept
    {
      if (set == nullptr || set->mHead == nullptr) {
        outLowerBound = nullptr;
        outUpperBound = nullptr;
        return;
      }

      SSelectionNodeUserEntity* upperBound = set->mHead;
      SSelectionNodeUserEntity* probe = upperBound->mParent;
      while (!IsSelectionNil(probe)) {
        if (key >= probe->mKey) {
          probe = probe->mRight;
        } else {
          upperBound = probe;
          probe = probe->mLeft;
        }
      }

      SSelectionNodeUserEntity* lowerBound = set->mHead;
      probe = lowerBound->mParent;
      while (!IsSelectionNil(probe)) {
        if (probe->mKey >= key) {
          lowerBound = probe;
          probe = probe->mLeft;
        } else {
          probe = probe->mRight;
        }
      }

      outLowerBound = lowerBound;
      outUpperBound = upperBound;
    }

    [[nodiscard]] SSelectionNodeUserEntity** InsertSelectionNodeUsingHint(
      SSelectionNodeUserEntity* const parentHint,
      SSelectionSetUserEntity* const set,
      SSelectionNodeUserEntity** const outNode,
      const bool insertLeft,
      UserEntity* const entity
    )
    {
      if (outNode == nullptr) {
        return nullptr;
      }

      *outNode = (set != nullptr) ? set->mHead : nullptr;
      if (set == nullptr || set->mHead == nullptr || parentHint == nullptr) {
        return outNode;
      }

      if (set->mSize >= 0x15555554u) {
        throw std::length_error("map/set<T> too long");
      }

      SSelectionNodeUserEntity* const inserted = AllocateAndInitSelectionNode(set, entity);
      inserted->mParent = parentHint;
      ++set->mSize;

      SSelectionNodeUserEntity* const head = set->mHead;
      if (parentHint == head) {
        head->mParent = inserted;
        head->mLeft = inserted;
        head->mRight = inserted;
      } else if (insertLeft) {
        parentHint->mLeft = inserted;
        if (parentHint == head->mLeft) {
          head->mLeft = inserted;
        }
      } else {
        parentHint->mRight = inserted;
        if (parentHint == head->mRight) {
          head->mRight = inserted;
        }
      }

      FixupAfterSelectionInsert(*set, inserted);
      RecomputeSelectionExtrema(*set);
      *outNode = inserted;
      return outNode;
    }

    [[nodiscard]] std::int32_t EraseSelectionKeyRangeAndCount(
      const UserEntity* const* entityLane,
      SSelectionSetUserEntity* set
    );

    [[nodiscard]] SSelectionNodeUserEntity** FindOrInsertSelectionNodeWithHint(
      SSelectionSetUserEntity* set,
      UserEntity* const* entityLane,
      SSelectionNodeUserEntity** outNode,
      SSelectionNodeUserEntity* hintNode
    );

    /**
     * Address: 0x008B2890 (FUN_008B2890, sub_8B2890)
     *
     * What it does:
     * Guards one entity weak-owner intrusive lane, erases all selection-set
     * entries matching that entity pointer key, restores owner links, and
     * returns removed-count.
     */
    [[nodiscard]] std::int32_t EraseSelectionEntityGuardedByOwnerLink(
      SSelectionSetUserEntity* const set,
      UserEntity* const entity
    )
    {
      ScopedSelectionOwnerLinkGuard ownerLinkGuard(entity);
      UserEntity* entityKey = entity;
      return EraseSelectionKeyRangeAndCount(&entityKey, set);
    }

    /**
     * Address: 0x008B2E70 (FUN_008B2E70, sub_8B2E70)
     *
     * What it does:
     * Resolves one equal-key range in the selection weak-set, counts how many
     * nodes the range contains, erases that full range, and returns the count.
     */
    [[nodiscard]] std::int32_t EraseSelectionKeyRangeAndCount(
      const UserEntity* const* const entityLane,
      SSelectionSetUserEntity* const set
    )
    {
      SSelectionNodeUserEntity* first = nullptr;
      SSelectionNodeUserEntity* last = nullptr;
      ResolveSelectionEqualRangeByKey(set, SelectionKeyFromEntityPointerLane(entityLane), first, last);

      std::int32_t erasedCount = 0;
      SSelectionNodeUserEntity* cursor = first;
      while (cursor != last) {
        ++erasedCount;
        SSelectionSetUserEntity::Iterator_inc(&cursor);
      }

      if (set != nullptr) {
        SSelectionNodeUserEntity* eraseCursor = first;
        (void)set->EraseRange(&eraseCursor, first, last);
      }
      return erasedCount;
    }

    /**
     * Address: 0x008B4D00 (FUN_008B4D00, sub_8B4D00)
     *
     * What it does:
     * Guards one entity weak-owner intrusive lane, resolves one hint-aware
     * selection node for that entity key, and writes `{set,node}` output.
     */
    [[nodiscard]] SSelectionSetUserEntity::FindResult* FindSelectionNodeWithHintGuardedByOwnerLink(
      SSelectionSetUserEntity::FindResult* const outResult,
      SSelectionSetUserEntity* const set,
      const SSelectionSetUserEntity::FindResult* const hintCursor,
      UserEntity* const entity
    )
    {
      if (outResult == nullptr) {
        return nullptr;
      }

      ScopedSelectionOwnerLinkGuard ownerLinkGuard(entity);
      UserEntity* entityKey = entity;
      SSelectionNodeUserEntity* const hintNode = (hintCursor != nullptr) ? hintCursor->mRes : nullptr;
      (void)FindOrInsertSelectionNodeWithHint(set, &entityKey, &outResult->mRes, hintNode);
      outResult->mSet = set;
      return outResult;
    }

    /**
     * Address: 0x008B4F50 (FUN_008B4F50, sub_8B4F50)
     *
     * What it does:
     * Performs one hint-aware find/insert operation in the selection weak-set:
     * when hint ordering proves a legal insertion side it inserts directly,
     * otherwise it falls back to canonical find-or-insert.
     */
    [[nodiscard]] SSelectionNodeUserEntity** FindOrInsertSelectionNodeWithHint(
      SSelectionSetUserEntity* const set,
      UserEntity* const* const entityLane,
      SSelectionNodeUserEntity** const outNode,
      SSelectionNodeUserEntity* hintNode
    )
    {
      if (outNode == nullptr) {
        return nullptr;
      }

      if (set == nullptr || set->mHead == nullptr || entityLane == nullptr) {
        *outNode = (set != nullptr) ? set->mHead : nullptr;
        return outNode;
      }

      SSelectionNodeUserEntity* const head = set->mHead;
      if (hintNode == nullptr) {
        hintNode = head;
      }

      const std::uint32_t key = SelectionKeyFromEntityPointerLane(entityLane);
      UserEntity* const entity = const_cast<UserEntity*>(*entityLane);

      if (set->mSize == 0u) {
        return InsertSelectionNodeUsingHint(head, set, outNode, true, entity);
      }

      SSelectionNodeUserEntity* const originalHint = hintNode;
      if (hintNode == head->mLeft) {
        if (key < hintNode->mKey) {
          return InsertSelectionNodeUsingHint(originalHint, set, outNode, true, entity);
        }
      } else if (hintNode == head) {
        SSelectionNodeUserEntity* const rightMost = head->mRight;
        if (rightMost->mKey < key) {
          return InsertSelectionNodeUsingHint(rightMost, set, outNode, false, entity);
        }
      } else if (
        key >= hintNode->mKey
        || ((hintNode = DecrementSelectionCursor(set, hintNode)), hintNode != nullptr && hintNode->mKey >= key)
      ) {
        SSelectionNodeUserEntity* nextHint = originalHint;
        SSelectionSetUserEntity::Iterator_inc(&nextHint);
        const bool keyNotLessThanSuccessor = nextHint != head && key >= nextHint->mKey;
        if (originalHint->mKey >= key || keyNotLessThanSuccessor) {
          SelectionInsertFindResult findResult{};
          *outNode = FindOrInsertSelectionNodeByUserEntity(&findResult, set, entity)->node;
          return outNode;
        }

        if (originalHint->mRight->mIsSentinel != 0u) {
          return InsertSelectionNodeUsingHint(originalHint, set, outNode, false, entity);
        }
        return InsertSelectionNodeUsingHint(nextHint, set, outNode, true, entity);
      } else {
        if (hintNode->mRight->mIsSentinel == 0u) {
          return InsertSelectionNodeUsingHint(originalHint, set, outNode, true, entity);
        }
        return InsertSelectionNodeUsingHint(hintNode, set, outNode, false, entity);
      }

      SelectionInsertFindResult findResult{};
      *outNode = FindOrInsertSelectionNodeByUserEntity(&findResult, set, entity)->node;
      return outNode;
    }

    /**
     * Address: 0x00822C50 (FUN_00822C50, sub_822C50)
     *
     * What it does:
     * Initializes one destination weak-set from one source iterator range by
     * copying live user-entity keys into a fresh RB-tree head/sentinel shape.
     */
    [[nodiscard]] SSelectionSetUserEntity* InitSelectionSetFromIteratorRange(
      SSelectionSetUserEntity* const destination,
      SSelectionSetUserEntity* const source,
      SSelectionNodeUserEntity* first,
      SSelectionNodeUserEntity* const last
    )
    {
      if (destination == nullptr) {
        return nullptr;
      }

      InitializeSelectionSetHeadStorage(destination);

      if (source == nullptr || source->mHead == nullptr) {
        return destination;
      }

      while (first != nullptr && first != last) {
        if (UserEntity* const entity = DecodeSelectedUserEntity(first->mEnt); entity != nullptr) {
          SSelectionSetUserEntity::AddResult addResult{};
          (void)SSelectionSetUserEntity::Add(&addResult, destination, entity);
        }

        SSelectionSetUserEntity::Iterator_inc(&first);
        first = SSelectionSetUserEntity::find(source, first, &first);
      }

      return destination;
    }

    /**
     * Address: 0x00831310 (FUN_00831310, sub_831310)
     *
     * What it does:
     * Initializes one destination weak-set from one source iterator range while
     * pruning source tombstone nodes (`nullptr`/`(void*)8` owner-link lanes) on
     * each iterator advance.
     */
    [[nodiscard]] SSelectionSetUserEntity* InitSelectionSetFromIteratorRangePruningSourceTombstones(
      SSelectionSetUserEntity* const destination,
      SSelectionSetUserEntity* const source,
      SSelectionNodeUserEntity* first,
      SSelectionNodeUserEntity* const last
    )
    {
      if (destination == nullptr) {
        return nullptr;
      }

      InitializeSelectionSetHeadStorage(destination);
      if (source == nullptr || source->mHead == nullptr) {
        return destination;
      }

      while (first != nullptr && first != last) {
        if (UserEntity* const entity = DecodeSelectedUserEntity(first->mEnt); entity != nullptr) {
          SSelectionSetUserEntity::AddResult addResult{};
          (void)SSelectionSetUserEntity::Add(&addResult, destination, entity);
        }

        SSelectionSetUserEntity::Iterator_inc(&first);
        (void)source->PruneTombstonesAndFindLive(&first, first);
      }

      return destination;
    }

    /**
     * Address: 0x00822210 (FUN_00822210, sub_822210)
     *
     * What it does:
     * Copies one source selection weak-set into one destination weak-set by
     * starting from the first live source node and cloning the full iterator
     * range into a fresh destination tree.
     */
    [[nodiscard]] SSelectionSetUserEntity* CopySelectionSetFromOther(
      SSelectionSetUserEntity* const destination,
      SSelectionSetUserEntity* const source
    )
    {
      if (source == nullptr || source->mHead == nullptr) {
        return InitSelectionSetFromIteratorRange(destination, source, nullptr, nullptr);
      }

      SSelectionNodeUserEntity* first = source->mHead->mLeft;
      first = SSelectionSetUserEntity::find(source, first, &first);
      return InitSelectionSetFromIteratorRange(destination, source, first, source->mHead);
    }

    struct SelectionWeakSetStorageRuntimeView
    {
      void* mAllocProxy;               // +0x00
      SSelectionNodeUserEntity* mHead; // +0x04
      std::uint32_t mSize;             // +0x08
    };

    static_assert(
      sizeof(SelectionWeakSetStorageRuntimeView) == 0x0C,
      "SelectionWeakSetStorageRuntimeView size must be 0x0C"
    );

    struct SelectionWeakSetStorageVectorRuntimeView
    {
      void* mProxy;                                // +0x00
      SelectionWeakSetStorageRuntimeView* mBegin;  // +0x04
      SelectionWeakSetStorageRuntimeView* mEnd;    // +0x08
      SelectionWeakSetStorageRuntimeView* mCapacityEnd; // +0x0C
    };

    static_assert(
      sizeof(SelectionWeakSetStorageVectorRuntimeView) == 0x10,
      "SelectionWeakSetStorageVectorRuntimeView size must be 0x10"
    );

    /**
     * Address: 0x00868E50 (FUN_00868E50, sub_868E50)
     *
     * What it does:
     * Releases one weak-set map storage lane by erasing all nodes, deleting
     * the head sentinel, and zeroing `{head,size}`.
     */
    [[nodiscard]] std::int32_t
    ReleaseSelectionWeakSetStorageCompat(SelectionWeakSetStorageRuntimeView* const storage)
    {
      if (storage == nullptr) {
        return 0;
      }

      if (storage->mHead != nullptr) {
        auto* const set = reinterpret_cast<SSelectionSetUserEntity*>(storage);
        SSelectionNodeUserEntity* cursor = nullptr;
        (void)set->EraseRange(&cursor, set->mHead->mLeft, set->mHead);
        ::operator delete(storage->mHead);
      }

      storage->mHead = nullptr;
      storage->mSize = 0u;
      return 0;
    }

    /**
     * Address: 0x00868CC0 (FUN_00868CC0, sub_868CC0)
     *
     * What it does:
     * Releases one half-open weak-set storage range by erasing each set and
     * deleting each per-set tree head sentinel.
     */
    void ReleaseSelectionWeakSetStorageRange(
      SelectionWeakSetStorageRuntimeView* rangeBegin,
      SelectionWeakSetStorageRuntimeView* const rangeEnd
    )
    {
      while (rangeBegin != rangeEnd) {
        (void)ReleaseSelectionWeakSetStorageCompat(rangeBegin);
        ++rangeBegin;
      }
    }

    /**
     * Address: 0x00865720 (FUN_00865720, sub_865720)
     *
     * What it does:
     * Assigns one selection weak-set from another by rebuilding destination
     * storage from source live entries.
     */
    [[nodiscard]] SSelectionSetUserEntity* AssignSelectionSetFromOther(
      SelectionWeakSetStorageRuntimeView* const sourceStorage,
      SSelectionSetUserEntity* const destinationSet
    )
    {
      auto* const sourceSet = reinterpret_cast<SSelectionSetUserEntity*>(sourceStorage);
      if (destinationSet == nullptr || destinationSet == sourceSet) {
        return destinationSet;
      }

      if (destinationSet->mHead != nullptr) {
        SSelectionNodeUserEntity* eraseCursor = nullptr;
        (void)destinationSet->EraseRange(&eraseCursor, destinationSet->mHead->mLeft, destinationSet->mHead);
        ::operator delete(destinationSet->mHead);
      }

      destinationSet->mHead = nullptr;
      destinationSet->mSize = 0u;
      destinationSet->mSizeMirrorOrUnused = 0u;

      SSelectionSetUserEntity rebuilt{};
      (void)CopySelectionSetFromOther(&rebuilt, sourceSet);
      destinationSet->mHead = rebuilt.mHead;
      destinationSet->mSize = rebuilt.mSize;
      destinationSet->mSizeMirrorOrUnused = rebuilt.mSize;
      return destinationSet;
    }

    /**
     * Address: 0x00865750 (FUN_00865750)
     *
     * What it does:
     * Compatibility entrypoint for selection weak-set assignment that rebuilds
     * one destination set from one source storage lane and returns destination.
     */
    [[nodiscard]] SSelectionSetUserEntity* AssignSelectionSetFromStorageLane(
      SelectionWeakSetStorageRuntimeView* const sourceStorage,
      SSelectionSetUserEntity* const destinationSet
    )
    {
      return AssignSelectionSetFromOther(sourceStorage, destinationSet);
    }

    /**
     * Address: 0x00867800 (FUN_00867800)
     *
     * What it does:
     * Alternate calling-lane entrypoint for selection weak-set assignment from
     * one source set into one destination set.
     */
    [[nodiscard]] SSelectionSetUserEntity* AssignSelectionSetFromSetLane(
      SSelectionSetUserEntity* const destinationSet,
      SSelectionSetUserEntity* const sourceSet
    )
    {
      return AssignSelectionSetFromOther(
        reinterpret_cast<SelectionWeakSetStorageRuntimeView*>(sourceSet),
        destinationSet
      );
    }

    /**
     * Address: 0x00867840 (FUN_00867840, sub_867840)
     *
     * What it does:
     * Releases vector-backed weak-set storage and resets begin/end/capacity
     * pointers to the empty state.
     */
    void ReleaseSelectionWeakSetStorageVector(
      SelectionWeakSetStorageVectorRuntimeView* const storage
    )
    {
      if (storage == nullptr) {
        return;
      }

      if (storage->mBegin != nullptr) {
        ReleaseSelectionWeakSetStorageRange(storage->mBegin, storage->mEnd);
        ::operator delete(storage->mBegin);
      }

      storage->mBegin = nullptr;
      storage->mEnd = nullptr;
      storage->mCapacityEnd = nullptr;
    }

    /**
     * Address: 0x00867CD0 (FUN_00867CD0)
     *
     * What it does:
     * Compatibility entrypoint that releases vector-backed weak-set storage and
     * rewires begin/end/capacity to null.
     */
    void ReleaseSelectionWeakSetStorageVectorAndReset(
      SelectionWeakSetStorageVectorRuntimeView* const storage
    )
    {
      ReleaseSelectionWeakSetStorageVector(storage);
    }

    /**
     * Address: 0x00868C80 (FUN_00868C80, sub_868C80)
     *
     * What it does:
     * Copies one half-open weak-set storage range forward, assigning each
     * destination lane from the corresponding source lane.
     */
    [[nodiscard]] SelectionWeakSetStorageRuntimeView* CopySelectionWeakSetStorageRangeForward(
      SelectionWeakSetStorageRuntimeView* destination,
      SelectionWeakSetStorageRuntimeView* sourceBegin,
      SelectionWeakSetStorageRuntimeView* sourceEnd
    )
    {
      SelectionWeakSetStorageRuntimeView* dst = destination;
      SelectionWeakSetStorageRuntimeView* src = sourceBegin;
      while (src != sourceEnd) {
        if (dst != src) {
          (void)ReleaseSelectionWeakSetStorageCompat(dst);
          (void)CopySelectionSetFromOther(
            reinterpret_cast<SSelectionSetUserEntity*>(dst),
            reinterpret_cast<SSelectionSetUserEntity*>(src)
          );
        }

        ++src;
        ++dst;
      }

      return dst;
    }

    /**
     * Address: 0x00868020 (FUN_00868020, sub_868020)
     *
     * What it does:
     * Compatibility adapter lane that forwards one empty weak-set storage range
     * into `ReleaseSelectionWeakSetStorageRange(...)` and returns zero status.
     */
    [[nodiscard]] std::int32_t ReleaseSelectionWeakSetStorageRangeEmptyAdapter(
      SelectionWeakSetStorageRuntimeView* const rangeBegin
    )
    {
      ReleaseSelectionWeakSetStorageRange(rangeBegin, rangeBegin);
      return 0;
    }

    /**
     * Address: 0x008688D0 (FUN_008688D0, sub_8688D0)
     *
     * What it does:
     * Compatibility adapter lane that forwards one null-bounds weak-set storage
     * copy into `CopySelectionWeakSetStorageRangeForward(...)`.
     */
    [[nodiscard]] SelectionWeakSetStorageRuntimeView*
    CopySelectionWeakSetStorageRangeForwardNullSourceAdapter(
      SelectionWeakSetStorageRuntimeView* const destination
    )
    {
      return CopySelectionWeakSetStorageRangeForward(destination, nullptr, nullptr);
    }

    /**
     * Address: 0x00867FC0 (FUN_00867FC0, sub_867FC0)
     *
     * What it does:
     * Erases one half-open weak-set storage range from a vector lane by
     * shifting the tail forward and releasing trailing stale slots.
     */
    [[nodiscard]] SelectionWeakSetStorageRuntimeView**
    EraseSelectionWeakSetStorageVectorRange(
      SelectionWeakSetStorageVectorRuntimeView* const storage,
      SelectionWeakSetStorageRuntimeView** const outIterator,
      SelectionWeakSetStorageRuntimeView* eraseBegin,
      SelectionWeakSetStorageRuntimeView* eraseEnd
    )
    {
      SelectionWeakSetStorageRuntimeView* iteratorResult = eraseBegin;
      if (storage != nullptr && eraseBegin != eraseEnd) {
        SelectionWeakSetStorageRuntimeView* const previousEnd = storage->mEnd;
        SelectionWeakSetStorageRuntimeView* const newEnd =
          CopySelectionWeakSetStorageRangeForward(eraseBegin, eraseEnd, previousEnd);
        ReleaseSelectionWeakSetStorageRange(newEnd, previousEnd);
        storage->mEnd = newEnd;
      }

      if (outIterator != nullptr) {
        *outIterator = iteratorResult;
      }
      return outIterator;
    }

    /**
     * Address: 0x00868D30 (FUN_00868D30, sub_868D30)
     *
     * What it does:
     * Fills one destination weak-set storage range with one source value lane.
     * Returns the last copied destination lane (or `fillValue` when no copy ran).
     */
    [[nodiscard]] SelectionWeakSetStorageRuntimeView* FillSelectionWeakSetStorageRange(
      SelectionWeakSetStorageRuntimeView* destinationBegin,
      SelectionWeakSetStorageRuntimeView* fillValue,
      SelectionWeakSetStorageRuntimeView* destinationEnd
    )
    {
      SelectionWeakSetStorageRuntimeView* result = fillValue;
      for (SelectionWeakSetStorageRuntimeView* dst = destinationBegin; dst != destinationEnd; ++dst) {
        if (dst == fillValue) {
          continue;
        }

        (void)ReleaseSelectionWeakSetStorageCompat(dst);
        (void)CopySelectionSetFromOther(
          reinterpret_cast<SSelectionSetUserEntity*>(dst),
          reinterpret_cast<SSelectionSetUserEntity*>(fillValue)
        );
        result = dst;
      }

      return result;
    }

    /**
     * Address: 0x00868EB0 (FUN_00868EB0, sub_868EB0)
     *
     * What it does:
     * Copies one half-open weak-set storage range backward, assigning each
     * destination lane from the matching source lane in reverse order.
     */
    [[nodiscard]] SelectionWeakSetStorageRuntimeView* CopySelectionWeakSetStorageRangeBackward(
      SelectionWeakSetStorageRuntimeView* destinationEnd,
      SelectionWeakSetStorageRuntimeView* sourceEnd,
      SelectionWeakSetStorageRuntimeView* sourceBegin
    )
    {
      SelectionWeakSetStorageRuntimeView* dst = destinationEnd;
      SelectionWeakSetStorageRuntimeView* src = sourceEnd;
      while (src != sourceBegin) {
        --src;
        --dst;

        if (dst == src) {
          continue;
        }

        (void)ReleaseSelectionWeakSetStorageCompat(dst);
        (void)CopySelectionSetFromOther(
          reinterpret_cast<SSelectionSetUserEntity*>(dst),
          reinterpret_cast<SSelectionSetUserEntity*>(src)
        );
      }

      return dst;
    }

    /**
     * Address: 0x00868900 (FUN_00868900)
     *
     * What it does:
     * Compatibility adapter that forwards one weak-set storage half-open range
     * into `ReleaseSelectionWeakSetStorageRange(...)`.
     */
    void ReleaseSelectionWeakSetStorageRangeAdapter(
      SelectionWeakSetStorageRuntimeView* const rangeBegin,
      SelectionWeakSetStorageRuntimeView* const rangeEnd
    )
    {
      ReleaseSelectionWeakSetStorageRange(rangeBegin, rangeEnd);
    }

    /**
     * Address: 0x00868950 (FUN_00868950)
     *
     * What it does:
     * Register-shape adapter for `FillSelectionWeakSetStorageRange(...)`.
     */
    [[nodiscard]] SelectionWeakSetStorageRuntimeView* FillSelectionWeakSetStorageRangeAdapter(
      SelectionWeakSetStorageRuntimeView* const destinationBegin,
      SelectionWeakSetStorageRuntimeView* const fillValue,
      SelectionWeakSetStorageRuntimeView* const destinationEnd
    )
    {
      return FillSelectionWeakSetStorageRange(destinationBegin, fillValue, destinationEnd);
    }

    /**
     * Address: 0x00868D80 (FUN_00868D80)
     *
     * What it does:
     * Compatibility adapter that forwards one legacy lane shape with null
     * source bounds into `CopySelectionWeakSetStorageRangeBackward(...)`.
     */
    [[nodiscard]] SelectionWeakSetStorageRuntimeView*
    CopySelectionWeakSetStorageRangeBackwardNullSourceAdapter(
      const SelectionWeakSetStorageRuntimeView* const unusedLaneA,
      const SelectionWeakSetStorageRuntimeView* const unusedLaneB,
      SelectionWeakSetStorageRuntimeView* const destinationEnd
    )
    {
      return CopySelectionWeakSetStorageRangeBackward(destinationEnd, nullptr, nullptr);
    }

    /**
     * Address: 0x00868F40 (FUN_00868F40)
     *
     * What it does:
     * Releases one weak-set storage lane, clears `{head,size}`, and returns
     * zero for legacy caller lanes that consume integer status.
     */
    [[nodiscard]] std::int32_t ReleaseSelectionWeakSetStorageAndReturnStatus(
      SelectionWeakSetStorageRuntimeView* const storage
    )
    {
      (void)ReleaseSelectionWeakSetStorageCompat(storage);
      return 0;
    }

    /**
     * Address: 0x00868F70 (FUN_00868F70)
     *
     * What it does:
     * Releases one weak-set storage lane and returns the original storage
     * pointer for pointer-returning compatibility callers.
     */
    [[nodiscard]] SelectionWeakSetStorageRuntimeView* ReleaseSelectionWeakSetStorageAndReturnStorage(
      SelectionWeakSetStorageRuntimeView* const storage
    )
    {
      (void)ReleaseSelectionWeakSetStorageCompat(storage);
      return storage;
    }

    struct RawPointerTripletRuntimeView
    {
      void* mBegin;       // +0x00
      void* mEnd;         // +0x04
      void* mCapacityEnd; // +0x08
      void* mInlineOrMeta; // +0x0C
    };

    static_assert(sizeof(RawPointerTripletRuntimeView) == 0x10, "RawPointerTripletRuntimeView size must be 0x10");
    static_assert(
      offsetof(RawPointerTripletRuntimeView, mInlineOrMeta) == 0x0C,
      "RawPointerTripletRuntimeView::mInlineOrMeta offset must be 0x0C"
    );

    struct DwordByteRuntimeView
    {
      std::uint32_t mValue; // +0x00
      std::uint8_t mFlag;   // +0x04
    };

    static_assert(offsetof(DwordByteRuntimeView, mFlag) == 0x04, "DwordByteRuntimeView::mFlag offset must be 0x04");

    struct TwoDwordByteRuntimeView
    {
      std::uint32_t mFirst;  // +0x00
      std::uint32_t mSecond; // +0x04
      std::uint8_t mFlag;    // +0x08
    };

    static_assert(
      offsetof(TwoDwordByteRuntimeView, mFlag) == 0x08,
      "TwoDwordByteRuntimeView::mFlag offset must be 0x08"
    );

    struct PackedTwoWordRuntimeView
    {
      std::uint16_t mFirst;  // +0x00
      std::uint16_t mSecond; // +0x02
    };

    struct PackedThreeWordRuntimeView
    {
      std::uint16_t mFirst;   // +0x00
      std::uint16_t mUnused;  // +0x02
      std::uint16_t mSecond;  // +0x04
    };

    static_assert(
      offsetof(PackedThreeWordRuntimeView, mSecond) == 0x04,
      "PackedThreeWordRuntimeView::mSecond offset must be 0x04"
    );

    [[nodiscard]] std::uint32_t ReadRuntimeDwordAt0(const void* const value) noexcept
    {
      if (value == nullptr) {
        return 0u;
      }
      return *static_cast<const std::uint32_t*>(value);
    }

    [[nodiscard]] std::uint32_t ReadRuntimeDwordAt4(const void* const value) noexcept
    {
      if (value == nullptr) {
        return 0u;
      }
      return *(reinterpret_cast<const std::uint32_t*>(value) + 1);
    }

    /**
     * Address: 0x00822250 (FUN_00822250, sub_822250)
     *
     * What it does:
     * Returns one first-dword runtime lane from one selection helper payload.
     */
    [[nodiscard]] std::uint32_t ReadSelectionRuntimeLane0(const void* const value) noexcept
    {
      return ReadRuntimeDwordAt0(value);
    }

    /**
     * Address: 0x00822260 (FUN_00822260, sub_822260)
     *
     * What it does:
     * Returns one first-dword runtime lane from one selection helper payload.
     */
    [[nodiscard]] std::uint32_t ReadSelectionRuntimeLane0Alt(const void* const value) noexcept
    {
      return ReadRuntimeDwordAt0(value);
    }

    /**
     * Address: 0x00822340 (FUN_00822340, sub_822340)
     *
     * What it does:
     * Returns one first-dword runtime lane from one command helper payload.
     */
    [[nodiscard]] std::uint32_t ReadCommandRuntimeLane0(const void* const value) noexcept
    {
      return ReadRuntimeDwordAt0(value);
    }

    /**
     * Address: 0x00822350 (FUN_00822350, sub_822350)
     *
     * What it does:
     * Returns one second-dword runtime lane from one command helper payload.
     */
    [[nodiscard]] std::uint32_t ReadCommandRuntimeLane4(const void* const value) noexcept
    {
      return ReadRuntimeDwordAt4(value);
    }

    /**
     * Address: 0x00822390 (FUN_00822390, sub_822390)
     *
     * What it does:
     * Returns one first-dword runtime lane from one command helper payload.
     */
    [[nodiscard]] std::uint32_t ReadCommandRuntimeLane0Alt(const void* const value) noexcept
    {
      return ReadRuntimeDwordAt0(value);
    }

    /**
     * Address: 0x008223A0 (FUN_008223A0, sub_8223A0)
     *
     * What it does:
     * Appends one `UserUnit*` from source lane into one fastvector and returns
     * the pre-append end pointer lane.
     */
    [[nodiscard]] UserUnit**
    AppendUserUnitPointerLane(gpg::fastvector<UserUnit*>& destination, UserUnit* const* const source)
    {
      UserUnit** const previousEnd = destination.end();
      destination.push_back(source != nullptr ? *source : nullptr);
      return previousEnd;
    }

    /**
     * Address: 0x008223D0 (FUN_008223D0, sub_8223D0)
     *
     * What it does:
     * Initializes one raw pointer-triplet lane with one inline 4-byte storage
     * fallback and resets begin/end/capacity links.
     */
    [[nodiscard]] RawPointerTripletRuntimeView*
    InitRawPointerTripletInlineLane(RawPointerTripletRuntimeView* const view) noexcept
    {
      if (view == nullptr) {
        return nullptr;
      }

      auto* const inlineBase = reinterpret_cast<std::uint8_t*>(view) + 0x10;
      view->mBegin = inlineBase;
      view->mEnd = inlineBase;
      view->mCapacityEnd = inlineBase + 0x4;
      view->mInlineOrMeta = inlineBase;
      return view;
    }

    /**
     * Address: 0x008223F0 (FUN_008223F0, sub_8223F0)
     *
     * What it does:
     * Resets one raw pointer-triplet lane to inline/meta fallback storage and
     * releases heap-buffer storage when currently detached from fallback.
     */
    [[nodiscard]] void* ResetRawPointerTripletToInlineLane(RawPointerTripletRuntimeView* const view)
    {
      if (view == nullptr) {
        return nullptr;
      }

      void* result = view->mBegin;
      if (view->mBegin == view->mInlineOrMeta) {
        view->mEnd = view->mBegin;
        return result;
      }

      ::operator delete[](view->mBegin);
      auto** const inlineOrMeta = static_cast<void**>(view->mInlineOrMeta);
      view->mBegin = inlineOrMeta;
      result = *inlineOrMeta;
      view->mCapacityEnd = result;
      view->mEnd = view->mBegin;
      return result;
    }

    /**
     * Address: 0x008225F0 (FUN_008225F0, sub_8225F0)
     *
     * What it does:
     * Seeds one raw pointer-triplet lane from one external buffer and element
     * count (`begin/end/capacity/meta` share the same base lane).
     */
    [[nodiscard]] RawPointerTripletRuntimeView* InitRawPointerTripletFromExternalLane(
      RawPointerTripletRuntimeView* const view,
      const std::int32_t elementCount,
      void* const begin
    ) noexcept
    {
      if (view == nullptr) {
        return nullptr;
      }

      view->mBegin = begin;
      view->mEnd = begin;
      view->mCapacityEnd =
        reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(begin) + (0x4u * static_cast<std::uintptr_t>(elementCount)));
      view->mInlineOrMeta = begin;
      return view;
    }

    /**
     * Address: 0x00822820 (FUN_00822820, nullsub_2792)
     *
     * What it does:
     * No-op hook lane retained for binary parity.
     */
    void NoOpSelectionHookA() noexcept
    {}

    /**
     * Address: 0x008229B0 (FUN_008229B0, sub_8229B0)
     *
     * What it does:
     * Performs one selection-cursor decrement and returns the updated cursor lane.
     */
    [[nodiscard]] SSelectionNodeUserEntity* StepSelectionCursorBackward(
      SSelectionSetUserEntity* const set,
      SSelectionNodeUserEntity* const cursor
    )
    {
      return DecrementSelectionCursor(set, cursor);
    }

    /**
     * Address: 0x008229C0 (FUN_008229C0, sub_8229C0)
     *
     * What it does:
     * Copies one `{dword,flag}` payload from lane pointers to one destination.
     */
    [[nodiscard]] DwordByteRuntimeView* CopyDwordByteRuntimeLane(
      DwordByteRuntimeView* const destination,
      const std::uint32_t* const valueSource,
      const std::uint8_t* const flagSource
    ) noexcept
    {
      if (destination == nullptr) {
        return nullptr;
      }

      destination->mValue = (valueSource != nullptr) ? *valueSource : 0u;
      destination->mFlag = (flagSource != nullptr) ? *flagSource : 0u;
      return destination;
    }

    /**
     * Address: 0x008229D0 (FUN_008229D0, sub_8229D0)
     *
     * What it does:
     * Returns one legacy map/set maximum-size guard constant lane.
     */
    [[nodiscard]] std::uint32_t GetLegacyMapSetMaxSizeGuard() noexcept
    {
      return 0x15555555u;
    }

    /**
     * Address: 0x00822A10 (FUN_00822A10, nullsub_2793)
     *
     * What it does:
     * No-op hook lane retained for binary parity.
     */
    void NoOpSelectionHookB() noexcept
    {}

    /**
     * Address: 0x00822A40 (FUN_00822A40, sub_822A40)
     *
     * What it does:
     * Returns one legacy map/set maximum-size guard constant lane.
     */
    [[nodiscard]] std::uint32_t GetLegacyMapSetMaxSizeGuardAlt() noexcept
    {
      return 0x15555555u;
    }

    /**
     * Address: 0x00822D70 (FUN_00822D70, sub_822D70)
     *
     * What it does:
     * Writes one `{first,second,flag}` payload into destination runtime storage.
     */
    [[nodiscard]] TwoDwordByteRuntimeView* InitTwoDwordByteRuntimeLane(
      TwoDwordByteRuntimeView* const destination,
      const std::uint32_t first,
      const std::uint32_t second,
      const std::uint8_t flag
    ) noexcept
    {
      if (destination == nullptr) {
        return nullptr;
      }

      destination->mFirst = first;
      destination->mSecond = second;
      destination->mFlag = flag;
      return destination;
    }

    /**
     * Address: 0x00822DF0 (FUN_00822DF0, sub_822DF0)
     *
     * What it does:
     * Copies one `{first,second,flag}` payload from lane pointers into destination.
     */
    [[nodiscard]] TwoDwordByteRuntimeView* CopyTwoDwordByteRuntimeLane(
      TwoDwordByteRuntimeView* const destination,
      const std::uint32_t* const pairSource,
      const std::uint8_t* const flagSource
    ) noexcept
    {
      if (destination == nullptr) {
        return nullptr;
      }

      destination->mFirst = (pairSource != nullptr) ? pairSource[0] : 0u;
      destination->mSecond = (pairSource != nullptr) ? pairSource[1] : 0u;
      destination->mFlag = (flagSource != nullptr) ? *flagSource : 0u;
      return destination;
    }

    /**
     * Address: 0x00822E10 (FUN_00822E10, sub_822E10)
     *
     * What it does:
     * Upcasts one reflected reference to `UserUnit` type lane and returns the
     * resulting object pointer payload.
     */
    [[nodiscard]] void* UpcastRRefToUserUnitObject(gpg::RRef* const sourceRef)
    {
      if (sourceRef == nullptr) {
        return nullptr;
      }

      static gpg::RType* sCachedUserUnitType = nullptr;
      if (sCachedUserUnitType == nullptr) {
        sCachedUserUnitType = gpg::LookupRType(typeid(UserUnit));
      }

      const gpg::RRef upcastedRef = gpg::REF_UpcastPtr(*sourceRef, sCachedUserUnitType);
      return upcastedRef.mObj;
    }

    /**
     * Address: 0x00822E50 (FUN_00822E50, nullsub_2794)
     *
     * What it does:
     * No-op hook lane retained for binary parity.
     */
    void NoOpSelectionHookC() noexcept
    {}

    /**
     * Address: 0x00822E60 (FUN_00822E60, sub_822E60)
     *
     * What it does:
     * Returns the high-byte lane from one packed 32-bit value.
     */
    [[nodiscard]] std::uint8_t ReadHighByteLaneA(const std::uint32_t value) noexcept
    {
      return static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
    }

    /**
     * Address: 0x00822E90 (FUN_00822E90, nullsub_2795)
     *
     * What it does:
     * No-op hook lane retained for binary parity.
     */
    void NoOpSelectionHookD() noexcept
    {}

    /**
     * Address: 0x00822EA0 (FUN_00822EA0, sub_822EA0)
     *
     * What it does:
     * Returns the high-byte lane from one packed 32-bit value.
     */
    [[nodiscard]] std::uint8_t ReadHighByteLaneB(const std::uint32_t value) noexcept
    {
      return static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
    }

    /**
     * Address: 0x00822ED0 (FUN_00822ED0, sub_822ED0)
     *
     * What it does:
     * Returns one first-dword runtime lane from one packed payload.
     */
    [[nodiscard]] std::uint32_t ReadPackedRuntimeLane0(const void* const value) noexcept
    {
      return ReadRuntimeDwordAt0(value);
    }

    /**
     * Address: 0x00822EE0 (FUN_00822EE0, sub_822EE0)
     *
     * What it does:
     * Copies one `{word0,word2}` pair from one three-word packed source lane.
     */
    [[nodiscard]] PackedTwoWordRuntimeView* CopyPackedWordPairSkippingMiddle(
      PackedTwoWordRuntimeView* const destination,
      const PackedThreeWordRuntimeView* const source
    ) noexcept
    {
      if (destination == nullptr) {
        return nullptr;
      }

      destination->mFirst = (source != nullptr) ? source->mFirst : 0u;
      destination->mSecond = (source != nullptr) ? source->mSecond : 0u;
      return destination;
    }

    /**
     * Address: 0x00822F20 (FUN_00822F20, sub_822F20)
     *
     * What it does:
     * Copies one 2-float lane (`x`,`y`) to one destination dword payload.
     */
    [[nodiscard]] std::uint32_t* CopyPackedFloat2Lane(
      std::uint32_t* const destination,
      const float* const source
    ) noexcept
    {
      if (destination == nullptr) {
        return nullptr;
      }

      if (source == nullptr) {
        destination[0] = 0u;
        destination[1] = 0u;
        return destination;
      }

      std::memcpy(destination, source, sizeof(float) * 2u);
      return destination;
    }

    void FixupAfterSelectionErase(
      WeakEntitySetUserEntity& selection,
      SSelectionNodeUserEntity* node,
      SSelectionNodeUserEntity* nodeParent
    )
    {
      SSelectionNodeUserEntity* const head = selection.mHead;
      SSelectionNodeUserEntity* parent = !IsSelectionNil(node) ? node->mParent : nodeParent;
      while (node != head->mParent && (IsSelectionNil(node) || node->mColor == 1u)) {
        if (parent == nullptr) {
          break;
        }

        if (node == parent->mLeft) {
          SSelectionNodeUserEntity* sibling = parent->mRight;
          if (sibling == head) {
            node = parent;
            parent = node->mParent;
            continue;
          }
          if (sibling->mColor == 0u) {
            sibling->mColor = 1;
            parent->mColor = 0;
            RotateSelectionLeft(selection, parent);
            sibling = parent->mRight;
          }

          const bool leftBlack = IsSelectionNil(sibling->mLeft) || sibling->mLeft->mColor == 1u;
          const bool rightBlack = IsSelectionNil(sibling->mRight) || sibling->mRight->mColor == 1u;
          if (leftBlack && rightBlack) {
            sibling->mColor = 0;
            node = parent;
            parent = node->mParent;
            continue;
          }

          if (IsSelectionNil(sibling->mRight) || sibling->mRight->mColor == 1u) {
            if (!IsSelectionNil(sibling->mLeft)) {
              sibling->mLeft->mColor = 1;
            }
            sibling->mColor = 0;
            RotateSelectionRight(selection, sibling);
            sibling = parent->mRight;
          }

          sibling->mColor = parent->mColor;
          parent->mColor = 1;
          if (!IsSelectionNil(sibling->mRight)) {
            sibling->mRight->mColor = 1;
          }
          RotateSelectionLeft(selection, parent);
          node = head->mParent;
          break;
        }

        SSelectionNodeUserEntity* sibling = parent->mLeft;
        if (sibling == head) {
          node = parent;
          parent = node->mParent;
          continue;
        }
        if (sibling->mColor == 0u) {
          sibling->mColor = 1;
          parent->mColor = 0;
          RotateSelectionRight(selection, parent);
          sibling = parent->mLeft;
        }

        const bool rightBlack = IsSelectionNil(sibling->mRight) || sibling->mRight->mColor == 1u;
        const bool leftBlack = IsSelectionNil(sibling->mLeft) || sibling->mLeft->mColor == 1u;
        if (rightBlack && leftBlack) {
          sibling->mColor = 0;
          node = parent;
          parent = node->mParent;
          continue;
        }

        if (IsSelectionNil(sibling->mLeft) || sibling->mLeft->mColor == 1u) {
          if (!IsSelectionNil(sibling->mRight)) {
            sibling->mRight->mColor = 1;
          }
          sibling->mColor = 0;
          RotateSelectionLeft(selection, sibling);
          sibling = parent->mLeft;
        }

        sibling->mColor = parent->mColor;
        parent->mColor = 1;
        if (!IsSelectionNil(sibling->mLeft)) {
          sibling->mLeft->mColor = 1;
        }
        RotateSelectionRight(selection, parent);
        node = head->mParent;
        break;
      }

      if (!IsSelectionNil(node)) {
        node->mColor = 1u;
      }
    }

    /**
     * Address: 0x0066AF90 (FUN_0066AF90)
     *
     * What it does:
     * Unlinks one weak-ref node from its intrusive owner chain and returns the
     * final owner-link cursor slot without resetting the weak-ref lanes.
     */
    [[nodiscard]] SSelectionWeakRefUserEntity**
    UnlinkSelectionWeakOwnerRefNoReset(SSelectionWeakRefUserEntity& weakRef) noexcept
    {
      auto** ownerLinkSlot = reinterpret_cast<SSelectionWeakRefUserEntity**>(weakRef.mOwnerLinkSlot);
      if (ownerLinkSlot != nullptr) {
        while (*ownerLinkSlot != nullptr && *ownerLinkSlot != &weakRef) {
          ownerLinkSlot = &(*ownerLinkSlot)->mNextOwner;
        }

        if (*ownerLinkSlot == &weakRef) {
          *ownerLinkSlot = weakRef.mNextOwner;
        }
      }

      return ownerLinkSlot;
    }

    struct SelectionWeakOwnerLinkNodeLane
    {
      std::uint32_t mLeadingDword;          // +0x00
      SSelectionWeakRefUserEntity mWeakRef; // +0x04
    };
    static_assert(sizeof(SelectionWeakOwnerLinkNodeLane) == 0x0C, "SelectionWeakOwnerLinkNodeLane size must be 0x0C");
    static_assert(
      offsetof(SelectionWeakOwnerLinkNodeLane, mWeakRef) == 0x04,
      "SelectionWeakOwnerLinkNodeLane::mWeakRef offset must be 0x04"
    );

    /**
     * Address: 0x0081D010 (FUN_0081D010)
     *
     * What it does:
     * Unlinks one owner-link node whose weak-ref lane begins at +0x04 and
     * returns the final owner-link cursor slot without resetting link fields.
     */
    [[nodiscard]] SSelectionWeakRefUserEntity**
    UnlinkSelectionWeakOwnerRefAfterLeadingDword(SelectionWeakOwnerLinkNodeLane& node) noexcept
    {
      SSelectionWeakRefUserEntity* const weakRef = &node.mWeakRef;
      auto** ownerLinkSlot = reinterpret_cast<SSelectionWeakRefUserEntity**>(weakRef->mOwnerLinkSlot);
      if (ownerLinkSlot != nullptr) {
        while (*ownerLinkSlot != nullptr && *ownerLinkSlot != weakRef) {
          ownerLinkSlot = &(*ownerLinkSlot)->mNextOwner;
        }

        if (*ownerLinkSlot == weakRef) {
          *ownerLinkSlot = weakRef->mNextOwner;
        }
      }

      return ownerLinkSlot;
    }

    struct CommandGraphAnchorSampleRuntimeView
    {
      std::int32_t mSampleKind = 0;            // +0x00
      SSelectionWeakRefUserEntity mWeakRef{};  // +0x04
      Wm3::Vector3f mWorldPosition{};          // +0x0C
    };
    static_assert(
      sizeof(CommandGraphAnchorSampleRuntimeView) == 0x18, "CommandGraphAnchorSampleRuntimeView size must be 0x18"
    );
    static_assert(
      offsetof(CommandGraphAnchorSampleRuntimeView, mWeakRef) == 0x04,
      "CommandGraphAnchorSampleRuntimeView::mWeakRef offset must be 0x04"
    );
    static_assert(
      offsetof(CommandGraphAnchorSampleRuntimeView, mWorldPosition) == 0x0C,
      "CommandGraphAnchorSampleRuntimeView::mWorldPosition offset must be 0x0C"
    );

    struct CommandGraphAnchorHistoryEntryRuntimeView
    {
      std::uint8_t mUnknown00_03[0x04]{};
      std::int32_t mEntryType = 0; // +0x04
      // Per-entry relation tree `sub_8B4300` looks `mRelationLookupKey` up in
      // (0x008B435F/0x008B4389: `eax = tree + 8`, `sub_82CEA0` reads
      // `*(eax+4)` as the tree's own head pointer - a `WeakEntitySetUserEntity`
      // proxy/head/size triple). See `CommandGraphAnchorHistoryRuntimeView::
      // mRelationLookupKey`'s doc comment for the same "shape confirmed,
      // semantic id not confirmed" caveat.
      WeakEntitySetUserEntity mRelationTree{}; // +0x08
      std::uint8_t mUnknown14_23[0x10]{};
      CommandGraphAnchorSampleRuntimeView mAnchorSample{}; // +0x24
    };
    static_assert(
      offsetof(CommandGraphAnchorHistoryEntryRuntimeView, mEntryType) == 0x04,
      "CommandGraphAnchorHistoryEntryRuntimeView::mEntryType offset must be 0x04"
    );
    static_assert(
      offsetof(CommandGraphAnchorHistoryEntryRuntimeView, mRelationTree) == 0x08,
      "CommandGraphAnchorHistoryEntryRuntimeView::mRelationTree offset must be 0x08"
    );
    static_assert(
      offsetof(CommandGraphAnchorHistoryEntryRuntimeView, mAnchorSample) == 0x24,
      "CommandGraphAnchorHistoryEntryRuntimeView::mAnchorSample offset must be 0x24"
    );

    struct CommandGraphAnchorHistoryRuntimeView
    {
      std::uint8_t mUnknown00_3F[0x40]{};
      // `sub_8B4300`'s fallback path (ring holds neither a type-0 nor a
      // type-3 entry) scans this `[begin, end)` run of entity ids
      // (0x008B4300-0x008B430A read `this+0x40`/`this+0x44` directly, before
      // the ring-scan setup at `this+0xB8` even runs) for the candidate's own
      // `UserEntity::mParams.mEntityId`.
      const std::int32_t* mFallbackIdRunBegin = nullptr; // +0x40
      const std::int32_t* mFallbackIdRunEnd = nullptr;   // +0x44
      std::uint8_t mUnknown48_5B[0x14]{};
      CommandGraphAnchorSampleRuntimeView mFallbackSample{}; // +0x5C
      std::uint8_t mUnknown74_B8[0x44]{};
      // Search key `sub_8B4300` (`IsCandidateExcludedByCachedRelation` below)
      // looks up in each history entry's own per-entry relation tree
      // (0x008B430A/0x008B4310: `ebx = this + 0xB8`, then `*ebx` is forwarded
      // unchanged through `sub_82B450`/`sub_82C2E0` as the lower-bound search
      // key). The tree-walk shape is confirmed against `SSelectionNodeUserEntity`
      // node-for-node; what this specific id counts (army? viewing-player?) is
      // not independently confirmed.
      std::uint32_t mRelationLookupKey = 0; // +0xB8
      CommandGraphAnchorHistoryEntryRuntimeView** mEntries = nullptr; // +0xBC
      std::uint32_t mEntryBase = 0; // +0xC0
      std::uint32_t mEntryStart = 0; // +0xC4
      std::uint32_t mEntryCount = 0; // +0xC8
    };
    static_assert(
      offsetof(CommandGraphAnchorHistoryRuntimeView, mFallbackIdRunBegin) == 0x40,
      "CommandGraphAnchorHistoryRuntimeView::mFallbackIdRunBegin offset must be 0x40"
    );
    static_assert(
      offsetof(CommandGraphAnchorHistoryRuntimeView, mFallbackIdRunEnd) == 0x44,
      "CommandGraphAnchorHistoryRuntimeView::mFallbackIdRunEnd offset must be 0x44"
    );
    static_assert(
      offsetof(CommandGraphAnchorHistoryRuntimeView, mFallbackSample) == 0x5C,
      "CommandGraphAnchorHistoryRuntimeView::mFallbackSample offset must be 0x5C"
    );
    static_assert(
      offsetof(CommandGraphAnchorHistoryRuntimeView, mRelationLookupKey) == 0xB8,
      "CommandGraphAnchorHistoryRuntimeView::mRelationLookupKey offset must be 0xB8"
    );
    static_assert(
      offsetof(CommandGraphAnchorHistoryRuntimeView, mEntries) == 0xBC,
      "CommandGraphAnchorHistoryRuntimeView::mEntries offset must be 0xBC"
    );
    static_assert(
      offsetof(CommandGraphAnchorHistoryRuntimeView, mEntryBase) == 0xC0,
      "CommandGraphAnchorHistoryRuntimeView::mEntryBase offset must be 0xC0"
    );
    static_assert(
      offsetof(CommandGraphAnchorHistoryRuntimeView, mEntryStart) == 0xC4,
      "CommandGraphAnchorHistoryRuntimeView::mEntryStart offset must be 0xC4"
    );
    static_assert(
      offsetof(CommandGraphAnchorHistoryRuntimeView, mEntryCount) == 0xC8,
      "CommandGraphAnchorHistoryRuntimeView::mEntryCount offset must be 0xC8"
    );

    [[nodiscard]] Wm3::Vector3f InvalidCommandGraphAnchorPosition() noexcept
    {
      const float qnan = std::numeric_limits<float>::quiet_NaN();
      return Wm3::Vector3f{qnan, qnan, qnan};
    }

    /**
     * Address: 0x008B40F0 (FUN_008B40F0)
     *
     * What it does:
     * Copies one command-graph anchor sample and rebinds its weak-owner lane
     * into the destination slot.
     */
    [[nodiscard]] CommandGraphAnchorSampleRuntimeView* CopyCommandGraphAnchorSampleWithRelink(
      CommandGraphAnchorSampleRuntimeView* const destination,
      const CommandGraphAnchorSampleRuntimeView* const source
    ) noexcept
    {
      if (destination == nullptr || source == nullptr) {
        return destination;
      }

      destination->mSampleKind = source->mSampleKind;
      destination->mWeakRef.mOwnerLinkSlot = source->mWeakRef.mOwnerLinkSlot;

      if (destination->mWeakRef.mOwnerLinkSlot != nullptr) {
        auto** const ownerLinkSlot =
          reinterpret_cast<SSelectionWeakRefUserEntity**>(destination->mWeakRef.mOwnerLinkSlot);
        destination->mWeakRef.mNextOwner = *ownerLinkSlot;
        *ownerLinkSlot = &destination->mWeakRef;
      } else {
        destination->mWeakRef.mNextOwner = nullptr;
      }

      destination->mWorldPosition = source->mWorldPosition;
      return destination;
    }

    /**
     * Address: 0x008BEC40 (FUN_008BEC40)
     *
     * What it does:
     * Builds one fallback anchor sample: for entity samples, resolves and links
     * the entity weak-owner lane; for literal samples, copies inline position.
     */
    [[nodiscard]] CommandGraphAnchorSampleRuntimeView* ResolveFallbackCommandGraphAnchorSample(
      CommandGraphAnchorSampleRuntimeView* const outSample,
      const CommandGraphAnchorSampleRuntimeView* const fallbackSample
    ) noexcept
    {
      if (outSample == nullptr || fallbackSample == nullptr) {
        return outSample;
      }

      outSample->mSampleKind = fallbackSample->mSampleKind;
      outSample->mWeakRef.mOwnerLinkSlot = nullptr;
      outSample->mWeakRef.mNextOwner = nullptr;

      if (outSample->mSampleKind == 1) {
        const std::uint32_t entityIdRaw = static_cast<std::uint32_t>(
          reinterpret_cast<std::uintptr_t>(fallbackSample->mWeakRef.mOwnerLinkSlot)
        );

        UserEntity* entity = nullptr;
        moho::CWldSession* const activeSession = moho::WLD_GetActiveSession();
        if (activeSession != nullptr) {
          entity = activeSession->LookupEntityId(static_cast<moho::EntId>(entityIdRaw));
        }

        if (entity != nullptr) {
          auto** const ownerLinkSlot = reinterpret_cast<SSelectionWeakRefUserEntity**>(&entity->mIUnitChainHead);
          outSample->mWeakRef.mOwnerLinkSlot = ownerLinkSlot;
          outSample->mWeakRef.mNextOwner = *ownerLinkSlot;
          *ownerLinkSlot = &outSample->mWeakRef;
        }
        return outSample;
      }

      if (outSample->mSampleKind == 2) {
        outSample->mWorldPosition = fallbackSample->mWorldPosition;
      }

      return outSample;
    }

    /**
     * Address: 0x008B4080 (FUN_008B4080)
     *
     * What it does:
     * Scans command-graph history backward for the latest entry tagged as
     * build-position sample (`type==4`), otherwise falls back to the cached
     * default sample lane.
     */
    [[nodiscard]] CommandGraphAnchorSampleRuntimeView* ResolveCommandGraphAnchorSampleFromHistory(
      CommandGraphAnchorSampleRuntimeView* const outSample,
      CommandGraphAnchorHistoryRuntimeView* const history
    ) noexcept
    {
      if (outSample == nullptr || history == nullptr || history->mEntries == nullptr) {
        return outSample;
      }

      std::uint32_t cursor = history->mEntryStart + history->mEntryCount;
      while (true) {
        if (cursor == history->mEntryStart) {
          return ResolveFallbackCommandGraphAnchorSample(outSample, &history->mFallbackSample);
        }

        const std::uint32_t previousCursor = cursor - 1u;
        std::uint32_t ringIndex = previousCursor;
        if (history->mEntryBase <= previousCursor) {
          ringIndex = previousCursor - history->mEntryBase;
        }

        const CommandGraphAnchorHistoryEntryRuntimeView* const entry = history->mEntries[ringIndex];
        if (entry != nullptr && entry->mEntryType == 4) {
          return CopyCommandGraphAnchorSampleWithRelink(outSample, &entry->mAnchorSample);
        }

        cursor = previousCursor;
      }
    }

    /**
     * Shared entity weak-link insert/remove, matching `LinkWeakEntityOwner`/
     * `UnlinkWeakEntityOwner` (UserUnit.cpp, internal linkage there - not
     * reachable from this TU) field-for-field. Used below by both
     * `ResolveCommandTargetEntityFromAnchorHistory`'s transient-sample
     * teardown and `ProcessCommandDrag`'s new-target construction.
     */
    void LinkEntityWeakRef(UserEntity* const entity, SSelectionWeakRefUserEntity& weakRef) noexcept
    {
      weakRef.mOwnerLinkSlot = nullptr;
      weakRef.mNextOwner = nullptr;
      if (entity == nullptr) {
        return;
      }

      auto** const ownerLinkSlot = reinterpret_cast<SSelectionWeakRefUserEntity**>(&entity->mIUnitChainHead);
      weakRef.mOwnerLinkSlot = ownerLinkSlot;
      weakRef.mNextOwner = *ownerLinkSlot;
      *ownerLinkSlot = &weakRef;
    }

    void UnlinkEntityWeakRef(SSelectionWeakRefUserEntity& weakRef) noexcept
    {
      auto** ownerLinkSlot = reinterpret_cast<SSelectionWeakRefUserEntity**>(weakRef.mOwnerLinkSlot);
      if (ownerLinkSlot != nullptr) {
        while (*ownerLinkSlot != nullptr && *ownerLinkSlot != &weakRef) {
          ownerLinkSlot = &(*ownerLinkSlot)->mNextOwner;
        }
        if (*ownerLinkSlot == &weakRef) {
          *ownerLinkSlot = weakRef.mNextOwner;
        }
      }
      weakRef.mOwnerLinkSlot = nullptr;
      weakRef.mNextOwner = nullptr;
    }

    /**
     * Address: 0x00824550 (FUN_00824550, sub_824550)
     *
     * Misclassified `external_dependency` by an earlier automated pass (its
     * sole callee `sub_8B4080` walks the helper's own event-ring fields, not
     * external runtime state - same misclassification family as the
     * `mMapAB0` hash-subsystem thunks landed earlier this session).
     *
     * What it does:
     * Resolves one command's live target entity from its command-graph
     * anchor history (falling back to its cached default anchor sample when
     * the history holds no build-position entry via
     * `ResolveCommandGraphAnchorSampleFromHistory`), then unlinks the
     * transient local sample from whatever weak-entity chain the lookup
     * joined it to before returning the resolved entity. Sole caller is
     * `func_ProcessCommandDrag` (0x00829B40).
     */
    [[nodiscard]] UserEntity* ResolveCommandTargetEntityFromAnchorHistory(
      CommandGraphAnchorHistoryRuntimeView* const history
    ) noexcept
    {
      CommandGraphAnchorSampleRuntimeView sample{};
      (void)ResolveCommandGraphAnchorSampleFromHistory(&sample, history);

      UserEntity* const entity = (sample.mSampleKind == 1) ? DecodeSelectedUserEntity(sample.mWeakRef) : nullptr;

      UnlinkEntityWeakRef(sample.mWeakRef);

      return entity;
    }

    /**
     * Address: 0x0082E560 (FUN_0082E560, sub_82E560)
     *
     * What it does:
     * Standard red-black-tree lower-bound walk over a `WeakEntitySetUserEntity`
     * tree: returns the first node whose key is `>= key`, or the tree's own
     * sentinel head when no such node exists. Node shape (mLeft/mParent/mRight,
     * key at +0xC, `mIsSentinel` at +0x19) matches `SSelectionNodeUserEntity`
     * exactly - this is the same node layout `WeakEntitySet.h` already models,
     * just walked for nearest-match rather than exact-match (contrast
     * `FindWeakEntitySetNodeByKey` in UserUnit.cpp, an exact-match walk over
     * the same node shape).
     */
    [[nodiscard]] SSelectionNodeUserEntity* LowerBoundWeakEntitySetNode(
      const WeakEntitySetUserEntity& tree, const std::uint32_t key
    ) noexcept
    {
      SSelectionNodeUserEntity* const head = tree.mHead;
      SSelectionNodeUserEntity* candidate = head;
      SSelectionNodeUserEntity* node = head->mParent;
      while (node->mIsSentinel == 0u) {
        if (key <= node->mKey) {
          candidate = node;
          node = node->mLeft;
        } else {
          node = node->mRight;
        }
      }
      return (candidate == head || key < candidate->mKey) ? head : candidate;
    }

    /**
     * Address: 0x008B4300 (FUN_008B4300, sub_8B4300) plus the scoped map
     * lookup it calls per matching ring entry, `sub_82CEA0` (0x0082CEA0),
     * which itself wraps the lower-bound walk above (`sub_82E560`).
     * Misclassified `external_dependency`/`owner_layout` by earlier automated
     * passes for the same reason as `ResolveCommandTargetEntityFromAnchorHistory`.
     *
     * `sub_82CEA0`'s own body additionally threads a transient weak node
     * through `candidateUnit`'s own link chain around the lookup
     * (0x0082CEB2-0x0082CF11: insert before, splice out after). Nothing else
     * runs between the insert and the splice-out in this single-threaded
     * call, so the chain membership is never observable from outside
     * `sub_82CEA0` itself; this recovery omits it as behaviorally inert.
     *
     * What it does:
     * Scans `history`'s cached command-issue event ring from newest to
     * oldest (same ring `ResolveCommandTargetEntityFromAnchorHistory` walks)
     * for the first entry tagged type `0` or type `3`; for that entry, looks
     * `history.mRelationLookupKey` up in the entry's own per-entry relation
     * tree (`LowerBoundWeakEntitySetNode`) and returns whether the lookup
     * came up empty (`true` = exclude the candidate). See
     * `CommandGraphAnchorHistoryRuntimeView::mRelationLookupKey`'s doc
     * comment: the lookup shape is confirmed, the exact game-rule the key
     * encodes is not. When the ring holds neither event type, falls back to
     * a direct membership scan of `history.mFallbackIdRunBegin/End` against
     * `candidateUnit->mParams.mEntityId`.
     */
    [[nodiscard]] bool IsCandidateExcludedByCachedRelation(
      CommandGraphAnchorHistoryRuntimeView& history, UserUnit* const candidateUnit
    ) noexcept
    {
      std::uint32_t cursor = history.mEntryStart + history.mEntryCount;
      while (cursor != history.mEntryStart) {
        const std::uint32_t previousCursor = cursor - 1u;
        std::uint32_t ringIndex = previousCursor;
        if (history.mEntryBase <= previousCursor) {
          ringIndex = previousCursor - history.mEntryBase;
        }
        cursor = previousCursor;

        CommandGraphAnchorHistoryEntryRuntimeView* const entry = history.mEntries[ringIndex];
        const std::int32_t entryType = entry->mEntryType;
        if (entryType != 0 && entryType != 3) {
          continue;
        }

        // 0x008B4370/0x008B439A: the binary runs this exact lookup (same tree,
        // same key) twice per entry - once as an immediate-exclude gate only
        // reachable for type 0 (0x008B434A: type 3 jumps straight past it via
        // loc_8B4375), once as the shared found/not-found gate both types share.
        // Nothing observable happens between the two calls (see this function's
        // own doc comment on sub_82CEA0's inert scope-guard dance), so both reads
        // are provably identical; computed once here instead of twice.
        const bool foundInRelationTree =
          LowerBoundWeakEntitySetNode(entry->mRelationTree, history.mRelationLookupKey) !=
          entry->mRelationTree.mHead;

        if (entryType == 0 && foundInRelationTree) {
          return true; // immediate exclude (0x008B43AB)
        }
        if (foundInRelationTree) {
          return false; // found on the shared gate: stop scanning, don't exclude (0x008B439F)
        }
        // not found: keep scanning older ring entries (0x008B439D -> loc_8B4320)
      }

      // Matches "return i != v15": excludes the candidate when its entity id
      // *is* present in the fallback id run (not when it's absent).
      for (const std::int32_t* idCursor = history.mFallbackIdRunBegin; idCursor != history.mFallbackIdRunEnd;
           ++idCursor) {
        if (*idCursor == candidateUnit->mParams.mEntityId) {
          return true;
        }
      }
      return false;
    }

  } // namespace

  /**
   * Address: 0x00829B40 (FUN_00829B40, func_ProcessCommandDrag)
     *
     * What it does:
     * The click-and-drag command redirect keystone both `UICommandDragger::
     * DragMove` and `DragRelease` (UiRuntimeTypes.h/.cpp) funnel into. Looks
     * the dragged command's live helper up by id; if the mouse position is
     * invalid or the command isn't found, does nothing. Otherwise updates
     * (or creates) the command's `mMapAB0` draw-node with the current mouse
     * position (keyed by the helper's own pointer identity - see
     * `sub_82C2E0`'s asm), and, for a factory-build command
     * (`ResolveCommandIssueHelperCommandType == 8`) whose draw node was
     * already resolved, re-validates build placement via
     * `USERUNIT_CanBeBuiltAt` and updates the node's visibility flag
     * (honoring `CWldSession::mShowInvalidBuildPlacementPreview`'s
     * override). On release, unless the drag just ended over an invalid
     * build placement, dispatches the new target: when the command already
     * follows a live cached target entity
     * (`ResolveCommandTargetEntityFromAnchorHistory`), searches nearby
     * collected entities for the closest live unit sharing the cached
     * target's army and not excluded by `IsCandidateExcludedByCachedRelation`,
     * and issues that entity as the new target; otherwise, for a live
     * factory-build command, snaps to the blueprint's resolved-footprint
     * world position; otherwise clamps the raw mouse position to the map's
     * playable rect and issues that as a `Position` target. All three paths
     * converge on `Moho::ISSUE_SetCommandTarget`.
     */
    void ProcessCommandDrag(
      const Wm3::Vector3f& mouse, UICommandGraph& graph, const CmdId cmdId, const bool released
    )
    {
      CommandManager* const commandManager = graph.mSession->mCommandManager;

      UserCommandIssueHelper* helper = nullptr;
      if (const auto found = commandManager->mCommands.find(cmdId); found != commandManager->mCommands.end()) {
        helper = found->second;
      }
      if (helper == nullptr) {
        return;
      }

      if (!IsValidVector3f(mouse)) {
        return;
      }

      // mMapAB0's draw-node hash is keyed by the helper's own pointer
      // identity, not its command id (0x0082C2E3: sub_82C2E0 dereferences
      // its "key" arg once via [esi]; this function's own call passes
      // &result where result held the helper pointer's raw value).
      const auto drawNodeKey = reinterpret_cast<std::uint32_t>(helper);

      bool suppressDispatch = false;
      if (UICommandGraph::CountHashListNode88(graph.mMapAB0, drawNodeKey) != 0) {
        UICommandGraph::UICommandGraphDrawNode* const drawNode =
          UICommandGraph::FindOrInsertCommandGraphDrawNode(drawNodeKey, graph.mMapAB0);

        drawNode->mPositionSum = mouse;
        drawNode->mWeight = 1.0f;

        if (drawNode->mHasResolvedPosition != 0 &&
            ResolveCommandIssueHelperCommandType(*helper) == static_cast<EUnitCommandType>(8)) {
          if (const REntityBlueprint* const genericBlueprint = helper->mConstantData.blueprint;
              genericBlueprint != nullptr) {
            gpg::RRef blueprintRef{};
            (void)gpg::RRef_REntityBlueprint(&blueprintRef, const_cast<REntityBlueprint*>(genericBlueprint));
            const gpg::RRef unitBlueprintRef = gpg::REF_UpcastPtr(blueprintRef, RUnitBlueprint::StaticGetClass());
            if (unitBlueprintRef.mObj != nullptr) {
              const auto* const unitBlueprint = static_cast<const RUnitBlueprint*>(unitBlueprintRef.mObj);
              const float inverseWeight = 1.0f / drawNode->mWeight;
              const SCoordsVec2 buildCenter{
                drawNode->mPositionSum.x * inverseWeight, drawNode->mPositionSum.z * inverseWeight
              };
              SOccupationResult buildInfo{};
              const bool canBuild = USERUNIT_CanBeBuiltAt(
                *graph.mSession, unitBlueprint, buildCenter, false, &buildInfo,
                reinterpret_cast<const UserCommand*>(helper)
              );
              drawNode->mIsVisible = (canBuild || !graph.mSession->mShowInvalidBuildPlacementPreview) ? 1u : 0u;
            }
          }
        }

        const bool wasInvalidPlacement = (drawNode->mIsVisible == 0);
        drawNode->mHasResolvedPosition = released ? 0u : 1u;
        if (wasInvalidPlacement && released) {
          suppressDispatch = true;
        }
      }

      if (!released || suppressDispatch) {
        return;
      }

      if (UserEntity* const cachedTargetEntity = ResolveCommandTargetEntityFromAnchorHistory(
            reinterpret_cast<CommandGraphAnchorHistoryRuntimeView*>(helper)
          );
          cachedTargetEntity != nullptr) {
        // Cached-target reacquire: search nearby collected entities for the
        // closest live unit sharing the cached target's army.
        gpg::fastvector<UserEntity*> candidates{};
        auto* const spatialDb = static_cast<SpatialDB_MeshInstance*>(graph.mSession->GetEntitySpatialDbStorage());
        (void)spatialDb->Collect(candidates, ENTITYTYPE_Unit);

        UserEntity* closest = nullptr;
        float closestDistanceSq = std::numeric_limits<float>::infinity();
        for (UserEntity* const candidate : candidates) {
          if (candidate == nullptr || candidate->IsBeingBuilt()) {
            continue;
          }

          if (UserUnit* const candidateUnit = candidate->IsUserUnit(); candidateUnit != nullptr) {
            auto& anchorHistory = reinterpret_cast<CommandGraphAnchorHistoryRuntimeView&>(*helper);
            if (IsCandidateExcludedByCachedRelation(anchorHistory, candidateUnit)) {
              continue;
            }
          }

          if (candidate->mArmy != cachedTargetEntity->mArmy) {
            continue;
          }

          const Wm3::Vec3f& candidatePos = candidate->mVariableData.mCurTransform.pos_;
          const float deltaX = mouse.x - candidatePos.x;
          const float deltaZ = mouse.z - candidatePos.z;
          const float distanceSq = (deltaX * deltaX) + (deltaZ * deltaZ);
          if (distanceSq < closestDistanceSq) {
            closestDistanceSq = distanceSq;
            closest = candidate;
          }
        }

        if (closest != nullptr) {
          UserCommandTargetView entityTarget{};
          entityTarget.targetType = UserTargetType::Entity;
          LinkEntityWeakRef(closest, reinterpret_cast<SSelectionWeakRefUserEntity&>(entityTarget.targetEntity));
          ISSUE_SetCommandTarget(helper, entityTarget);
          UnlinkEntityWeakRef(reinterpret_cast<SSelectionWeakRefUserEntity&>(entityTarget.targetEntity));
        }
        return;
      }

      const REntityBlueprint* const genericBlueprint = helper->mConstantData.blueprint;
      if (ResolveCommandIssueHelperCommandType(*helper) == static_cast<EUnitCommandType>(8) &&
          genericBlueprint != nullptr) {
        // Factory-build command: snap to the blueprint's resolved-footprint
        // world position.
        gpg::RRef blueprintRef{};
        (void)gpg::RRef_REntityBlueprint(&blueprintRef, const_cast<REntityBlueprint*>(genericBlueprint));
        const gpg::RRef unitBlueprintRef = gpg::REF_UpcastPtr(blueprintRef, RUnitBlueprint::StaticGetClass());
        const auto* const unitBlueprint = static_cast<const RUnitBlueprint*>(unitBlueprintRef.mObj);
        const SFootprint* const footprint =
          (unitBlueprint != nullptr) ? unitBlueprint->Physics.ResolvedFootprint : nullptr;
        if (footprint != nullptr) {
          const STIMap* const map =
            reinterpret_cast<STIMap*>(graph.mSession->mWldMap->mTerrainRes->mPlayableRectSource);
          const SOCellPos cell = footprint->ToCellPos(mouse);
          const Wm3::Vector3f worldPos = COORDS_ToWorldPos(map, cell, LAYER_None, 1, 1);

          UserCommandTargetView positionTarget{};
          positionTarget.targetType = UserTargetType::Position;
          positionTarget.position = worldPos;
          ISSUE_SetCommandTarget(helper, positionTarget);
        }
        return;
      }

      // Default: clamp the raw mouse position to the map's playable rect and
      // issue it as a `Position` target.
      const STIMap* const map = reinterpret_cast<STIMap*>(graph.mSession->mWldMap->mTerrainRes->mPlayableRectSource);
      Wm3::Vector3f clampedPos = mouse;
      clampedPos.x = std::clamp(
        clampedPos.x, static_cast<float>(map->mPlayableRect.x0 + 1), static_cast<float>(map->mPlayableRect.x1 - 1)
      );
      clampedPos.z = std::clamp(
        clampedPos.z, static_cast<float>(map->mPlayableRect.z0 + 1), static_cast<float>(map->mPlayableRect.z1 - 1)
      );

      UserCommandTargetView positionTarget{};
      positionTarget.targetType = UserTargetType::Position;
      positionTarget.position = clampedPos;
      ISSUE_SetCommandTarget(helper, positionTarget);
    }

  namespace
  {
    /**
     * Alias of FUN_008BED50.
     *
     * What it does:
     * Resolves one anchor sample to world position: owner-linked entity
     * position for kind `1`, inline position for kind `2`, otherwise invalid.
     */
    [[nodiscard]] Wm3::Vector3f* ResolveCommandGraphAnchorSamplePositionAlias(
      const CommandGraphAnchorSampleRuntimeView* const sample,
      Wm3::Vector3f* const outPosition
    ) noexcept
    {
      if (outPosition == nullptr) {
        return nullptr;
      }
      if (sample == nullptr) {
        *outPosition = InvalidCommandGraphAnchorPosition();
        return outPosition;
      }

      if (sample->mSampleKind == 1) {
        UserEntity* const entity = DecodeSelectedUserEntity(sample->mWeakRef);
        if (entity == nullptr) {
          *outPosition = InvalidCommandGraphAnchorPosition();
        } else {
          const Wm3::Vec3f& entityPos = entity->mVariableData.mCurTransform.pos_;
          outPosition->x = entityPos.x;
          outPosition->y = entityPos.y;
          outPosition->z = entityPos.z;
        }
        return outPosition;
      }

      if (sample->mSampleKind == 2) {
        *outPosition = sample->mWorldPosition;
        return outPosition;
      }

      *outPosition = InvalidCommandGraphAnchorPosition();
      return outPosition;
    }

    /**
     * Address: 0x0081CFD0 (FUN_0081CFD0)
     *
     * What it does:
     * Resolves one command-graph anchor sample from history into world space
     * and then unlinks temporary weak-owner lanes from the owner chain.
     */
    [[nodiscard]] Wm3::Vector3f* ResolveCommandGraphAnchorHistoryWorldPosition(
      Wm3::Vector3f* const outPosition,
      CommandGraphAnchorHistoryRuntimeView* const history
    ) noexcept
    {
      if (outPosition == nullptr) {
        return nullptr;
      }

      CommandGraphAnchorSampleRuntimeView sample{};
      (void)ResolveCommandGraphAnchorSampleFromHistory(&sample, history);
      (void)ResolveCommandGraphAnchorSamplePositionAlias(&sample, outPosition);

      if (sample.mWeakRef.mOwnerLinkSlot != nullptr) {
        (void)UnlinkSelectionWeakOwnerRefNoReset(sample.mWeakRef);
      }

      return outPosition;
    }

    /**
     * Address: 0x008B38C0 (FUN_008B38C0)
     *
     * What it does:
     * Unlinks each weak-ref node in one half-open `[begin,end)` range from its
     * intrusive owner chain without resetting link fields.
     */
    void UnlinkSelectionWeakOwnerRefRangeNoReset(
      SSelectionWeakRefUserEntity* const begin,
      SSelectionWeakRefUserEntity* const end
    ) noexcept
    {
      for (SSelectionWeakRefUserEntity* weakRef = begin; weakRef != end; ++weakRef) {
        (void)UnlinkSelectionWeakOwnerRefNoReset(*weakRef);
      }
    }

    void UnlinkSelectionWeakOwnerRef(SSelectionWeakRefUserEntity& weakRef)
    {
      (void)UnlinkSelectionWeakOwnerRefNoReset(weakRef);
      weakRef.mOwnerLinkSlot = nullptr;
      weakRef.mNextOwner = nullptr;
    }

    [[nodiscard]] SessionSaveSourceNode* GetSaveSourceTreeHead(const CWldSession* const session)
    {
      return static_cast<SessionSaveSourceNode*>(session->mSaveSourceTreeHead);
    }

    [[nodiscard]] SessionEntityMap& GetSessionEntityMap(CWldSession* const session)
    {
      static_assert(offsetof(CWldSession, mUnknownOwner44) == 0x44, "CWldSession::mUnknownOwner44 offset must be 0x44");
      static_assert(
        offsetof(CWldSession, mSaveSourceTreeHead) == 0x48,
        "CWldSession::mSaveSourceTreeHead offset must be 0x48"
      );
      static_assert(
        offsetof(CWldSession, mSaveSourceTreeSize) == 0x4C,
        "CWldSession::mSaveSourceTreeSize offset must be 0x4C"
      );
      return *reinterpret_cast<SessionEntityMap*>(&session->mUnknownOwner44);
    }

    struct CommandIssueOwnerRuntimeView
    {
      std::uint8_t mUnknown00_20F[0x210];
      moho::EntId mEntityId; // +0x210
    };

    static_assert(
      offsetof(CommandIssueOwnerRuntimeView, mEntityId) == 0x210,
      "CommandIssueOwnerRuntimeView::mEntityId offset must be 0x210"
    );

    /**
     * Address: 0x00824500 (FUN_00824500, sub_824500)
     *
     * What it does:
     * Reads one entity-id lane at `+0x210` from command-owner runtime storage,
     * then resolves the live `UserEntity*` through the active session entity map.
     */
    [[nodiscard]] UserEntity* ResolveEntityFromCommandIssueOwner(const void* const commandOwner)
    {
      CWldSession* const session = moho::WLD_GetSession();
      if (commandOwner == nullptr || session == nullptr) {
        return nullptr;
      }

      const auto* const ownerView = static_cast<const CommandIssueOwnerRuntimeView*>(commandOwner);
      return session->LookupEntityId(ownerView->mEntityId);
    }

    [[nodiscard]] bool IsSessionEntityNodeNil(
      const SessionEntityMapNode* const node,
      const SessionEntityMapNode* const head
    ) noexcept
    {
      return node == nullptr || node == head || node->mIsSentinel != 0u;
    }

    [[nodiscard]] SessionEntityMapNode* SessionEntityTreeMin(
      SessionEntityMapNode* node,
      SessionEntityMapNode* const head
    ) noexcept
    {
      while (!IsSessionEntityNodeNil(node, head) && !IsSessionEntityNodeNil(node->mLeft, head)) {
        node = node->mLeft;
      }
      return IsSessionEntityNodeNil(node, head) ? head : node;
    }

    [[nodiscard]] SessionEntityMapNode* SessionEntityTreeMax(
      SessionEntityMapNode* node,
      SessionEntityMapNode* const head
    ) noexcept
    {
      while (!IsSessionEntityNodeNil(node, head) && !IsSessionEntityNodeNil(node->mRight, head)) {
        node = node->mRight;
      }
      return IsSessionEntityNodeNil(node, head) ? head : node;
    }

    void RecomputeSessionEntityMapExtrema(SessionEntityMap& map) noexcept
    {
      SessionEntityMapNode* const head = map.mHead;
      if (head == nullptr) {
        return;
      }

      SessionEntityMapNode* const root = head->mParent;
      if (IsSessionEntityNodeNil(root, head)) {
        head->mParent = head;
        head->mLeft = head;
        head->mRight = head;
        return;
      }

      head->mLeft = SessionEntityTreeMin(root, head);
      head->mRight = SessionEntityTreeMax(root, head);
    }

    void DestroySessionEntityMapIteratorRange(
      SessionEntityMapNode* node,
      SessionEntityMapNode* const head
    ) noexcept
    {
      while (!IsSessionEntityNodeNil(node, head)) {
        SessionEntityMapNode* const eraseNode = node;
        node = NextTreeNode(node);
        ::operator delete(eraseNode);
      }
    }

    /**
     * Address: 0x008939D0 (FUN_008939D0, sub_8939D0)
     *
     * What it does:
     * Destroys one full session-entity tree rooted under `map.mHead`, releases
     * the sentinel head node, and clears retained head/size lanes.
     */
    void DestroySessionEntityMapStorage(SessionEntityMap& map) noexcept
    {
      SessionEntityMapNode* const head = map.mHead;
      if (head != nullptr) {
        DestroySessionEntityMapIteratorRange(head->mLeft, head);
        ::operator delete(head);
      }

      map.mHead = nullptr;
      map.mSize = 0u;
    }

    [[nodiscard]] SessionEntityMapNode* FindSessionEntityMapNodeById(
      SessionEntityMap& map,
      const std::uint32_t entityId
    ) noexcept
    {
      SessionEntityMapNode* const head = map.mHead;
      if (head == nullptr) {
        return nullptr;
      }

      SessionEntityMapNode* node = head->mParent;
      while (!IsSessionEntityNodeNil(node, head)) {
        if (entityId < node->mEntityId) {
          node = node->mLeft;
          continue;
        }
        if (node->mEntityId < entityId) {
          node = node->mRight;
          continue;
        }
        return node;
      }

      return head;
    }

    void RotateSessionEntityLeft(SessionEntityMap& map, SessionEntityMapNode* const node) noexcept
    {
      SessionEntityMapNode* const head = map.mHead;
      SessionEntityMapNode* const pivot = node->mRight;
      node->mRight = pivot->mLeft;
      if (!IsSessionEntityNodeNil(pivot->mLeft, head)) {
        pivot->mLeft->mParent = node;
      }

      pivot->mParent = node->mParent;
      if (node->mParent == head) {
        head->mParent = pivot;
      } else if (node == node->mParent->mLeft) {
        node->mParent->mLeft = pivot;
      } else {
        node->mParent->mRight = pivot;
      }

      pivot->mLeft = node;
      node->mParent = pivot;
    }

    void RotateSessionEntityRight(SessionEntityMap& map, SessionEntityMapNode* const node) noexcept
    {
      SessionEntityMapNode* const head = map.mHead;
      SessionEntityMapNode* const pivot = node->mLeft;
      node->mLeft = pivot->mRight;
      if (!IsSessionEntityNodeNil(pivot->mRight, head)) {
        pivot->mRight->mParent = node;
      }

      pivot->mParent = node->mParent;
      if (node->mParent == head) {
        head->mParent = pivot;
      } else if (node == node->mParent->mRight) {
        node->mParent->mRight = pivot;
      } else {
        node->mParent->mLeft = pivot;
      }

      pivot->mRight = node;
      node->mParent = pivot;
    }

    [[nodiscard]] SessionEntityMapNode* AllocateSessionEntityMapNode()
    {
      SessionEntityMapNode* const node =
        static_cast<SessionEntityMapNode*>(::operator new(sizeof(SessionEntityMapNode)));
      node->mLeft = nullptr;
      node->mParent = nullptr;
      node->mRight = nullptr;
      node->mEntityId = 0u;
      node->mEntity = nullptr;
      node->pad_14_17[0] = 0u;
      node->pad_14_17[1] = 0u;
      node->pad_14_17[2] = 0u;
      node->pad_14_17[3] = 0u;
      node->mColor = 0u;
      node->mIsSentinel = 0u;
      node->pad_1A[0] = 0u;
      node->pad_1A[1] = 0u;
      return node;
    }

    [[nodiscard]] SessionEntityMapNode* CreateSessionEntityMapHead()
    {
      SessionEntityMapNode* const head = AllocateSessionEntityMapNode();
      head->mColor = 1u;
      head->mIsSentinel = 1u;
      head->mLeft = head;
      head->mParent = head;
      head->mRight = head;
      return head;
    }

    [[nodiscard]] SessionEntityMapNode* EnsureSessionEntityMapHead(SessionEntityMap& map)
    {
      if (map.mHead == nullptr) {
        map.mHead = CreateSessionEntityMapHead();
        map.mSize = 0u;
      }
      return map.mHead;
    }

    void FixupAfterSessionEntityInsert(SessionEntityMap& map, SessionEntityMapNode* node) noexcept
    {
      SessionEntityMapNode* const head = map.mHead;
      while (node->mParent->mColor == 0u) {
        SessionEntityMapNode* const parent = node->mParent;
        SessionEntityMapNode* const grand = parent->mParent;
        if (parent == grand->mLeft) {
          SessionEntityMapNode* const uncle = grand->mRight;
          if (uncle->mColor == 0u) {
            parent->mColor = 1u;
            uncle->mColor = 1u;
            grand->mColor = 0u;
            node = grand;
          } else {
            if (node == parent->mRight) {
              node = parent;
              RotateSessionEntityLeft(map, node);
            }
            node->mParent->mColor = 1u;
            node->mParent->mParent->mColor = 0u;
            RotateSessionEntityRight(map, node->mParent->mParent);
          }
        } else {
          SessionEntityMapNode* const uncle = grand->mLeft;
          if (uncle->mColor == 0u) {
            parent->mColor = 1u;
            uncle->mColor = 1u;
            grand->mColor = 0u;
            node = grand;
          } else {
            if (node == parent->mLeft) {
              node = parent;
              RotateSessionEntityRight(map, node);
            }
            node->mParent->mColor = 1u;
            node->mParent->mParent->mColor = 0u;
            RotateSessionEntityLeft(map, node->mParent->mParent);
          }
        }
      }

      head->mParent->mColor = 1u;
    }

    /**
     * Address: 0x00898A50 (FUN_00898A50, std::map<Moho::EntId,Moho::UserEntity*>::insert)
     *
     * What it does:
     * BST-descends `SessionEntityMap` by `entityId`, returns immediately on an
     * existing key (matching `std::map::insert`'s "keeps the existing value"
     * semantics), otherwise allocates and links a fresh node then red-black
     * rebalances from it. The binary's own decompile splits find-position and
     * link+rebalance across this function and a `sub_899490` tail; both phases
     * are faithfully present here in one method rather than split further.
     */
    void InsertSessionEntityMapEntry(
      SessionEntityMap& map,
      const std::uint32_t entityId,
      UserEntity* const entity
    ) noexcept
    {
      SessionEntityMapNode* const head = EnsureSessionEntityMapHead(map);
      SessionEntityMapNode* parent = head;
      SessionEntityMapNode* current = head->mParent;
      bool insertLeft = true;

      while (!IsSessionEntityNodeNil(current, head)) {
        parent = current;
        if (entityId < current->mEntityId) {
          insertLeft = true;
          current = current->mLeft;
          continue;
        }
        if (current->mEntityId < entityId) {
          insertLeft = false;
          current = current->mRight;
          continue;
        }

        // std::map::insert keeps the existing value when key already exists.
        return;
      }

      SessionEntityMapNode* const node = AllocateSessionEntityMapNode();
      node->mEntityId = entityId;
      node->mEntity = entity;
      node->mLeft = head;
      node->mRight = head;
      node->mParent = parent;

      ++map.mSize;
      if (parent == head) {
        head->mParent = node;
        head->mLeft = node;
        head->mRight = node;
      } else if (insertLeft) {
        parent->mLeft = node;
        if (parent == head->mLeft) {
          head->mLeft = node;
        }
      } else {
        parent->mRight = node;
        if (parent == head->mRight) {
          head->mRight = node;
        }
      }

      FixupAfterSessionEntityInsert(map, node);
    }

    void TransplantSessionEntityNode(
      SessionEntityMap& map,
      SessionEntityMapNode* const source,
      SessionEntityMapNode* const replacement
    ) noexcept
    {
      SessionEntityMapNode* const head = map.mHead;
      if (source->mParent == head) {
        head->mParent = replacement;
      } else if (source == source->mParent->mLeft) {
        source->mParent->mLeft = replacement;
      } else {
        source->mParent->mRight = replacement;
      }

      if (replacement != head) {
        replacement->mParent = source->mParent;
      }
    }

    void FixupAfterSessionEntityErase(
      SessionEntityMap& map,
      SessionEntityMapNode* node,
      SessionEntityMapNode* nodeParent
    ) noexcept
    {
      SessionEntityMapNode* const head = map.mHead;
      SessionEntityMapNode* parent = !IsSessionEntityNodeNil(node, head) ? node->mParent : nodeParent;

      while (node != head->mParent && (IsSessionEntityNodeNil(node, head) || node->mColor == 1u)) {
        if (parent == nullptr) {
          break;
        }

        if (node == parent->mLeft) {
          SessionEntityMapNode* sibling = parent->mRight;
          if (sibling == head) {
            break;
          }

          if (sibling->mColor == 0u) {
            sibling->mColor = 1u;
            parent->mColor = 0u;
            RotateSessionEntityLeft(map, parent);
            sibling = parent->mRight;
          }

          const bool siblingLeftBlack = (sibling->mLeft == head) || (sibling->mLeft->mColor == 1u);
          const bool siblingRightBlack = (sibling->mRight == head) || (sibling->mRight->mColor == 1u);
          if (siblingLeftBlack && siblingRightBlack) {
            sibling->mColor = 0u;
            node = parent;
            parent = node->mParent;
          } else {
            if ((sibling->mRight == head) || (sibling->mRight->mColor == 1u)) {
              if (sibling->mLeft != head) {
                sibling->mLeft->mColor = 1u;
              }
              sibling->mColor = 0u;
              RotateSessionEntityRight(map, sibling);
              sibling = parent->mRight;
            }

            sibling->mColor = parent->mColor;
            parent->mColor = 1u;
            if (sibling->mRight != head) {
              sibling->mRight->mColor = 1u;
            }
            RotateSessionEntityLeft(map, parent);
            node = head->mParent;
            break;
          }
        } else {
          SessionEntityMapNode* sibling = parent->mLeft;
          if (sibling == head) {
            break;
          }

          if (sibling->mColor == 0u) {
            sibling->mColor = 1u;
            parent->mColor = 0u;
            RotateSessionEntityRight(map, parent);
            sibling = parent->mLeft;
          }

          const bool siblingRightBlack = (sibling->mRight == head) || (sibling->mRight->mColor == 1u);
          const bool siblingLeftBlack = (sibling->mLeft == head) || (sibling->mLeft->mColor == 1u);
          if (siblingRightBlack && siblingLeftBlack) {
            sibling->mColor = 0u;
            node = parent;
            parent = node->mParent;
          } else {
            if ((sibling->mLeft == head) || (sibling->mLeft->mColor == 1u)) {
              if (sibling->mRight != head) {
                sibling->mRight->mColor = 1u;
              }
              sibling->mColor = 0u;
              RotateSessionEntityLeft(map, sibling);
              sibling = parent->mLeft;
            }

            sibling->mColor = parent->mColor;
            parent->mColor = 1u;
            if (sibling->mLeft != head) {
              sibling->mLeft->mColor = 1u;
            }
            RotateSessionEntityRight(map, parent);
            node = head->mParent;
            break;
          }
        }
      }

      if (!IsSessionEntityNodeNil(node, head)) {
        node->mColor = 1u;
      }
    }

    /**
     * Address: 0x00898B10 (FUN_00898B10, std::map<Moho::EntId,Moho::UserEntity*>::erase)
     *
     * What it does:
     * Splices `node` out of `SessionEntityMap`'s red-black tree and red-black
     * rebalances from the splice point, mirroring the standard `_Tree::erase`
     * unlink/rebalance shape.
     *
     * Known simplification: the binary throws `std::out_of_range("invalid
     * map/set<T> iterator")` when `node` is the nil sentinel; this recovery
     * treats that case as a silent no-op instead. Every real caller
     * (`CWldSession::RemoveEntity`/`OrphanEntity`) already guards
     * `mapNode != nullptr && mapNode != entityMap.mHead` before calling this,
     * so the divergence is unreachable from any currently-recovered call
     * site — left as a documented gap rather than silently claimed identical.
     */
    void EraseSessionEntityMapNode(SessionEntityMap& map, SessionEntityMapNode* const node) noexcept
    {
      SessionEntityMapNode* const head = map.mHead;
      if (head == nullptr || IsSessionEntityNodeNil(node, head)) {
        return;
      }

      SessionEntityMapNode* splice = node;
      std::uint8_t removedColor = splice->mColor;
      SessionEntityMapNode* fixNode = head;
      SessionEntityMapNode* fixParent = nullptr;

      if (node->mLeft == head) {
        fixNode = node->mRight;
        fixParent = node->mParent;
        TransplantSessionEntityNode(map, node, node->mRight);
      } else if (node->mRight == head) {
        fixNode = node->mLeft;
        fixParent = node->mParent;
        TransplantSessionEntityNode(map, node, node->mLeft);
      } else {
        splice = SessionEntityTreeMin(node->mRight, head);
        removedColor = splice->mColor;
        fixNode = splice->mRight;
        if (splice->mParent == node) {
          fixParent = splice;
          if (fixNode != head) {
            fixNode->mParent = splice;
          }
        } else {
          TransplantSessionEntityNode(map, splice, splice->mRight);
          splice->mRight = node->mRight;
          splice->mRight->mParent = splice;
          fixParent = splice->mParent;
        }

        TransplantSessionEntityNode(map, node, splice);
        splice->mLeft = node->mLeft;
        splice->mLeft->mParent = splice;
        splice->mColor = node->mColor;
      }

      ::operator delete(node);
      if (map.mSize > 0u) {
        --map.mSize;
      }

      if (removedColor == 1u) {
        FixupAfterSessionEntityErase(map, fixNode, fixParent);
      }

      RecomputeSessionEntityMapExtrema(map);
    }

    void CollectSessionUserUnits(CWldSession* const session, msvc8::vector<UserUnit*>& outUnits)
    {
      outUnits.clear();
      if (session == nullptr) {
        return;
      }

      SessionEntityMap& entityMap = GetSessionEntityMap(session);
      SessionEntityMapNode* const head = entityMap.mHead;
      if (head == nullptr || head->mLeft == head) {
        return;
      }

      for (SessionEntityMapNode* node = head->mLeft; node != nullptr && node != head; node = NextTreeNode(node)) {
        UserEntity* const entity = node->mEntity;
        if (entity == nullptr) {
          continue;
        }

        UserUnit* const unit = entity->IsUserUnit();
        if (unit == nullptr) {
          continue;
        }

        AppendUnitUnique(outUnits, unit);
      }
    }

    [[nodiscard]] bool ApplyTerrainPlayableRect(IWldTerrainRes* const terrainRes, const gpg::Rect2i& playableRect)
    {
      if (terrainRes == nullptr) {
        return false;
      }
      return terrainRes->SetPlayableMapRect(VisibilityRect::FromRect2i(playableRect));
    }

    /**
     * Address: 0x0089A970 (FUN_0089A970) allocation path (FUN_0089A970) for insert-node creation.
     *
     * Source-side typed helper used to keep node allocation/layout explicit.
     */
    [[nodiscard]] SSessionSaveNodeMapNode* AllocateSaveDataMapNode()
    {
      auto* const raw = ::operator new(sizeof(SSessionSaveNodeMapNode));
      auto* const node = new (raw) SSessionSaveNodeMapNode{};
      node->mColor = 0u;
      node->mIsSentinel = 0u;
      return node;
    }

    /**
     * Address: 0x0089AC40 (FUN_0089AC40) cleanup chain (FUN_008971A0 -> FUN_0089AC40 call path).
     */
    void DestroySaveDataMapNode(SSessionSaveNodeMapNode* const node)
    {
      if (!node) {
        return;
      }

      node->~SSessionSaveNodeMapNode();
      ::operator delete(node);
    }

    /**
     * Address: 0x0089A930 (FUN_0089A930) sentinel header-node allocation/init path.
     */
    [[nodiscard]] SSessionSaveNodeMapNode* CreateSaveDataMapHead()
    {
      SSessionSaveNodeMapNode* const head = AllocateSaveDataMapNode();
      head->mColor = 1u;
      head->mIsSentinel = 1u;
      head->mLeft = head;
      head->mParent = head;
      head->mRight = head;
      return head;
    }

    /**
     * Address: 0x00897140 (FUN_00897140)
     *
     * What it does:
     * Initializes one session save-node map header lane (sentinel self-links)
     * and clears entry count.
     */
    SSessionSaveNodeMap* InitializeSessionSaveNodeMapHeader(
      SSessionSaveNodeMap* const outMap
    )
    {
      SSessionSaveNodeMapNode* const head = CreateSaveDataMapHead();
      outMap->mHead = head;
      head->mIsSentinel = 1u;
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      outMap->mSize = 0u;
      return outMap;
    }

    /**
     * Address: 0x0089A8E0 (FUN_0089A8E0).
     */
    void RotateSaveDataLeft(SSessionSaveNodeMap& map, SSessionSaveNodeMapNode* const node)
    {
      SSessionSaveNodeMapNode* const head = map.mHead;
      SSessionSaveNodeMapNode* const pivot = node->mRight;
      node->mRight = pivot->mLeft;
      if (!IsSentinelNode(pivot->mLeft)) {
        pivot->mLeft->mParent = node;
      }

      pivot->mParent = node->mParent;
      if (node == head->mParent) {
        head->mParent = pivot;
      } else if (node == node->mParent->mLeft) {
        node->mParent->mLeft = pivot;
      } else {
        node->mParent->mRight = pivot;
      }

      pivot->mLeft = node;
      node->mParent = pivot;
    }

    /**
     * Address: 0x0089A880 (FUN_0089A880).
     */
    void RotateSaveDataRight(SSessionSaveNodeMap& map, SSessionSaveNodeMapNode* const node)
    {
      SSessionSaveNodeMapNode* const head = map.mHead;
      SSessionSaveNodeMapNode* const pivot = node->mLeft;
      node->mLeft = pivot->mRight;
      if (!IsSentinelNode(pivot->mRight)) {
        pivot->mRight->mParent = node;
      }

      pivot->mParent = node->mParent;
      if (node == head->mParent) {
        head->mParent = pivot;
      } else if (node == node->mParent->mRight) {
        node->mParent->mRight = pivot;
      } else {
        node->mParent->mLeft = pivot;
      }

      pivot->mRight = node;
      node->mParent = pivot;
    }

    /**
     * Address: 0x00899DC0 (FUN_00899DC0) RB-tree insert rebalance sequence.
     *
     * Source-side typed split of the original monolithic helper body.
     */
    void FixupSaveDataInsert(SSessionSaveNodeMap& map, SSessionSaveNodeMapNode* node)
    {
      SSessionSaveNodeMapNode* const head = map.mHead;
      while (node->mParent->mColor == 0u) {
        SSessionSaveNodeMapNode* const parent = node->mParent;
        SSessionSaveNodeMapNode* const grand = parent->mParent;
        if (parent == grand->mLeft) {
          SSessionSaveNodeMapNode* const uncle = grand->mRight;
          if (uncle->mColor == 0u) {
            parent->mColor = 1u;
            uncle->mColor = 1u;
            grand->mColor = 0u;
            node = grand;
          } else {
            if (node == parent->mRight) {
              node = parent;
              RotateSaveDataLeft(map, node);
            }
            node->mParent->mColor = 1u;
            node->mParent->mParent->mColor = 0u;
            RotateSaveDataRight(map, node->mParent->mParent);
          }
        } else {
          SSessionSaveNodeMapNode* const uncle = grand->mLeft;
          if (uncle->mColor == 0u) {
            parent->mColor = 1u;
            uncle->mColor = 1u;
            grand->mColor = 0u;
            node = grand;
          } else {
            if (node == parent->mLeft) {
              node = parent;
              RotateSaveDataRight(map, node);
            }
            node->mParent->mColor = 1u;
            node->mParent->mParent->mColor = 0u;
            RotateSaveDataLeft(map, node->mParent->mParent);
          }
        }
      }

      head->mParent->mColor = 1u;
    }

    /**
      * Alias of FUN_008992D0 (non-canonical helper lane).
     * (FUN_008992D0 -> FUN_00899DC0 -> FUN_0089A970 chain).
     *
     * Source-side typed split around search/insert/fixup stages.
     */
    void InsertSaveDataLabelNode(SSessionSaveNodeMap& map, const SSessionSaveNodeLabel& label)
    {
      SSessionSaveNodeMapNode* const head = map.mHead;
      SSessionSaveNodeMapNode* parent = head;
      SSessionSaveNodeMapNode* current = head->mParent;
      bool insertLeft = true;

      while (!IsSentinelNode(current)) {
        parent = current;
        insertLeft = (label.mCommandSourceId < current->mLabel.mCommandSourceId);
        current = insertLeft ? current->mLeft : current->mRight;
      }

      SSessionSaveNodeMapNode* const node = AllocateSaveDataMapNode();
      node->mLabel.mCommandSourceId = label.mCommandSourceId;
      node->mLabel.mSaveNodeName = label.mSaveNodeName;
      node->mLeft = head;
      node->mRight = head;
      node->mParent = parent;

      ++map.mSize;
      if (parent == head) {
        head->mParent = node;
        head->mLeft = node;
        head->mRight = node;
      } else if (insertLeft) {
        parent->mLeft = node;
        if (parent == head->mLeft) {
          head->mLeft = node;
        }
      } else {
        parent->mRight = node;
        if (parent == head->mRight) {
          head->mRight = node;
        }
      }

      FixupSaveDataInsert(map, node);
    }

    /**
      * Alias of FUN_008971A0 (non-canonical helper lane).
     *
     * Source-side typed cleanup helper equivalent.
     */
    void DestroySaveDataSubtree(SSessionSaveNodeMapNode* const node, SSessionSaveNodeMapNode* const head)
    {
      if (!node || node == head || node->mIsSentinel != 0u) {
        return;
      }

      DestroySaveDataSubtree(node->mLeft, head);
      DestroySaveDataSubtree(node->mRight, head);
      DestroySaveDataMapNode(node);
    }

    /**
      * Alias of FUN_008971A0 (non-canonical helper lane).
     */
    void ClearSaveDataMap(SSessionSaveNodeMap& map)
    {
      SSessionSaveNodeMapNode* const head = map.mHead;
      if (!head) {
        map.mSize = 0u;
        return;
      }

      DestroySaveDataSubtree(head->mParent, head);
      head->mLeft = head;
      head->mParent = head;
      head->mRight = head;
      map.mSize = 0u;
    }

    [[nodiscard]] ECommandMode DefaultModeFromDrag(const std::int32_t dragWord) noexcept
    {
      const std::uint32_t dragMask = static_cast<std::uint32_t>(dragWord) & 0xFF000000u;
      return (dragMask != 0xFF000000u) ? COMMOD_Reclaim : COMMOD_Move;
    }

    [[nodiscard]] LuaPlus::LuaObject
    GetLuaIndex(LuaPlus::LuaState* state, const LuaPlus::LuaObject& tableObj, const std::int32_t index)
    {
      if (!state || !tableObj || !tableObj.IsTable()) {
        return {};
      }

      lua_State* const lstate = state->GetCState();
      if (!lstate) {
        return {};
      }

      const int savedTop = lua_gettop(lstate);
      const_cast<LuaPlus::LuaObject&>(tableObj).PushStack(lstate);
      // Lua 5.0-era ABI: integer index is pushed as number.
      lua_pushnumber(lstate, static_cast<lua_Number>(index));
      lua_gettable(lstate, -2);
      LuaPlus::LuaObject result{LuaPlus::LuaStackObject(state, -1)};
      lua_settop(lstate, savedTop);
      return result;
    }

    [[nodiscard]] bool IsLuaFunction(LuaPlus::LuaState* state, const LuaPlus::LuaObject& obj)
    {
      if (!state || !obj) {
        return false;
      }

      lua_State* const lstate = state->GetCState();
      if (!lstate) {
        return false;
      }

      const int savedTop = lua_gettop(lstate);
      const_cast<LuaPlus::LuaObject&>(obj).PushStack(lstate);
      const bool isFn = lua_isfunction(lstate, -1) != 0;
      lua_settop(lstate, savedTop);
      return isFn;
    }

    /**
     * Address: 0x0083DDA0 (FUN_0083DDA0, Moho::UI_GetCommandMode)
     *
     * What it does:
     * Imports `/lua/ui/game/commandmode.lua`, calls `GetCommandMode()`, and
     * extracts `(modeString, payloadTable)` when present.
     */
    [[nodiscard]] bool TryGetUICommandMode(LuaPlus::LuaState* state, UICommandModeData& out)
    {
      LuaPlus::LuaObject module = moho::SCR_ImportLuaModule(state, "/lua/ui/game/commandmode.lua");
      if (!module || !module.IsTable()) {
        return false;
      }

      LuaPlus::LuaObject getCommandMode = moho::SCR_GetLuaTableField(state, module, "GetCommandMode");
      if (!IsLuaFunction(state, getCommandMode)) {
        return false;
      }

      LuaPlus::LuaFunction<LuaPlus::LuaObject> fn{getCommandMode};
      LuaPlus::LuaObject result = fn();
      if (!result || !result.IsTable()) {
        return false;
      }

      LuaPlus::LuaObject modeField = GetLuaIndex(state, result, 1);
      if (modeField && modeField.IsString()) {
        const char* const modeName = modeField.GetString();
        out.mMode = modeName ? modeName : "";
      }

      LuaPlus::LuaObject payloadField = GetLuaIndex(state, result, 2);
      if (payloadField && payloadField.IsTable()) {
        out.mPayload = payloadField;
      }

      return true;
    }

    [[nodiscard]] VizUpdateNode* TreeMin(VizUpdateNode* node, VizUpdateNode* head)
    {
      while (node != nullptr && node != head && node->left != head) {
        node = node->left;
      }
      return node ? node : head;
    }

    [[nodiscard]] VizUpdateNode* TreeMax(VizUpdateNode* node, VizUpdateNode* head)
    {
      while (node != nullptr && node != head && node->right != head) {
        node = node->right;
      }
      return node ? node : head;
    }

    [[nodiscard]] VizUpdateNode* FindVizUpdateNode(VizUpdateTree* tree, const std::uintptr_t key)
    {
      if (!tree || !tree->head) {
        return nullptr;
      }

      VizUpdateNode* candidate = tree->head;
      VizUpdateNode* current = tree->head->parent;
      while (current && current->isSentinel == 0) {
        if (current->key >= key) {
          candidate = current;
          current = current->left;
        } else {
          current = current->right;
        }
      }

      if (!candidate || candidate == tree->head || key < candidate->key) {
        return tree->head;
      }
      return candidate;
    }

    [[nodiscard]] bool IsVizNodeNil(const VizUpdateNode* const node) noexcept
    {
      return node == nullptr || node->isSentinel != 0u;
    }

    void RecomputeVizUpdateExtrema(VizUpdateTree* tree)
    {
      if (!tree || !tree->head) {
        return;
      }

      VizUpdateNode* const head = tree->head;
      VizUpdateNode* const root = head->parent;
      if (IsVizNodeNil(root)) {
        head->parent = head;
        head->left = head;
        head->right = head;
        return;
      }

      head->left = TreeMin(root, head);
      head->right = TreeMax(root, head);
    }

    void LinkVizUpdateOwner(UserEntity* const entity, VizUpdateNode* const node)
    {
      node->ownerLinkHead = 0u;
      node->ownerNextLink = 0u;
      if (entity == nullptr) {
        return;
      }

      auto* const ownerLinkSlot = reinterpret_cast<std::uintptr_t*>(&entity->mIUnitChainHead);
      node->ownerLinkHead = reinterpret_cast<std::uintptr_t>(ownerLinkSlot);
      node->ownerNextLink = *ownerLinkSlot;
      *ownerLinkSlot = reinterpret_cast<std::uintptr_t>(&node->ownerLinkHead);
    }

    void RotateLeft(VizUpdateTree* tree, VizUpdateNode* node);
    void RotateRight(VizUpdateTree* tree, VizUpdateNode* node);

    void FixupAfterVizInsert(VizUpdateTree* tree, VizUpdateNode* node)
    {
      VizUpdateNode* const head = tree->head;
      while (node != head->parent && node->parent->color == 0u) {
        VizUpdateNode* const parent = node->parent;
        VizUpdateNode* const grand = parent->parent;
        if (parent == grand->left) {
          VizUpdateNode* const uncle = grand->right;
          if (uncle->color == 0u) {
            parent->color = 1u;
            uncle->color = 1u;
            grand->color = 0u;
            node = grand;
          } else {
            if (node == parent->right) {
              node = parent;
              RotateLeft(tree, node);
            }
            node->parent->color = 1u;
            grand->color = 0u;
            RotateRight(tree, grand);
          }
        } else {
          VizUpdateNode* const uncle = grand->left;
          if (uncle->color == 0u) {
            parent->color = 1u;
            uncle->color = 1u;
            grand->color = 0u;
            node = grand;
          } else {
            if (node == parent->left) {
              node = parent;
              RotateRight(tree, node);
            }
            node->parent->color = 1u;
            grand->color = 0u;
            RotateLeft(tree, grand);
          }
        }
      }

      head->parent->color = 1u;
    }

    [[nodiscard]] bool InsertVizUpdateNode(VizUpdateTree* tree, UserEntity* const entity)
    {
      if (!tree || !tree->head || entity == nullptr) {
        return false;
      }

      const std::uintptr_t key = reinterpret_cast<std::uintptr_t>(entity);
      VizUpdateNode* const head = tree->head;
      VizUpdateNode* parent = head;
      VizUpdateNode* probe = head->parent;
      while (!IsVizNodeNil(probe)) {
        parent = probe;
        if (key < probe->key) {
          probe = probe->left;
        } else if (probe->key < key) {
          probe = probe->right;
        } else {
          return false;
        }
      }

      auto* const inserted = static_cast<VizUpdateNode*>(::operator new(sizeof(VizUpdateNode)));
      inserted->left = head;
      inserted->parent = parent;
      inserted->right = head;
      inserted->key = key;
      inserted->color = 0u;
      inserted->isSentinel = 0u;
      inserted->pad_1A[0] = 0u;
      inserted->pad_1A[1] = 0u;
      LinkVizUpdateOwner(entity, inserted);

      if (parent == head) {
        head->parent = inserted;
      } else if (key < parent->key) {
        parent->left = inserted;
      } else {
        parent->right = inserted;
      }

      ++tree->size;
      FixupAfterVizInsert(tree, inserted);
      RecomputeVizUpdateExtrema(tree);
      return true;
    }

    void RotateLeft(VizUpdateTree* tree, VizUpdateNode* node)
    {
      VizUpdateNode* const pivot = node->right;
      node->right = pivot->left;
      if (pivot->left && pivot->left->isSentinel == 0) {
        pivot->left->parent = node;
      }

      pivot->parent = node->parent;
      if (node == tree->head->parent) {
        tree->head->parent = pivot;
      } else if (node == node->parent->left) {
        node->parent->left = pivot;
      } else {
        node->parent->right = pivot;
      }

      pivot->left = node;
      node->parent = pivot;
    }

    void RotateRight(VizUpdateTree* tree, VizUpdateNode* node)
    {
      VizUpdateNode* const pivot = node->left;
      node->left = pivot->right;
      if (pivot->right && pivot->right->isSentinel == 0) {
        pivot->right->parent = node;
      }

      pivot->parent = node->parent;
      if (node == tree->head->parent) {
        tree->head->parent = pivot;
      } else if (node == node->parent->right) {
        node->parent->right = pivot;
      } else {
        node->parent->left = pivot;
      }

      pivot->right = node;
      node->parent = pivot;
    }

    void Transplant(VizUpdateTree* tree, VizUpdateNode* from, VizUpdateNode* to)
    {
      if (from->parent == tree->head) {
        tree->head->parent = to;
      } else if (from == from->parent->left) {
        from->parent->left = to;
      } else {
        from->parent->right = to;
      }

      if (to != tree->head) {
        to->parent = from->parent;
      }
    }

    void UnlinkOwnerChain(VizUpdateNode* node)
    {
      if (!node || node->ownerLinkHead == 0u) {
        return;
      }

      auto* slot = reinterpret_cast<std::uintptr_t*>(node->ownerLinkHead);
      const std::uintptr_t target = reinterpret_cast<std::uintptr_t>(&node->ownerLinkHead);

      std::size_t guard = 0;
      while (slot && *slot != target && guard < 65536u) {
        slot = reinterpret_cast<std::uintptr_t*>(*slot + sizeof(std::uintptr_t));
        ++guard;
      }

      if (slot && *slot == target) {
        *slot = node->ownerNextLink;
      }

      node->ownerLinkHead = 0u;
      node->ownerNextLink = 0u;
    }

    void DeleteFixup(VizUpdateTree* tree, VizUpdateNode* node, VizUpdateNode* parentHint)
    {
      VizUpdateNode* head = tree->head;
      VizUpdateNode* parent = (node != head) ? node->parent : parentHint;

      while (node != head->parent && (node == head || node->color == 1u)) {
        if (!parent) {
          break;
        }

        if (node == parent->left) {
          VizUpdateNode* sibling = parent->right;
          if (sibling == head) {
            break;
          }

          if (sibling->color == 0u) {
            sibling->color = 1u;
            parent->color = 0u;
            RotateLeft(tree, parent);
            sibling = parent->right;
          }

          const bool siblingLeftBlack = (sibling->left == head) || (sibling->left->color == 1u);
          const bool siblingRightBlack = (sibling->right == head) || (sibling->right->color == 1u);
          if (siblingLeftBlack && siblingRightBlack) {
            sibling->color = 0u;
            node = parent;
            parent = node->parent;
          } else {
            if ((sibling->right == head) || (sibling->right->color == 1u)) {
              if (sibling->left != head) {
                sibling->left->color = 1u;
              }
              sibling->color = 0u;
              RotateRight(tree, sibling);
              sibling = parent->right;
            }

            sibling->color = parent->color;
            parent->color = 1u;
            if (sibling->right != head) {
              sibling->right->color = 1u;
            }
            RotateLeft(tree, parent);
            node = head->parent;
            break;
          }
        } else {
          VizUpdateNode* sibling = parent->left;
          if (sibling == head) {
            break;
          }

          if (sibling->color == 0u) {
            sibling->color = 1u;
            parent->color = 0u;
            RotateRight(tree, parent);
            sibling = parent->left;
          }

          const bool siblingRightBlack = (sibling->right == head) || (sibling->right->color == 1u);
          const bool siblingLeftBlack = (sibling->left == head) || (sibling->left->color == 1u);
          if (siblingRightBlack && siblingLeftBlack) {
            sibling->color = 0u;
            node = parent;
            parent = node->parent;
          } else {
            if ((sibling->left == head) || (sibling->left->color == 1u)) {
              if (sibling->right != head) {
                sibling->right->color = 1u;
              }
              sibling->color = 0u;
              RotateLeft(tree, sibling);
              sibling = parent->left;
            }

            sibling->color = parent->color;
            parent->color = 1u;
            if (sibling->left != head) {
              sibling->left->color = 1u;
            }
            RotateRight(tree, parent);
            node = head->parent;
            break;
          }
        }
      }

      if (node != head) {
        node->color = 1u;
      }
    }

    void EraseVizUpdateNode(VizUpdateTree* tree, VizUpdateNode* node)
    {
      VizUpdateNode* const head = tree->head;
      VizUpdateNode* y = node;
      std::uint8_t yOriginalColor = y->color;
      VizUpdateNode* x = head;
      VizUpdateNode* xParent = nullptr;

      if (node->left == head) {
        x = node->right;
        xParent = node->parent;
        Transplant(tree, node, node->right);
      } else if (node->right == head) {
        x = node->left;
        xParent = node->parent;
        Transplant(tree, node, node->left);
      } else {
        y = TreeMin(node->right, head);
        yOriginalColor = y->color;
        x = y->right;
        if (y->parent == node) {
          xParent = y;
          if (x != head) {
            x->parent = y;
          }
        } else {
          Transplant(tree, y, y->right);
          y->right = node->right;
          y->right->parent = y;
          xParent = y->parent;
        }
        Transplant(tree, node, y);
        y->left = node->left;
        y->left->parent = y;
        y->color = node->color;
      }

      if (head->left == node) {
        head->left =
          (node->left != head) ? TreeMax(node->left, head) : ((node->parent != nullptr) ? node->parent : head);
      }
      if (head->right == node) {
        head->right =
          (node->right != head) ? TreeMin(node->right, head) : ((node->parent != nullptr) ? node->parent : head);
      }

      UnlinkOwnerChain(node);
      ::operator delete(node);
      if (tree->size > 0u) {
        --tree->size;
      }

      if (yOriginalColor == 1u) {
        DeleteFixup(tree, x, xParent);
      }
    }

    // ===================================================================
    // Right-mouse-button command resolution helpers (FUN_0081EC00 family)
    // ===================================================================
    //
    // These file-static helpers back the global right-click dispatcher
    // `func_GetRightMouseButtonAction` (FUN_0081EC00). They are only ever
    // called from that dispatcher inside this translation unit, so they stay
    // in this anonymous namespace next to the selection-iteration helpers they
    // reuse (DecodeSelectedUserEntity / ResolveIUnitBridge / IsSentinelNode).

    // Session command-manager runtime views. The session's command manager
    // lives behind `CWldSession::mCommandManager`; its command-issue map (keyed by
    // CmdId) starts at manager offset +0xCB4 with the RB-tree head at +0xCB8.
    // Same per-TU view shape used by Sim.cpp / UserUnit.cpp.
    struct RightClickCommandIssueMapNodeView
    {
      RightClickCommandIssueMapNodeView* left;   // +0x00
      RightClickCommandIssueMapNodeView* parent; // +0x04
      RightClickCommandIssueMapNodeView* right;  // +0x08
      std::uint32_t key;                         // +0x0C (CmdId)
      void* value;                               // +0x10 (helper*)
      std::uint8_t color;                        // +0x14
      std::uint8_t isNil;                        // +0x15
      std::uint8_t pad_16[2];
    };
    static_assert(offsetof(RightClickCommandIssueMapNodeView, key) == 0x0C, "cmd-issue node key offset must be 0x0C");
    static_assert(offsetof(RightClickCommandIssueMapNodeView, value) == 0x10, "cmd-issue node value offset must be 0x10");
    static_assert(offsetof(RightClickCommandIssueMapNodeView, isNil) == 0x15, "cmd-issue node isNil offset must be 0x15");

    struct RightClickCommandIssueMapView
    {
      void* allocatorProxy;                    // +0x00
      RightClickCommandIssueMapNodeView* head; // +0x04
      std::uint32_t size;                      // +0x08
    };
    static_assert(offsetof(RightClickCommandIssueMapView, head) == 0x04, "cmd-issue map head offset must be 0x04");

    struct RightClickCommandManagerView
    {
      std::uint8_t pad_0000_0CB4[0xCB4];
      RightClickCommandIssueMapView commandIssueMap; // +0xCB4
    };
    static_assert(
      offsetof(RightClickCommandManagerView, commandIssueMap) == 0xCB4, "command manager issue-map offset must be 0xCB4"
    );

    // The command-issue helper stores its baseline unit-command type at +0x58.
    // The dispatcher only needs that field to detect Attack / FormAttack; the
    // IDA helper `sub_8B4140` resolves the most-recent override event, which for
    // this Attack/FormAttack test degrades to the same baseline command-type
    // read (ResolveHelperCommandType in UserUnit.cpp, FUN_008B4140).
    struct RightClickCommandIssueHelperView
    {
      std::uint8_t pad_0000_0058[0x58];
      EUnitCommandType commandType; // +0x58
    };
    static_assert(
      offsetof(RightClickCommandIssueHelperView, commandType) == 0x58,
      "command-issue helper command-type offset must be 0x58"
    );

    /**
     * Ordered lookup of one command-issue helper by CmdId in the session
     * command manager's RB-tree, mirroring the `std::map<CmdId,...>::find` in
     * FUN_0081EC00. Returns nullptr when the manager is absent or the key is
     * not present.
     */
    [[nodiscard]] RightClickCommandIssueHelperView*
      FindRightClickCommandIssueHelper(CWldSession* const session, const std::uint32_t commandId) noexcept
    {
      if (session == nullptr || session->mCommandManager == nullptr) {
        return nullptr;
      }

      auto* const manager = reinterpret_cast<RightClickCommandManagerView*>(session->mCommandManager);
      RightClickCommandIssueMapView& issueMap = manager->commandIssueMap;
      RightClickCommandIssueMapNodeView* const head = issueMap.head;
      if (head == nullptr) {
        return nullptr;
      }

      RightClickCommandIssueMapNodeView* result = head;
      RightClickCommandIssueMapNodeView* node = head->parent;
      while (node != nullptr && node != head && node->isNil == 0u) {
        if (node->key >= commandId) {
          result = node;
          node = node->left;
        } else {
          node = node->right;
        }
      }

      if (result == head || commandId < result->key) {
        return nullptr;
      }

      return reinterpret_cast<RightClickCommandIssueHelperView*>(result->value);
    }

    /**
     * Address: 0x0081D080 (FUN_0081D080, sub_81D080)
     *
     * IDA signature:
     * char __cdecl sub_81D080(Moho::UserEntity *a1, Moho::CWldSession *a2);
     *
     * What it does:
     * Returns true when the hovered target `hoverEntity` is a live, non-destroy-
     * queued entity that at least one currently selected unit can attack (range-
     * checked). Backs the enemy-hover Attack decision in the right-click
     * dispatcher.
     */
    [[nodiscard]] bool AnySelectedUnitCanAttackHover(UserEntity* const hoverEntity, CWldSession* const session)
    {
      if (hoverEntity == nullptr) {
        return false;
      }
      if (hoverEntity->mVariableData.mIsDead != 0u) {
        return false;
      }

      if (UserUnit* const hoverUnit = hoverEntity->IsUserUnit(); hoverUnit != nullptr) {
        IUnit* const hoverBridge = GetIUnitBridge(hoverUnit);
        if (hoverBridge != nullptr && hoverBridge->DestroyQueued()) { // IUnit subobject slot +0x2C
          return false;
        }
      }

      SSelectionSetUserEntity& selection = session->mSelection;
      SSelectionNodeUserEntity* node = selection.mHead->mLeft;
      node = SSelectionSetUserEntity::find(&selection, node, &node);
      while (node != selection.mHead) {
        if (UserEntity* const selectedEntity = DecodeSelectedUserEntity(node->mEnt); selectedEntity != nullptr) {
          if (UserUnit* const selectedUnit = selectedEntity->IsUserUnit(); selectedUnit != nullptr) {
            if (selectedUnit->CanAttackTarget(hoverEntity, true)) {
              return true;
            }
          }
        }

        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&selection, node, &node);
      }

      return false;
    }

    /**
     * Address: 0x0081D280 (FUN_0081D280, func_RightClickWithTransport)
     *
     * IDA signature:
     * char __cdecl func_RightClickWithTransport(Moho::WeakSet_UserEntity *a1, Moho::UserUnit *arg4);
     *
     * What it does:
     * Scans the current selection for any live transporter that may pick up or
     * interact with the hovered entity `hoverEntity`, honoring the transport-
     * eligibility category rules (CANTRANSPORTCOMMANDER / FERRYBEACON / COMMAND
     * / TRANSPORTATION / TELEPORTATION / AIRSTAGINGPLATFORM / CANNOTUSEAIRSTAGING).
     * Returns true on the first eligible transporter. `arg4` is declared
     * `UserUnit*` by the decompiler but only ever used through UserEntity
     * members, so the recovered parameter is typed as the base `UserEntity*`.
     */
    [[nodiscard]] bool SelectionHasTransportForTarget(SSelectionSetUserEntity* const selection, UserEntity* const hoverEntity)
    {
      if (hoverEntity == nullptr) {
        return false;
      }
      if (hoverEntity->mVariableData.mIsDead != 0u) {
        return false;
      }
      if (hoverEntity->mVariableData.mLayerMask == static_cast<std::uint32_t>(LAYER_Seabed)) {
        return false;
      }
      if (hoverEntity->IsBeingBuilt()) { // arg4 vtable slot +0x34
        return false;
      }

      SSelectionSetUserEntity::FindResult cursor{};
      (void)selection->First(&cursor);
      while (cursor.mRes != selection->mHead) {
        UserEntity* const selectedEntity = DecodeSelectedUserEntity(cursor.mRes->mEnt);
        UserUnit* const transporter = selectedEntity ? selectedEntity->IsUserUnit() : nullptr;
        if (transporter != nullptr) {
          IUnit* const transporterBridge = GetIUnitBridge(transporter);
          if (transporterBridge != nullptr && !transporterBridge->IsDead() // slot +0x28
              && !transporter->IsBeingBuilt()                              // v6 vtable slot +0x34
              && !transporterBridge->DestroyQueued())                      // slot +0x2C
          {
            // Group 1: decide whether to skip this transporter.
            // CANTRANSPORTCOMMANDER(hover) or FERRYBEACON(hover) -> not a skip;
            // otherwise skip iff the transporter is not COMMAND.
            bool skip;
            if (hoverEntity->IsInCategory(msvc8::string("CANTRANSPORTCOMMANDER"))) {
              skip = false;
            } else if (hoverEntity->IsInCategory(msvc8::string("FERRYBEACON"))) {
              skip = false;
            } else {
              skip = !reinterpret_cast<const UserEntity*>(transporter)->IsInCategory(msvc8::string("COMMAND"));
            }

            if (!skip) {
              // Group 2: does the hovered entity want air transport?
              bool wantsAir;
              if (hoverEntity->IsInCategory(msvc8::string("TRANSPORTATION"))) {
                wantsAir = true;
              } else if (hoverEntity->IsInCategory(msvc8::string("TELEPORTATION"))) {
                wantsAir = true;
              } else {
                wantsAir = hoverEntity->IsInCategory(msvc8::string("FERRYBEACON"));
              }

              if (wantsAir) {
                // Non-flying transporter for an air-transport request -> accept.
                // GetBlueprint() on the transporter IUnit subobject (slot +0x1C),
                // then Air.CanFly (blueprint + 0x368).
                if (transporterBridge->GetBlueprint()->Air.CanFly == 0u) {
                  return true;
                }
              } else if (hoverEntity->IsInCategory(msvc8::string("AIRSTAGINGPLATFORM"))) {
                // Accept if the transporter can't fly, or can fly but is
                // CANNOTUSEAIRSTAGING (still a valid staging interaction).
                if (transporterBridge->GetBlueprint()->Air.CanFly == 0u
                    || reinterpret_cast<const UserEntity*>(transporter)->IsInCategory(msvc8::string("CANNOTUSEAIRSTAGING"))) {
                  return true;
                }
              }
            }
          }
        }

        SSelectionSetUserEntity::Iterator_inc(&cursor.mRes);
        cursor.mRes = SSelectionSetUserEntity::find(cursor.mSet, cursor.mRes, &cursor.mRes);
      }

      return false;
    }

    /**
     * Address: 0x0081D660 (FUN_0081D660, func_RightClickTransport)
     *
     * IDA signature:
     * char __usercall func_RightClickTransport@<al>(int a1, Moho::UserEntity *a2@<ecx>);
     *
     * What it does:
     * Scans the current selection for any selected unit that the hovered
     * transporter `hoverEntity` is allowed to carry, honoring the transport
     * category rules (TELEPORTATION / EXPERIMENTAL / TRANSPORTFOCUS /
     * CANTRANSPORTCOMMANDER / COMMAND / TRANSPORTATION / FERRYBEACON /
     * AIRSTAGINGPLATFORM) against the hovered unit's air capability. Returns
     * true on the first accepted selected unit.
     */
    [[nodiscard]] bool HoverTransportAcceptsSelection(SSelectionSetUserEntity* const selection, UserEntity* const hoverEntity)
    {
      if (hoverEntity == nullptr) {
        return false;
      }
      if (hoverEntity->mVariableData.mIsDead != 0u || hoverEntity->IsBeingBuilt()) {
        return false;
      }

      UserUnit* const hoverUnit = hoverEntity->IsUserUnit();
      if (hoverUnit == nullptr) {
        return false;
      }
      IUnit* const hoverBridge = GetIUnitBridge(hoverUnit);
      if (hoverBridge == nullptr) {
        return false;
      }

      SSelectionSetUserEntity::FindResult cursor{};
      (void)selection->First(&cursor);
      while (cursor.mRes != selection->mHead) {
        // The binary rejects both null and the encoded sentinel (v5 == 8);
        // DecodeSelectedUserEntity returns nullptr for both, so one guard covers it.
        UserEntity* const candidate = DecodeSelectedUserEntity(cursor.mRes->mEnt);
        if (candidate != nullptr) {
          // Group 1: TELEPORTATION(candidate) or EXPERIMENTAL(hover).
          bool teleOrExperimental;
          if (candidate->IsInCategory(msvc8::string("TELEPORTATION"))) {
            teleOrExperimental = true;
          } else {
            teleOrExperimental = reinterpret_cast<const UserEntity*>(hoverUnit)->IsInCategory(msvc8::string("EXPERIMENTAL"));
          }

          if (!teleOrExperimental
              && candidate->mVariableData.mLayerMask != static_cast<std::uint32_t>(LAYER_Seabed)) {
            // Group 2: TRANSPORTFOCUS(candidate).
            if (candidate->IsInCategory(msvc8::string("TRANSPORTFOCUS"))) {
              // Group 3: CANTRANSPORTCOMMANDER(candidate) -> not a skip;
              // otherwise skip iff the hover unit is not COMMAND.
              bool skip;
              if (candidate->IsInCategory(msvc8::string("CANTRANSPORTCOMMANDER"))) {
                skip = false;
              } else {
                skip = !reinterpret_cast<const UserEntity*>(hoverUnit)->IsInCategory(msvc8::string("COMMAND"));
              }

              if (!skip) {
                // Group 4: TRANSPORTATION(candidate) or FERRYBEACON(candidate).
                bool wantsAir;
                if (candidate->IsInCategory(msvc8::string("TRANSPORTATION"))) {
                  wantsAir = true;
                } else {
                  wantsAir = candidate->IsInCategory(msvc8::string("FERRYBEACON"));
                }

                if (wantsAir) {
                  // Non-flying hover unit for an air-transport request -> accept.
                  if (hoverBridge->GetBlueprint()->Air.CanFly == 0u) {
                    return true;
                  }
                } else if (candidate->IsInCategory(msvc8::string("AIRSTAGINGPLATFORM"))
                           && hoverBridge->GetBlueprint()->Air.CanFly != 0u) {
                  // Air-staging platform docking a flying hover unit -> accept.
                  return true;
                }
              }
            }
          }
        }

        SSelectionSetUserEntity::Iterator_inc(&cursor.mRes);
        cursor.mRes = SSelectionSetUserEntity::find(cursor.mSet, cursor.mRes, &cursor.mRes);
      }

      return false;
    }

    /**
     * Address: 0x0081DA20 (FUN_0081DA20, sub_81DA20)
     *
     * IDA signature:
     * char __usercall sub_81DA20@<al>(int a1@<ebx>, Moho::CWldSession *a2);
     *
     * What it does:
     * Returns true only when every currently selected entity is in the FACTORY
     * category. Used by the ferry-beacon right-click path to allow a
     * CallTransport order when the whole selection is factories. The binary
     * snapshots the FACTORY category's bit-vector and tests each selected
     * entity's blueprint ordinal against it; `EntityCategory::HasBlueprint`
     * expresses that same membership test.
     */
    [[nodiscard]] bool AllSelectedAreFactories(SSelectionSetUserEntity* const selection, CWldSession* const session)
    {
      const CategoryWordRangeView* const factoryCategory =
        static_cast<RRuleGameRules*>(session->mRules)->GetEntityCategory("FACTORY");

      SSelectionNodeUserEntity* node = selection->mHead->mLeft;
      node = SSelectionSetUserEntity::find(selection, node, &node);
      while (node != selection->mHead) {
        UserEntity* const selectedEntity = DecodeSelectedUserEntity(node->mEnt);
        if (selectedEntity == nullptr
            || !EntityCategory::HasBlueprint(selectedEntity->mParams.mBlueprint, factoryCategory)) {
          return false;
        }

        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(selection, node, &node);
      }

      return true;
    }
  } // namespace

  /**
   * Address: 0x0066A550 (FUN_0066A550, Moho::WeakSet_UserEntity::next)
   * Address: 0x007B30D0 (FUN_007B30D0, std::map<unsigned int,WeakPtr<UserEntity>>::erase
   * — identical node-splice/rebalance/return-next shape, a separate
   * per-call-site emission of the same std::_Tree::erase(iterator) operation;
   * reached via CWldSession.cpp's own EraseSelectionNodeAndAdvance callers)
   *
   * What it does:
   * Erases one `UserEntity` weak-set node from the selection RB-tree, unlinks
   * its intrusive weak-owner chain lane, and returns the next in-order node.
   *
   * Hoisted to external linkage (was file-local in the anonymous namespace
   * above) and declared in CWldSession.h so `CFormation::ChooseFormation`
   * (CFormation.cpp) can prune its own selection-set walk the same way
   * `SSelectionSetUserEntity::PruneTombstonesAndFindLive`/`EraseRange` do.
   */
  [[nodiscard]] SSelectionNodeUserEntity*
  EraseSelectionNodeAndAdvance(WeakEntitySetUserEntity& selection, SSelectionNodeUserEntity* const node)
  {
    if (selection.mHead == nullptr || IsSelectionNil(node)) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    SSelectionNodeUserEntity* const head = selection.mHead;
    SSelectionNodeUserEntity* const next = NextTreeNode(node);

    SSelectionNodeUserEntity* removed = node;
    SSelectionNodeUserEntity* spliceTarget = node;
    std::uint8_t removedColor = spliceTarget->mColor;
    SSelectionNodeUserEntity* fixNode = head;
    SSelectionNodeUserEntity* fixParent = head;

    if (IsSelectionNil(node->mLeft)) {
      fixNode = node->mRight;
      fixParent = node->mParent;
      ReplaceSelectionSubtree(selection, node, node->mRight);
    } else if (IsSelectionNil(node->mRight)) {
      fixNode = node->mLeft;
      fixParent = node->mParent;
      ReplaceSelectionSubtree(selection, node, node->mLeft);
    } else {
      spliceTarget = SelectionMin(node->mRight, head);
      removedColor = spliceTarget->mColor;
      fixNode = spliceTarget->mRight;
      if (spliceTarget->mParent == node) {
        fixParent = spliceTarget;
        if (!IsSelectionNil(fixNode)) {
          fixNode->mParent = spliceTarget;
        }
      } else {
        fixParent = spliceTarget->mParent;
        ReplaceSelectionSubtree(selection, spliceTarget, spliceTarget->mRight);
        spliceTarget->mRight = node->mRight;
        spliceTarget->mRight->mParent = spliceTarget;
      }

      ReplaceSelectionSubtree(selection, node, spliceTarget);
      spliceTarget->mLeft = node->mLeft;
      spliceTarget->mLeft->mParent = spliceTarget;
      spliceTarget->mColor = node->mColor;
    }

    UnlinkSelectionWeakOwnerRef(removed->mEnt);
    ::operator delete(removed);

    if (selection.mSize > 0u) {
      --selection.mSize;
    }
    if (removedColor == 1u) {
      FixupAfterSelectionErase(selection, fixNode, fixParent);
    }

    RecomputeSelectionExtrema(selection);
    return next;
  }

  /**
   * Bridge for the recovered `cfunc_IssueDockCommandL` worker (FUN_00840A70):
   * copies one source selection weak-set into a fresh destination weak-set.
   * Forwards to the file-local `CopySelectionSetFromOther` (FUN_00822210), which
   * the dock worker uses to snapshot `CWldSession::mSelection` before scanning it.
   */
  SSelectionSetUserEntity* CopySessionSelectionSet(
    SSelectionSetUserEntity* const destination,
    const SSelectionSetUserEntity* const source
  )
  {
    return CopySelectionSetFromOther(destination, const_cast<SSelectionSetUserEntity*>(source));
  }

  /**
   * Bridge for the recovered `cfunc_IssueDockCommandL` worker: resolves the world
   * position seeded from one unit's last-queued command-graph anchor history.
   * Reinterprets the opaque `QueuedUserCommandRecord` handle (produced by
   * `GetLastQueuedUserCommandAnchor`) as the command-graph anchor history and
   * forwards to the file-local `ResolveCommandGraphAnchorHistoryWorldPosition`
   * (FUN_0081CFD0), which resolves the sample position and unlinks the transient
   * weak-owner lane.
   */
  Wm3::Vector3f ResolveLastQueuedCommandAnchorPosition(const QueuedUserCommandRecord* const record)
  {
    Wm3::Vector3f out{};
    auto* const history = reinterpret_cast<CommandGraphAnchorHistoryRuntimeView*>(
      const_cast<QueuedUserCommandRecord*>(record)
    );
    (void)ResolveCommandGraphAnchorHistoryWorldPosition(&out, history);
    return out;
  }

  /**
   * Bridge for `Moho::DrawAllUnitSkirts` (FUN_0085AD80): resolves the world
   * position a pending command-issue helper is anchored at.
   *
   * A `UserCommandIssueHelper` *is* the command-graph anchor history - its
   * local issue-event ring at +0xB8 is the entry ring
   * `CommandGraphAnchorHistoryRuntimeView` models at +0xBC..+0xC8 - so the
   * binary reaches the same code path by inlining FUN_0081CFD0's
   * resolve-sample / sample-to-position / unlink-weak-lane trio straight into
   * the skirt loop (asm 0x0085AE88..0x0085AEB7).
   */
  MouseInfo& CWldSession::CursorInfo() noexcept
  {
    static_assert(
      offsetof(CWldSession, CursorWorldPos) - offsetof(CWldSession, mCursorWorldState)
        == offsetof(MouseInfo, mMouseWorldPos),
      "CWldSession's flattened cursor snapshot must line up with MouseInfo"
    );
    static_assert(
      offsetof(CWldSession, CursorScreenPos) - offsetof(CWldSession, mCursorWorldState)
        == offsetof(MouseInfo, mMouseScreenPos),
      "CWldSession's flattened cursor snapshot must line up with MouseInfo"
    );
    return *reinterpret_cast<MouseInfo*>(&mCursorWorldState[0]);
  }

  Wm3::Vector3f ResolveCommandIssueHelperAnchorPosition(UserCommandIssueHelper& helper)
  {
    Wm3::Vector3f out{};
    (void)ResolveCommandGraphAnchorHistoryWorldPosition(
      &out,
      reinterpret_cast<CommandGraphAnchorHistoryRuntimeView*>(&helper)
    );
    return out;
  }

  std::uint32_t EvaluateBuildTemplatePlacementPreview(
    const Wm3::Vector3f& worldPosition,
    const RUnitBlueprint* const buildBlueprint,
    CWldSession& session,
    VTransform& previewTransform
  )
  {
    std::uint32_t previewColor = 0u;
    return ApplyBuildTemplatePlacementPreviewStatus(
      worldPosition,
      buildBlueprint,
      previewTransform,
      session,
      previewColor
    );
  }

  std::uint32_t EvaluateCommandModeBuildPlacementPreview(
    const CommandModeData& commandMode,
    const Wm3::Vector3f& worldPosition,
    CWldSession& session,
    VTransform& previewTransform
  )
  {
    std::uint32_t previewColor = 0u;
    (void)ApplyCommandModeBuildPlacementPreviewStatus(
      commandMode,
      worldPosition,
      session,
      previewTransform,
      previewColor
    );
    return previewColor;
  }

  /**
   * Bridge for the recovered `cfunc_IssueDockCommandL` worker (FUN_00840A70):
   * walks the whole session entity map in id order and appends every live
   * `UserUnit*`. Wraps the CWldSession.cpp-local `CollectSessionUserUnits`,
   * matching the binary's inline `mEntityMap` in-order scan (entity ids are
   * unique keys, so the collection order equals the binary's iteration order).
   */
  void GetSessionUserUnits(CWldSession* const session, msvc8::vector<UserUnit*>& outUnits)
  {
    CollectSessionUserUnits(session, outUnits);
  }

  /**
   * Address: 0x007AE1B0 (FUN_007AE1B0, Moho::WeakSet_UserEntity::Add)
   *
   * What it does:
   * Inserts one user-entity pointer key into the selection weak-set tree and
   * returns `{ownerSet,node,inserted}` in `outResult`.
   */
  SSelectionSetUserEntity::AddResult* SSelectionSetUserEntity::Add(
    AddResult* const outResult,
    SSelectionSetUserEntity* const set,
    UserEntity* const entity
  )
  {
    GPG_ASSERT(outResult != nullptr);
    if (!outResult) {
      return nullptr;
    }

    outResult->mOwnerSet = set;
    outResult->mNode = (set != nullptr) ? set->mHead : nullptr;
    outResult->mWasInserted = 0u;
    outResult->mReserved09_0B[0] = 0u;
    outResult->mReserved09_0B[1] = 0u;
    outResult->mReserved09_0B[2] = 0u;

    if (set == nullptr) {
      return outResult;
    }

    ScopedSelectionOwnerLinkGuard ownerLinkGuard(entity);
    SSelectionNodeUserEntity* node = set->mHead;
    const bool inserted = InsertSelectionEntity(*set, entity, &node);
    outResult->mNode = node;
    outResult->mWasInserted = inserted ? 1u : 0u;
    return outResult;
  }

  /**
   * Address: 0x007FDD50 (FUN_007FDD50, Moho::WeakSet_UserEntity::Find)
   *
   * What it does:
   * Resolves one weak-set tree node for `entity` and writes one `{set,node}`
   * cursor pair to `outResult`.
   */
  /**
   * Address: 0x008676E0 (FUN_008676E0, sub_8676E0)
   *
   * What it does:
   * Removes one user-entity key from a weak set. The binary parks a marker in
   * the entity's weak-owner chain for the duration of the erase and unwinds it
   * afterwards, so the node teardown cannot lose the chain; that guard is what
   * `ScopedSelectionOwnerLinkGuard` reproduces.
   */
  bool SSelectionSetUserEntity::Erase(WeakEntitySetUserEntity& set, UserEntity* const entity)
  {
    const SSelectionNodeUserEntity* const head = set.mHead;
    if (head == nullptr || entity == nullptr) {
      return false;
    }

    ScopedSelectionOwnerLinkGuard ownerLinkGuard(entity);
    SSelectionNodeUserEntity* const node = FindSelectionNodeByKey(set, SelectionKeyFromEntity(entity));
    if (node == nullptr || node == head) {
      return false;
    }

    (void)EraseSelectionNodeAndAdvance(set, node);
    return true;
  }

  SSelectionSetUserEntity::FindResult* SSelectionSetUserEntity::Find(
    FindResult* const outResult,
    SSelectionSetUserEntity* const set,
    UserEntity* const entity
  )
  {
    GPG_ASSERT(outResult != nullptr);
    if (outResult == nullptr) {
      return nullptr;
    }

    outResult->mSet = set;
    outResult->mRes = (set != nullptr) ? set->mHead : nullptr;
    if (set == nullptr) {
      return outResult;
    }

    return FindSelectionNodeByEntityGuarded(outResult, set, entity);
  }

  /**
   * Address: 0x007B59B0 (FUN_007B59B0, Moho::WeakSet_UserEntity::size)
   *
   * What it does:
   * Counts live weak-set tree nodes by in-order traversal of the selection
   * RB-tree lane.
   */
  std::int32_t SSelectionSetUserEntity::size() const
  {
    const SSelectionNodeUserEntity* const head = mHead;
    if (head == nullptr) {
      return 0;
    }

    auto isSentinel = [](const SSelectionNodeUserEntity* const node) -> bool {
      return node == nullptr || node->mIsSentinel != 0u;
    };

    std::int32_t count = 0;
    const SSelectionNodeUserEntity* node = head->mLeft;
    while (!isSentinel(node) && node != head) {
      ++count;

      if (!isSentinel(node->mRight)) {
        node = node->mRight;
        while (!isSentinel(node->mLeft)) {
          node = node->mLeft;
        }
        continue;
      }

      const SSelectionNodeUserEntity* parent = node->mParent;
      while (!isSentinel(parent) && node == parent->mRight) {
        node = parent;
        parent = parent->mParent;
      }
      node = parent;
    }

    return count;
  }

  /**
   * Address: 0x007B2620 (FUN_007B2620, sub_7B2620)
   *
   * What it does:
   * Returns true when tombstone pruning from the left-most weak-set node
   * reaches the head sentinel immediately.
   */
  bool SSelectionSetUserEntity::IsEmptyAfterPrune()
  {
    SSelectionNodeUserEntity* firstLive = nullptr;
    SSelectionNodeUserEntity* const head = mHead;
    (void)PruneTombstonesAndFindLive(&firstLive, head->mLeft);
    return firstLive == head;
  }

  /**
   * Address: 0x0066A090 (FUN_0066A090, sub_66A090)
   *
   * What it does:
   * Resolves the first live node from `mHead->mLeft` through `find` and
   * returns true when that result is the head sentinel.
   */
  bool SSelectionSetUserEntity::IsEmptyFromHeadFind()
  {
    const SSelectionNodeUserEntity* const head = mHead;
    if (head == nullptr) {
      return true;
    }

    SSelectionNodeUserEntity* found = nullptr;
    return find(this, head->mLeft, &found) == head;
  }

  /**
   * Address: 0x00863760 (FUN_00863760, sub_863760)
   *
   * What it does:
   * Counts live weak-set entries in this set that are absent from `other`.
   */
  std::int32_t SSelectionSetUserEntity::CountEntitiesMissingFrom(const SSelectionSetUserEntity& other) const
  {
    auto* const thisMutable = const_cast<SSelectionSetUserEntity*>(this);
    auto* const otherMutable = const_cast<SSelectionSetUserEntity*>(&other);
    if (thisMutable->mHead == nullptr) {
      return 0;
    }

    std::int32_t missingCount = 0;
    SSelectionNodeUserEntity* node = thisMutable->mHead->mLeft;
    node = SSelectionSetUserEntity::find(thisMutable, node, &node);
    while (node != thisMutable->mHead) {
      UserEntity* const selectedEntity = DecodeSelectedUserEntity(node->mEnt);
      SSelectionSetUserEntity::FindResult foundInOther{};
      (void)FindSelectionNodeByEntityGuarded(&foundInOther, otherMutable, selectedEntity);
      if (foundInOther.mRes == otherMutable->mHead) {
        ++missingCount;
      }

      SSelectionSetUserEntity::Iterator_inc(&node);
      node = SSelectionSetUserEntity::find(thisMutable, node, &node);
    }

    return missingCount;
  }

  /**
   * Address: 0x00868690 (FUN_00868690, sub_868690)
   *
   * What it does:
   * Returns true when this set and `other` contain the same live entity keys.
   */
  bool SSelectionSetUserEntity::HasSameLiveEntitySet(const SSelectionSetUserEntity& other) const
  {
    const auto* const thisHead = mHead;
    const auto* const otherHead = other.mHead;
    if (thisHead == nullptr || otherHead == nullptr) {
      return thisHead == otherHead;
    }

    auto* thisMutable = const_cast<SSelectionSetUserEntity*>(this);
    auto* otherMutable = const_cast<SSelectionSetUserEntity*>(&other);

    SSelectionNodeUserEntity* thisFirst = thisHead->mLeft;
    thisFirst = SSelectionSetUserEntity::find(thisMutable, thisFirst, &thisFirst);
    SSelectionNodeUserEntity* otherFirst = otherHead->mLeft;
    otherFirst = SSelectionSetUserEntity::find(otherMutable, otherFirst, &otherFirst);

    const bool thisEmpty = (thisFirst == thisHead);
    const bool otherEmpty = (otherFirst == otherHead);
    if (thisEmpty != otherEmpty) {
      return false;
    }
    if (thisEmpty) {
      return true;
    }

    return (CountEntitiesMissingFrom(other) == 0) && (other.CountEntitiesMissingFrom(*this) == 0);
  }

  /**
   * Address: 0x00831110 (FUN_00831110, sub_831110)
   *
   * What it does: see the header.
   */
  bool SSelectionSetUserEntity::HasCommonLiveEntityWith(const SSelectionSetUserEntity& other) const
  {
    auto* const thisMutable = const_cast<SSelectionSetUserEntity*>(this);
    auto* const otherMutable = const_cast<SSelectionSetUserEntity*>(&other);
    if (thisMutable->mHead == nullptr || otherMutable->mHead == nullptr) {
      return false;
    }

    SSelectionNodeUserEntity* node = thisMutable->mHead->mLeft;
    node = SSelectionSetUserEntity::find(thisMutable, node, &node);
    while (node != thisMutable->mHead) {
      UserEntity* const selectedEntity = DecodeSelectedUserEntity(node->mEnt);
      SSelectionSetUserEntity::FindResult foundInOther{};
      (void)FindSelectionNodeByEntityGuarded(&foundInOther, otherMutable, selectedEntity);
      if (foundInOther.mRes != otherMutable->mHead) {
        return true;
      }

      SSelectionSetUserEntity::Iterator_inc(&node);
      node = SSelectionSetUserEntity::find(thisMutable, node, &node);
    }

    return false;
  }

  /**
   * Address: 0x007B0870 (FUN_007B0870, sub_7B0870)
   *
   * What it does:
   * Recursively destroys one weak-set subtree and unlinks each node from its
   * user-entity weak-owner intrusive lane before delete.
   */
  void SSelectionSetUserEntity::DestroySubtree(SSelectionNodeUserEntity* node)
  {
    SSelectionNodeUserEntity* cursor = node;
    while (cursor != nullptr && cursor->mIsSentinel == 0u) {
      DestroySubtree(cursor->mRight);

      SSelectionNodeUserEntity* const left = cursor->mLeft;
      UnlinkSelectionWeakOwnerRef(cursor->mEnt);
      ::operator delete(cursor);
      cursor = left;
    }
  }

  /**
   * Address: 0x007AF740 (FUN_007AF740, sub_7AF740)
   *
   * What it does:
   * Erases one half-open weak-set node range `[first,last)`. For full-range
   * erases (`first == mHead->mLeft` and `last == mHead`) it drops the whole
   * subtree in one pass and resets tree head links to empty sentinels.
   */
  SSelectionNodeUserEntity** SSelectionSetUserEntity::EraseRange(
    SSelectionNodeUserEntity** const outNode,
    SSelectionNodeUserEntity* const first,
    SSelectionNodeUserEntity* const last
  )
  {
    SSelectionNodeUserEntity* const head = mHead;
    if (head == nullptr) {
      *outNode = nullptr;
      return outNode;
    }

    SSelectionNodeUserEntity* node = first;
    if (first == head->mLeft && last == head) {
      DestroySubtree(head->mParent);
      head->mParent = head;
      mSize = 0u;
      head->mLeft = head;
      head->mRight = head;
      *outNode = head->mLeft;
      return outNode;
    }

    while (node != last) {
      SSelectionNodeUserEntity* const eraseNode = node;
      if (eraseNode->mIsSentinel == 0u) {
        node = NextTreeNode(node);
      }

      (void)EraseSelectionNodeAndAdvance(*this, eraseNode);
    }

    *outNode = node;
    return outNode;
  }

  /**
   * Address: 0x007B29C0 (FUN_007B29C0, sub_7B29C0)
   *
   * What it does:
   * Advances from `start` to the first live weak-set node, deleting tombstone
   * entries (null/`(void*)8` owner-link slots) as it goes. Generalized over the
   * shared `WeakEntitySetUserEntity` header (declared in CWldSession.h) rather
   * than left as an `SSelectionSetUserEntity` member, since the only field this
   * touches is `mHead` (common to every weak-entity-set instantiation) and it
   * forwards straight into `EraseSelectionNodeAndAdvance`, which already takes
   * the same shared base. `CFormation::Finalize` (CFormation.cpp) calls this
   * directly on `mParticipants` (a `WeakUnitSetUserUnit`), exactly as the binary
   * does by pointing `this` at `CFormation`'s own `+0x00` participant set.
   */
  SSelectionNodeUserEntity** PruneTombstonesAndFindLive(
    WeakEntitySetUserEntity& set,
    SSelectionNodeUserEntity** const outNode,
    SSelectionNodeUserEntity* const start
  )
  {
    SSelectionNodeUserEntity* node = start;
    if (set.mHead == nullptr) {
      *outNode = nullptr;
      return outNode;
    }

    while (node != set.mHead) {
      void* const ownerLinkSlot = node->mEnt.mOwnerLinkSlot;
      if (ownerLinkSlot != nullptr && ownerLinkSlot != reinterpret_cast<void*>(8)) {
        break;
      }

      node = EraseSelectionNodeAndAdvance(set, node);
    }

    *outNode = node;
    return outNode;
  }

  /**
   * Address: 0x007B29C0 (FUN_007B29C0, sub_7B29C0)
   *
   * Thin forwarder preserving the original member-call shape for every existing
   * `SSelectionSetUserEntity`-typed caller in this file; the real body now lives
   * in the free `moho::PruneTombstonesAndFindLive` above.
   */
  SSelectionNodeUserEntity** SSelectionSetUserEntity::PruneTombstonesAndFindLive(
    SSelectionNodeUserEntity** const outNode,
    SSelectionNodeUserEntity* const start
  )
  {
    return moho::PruneTombstonesAndFindLive(*this, outNode, start);
  }

  /**
   * Address: 0x007ABDE0 (FUN_007ABDE0, sub_7ABDE0)
   * Address: 0x007ABE10 (FUN_007ABE10, sub_7ABE10)
   *
   * What it does:
   * Clears all weak-set nodes, destroys the tree head sentinel, and resets
   * storage links/counters for this set.
   */
  std::int32_t SSelectionSetUserEntity::ReleaseStorage()
  {
    if (mHead == nullptr) {
      mSize = 0u;
      return 0;
    }

    SSelectionNodeUserEntity* node = nullptr;
    (void)EraseRange(&node, mHead->mLeft, mHead);
    ::operator delete(mHead);
    mHead = nullptr;
    mSize = 0u;
    return 0;
  }

  /**
   * Address: 0x0066ADD0 (FUN_0066ADD0, Moho::WeakSet_UserEntity::Iterator::inc)
   * Address: 0x00856860 (FUN_00856860)
   *
   * What it does:
   * Standard MSVC red-black tree successor iterator. If the current node has
   * a non-sentinel right subtree, descends to its leftmost descendant. Otherwise
   * climbs ancestors until reaching one whose right child is not the current
   * traversal path. No-op when already at the sentinel.
   */
  void SSelectionSetUserEntity::Iterator_inc(SSelectionNodeUserEntity** const cursor)
  {
    SSelectionNodeUserEntity* node = *cursor;
    if (node->mIsSentinel != 0u) {
      return;
    }

    SSelectionNodeUserEntity* right = node->mRight;
    if (right->mIsSentinel != 0u) {
      // No right subtree: climb until we find an ancestor that we came from the left of.
      SSelectionNodeUserEntity* parent = node->mParent;
      while (parent->mIsSentinel == 0u) {
        if (*cursor != parent->mRight) {
          break;
        }
        *cursor = parent;
        parent = parent->mParent;
      }
      *cursor = parent;
    } else {
      // Has right subtree: leftmost descendant of right child is the successor.
      SSelectionNodeUserEntity* leftmost = right->mLeft;
      while (leftmost->mIsSentinel == 0u) {
        right = leftmost;
        leftmost = leftmost->mLeft;
      }
      *cursor = right;
    }
  }

  /**
   * Address: 0x0066A330 (FUN_0066A330, Moho::WeakSet_UserEntity::find)
   *
   * What it does:
   * Walks forward from `start` and uses the prune helper to remove tombstone
   * entries (null/`(void*)8` owner-link slots), returning the first live node
   * or `mHead` (sentinel) when no live entries remain.
   */
  SSelectionNodeUserEntity* SSelectionSetUserEntity::find(
    WeakEntitySetUserEntity* const set,
    SSelectionNodeUserEntity* const start,
    SSelectionNodeUserEntity** const outNode)
  {
    if (set == nullptr) {
      if (outNode != nullptr) {
        *outNode = nullptr;
      }
      return nullptr;
    }

    SSelectionNodeUserEntity* node = start;
    (void)moho::PruneTombstonesAndFindLive(*set, &node, node);
    *outNode = node;
    return node;
  }

  /**
   * Address: 0x0066A060 (FUN_0066A060, Moho::WeakSet_UserEntity::First)
   * Address: 0x007B25F0 (FUN_007B25F0, sub_7B25F0)
   *
   * What it does:
   * Starts weak-set iteration from the head-left node and stores one
   * `{set,node}` cursor pair into `outResult`.
   *
   * 0x007B25F0 is the `WeakSet<UserUnit>` emission of this exact body; the two
   * are byte-identical, which is why one definition serves both. See the
   * declaration in WeakEntitySet.h for the emission-level evidence.
   */
  WeakEntitySetUserEntity::FindResult* WeakEntitySetUserEntity::First(FindResult* const outResult)
  {
    return BuildSelectionFindResultFromHeadLeft(this, outResult);
  }

  /**
   * Address: 0x007F0490 (FUN_007F0490, sub_7F0490)
   *
   * IDA signature:
   * Moho::WeakSet_UserEntity_FindRes *__stdcall sub_7F0490(
   *     Moho::WeakSet_UserEntity_FindRes *cursor);
   *
   * What it does:
   * Advances one weak-set iteration cursor by exactly one live node: the
   * red-black successor step, then tombstone filtering through `find` against
   * the set the cursor already carries. The filtered node is written back into
   * `cursor->mRes` and the cursor is returned.
   *
   * This is the `++it` half of the `First`/`Next` pair `CUIWorldView::HandleEvent`
   * drives its two weak-set scans with (0x008706D8 and 0x0087108C).
   */
  WeakEntitySetUserEntity::FindResult* WeakEntitySetUserEntity::Next(FindResult* const cursor)
  {
    SSelectionSetUserEntity::Iterator_inc(&cursor->mRes);
    cursor->mRes = SSelectionSetUserEntity::find(cursor->mSet, cursor->mRes, &cursor->mRes);
    return cursor;
  }

  /**
   * Address: 0x007AE7E0 (FUN_007AE7E0, Moho::WeakSet_UserEntity::Iterator::Next)
   *
   * What it does:
   * Advances one weak-set iterator cursor with `Iterator_inc`, then filters to
   * the next live node via `find`, storing the resulting node back into `mNode`.
   */
  SSelectionSetUserEntity::Index* SSelectionSetUserEntity::Index::Next()
  {
    SSelectionSetUserEntity::Iterator_inc(&mNode);
    mNode = SSelectionSetUserEntity::find(mOwnerSet, mNode, &mNode);
    return this;
  }

  /**
   * Address: 0x00896F00 (FUN_00896F00) init path (FUN_00896F00 -> sub_89A930).
   */
  SSessionSaveData::SSessionSaveData()
  {
    mNodeMap.mAllocProxy = nullptr;
    (void)InitializeSessionSaveNodeMapHeader(&mNodeMap);
  }

  /**
   * Address: 0x008971A0 cleanup path (FUN_008971A0 + sub_89AC40).
   */
  SSessionSaveData::~SSessionSaveData()
  {
    ClearSaveDataMap(mNodeMap);
    DestroySaveDataMapNode(mNodeMap.mHead);
    mNodeMap.mHead = nullptr;
    mNodeMap.mAllocProxy = nullptr;
    mNodeMap.mSize = 0u;
  }

  /**
   * Address: 0x008992D0 (FUN_008992D0)/0x00899DC0/0x0089A970 helper chain.
   */
  void SSessionSaveData::InsertNodeLabel(const std::uint32_t commandSourceId, const msvc8::string& saveNodeName)
  {
    SSessionSaveNodeLabel label{};
    label.mCommandSourceId = commandSourceId;
    label.mSaveNodeName = saveNodeName;
    InsertSaveDataLabelNode(mNodeMap, label);
  }

  /**
   * Address: 0x00893160 (FUN_00893160,
   * ??0CWldSession@Moho@@QAE@AAV?$auto_ptr@VLuaState@LuaPlus@@@std@@AAV?$auto_ptr@VRRuleGameRules@Moho@@@3@AAV?$auto_ptr@VCWldMap@Moho@@@3@AAUSWldSessionInfo@1@@Z)
   */
  CWldSession::CWldSession(
    msvc8::auto_ptr<LuaPlus::LuaState>& state,
    msvc8::auto_ptr<RRuleGameRules>& rulesOwner,
    msvc8::auto_ptr<CWldMap>& wldMap,
    SWldSessionInfo& sessionInfo
  )
  {
    // Partial lift of 0x00893160: ownership transfers + proven field initialization.
    // Remaining helper-heavy initialization chain (vision/task/lua options/spatial builders)
    // is tracked for subsequent recovery pass.
    InitSessionPauseCallbackHead(head0);
    InitSessionPauseCallbackHead(head1);

    mState = state.release();
    mCurThread = nullptr;
    mRules = static_cast<RRuleGameRulesImpl*>(rulesOwner.release());
    mWldMap = wldMap.release();
    mLaunchInfo = sessionInfo.mLaunchInfo;

    mMapName = sessionInfo.mMapName;
    mUnknownOwner44 = nullptr;
    mSaveSourceTreeHead = nullptr;
    mSaveSourceTreeSize = 0u;

    std::memset(mEntitySpatialDbStorage, 0, sizeof(mEntitySpatialDbStorage));
    SBuildTemplateInfo* const inlineStart = reinterpret_cast<SBuildTemplateInfo*>(&mBuildTemplates.mInlineStorage[0]);
    SBuildTemplateInfo* const inlineCapacity =
      reinterpret_cast<SBuildTemplateInfo*>(mBuildTemplates.mInlineStorage + sizeof(mBuildTemplates.mInlineStorage));
    mBuildTemplates.mStart = inlineStart;
    mBuildTemplates.mFinish = inlineStart;
    mBuildTemplates.mCapacity = inlineCapacity;
    mBuildTemplates.mOriginalStart = inlineStart;
    mBuildTemplateArg1 = 0.0f;
    mBuildTemplateArg2 = 0.0f;

    // Address: 0x008B58A0 (FUN_008B58A0, CommandManager ctor - IdPool +
    //   command-map head sentinel allocation). The manager type is modeled
    //   now (moho/command/CommandManager.h) but its constructor is not lifted
    //   yet, so the field is still left null here.
    // 0x008932C0: the session owns one command manager, stamped with the
    // command source it issues under.
    mCommandManager = new CommandManager(sessionInfo.mSourceId);

    // Current build/move formation (0x00893529: `new CFormation` @0x64). The
    // session frame calls into it unconditionally through
    // `CFormation::UpdateOrientation`, so leaving it null faults on the first
    // frame after the session starts playing.
    mCurFormation = new CFormation();
    mUICommandGraphPx = nullptr;
    mUICommandGraphControl = nullptr;
    mUnknownShared40C = {};
    mDebugCanvas = {};
    mBeatDebugCanvas = {};
    mSimResources = {};
    // Both weak-entity sets get their head sentinel here, exactly as the
    // binary does at 0x00893358 / 0x0089338C. Leaving them null is not a
    // harmless deferral: every insert path checks the head first and silently
    // does nothing without it, which is why visibility updates never ran.
    mAuxUpdateRoot = nullptr;
    mAuxUpdateHead = AllocateWeakEntitySetHead();
    mAuxUpdateSize = 0;
    mVizUpdateRoot = nullptr;
    mVizUpdateHead = AllocateWeakEntitySetHead();
    mVizUpdateSize = 0;

    mGameTick = 0;
    mLastBeatWasTick = 0;
    mTimeSinceLastTick = 0.0f;
    mSessionPauseStateA = 0;
    mRequestingPauseState = 0;
    mRequestingPause = 0;
    mPauseRequester = 0;
    mReplayIsPaused = 0;

    ourCmdSource = static_cast<std::int32_t>(sessionInfo.mSourceId);
    IsReplay = sessionInfo.mIsReplay;
    IsBeingRecorded = sessionInfo.mIsBeingRecorded;
    IsMultiplayer = sessionInfo.mIsMultiplayer;
    IsGameOver = 0;

    if (const LaunchInfoBase* const launchInfo = mLaunchInfo.get(); launchInfo != nullptr) {
      // One null army slot per launch-info army (0x008932A7): the run has to
      // exist before the first beat, because `DoBeat` addresses it by army
      // index (`userArmies[army->mArmyIndex] = army`) rather than appending,
      // and every consumer indexes it the same way - `cfunc_IsObserverL`
      // dereferences `userArmies[FocusArmy]` the moment the in-game UI asks
      // whether the local player is an observer.
      // FUN_00899880 / FUN_00898EC0 are the two halves of
      // msvc8::vector<UserArmy*>::assign(count, nullptr) -- see the address
      // block on that member in legacy/containers/Vector.h.
      userArmies.assign(launchInfo->mArmyLaunchInfo.size(), nullptr);

      // Command sources and the focus army come off the same launch info.
      (void)CopyConstructCommandSourceVector(launchInfo->mCommandSources.mSrcs, &cmdSources);
      FocusArmy = launchInfo->mCommandSources.mOriginalSource;
      IsCheatsEnabled = launchInfo->mCheatsEnabled;
    } else {
      FocusArmy = -1;
      IsCheatsEnabled = false;
    }

    mSelection.mAllocProxy = nullptr;
    mSelection.mHead = nullptr;
    mSelection.mSize = 0;
    mSelection.mSizeMirrorOrUnused = 0;

    CursorWorldPos.x = 0.0f;
    CursorWorldPos.y = 0.0f;
    CursorWorldPos.z = 0.0f;
    CursorScreenPos.x = 0.0f;
    CursorScreenPos.y = 0.0f;
    HighlightCommandId = -1;

    mShowInvalidBuildPlacementPreview = false;
    DisplayEconomyOverlay = false;
    mTeamColorMode = false;

    // Session task stage. The binary allocates it, swaps it into `mCurThread`
    // destroying whatever was there, and then publishes it on the session Lua
    // state: for a root state `LuaState::m_luaTask` carries the owning
    // `CTaskStage`, not a `CLuaTask`, and `cfunc_ForkThreadL` reads it back
    // that way. Without this, every session script calling `ForkThread` dies
    // with "Lua state has not been set up for multiple threads".
    {
      auto* const sessionStage = new CTaskStage();
      CTaskStage* const previousStage = mCurThread;
      mCurThread = sessionStage;
      if (previousStage != nullptr) {
        previousStage->Teardown();
        delete previousStage;
      }
    }
    mState->m_luaTask = reinterpret_cast<CLuaTask*>(mCurThread);

    // Disk-watcher task, staged on the session task stage so reloaded script
    // files reach the session state's `__diskwatch` callbacks.
    (void)CTask::CreateTaskThread(new ScrDiskWatcherTask(mState), mCurThread, true);

    ClearBuildTemplates();

    // Scenario table. The lobby hands the session its scenario as a serialized
    // Lua value on the launch info (`LaunchInfoBase::mScenarioInfo`, +0x28) and
    // the session parses it into its own Lua universe. Leaving `mScenarioInfo`
    // default-constructed gives it a null owning state, so every
    // `SessionGetScenarioInfo` call from the in-game UI throws inside
    // `LuaObject::PushStack` before it can even compare global states.
    if (const LaunchInfoBase* const launchInfo = mLaunchInfo.get(); launchInfo != nullptr) {
      LuaPlus::LuaObject parsedScenario;
      (void)SCR_FromString(&parsedScenario, launchInfo->mScenarioInfo, mState);
      mScenarioInfo = parsedScenario;
    }

    // Observers are unconditionally allowed while watching a replay; otherwise
    // the scenario's own Options table decides, and a scenario without one
    // means no observers.
    if (IsReplay) {
      IsObservingAllowed = true;
    } else if (mScenarioInfo.IsTable()) {
      const LuaPlus::LuaObject options = mScenarioInfo["Options"];
      IsObservingAllowed = options.IsTable() && options["AllowObservers"].GetBoolean();
    } else {
      IsObservingAllowed = false;
    }

    gActiveWldSession = this;
  }

  /**
   * Address: 0x00893A60 (FUN_00893A60, ??1CWldSession@Moho@@QAE@XZ)
   */
  CWldSession::~CWldSession()
  {
    // Partial lift of 0x00893A60: core owner releases + recovered shared/weak cleanup.

    // 0x00893A9E..0x00893AEE: the very first thing the session unwinds is its
    // army-mirror table. Every populated slot is deleted - `~UserArmy`
    // (0x008B1650) followed by `operator delete` (0x00893AD4) - and every slot
    // is then blanked, occupied or not.
    for (std::size_t armyIndex = 0; armyIndex < userArmies.size(); ++armyIndex) {
      if (UserArmy* const army = userArmies[armyIndex]; army != nullptr) {
        delete army;
      }
      userArmies[armyIndex] = nullptr;
    }

    ReleaseWeakCommandGraph(mUICommandGraphPx, mUICommandGraphControl);
    mSimResources.release();
    mBeatDebugCanvas.release();
    mDebugCanvas.release();
    mUnknownShared40C.release();
    ClearBuildTemplates();

    // Drop every formation-preview shared-pair payload still parked in the
    // session-global preview vector. Using the recovered range-erase helper
    // (FUN_0085A130) keeps the global begin/end pointers coherent with the
    // destructor path the binary uses when the last world session unwinds.
    if (gFormationPreviewSharedPairsBegin != nullptr && gFormationPreviewSharedPairsEnd != gFormationPreviewSharedPairsBegin) {
      FormationPreviewSharedPairRuntimeView* firstIterator = nullptr;
      (void)EraseFormationPreviewSharedPairRange(
        &firstIterator,
        gFormationPreviewSharedPairsBegin,
        gFormationPreviewSharedPairsEnd
      );
    }

    if (mRules) {
      delete mRules;
      mRules = nullptr;
    }

    if (mWldMap) {
      delete mWldMap;
      mWldMap = nullptr;
    }

    // Tear the session task stage down before the Lua state it is published
    // on: the stage owns the disk-watcher task and every ForkThread coroutine
    // still parked on it, and those hold `mState`.
    if (mCurThread) {
      mCurThread->Teardown();
      delete mCurThread;
      mCurThread = nullptr;
    }

    if (mState) {
      delete mState;
      mState = nullptr;
    }

    if (mCurFormation) {
      delete mCurFormation;
      mCurFormation = nullptr;
    }
    mLaunchInfo.reset();
    DestroySessionEntityMapStorage(GetSessionEntityMap(this));

    InitSessionPauseCallbackHead(head0);
    InitSessionPauseCallbackHead(head1);

    if (gActiveWldSession == this) {
      gActiveWldSession = nullptr;
    }
  }

  /**
    * Alias of FUN_008B9580 (non-canonical helper lane).
   */
  bool CWldSession::TryGetPlayableMapRect(VisibilityRect& outRect) const
  {
    if (!mWldMap) {
      return false;
    }
    IWldTerrainRes* const terrainRes = mWldMap->mTerrainRes;
    if (!terrainRes) {
      return false;
    }
    terrainRes->GetPlayableMapRect(outRect);
    return true;
  }

  /**
   * Address: 0x007A6360 (FUN_007A6360, ?GetFocusArmy@CWldSession@Moho@@QBEPAVUserArmy@2@XZ)
   *
   * What it does:
   * Returns the focused army slot when focus is active, otherwise `nullptr`.
   */
  UserArmy* CWldSession::GetFocusArmy() const
  {
    const int focusArmy = FocusArmy;
    if (focusArmy < 0) {
      return nullptr;
    }

    return userArmies[static_cast<std::size_t>(focusArmy)];
  }

  /**
   * Address: 0x00896590 (FUN_00896590, ?IsObserver@CWldSession@Moho@@QBE_NXZ)
   *
   * What it does:
   * Returns true when focus army is disabled (`FocusArmy < 0`) or when the
   * focused army lane has no live `UserArmy*` owner.
   */
  bool CWldSession::IsObserver() const
  {
    const int focusArmy = FocusArmy;
    return focusArmy < 0 || userArmies[static_cast<std::size_t>(focusArmy)] == nullptr;
  }

  /**
   * Address: 0x00896570 (FUN_00896570, ?SetCursorInfo@CWldSession@Moho@@QAEXABUUICursorInfo@2@@Z)
   *
   * What it does:
   * Copies one cursor-info payload into the session cursor-info lane.
   */
  void CWldSession::SetCursorInfo(const MouseInfo& cursorInfo)
  {
    AccessCursorInfo(*this) = cursorInfo;
  }

  /**
   * Address: 0x00895FF0 (FUN_00895FF0, ?GetSelection@CWldSession@Moho@@QBEABV?$WeakSet@VUserEntity@Moho@@@2@XZ)
   *
   * What it does:
   * Returns the current world-session selection weak-set.
   */
  const SSelectionSetUserEntity& CWldSession::GetSelection() const
  {
    return mSelection;
  }

  /**
   * Address: 0x00896730 (FUN_00896730, ?GetExtraSelectList@CWldSession@Moho@@QBE?AV?$WeakSet@VUserEntity@Moho@@@2@XZ)
   *
   * What it does:
   * Returns one by-value clone of the extra-selection weak-set by copying the
   * live iterator range `[find(head->left), head)` into caller-owned storage.
   */
  SSelectionSetUserEntity CWldSession::GetExtraSelectList() const
  {
    SSelectionSetUserEntity outSelection{};
    SSelectionSetUserEntity* const extraSelection = const_cast<SSelectionSetUserEntity*>(&ExtraSelectionView());
    if (extraSelection == nullptr || extraSelection->mHead == nullptr) {
      (void)InitSelectionSetFromIteratorRange(&outSelection, extraSelection, nullptr, nullptr);
      return outSelection;
    }

    SSelectionNodeUserEntity* first = extraSelection->mHead->mLeft;
    first = SSelectionSetUserEntity::find(extraSelection, first, &first);
    (void)InitSelectionSetFromIteratorRange(&outSelection, extraSelection, first, extraSelection->mHead);
    return outSelection;
  }

  /**
   * Address: 0x00896580 (FUN_00896580, ?GetCursorInfo@CWldSession@Moho@@QBEABUUICursorInfo@2@XZ)
   *
   * What it does:
   * Returns the current cursor-info payload stored by this world session.
   */
  const MouseInfo& CWldSession::GetCursorInfo() const
  {
    return AccessCursorInfo(*this);
  }

  /**
   * Not a distinct binary function - every caller inlines the same
   * `mCursorInfo.mUnitHover` weak-link decode (0x0086ECE8's own body plus
   * three call sites already in this file). Promoted to a public accessor
   * so callers outside this TU (`sub_8281E0`'s recovered form in the
   * command-graph render pass) don't need their own copy.
   *
   * `MouseInfo::mUnitHover` (the public struct) is declared as a raw
   * `UserEntity*`, but the binary stores an intrusive weak-link slot there,
   * not a live pointer - `CursorInfoRuntimeView::mUnitHover` already models
   * it correctly as `UserEntityWeakLinkSlotRuntimeView`. Decode through that
   * view rather than reading `MouseInfo::mUnitHover` directly.
   */
  UserEntity* CWldSession::GetHoveredUserEntity() const noexcept
  {
    return DecodeUserEntityWeakLinkSlot(AccessCursorInfoRuntime(*this).mUnitHover);
  }

  /**
   * Not a distinct binary function - promotes the file-private
   * `ResolveCommandGraphAnchorHistoryWorldPosition` (= FUN_0081CFD0) so
   * `UICommandGraph::DrawPositionNodeMesh` (a different TU) can resolve a
   * command's fallback world-space anchor without its own copy of the
   * `CommandGraphAnchorHistoryRuntimeView` reinterpret, which - like the
   * event-slot view it shares every offset with - reads the whole
   * `UserCommandIssueHelper` from its own base, not a sub-object.
   */
  Wm3::Vector3f ResolveCommandGraphAnchorWorldPosition(UserCommandIssueHelper& helper) noexcept
  {
    Wm3::Vector3f position{};
    (void)ResolveCommandGraphAnchorHistoryWorldPosition(
      &position, reinterpret_cast<CommandGraphAnchorHistoryRuntimeView*>(&helper)
    );
    return position;
  }

  /**
   * Address: 0x008965C0 (FUN_008965C0, ?BecomeObserver@CWldSession@Moho@@QAEXXZ)
   *
   * What it does:
   * Validates observer focus request (`-1`) and applies it to the active sim
   * driver when allowed.
   */
  void CWldSession::BecomeObserver()
  {
    if (!ValidateFocusArmyRequest(-1)) {
      return;
    }

    if (ISTIDriver* const activeDriver = SIM_GetActiveDriver()) {
      activeDriver->SetArmyIndex(-1);
    }
  }

  /**
   * Address context: compatibility wrapper lane used by recovered callsites.
   */
  UserArmy* CWldSession::GetFocusUserArmy()
  {
    return GetFocusArmy();
  }

  /**
   * Address context: compatibility wrapper lane used by recovered callsites.
   */
  const UserArmy* CWldSession::GetFocusUserArmy() const
  {
    return GetFocusArmy();
  }

  /**
   * Address: 0x008965E0 (FUN_008965E0, ?RequestFocusArmy@CWldSession@Moho@@QAEXH@Z)
   *
   * What it does:
   * Validates one zero-based focus-army index (`-1` allowed) and forwards
   * accepted changes to the active sim driver.
   */
  void CWldSession::RequestFocusArmy(const int index)
  {
    const int maxArmyIndex = static_cast<int>(userArmies.size()) - 1;
    if (index < -1 || index > maxArmyIndex) {
      gpg::Logf(
        "CWldSession::RequestFocusArmy(): invalid army index %d.  Must be between -1 and %d inclusive",
        index,
        maxArmyIndex
      );
      return;
    }

    if (!ValidateFocusArmyRequest(index)) {
      return;
    }

    if (ISTIDriver* const activeDriver = SIM_GetActiveDriver()) {
      activeDriver->SetArmyIndex(index);
    }
  }

  /**
   * Address: 0x00896670 (FUN_00896670, ?ValidateFocusArmyRequest@CWldSession@Moho@@AAE_NH@Z)
   *
   * What it does:
   * Returns whether one focus-army switch is allowed for the current command
   * source/session observation state.
   */
  bool CWldSession::ValidateFocusArmyRequest(const int index)
  {
    const unsigned int localCommandSource = static_cast<unsigned int>(ourCmdSource);

    bool hasDirectCommandSourceAccess = false;
    if (index != -1 && index >= 0) {
      const std::size_t focusIndex = static_cast<std::size_t>(index);
      if (focusIndex < userArmies.size()) {
        const UserArmy* const targetArmy = userArmies[focusIndex];
        if (targetArmy != nullptr) {
          hasDirectCommandSourceAccess = targetArmy->mVarDat.mValidCommandSources.Contains(localCommandSource);
        }
      }
    }

    if (localCommandSource == 0xFFu || IsCheatsEnabled || hasDirectCommandSourceAccess || IsGameOver != 0u) {
      return true;
    }

    if (!IsObservingAllowed) {
      return false;
    }

    for (UserArmy* const army : userArmies) {
      if (army == nullptr) {
        continue;
      }

      if (army->mVarDat.mValidCommandSources.Contains(localCommandSource) && army->mVarDat.mIsOutOfGame == 0u) {
        return false;
      }
    }

    return true;
  }

  /**
    * Alias of FUN_008B97C0 (non-canonical helper lane).
   */
  EntityCategoryLookupResolver* CWldSession::GetCategoryLookupResolver()
  {
    return const_cast<EntityCategoryLookupResolver*>(
      static_cast<const CWldSession*>(this)->GetCategoryLookupResolver()
    );
  }

  /**
    * Alias of FUN_008B97C0 (non-canonical helper lane).
   */
  const EntityCategoryLookupResolver* CWldSession::GetCategoryLookupResolver() const
  {
    if (!mRules) {
      return nullptr;
    }

    // RRuleGameRulesImpl exposes the category-lookup contract in the same primary
    // vtable; this is a typed interface view, not a separate base subobject.
    return reinterpret_cast<const EntityCategoryLookupResolver*>(mRules);
  }

  /**
    * Alias of FUN_008B85E0 (non-canonical helper lane).
   */
  void* CWldSession::GetEntitySpatialDbStorage()
  {
    return mEntitySpatialDbStorage;
  }

  /**
    * Alias of FUN_008B85E0 (non-canonical helper lane).
   */
  const void* CWldSession::GetEntitySpatialDbStorage() const
  {
    return mEntitySpatialDbStorage;
  }

  /**
   * Address context: 0x00896870 (`ClearExtraSelectList`) field lane.
   */
  SSelectionSetUserEntity& CWldSession::ExtraSelectionView()
  {
    constexpr std::size_t kExtraSelectionOffsetInStorage = 0x90;
    static_assert(
      offsetof(CWldSession, mEntitySpatialDbStorage) + kExtraSelectionOffsetInStorage == 0xE0,
      "CWldSession::ExtraSelectionView offset must be 0xE0"
    );
    return *reinterpret_cast<SSelectionSetUserEntity*>(mEntitySpatialDbStorage + kExtraSelectionOffsetInStorage);
  }

  /**
   * Address context: 0x00896870 (`ClearExtraSelectList`) field lane.
   */
  const SSelectionSetUserEntity& CWldSession::ExtraSelectionView() const
  {
    return const_cast<CWldSession*>(this)->ExtraSelectionView();
  }

  /**
   * Address: 0x00896780 (FUN_00896780, ?AddToExtraSelectList@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Starts transport order command mode and inserts one entity into the
   * world-session extra-selection weak-set.
   */
  void CWldSession::AddToExtraSelectList(UserEntity* const entity)
  {
    UICommandModeData commandModeData{};
    commandModeData.mMode = msvc8::string("order", 5u);
    commandModeData.mPayload.AssignNewTable(mState, 0, 0);
    commandModeData.mPayload.SetString("name", "RULEUCC_Transport");
    UI_StartCommandMode(commandModeData);

    SSelectionSetUserEntity& extraSelection = ExtraSelectionView();
    (void)InsertSelectionEntity(extraSelection, entity);
  }

  /**
   * Address: 0x00896830 (FUN_00896830, ?RemoveFromExtraSelectList@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Removes one entity from the world-session extra-selection weak-set and
   * exits command mode when the set becomes empty.
   */
  void CWldSession::RemoveFromExtraSelectList(UserEntity* const entity)
  {
    SSelectionSetUserEntity& extraSelection = ExtraSelectionView();
    if (!SSelectionSetUserEntity::Erase(extraSelection, entity)) {
      return;
    }

    SSelectionNodeUserEntity* const head = extraSelection.mHead;
    if (head != nullptr && head->mLeft == head) {
      UI_EndCommandMode();
    }
  }

  /**
   * Address: 0x00896870 (FUN_00896870, ?ClearExtraSelectList@CWldSession@Moho@@QAEXXZ)
   *
   * What it does:
   * Clears world-session extra selection weak-set and exits command mode when
   * any entries were present.
   */
  void CWldSession::ClearExtraSelectList()
  {
    SSelectionSetUserEntity& extraSelection = ExtraSelectionView();
    SSelectionNodeUserEntity* const head = extraSelection.mHead;
    if (head == nullptr || head->mLeft == head) {
      return;
    }

    SSelectionNodeUserEntity* node = head->mLeft;
    (void)extraSelection.EraseRange(&node, head->mLeft, head);
    extraSelection.mSizeMirrorOrUnused = extraSelection.mSize;
    UI_EndCommandMode();
  }

  /**
   * Address: 0x0081DC70 (FUN_0081DC70, Moho::CWldSession::UnitFirstInSelection)
   *
   * What it does:
   * Returns true when selection is empty or every live selected entity
   * resolves to the supplied user-unit pointer.
   */
  bool CWldSession::UnitFirstInSelection(const UserUnit* const unit) const
  {
    SSelectionSetUserEntity& selection = const_cast<SSelectionSetUserEntity&>(mSelection);
    SSelectionNodeUserEntity* const head = selection.mHead;
    if (head == nullptr) {
      return true;
    }

    SSelectionNodeUserEntity* node = head->mLeft;
    SSelectionSetUserEntity::find(&selection, node, &node);
    while (node != head) {
      const UserEntity* const selectedEntity = DecodeSelectedUserEntity(node->mEnt);
      const UserUnit* const selectedUnit = selectedEntity ? selectedEntity->IsUserUnit() : nullptr;
      if (selectedUnit != unit) {
        return false;
      }

      SSelectionSetUserEntity::Iterator_inc(&node);
      SSelectionSetUserEntity::find(&selection, node, &node);
    }

    return true;
  }

  /**
   * Address: 0x00894120 (FUN_00894120, ?GetTerrainRes@CWldSession@Moho@@QBEPAVIWldTerrainRes@2@XZ)
   *
   * What it does:
   * Returns the world-map terrain resource lane owned by this world session.
   */
  IWldTerrainRes* CWldSession::GetTerrainRes() const
  {
    return mWldMap->mTerrainRes;
  }

  /**
   * Address: 0x00894130 (FUN_00894130, ?GetSTIMap@CWldSession@Moho@@QBEPAVSTIMap@2@XZ)
   *
   * What it does:
   * Returns the terrain STI map lane from the world-map terrain resource.
   */
  STIMap* CWldSession::GetSTIMap() const
  {
    return reinterpret_cast<STIMap*>(mWldMap->mTerrainRes->mPlayableRectSource);
  }

  /**
   * Address: 0x00894140 (FUN_00894140, ?AddEntity@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Inserts one `(entityId, entity*)` mapping into the world-session entity map.
   */
  void CWldSession::AddEntity(UserEntity* const entity)
  {
    if (entity == nullptr) {
      return;
    }

    SessionEntityMap& entityMap = GetSessionEntityMap(this);
    InsertSessionEntityMapEntry(entityMap, static_cast<std::uint32_t>(entity->mParams.mEntityId), entity);
  }

  /**
   * Address: 0x00894170 (FUN_00894170, ?RemoveEntity@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Removes one entity-id mapping from the world-session entity map.
   */
  void CWldSession::RemoveEntity(UserEntity* const entity)
  {
    if (entity == nullptr) {
      return;
    }

    SessionEntityMap& entityMap = GetSessionEntityMap(this);
    SessionEntityMapNode* const mapNode = FindSessionEntityMapNodeById(
      entityMap,
      static_cast<std::uint32_t>(entity->mParams.mEntityId)
    );
    if (mapNode != nullptr && mapNode != entityMap.mHead) {
      EraseSessionEntityMapNode(entityMap, mapNode);
    }
  }

  /**
   * Address: 0x008941B0 (FUN_008941B0, ?OrphanEntity@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Removes one entity-id mapping from the session entity map, marks the
   * entity as pending deletion, and inserts it into the orphan weak-set lane.
   */
  void CWldSession::OrphanEntity(UserEntity* const entity)
  {
    if (entity == nullptr) {
      return;
    }

    auto* const runtimeView = reinterpret_cast<CWldSessionOrphanRuntimeView*>(this);
    SessionEntityMap& entityMap = runtimeView->mEntityMap;
    SessionEntityMapNode* const mapNode = FindSessionEntityMapNodeById(
      entityMap,
      static_cast<std::uint32_t>(entity->mParams.mEntityId)
    );
    if (mapNode != nullptr && mapNode != entityMap.mHead) {
      EraseSessionEntityMapNode(entityMap, mapNode);
    }

    // The flag is what keeps the render side from treating the entity as live
    // while it finishes its death animation; 0x008941FA writes it right before
    // the weak-set insert.
    entity->mMarkedForDeletion = 1;

    SSelectionSetUserEntity::AddResult addResult{};
    (void)SSelectionSetUserEntity::Add(&addResult, &runtimeView->mPendingOrphanSet, entity);
  }

  /**
   * Address: 0x00894210 (FUN_00894210, ?AddToVizUpdate@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   */
  void CWldSession::AddToVizUpdate(UserEntity* const entity)
  {
    if (!entity) {
      return;
    }

    VizUpdateTree* const tree = GetVizUpdateTree(this);
    if (!tree || !tree->head) {
      return;
    }

    (void)InsertVizUpdateNode(tree, entity);
  }

  /**
   * Address: 0x00894230 (FUN_00894230, ?RemoveFromVizUpdate@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   */
  void CWldSession::RemoveFromVizUpdate(UserEntity* const entity)
  {
    if (!entity) {
      return;
    }

    VizUpdateTree* const tree = GetVizUpdateTree(this);
    if (!tree || !tree->head) {
      return;
    }

    VizUpdateNode* const node = FindVizUpdateNode(tree, reinterpret_cast<std::uintptr_t>(entity));
    if (!node || node == tree->head) {
      return;
    }

    EraseVizUpdateNode(tree, node);
  }

  /**
   * Address: 0x008942B0 (FUN_008942B0, ?RequestPause@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::RequestPause()
  {
    std::int32_t commandCookie = 0;
    ISTIDriver* const simDriver = SIM_GetActiveDriver();
    if (IsReplay) {
      if (mReplayIsPaused == 0u) {
        mReplayIsPaused = 1;
        simDriver->IncrementOutstandingRequests();
      }
    } else {
      simDriver->RequestPause(&commandCookie);
      mRequestingPauseState = 1;
      mRequestingPause = 1;
      mPauseRequester = commandCookie;
    }

    DispatchSessionPauseCallbacks(head0, true);
  }

  /**
   * Address: 0x00894330 (FUN_00894330, ?Resume@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::Resume()
  {
    std::int32_t commandCookie = 0;
    ISTIDriver* const simDriver = SIM_GetActiveDriver();
    if (IsReplay) {
      if (mReplayIsPaused != 0u) {
        mReplayIsPaused = 0;
        simDriver->DecrementOutstandingRequestsAndSignal();
      }
    } else {
      simDriver->Resume(&commandCookie);
      mRequestingPauseState = 1;
      mRequestingPause = 0;
      mPauseRequester = commandCookie;
    }

    DispatchSessionPauseCallbacks(head0, false);
  }

  /**
   * Address: 0x008943E0 (FUN_008943E0, ?CheckForNecessaryUIRefresh@CWldSession@Moho@@QAEXXZ)
   *
   * What it does:
   * Rebuilds the current selection when stale/dead weak entries are detected
   * or selected entities requested a UI refresh during beat processing.
   */
  void CWldSession::CheckForNecessaryUIRefresh()
  {
    const std::uint32_t previousSelectionSize = mSelection.mSize;
    bool needsSelectionRefresh = false;

    msvc8::vector<UserEntity*> filteredSelection{};
    filteredSelection.reserve(static_cast<std::size_t>(previousSelectionSize));

    const SSelectionNodeUserEntity* const head = mSelection.mHead;
    if (head != nullptr) {
      for (const SSelectionNodeUserEntity* node = head->mLeft; node != nullptr && node != head; node = NextTreeNode(node)
      ) {
        UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
        if (entity == nullptr) {
          needsSelectionRefresh = true;
          continue;
        }

        if (entity->RequiresUIRefresh()) {
          needsSelectionRefresh = true;
        }

        if (entity->mVariableData.mIsDead != 0u) {
          needsSelectionRefresh = true;
          continue;
        }

        if (!ContainsEntityPtr(filteredSelection, entity)) {
          filteredSelection.push_back(entity);
        }
      }
    }

    const std::int32_t maxSelectionSizeRuntime =
      reinterpret_cast<const CWldSessionSelectionStatsRuntimeView*>(this)->maxSelectionSize;
    const std::uint32_t maxSelectionSize = maxSelectionSizeRuntime > 0 ? static_cast<std::uint32_t>(maxSelectionSizeRuntime)
                                                                        : 0u;
    const std::uint32_t liveSelectionSize = static_cast<std::uint32_t>(filteredSelection.size());

    if (!needsSelectionRefresh && !(previousSelectionSize < maxSelectionSize) && !(liveSelectionSize < previousSelectionSize
        )) {
      return;
    }

    msvc8::vector<UserEntity*> previousSelection{};
    CollectSelectionEntities(mSelection, previousSelection);
    const bool selectionChanged = !AreEntitySetsEqual(previousSelection, filteredSelection);

    ClearSelectionSet(mSelection);
    for (UserEntity* const entity : filteredSelection) {
      (void)InsertSelectionEntity(mSelection, entity);
    }

    mSelection.mSizeMirrorOrUnused = mSelection.mSize;
    reinterpret_cast<CWldSessionSelectionStatsRuntimeView*>(this)->maxSelectionSize =
      static_cast<std::int32_t>(mSelection.mSize);

    if (!selectionChanged) {
      return;
    }

    if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
      SSyncFilterMaskBlock selectionMask{};
      BuildSelectionSyncMask(mSelection, selectionMask);
      activeDriver->SetSyncFilterMaskB(selectionMask);
    }

    UI_EndCommandMode();
  }

  /**
   * Address: 0x00896A40 (FUN_00896A40, ?GetActiveBuildTemplate@CWldSession@Moho@@QBE?AV?$fastvector_n@USBuildTemplateInfo@Moho@@$0BA@@gpg@@AAH0@Z)
   *
   * What it does:
   * Copies the active build-template buffer into one caller-owned inline
   * fastvector lane and returns the current template X/Z extents.
   */
  SBuildTemplateBuffer* CWldSession::GetActiveBuildTemplate(
    float* const outTemplateSpanZ,
    float* const outTemplateSpanX,
    SBuildTemplateBuffer* const result
  ) const
  {
    *outTemplateSpanX = mBuildTemplateArg1;
    *outTemplateSpanZ = mBuildTemplateArg2;
    return RebindAndCopyBuildTemplateBufferInline(result, mBuildTemplates);
  }

  /**
   * Address: 0x00896AA0 (FUN_00896AA0, ?GenerateBuildTemplates@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::GenerateBuildTemplates()
  {
    std::int32_t selectableTemplateUnitCount = 0;

    SSelectionSetUserEntity::FindResult cursor{};
    (void)mSelection.First(&cursor);
    while (cursor.mRes != mSelection.mHead) {
      UserEntity* const selectedEntity = DecodeSelectedUserEntity(cursor.mRes->mEnt);
      UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
      const IUnit* const selectedBridge = GetIUnitBridge(selectedUnit);
      if (selectedBridge != nullptr && !selectedBridge->IsMobile() && !selectedBridge->IsDead()) {
        ++selectableTemplateUnitCount;
      }

      SSelectionSetUserEntity::Iterator_inc(&cursor.mRes);
      cursor.mRes = SSelectionSetUserEntity::find(&mSelection, cursor.mRes, &cursor.mRes);
    }

    if (selectableTemplateUnitCount <= 0) {
      return;
    }

    ClearBuildTemplates();

    float minX = 10000.0f;
    float minY = 10000.0f;
    float maxX = -10000.0f;
    float maxY = -10000.0f;

    (void)mSelection.First(&cursor);
    while (cursor.mRes != mSelection.mHead) {
      UserEntity* const selectedEntity = DecodeSelectedUserEntity(cursor.mRes->mEnt);
      UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
      IUnit* const selectedBridge = GetIUnitBridge(selectedUnit);
      if (selectedBridge != nullptr && !selectedBridge->IsMobile() && !selectedBridge->IsDead()) {
        SBuildTemplateInfo templateInfo{};

        const auto& position = selectedBridge->GetPosition();
        templateInfo.mPos.x = position.x;
        templateInfo.mPos.y = 0.0f;
        templateInfo.mPos.z = position.z;
        templateInfo.mBuildOrder = selectedUnit->mUnitVarDat.mCreationTick;

        const RUnitBlueprint* const blueprint = selectedBridge->GetBlueprint();
        templateInfo.mBlueprintId.assign(blueprint->mBlueprintId, 0u, 0xFFFFFFFFu);

        const SCoordsVec2 unitCoords{
          selectedEntity->mVariableData.mCurTransform.pos_.x,
          selectedEntity->mVariableData.mCurTransform.pos_.z
        };
        const gpg::Rect2f skirtRect = blueprint->GetSkirtRect(unitCoords);
        minX = std::min(minX, skirtRect.x0);
        minY = std::min(minY, skirtRect.z0);
        maxX = std::max(maxX, skirtRect.x1);
        maxY = std::max(maxY, skirtRect.z1);

        AppendBuildTemplateEntry(mBuildTemplates, templateInfo);
      }

      SSelectionSetUserEntity::Iterator_inc(&cursor.mRes);
      cursor.mRes = SSelectionSetUserEntity::find(&mSelection, cursor.mRes, &cursor.mRes);
    }

    SortBuildTemplateRangeByOrder(mBuildTemplates.mStart, mBuildTemplates.mFinish);
    mBuildTemplateArg1 = maxX - minX;
    mBuildTemplateArg2 = maxY - minY;

    const Wm3::Vector3f origin = mBuildTemplates.mStart->mPos;
    for (SBuildTemplateInfo* entry = mBuildTemplates.mStart; entry != mBuildTemplates.mFinish; ++entry) {
      entry->mPos.x -= origin.x;
      entry->mPos.y -= origin.y;
      entry->mPos.z -= origin.z;
    }
  }

  /**
   * Address: 0x008969E0 (FUN_008969E0, ?ClearBuildTemplates@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::ClearBuildTemplates()
  {
    SBuildTemplateInfo* start = mBuildTemplates.mStart;
    SBuildTemplateInfo* finish = mBuildTemplates.mFinish;
    if (start && finish && start <= finish) {
      DestroyBuildTemplateRange(start, finish);
    }

    SBuildTemplateInfo* const inlineStart = mBuildTemplates.mOriginalStart
      ? mBuildTemplates.mOriginalStart
      : reinterpret_cast<SBuildTemplateInfo*>(&mBuildTemplates.mInlineStorage[0]);
    if (start && start != inlineStart) {
      ::operator delete[](start);
      mBuildTemplates.mStart = inlineStart;
      mBuildTemplates.mCapacity =
        reinterpret_cast<SBuildTemplateInfo*>(mBuildTemplates.mInlineStorage + sizeof(mBuildTemplates.mInlineStorage));
    }

    mBuildTemplates.mFinish = mBuildTemplates.mStart;
    mBuildTemplateArg1 = 0.0f;
    mBuildTemplateArg2 = 0.0f;
  }

  // gpg::fastvector_n<SBuildTemplateInfo, 16> behaviour, out-of-line so the
  // inline-buffer growth/teardown helpers above are in scope. Used by callers in
  // other translation units (e.g. the SetActiveBuildTemplate Lua callback) that
  // build a template buffer before handing it to CWldSession::SetActiveBuildTemplate.
  void SBuildTemplateBuffer::InitInlineStorage() noexcept
  {
    mStart = reinterpret_cast<SBuildTemplateInfo*>(&mInlineStorage[0]);
    mFinish = mStart;
    mCapacity = mStart + (sizeof(mInlineStorage) / sizeof(SBuildTemplateInfo)); // 16 inline entries
    mOriginalStart = mStart;
  }

  void SBuildTemplateBuffer::PushBack(const SBuildTemplateInfo& info)
  {
    AppendBuildTemplateEntry(*this, info);
  }

  void SBuildTemplateBuffer::DestroyStorage()
  {
    DestroyBuildTemplateRange(mStart, mFinish);
    if (mStart != mOriginalStart) {
      ::operator delete[](mStart);
    }
    mStart = mOriginalStart;
    mFinish = mOriginalStart;
  }

  /**
   * Address: 0x00899790 (FUN_00899790,
   *   gpg::fastvector_n<Moho::SBuildTemplateInfo, 16>::operator=)
   *
   * What it does:
   * Per-T named helper that drives the engine-emitted assignment-operator
   * body of `gpg::fastvector_n<SBuildTemplateInfo, 16>`. Performs the
   * self-assignment guard, then either copies into the existing tail when
   * destination has spare capacity, grows storage and copies otherwise, or
   * truncates+copies when destination already has more elements than source.
   *
   * The body is expressed in terms of the recovered build-template helpers
   * (`DestroyBuildTemplateRange`, `RebindAndCopyBuildTemplateBufferInline`)
   * so we preserve the existing source-level invocation graph; the linker
   * keeps the FUN_00899790 symbol bound because the call from
   * `CWldSession::SetActiveBuildTemplate` invokes this named entry directly.
   */
  void AssignBuildTemplateBuffer(SBuildTemplateBuffer& destination, const SBuildTemplateBuffer& source)
  {
    if (&destination == &source) {
      return;
    }

    SBuildTemplateInfo* const oldStart = destination.mStart;
    SBuildTemplateInfo* const oldFinish = destination.mFinish;
    if (oldStart && oldFinish && oldStart <= oldFinish) {
      DestroyBuildTemplateRange(oldStart, oldFinish);
    }

    SBuildTemplateInfo* const inlineStart = reinterpret_cast<SBuildTemplateInfo*>(&destination.mInlineStorage[0]);
    if (oldStart && oldStart != inlineStart && oldStart != destination.mOriginalStart) {
      ::operator delete[](oldStart);
    }

    destination.mStart = inlineStart;
    destination.mFinish = inlineStart;
    destination.mCapacity = inlineStart + 16u;
    destination.mOriginalStart = inlineStart;

    (void)RebindAndCopyBuildTemplateBufferInline(&destination, source);
  }

  /**
   * Address: 0x00896A70 (FUN_00896A70,
   *   ?SetActiveBuildTemplate@CWldSession@Moho@@QAEXABV?$fastvector_n@USBuildTemplateInfo@Moho@@$0BA@@gpg@@HH@Z)
   *
   * What it does:
   * Replaces the active build-template fastvector buffer with `templates`
   * and records the placement preview anchor as (`templateSpanX`,
   * `templateSpanZ`). The buffer copy is delegated to the per-T named
   * assignment helper `moho::AssignBuildTemplateBuffer` (FUN_00899790) so
   * the linker keeps the engine-emitted assignment symbol bound.
   */
  void CWldSession::SetActiveBuildTemplate(
    const SBuildTemplateBuffer& templates,
    const float templateSpanX,
    const float templateSpanZ
  )
  {
    AssignBuildTemplateBuffer(mBuildTemplates, templates);
    mBuildTemplateArg1 = templateSpanX;
    mBuildTemplateArg2 = templateSpanZ;
  }

  /**
   * Address: 0x00895EB0 (FUN_00895EB0,
   * ?GetCommandGraph@CWldSession@Moho@@QAE?AV?$shared_ptr@VUICommandGraph@Moho@@@boost@@_N@Z)
   */
  boost::SharedPtrRaw<UICommandGraph> CWldSession::GetCommandGraph(const bool allowCreate)
  {
    boost::SharedPtrRaw<UICommandGraph> graph = LockWeakCommandGraph(mUICommandGraphPx, mUICommandGraphControl);
    if (!graph.px && allowCreate) {
      UICommandGraph* createdGraph = nullptr;
      void* const raw = ::operator new(sizeof(UICommandGraph), std::nothrow);
      if (raw) {
        createdGraph = new (raw) UICommandGraph(this);
      }

      AssignSharedCommandGraph(graph, createdGraph);
      CopySharedToWeakCommandGraph(graph, mUICommandGraphPx, mUICommandGraphControl);
    }

    return graph;
  }

  /**
   * Address: 0x00895DC0 (FUN_00895DC0, ?HandleFogEdge@CWldSession@Moho@@AAEXABV?$Rect2@H@gpg@@HH@Z)
   *
   * What it does:
   * Clears edge-fog rows when focus army is invalid and marks every edge lane
   * outside the visible rectangle as blocked (`0xFF`).
   */
  void CWldSession::HandleFogEdge(const gpg::Rect2i& visibleRect, const int width, const int height)
  {
    if (FocusArmy < 0 || userArmies[static_cast<std::size_t>(FocusArmy)] == nullptr) {
      char* row = mEdgeFog.GetPtr(0u, 0u);
      for (int y = 0; y < height; ++y) {
        std::memset(row, 0, static_cast<std::size_t>(width));
        row += width;
      }
    }

    if (visibleRect.x0 > 0 || visibleRect.z0 > 0 || visibleRect.x1 < width || visibleRect.z1 < height) {
      char* row = mEdgeFog.GetPtr(0u, 0u);
      for (int y = 0; y < height; ++y, row += width) {
        if (y < visibleRect.z0 || y >= visibleRect.z1) {
          std::memset(row, 0xFF, static_cast<std::size_t>(width));
          continue;
        }

        if (visibleRect.x0 <= 0) {
          *row = static_cast<char>(0xFF);
        } else {
          std::memset(row, 0xFF, static_cast<std::size_t>(visibleRect.x0));
        }

        if (visibleRect.x1 >= (width - 1)) {
          row[width - 1] = static_cast<char>(0xFF);
        } else {
          std::memset(row + visibleRect.x1, 0xFF, static_cast<std::size_t>(width - visibleRect.x1));
        }
      }
    }
  }

  /**
   * Address: 0x00895F70 (FUN_00895F70, ?DirtyCommandGraph@CWldSession@Moho@@QAEXXZ)
   *
   * What it does:
   * Locks the cached UI command-graph weak handle, marks it dirty when
   * present, and releases the temporary shared hold.
   */
  void CWldSession::DirtyCommandGraph()
  {
    boost::SharedPtrRaw<UICommandGraph> graph = GetCommandGraph(false);
    if (graph.px != nullptr) {
      graph.px->MarkDirty();
    }
    graph.release();
  }

  /**
   * Address: 0x008958B0 (FUN_008958B0, ?ApplyPendingSaveData@CWldSession@Moho@@AAEXXZ)
   *
   * What it does:
   * Replays save-data selection-set labels onto live user units, groups those
   * units by selection-set name in Lua, calls
   * `/lua/ui/game/selection.lua:ResetSelectionSets`, then releases the pending
   * save-data shared pointer.
   */
  void CWldSession::ApplyPendingSaveData()
  {
    LuaPlus::LuaObject selectionSetsByName;
    selectionSetsByName.AssignNewTable(mState, 0, 0);

    SSessionSaveData& saveData = *mPendingSaveData;
    SSessionSaveNodeMapNode* const head = saveData.mNodeMap.mHead;
    for (SSessionSaveNodeMapNode* node = head->mLeft; node != nullptr && node != head; node = NextTreeNode(node)) {
      UserEntity* const entity = LookupEntityId(static_cast<EntId>(node->mLabel.mCommandSourceId));
      if (entity == nullptr) {
        continue;
      }

      UserUnit* const unit = entity->IsUserUnit();
      if (unit == nullptr) {
        continue;
      }

      const char* const selectionSetName = node->mLabel.mSaveNodeName.c_str();
      unit->AddSelectionSet(selectionSetName);

      LuaPlus::LuaObject setUnits = selectionSetsByName[selectionSetName];
      if (setUnits.IsNil()) {
        setUnits.AssignNewTable(mState, 0, 0);
        selectionSetsByName.SetObject(selectionSetName, setUnits);
      }

      IUnit* const iunitBridge = GetIUnitBridge(unit);
      LuaPlus::LuaObject unitObject = iunitBridge->GetLuaObject();
      setUnits.Insert(setUnits.GetN() + 1, unitObject);
    }

    try {
      LuaPlus::LuaObject selectionModule = SCR_Import(mState, "/lua/ui/game/selection.lua");
      LuaPlus::LuaFunction<> resetSelectionSets(selectionModule["ResetSelectionSets"]);
      resetSelectionSets.Call_Object(selectionSetsByName);
    } catch (const std::exception& exception) {
      gpg::Warnf(
        "Unable to reset selection sets: %s",
        exception.what() != nullptr ? exception.what() : ""
      );
    }

    mPendingSaveData.reset();
  }

  namespace
  {
    /**
     * Address: 0x008945C1..0x008945D8 (inside FUN_00894530)
     *
     * What it does:
     * Resolves one army slot for the sound listener, treating a negative focus
     * army (observer, or not yet assigned) as "no listener".
     */
    [[nodiscard]] UserArmy* ArmyAtIndexOrNull(const msvc8::vector<UserArmy*>& armies, const std::int32_t index)
    {
      if (index < 0) {
        return nullptr;
      }
      return armies[static_cast<std::size_t>(index)];
    }

    /**
     * Address: 0x00894E11..0x00894E45 (inside FUN_00894530)
     *
     * What it does:
     * Looks one live command-issue helper up by id, returning null when the
     * manager's map has no entry (the walk lands on the sentinel head).
     */
    [[nodiscard]] UserCommandIssueHelper* FindCommandIssueHelper(CommandManager& manager, const CmdId commandId)
    {
      const auto found = manager.mCommands.find(commandId);
      return found == manager.mCommands.end() ? nullptr : found->second;
    }

    /**
     * Address: 0x008955F2..0x00895617 / 0x0089564A..0x00895667 (inside FUN_00894530)
     *
     * What it does:
     * Opens a pruning cursor on one weak-entity set. `find` drops entries whose
     * owner died since the last beat instead of handing them out, so the first
     * position has to come through it rather than straight off `mHead->mLeft`.
     */
    /**
     * Address: 0x00895097..0x0089511F and three siblings (inside FUN_00894530)
     *
     * What it does:
     * Re-seats one raw shared-pointer lane onto the beat payload's owner. The
     * raw pointer is copied unconditionally; the control block is only swapped
     * when it actually changes, taking the new reference before dropping the
     * old one so a self-assignment cannot free what it is about to keep.
     */
    template <typename TLane, typename TSource>
    void ReseatSharedLane(boost::SharedPtrRaw<TLane>& lane, const boost::SharedPtrRaw<TSource>& source)
    {
      lane.px = source.px;
      if (lane.pi == source.pi) {
        return;
      }

      if (source.pi != nullptr) {
        source.pi->add_ref_copy();
      }
      boost::detail::sp_counted_base* const previous = lane.pi;
      lane.pi = source.pi;
      if (previous != nullptr) {
        previous->release();
      }
    }

    /**
     * Address: 0x00895214 -> FUN_007530C0 (inside FUN_00894530)
     *
     * What it does:
     * Replaces the session's scratch run with the beat payload's, one element
     * at a time. Each element owns a small inline buffer, so the run cannot be
     * copied wholesale - the binary's vector assignment reaches the same
     * per-element copy lane.
     */
    void AssignSyncInlineVectors(msvc8::vector<SyncInlineVector>& destination, const msvc8::vector<SyncInlineVector>& source)
    {
      destination.resize(source.size());

      auto destinationIt = destination.begin();
      for (const SyncInlineVector& run : source) {
        destinationIt->clear();
        destinationIt->Reserve(run.size());
        for (const std::int32_t value : run) {
          destinationIt->push_back(value);
        }
        ++destinationIt;
      }
    }

    [[nodiscard]] SSelectionSetUserEntity::Index OpenLiveWeakSetCursor(SSelectionSetUserEntity& set)
    {
      SSelectionNodeUserEntity* firstLive = nullptr;
      (void)SSelectionSetUserEntity::find(&set, set.mHead->mLeft, &firstLive);
      return SSelectionSetUserEntity::Index{&set, firstLive};
    }
  } // namespace

  /**
   * Address: 0x007F6390 (FUN_007F6390, Moho::CWldSession::GetTickDebugCanvas)
   *
   * IDA signature:
   * boost::shared_ptr_CDebugCanvas *__usercall Moho::CWldSession::GetTickDebugCanvas(
   *   boost::shared_ptr_CDebugCanvas *result, Moho::CWldSession *this);
   *
   * What it does:
   * Returns a retained copy of `mDebugCanvas` (+0x0414/+0x0418) - the tick
   * debug canvas `DoBeat` re-seats every beat from `beat.mTickDebugCanvas`.
   */
  boost::SharedPtrRaw<CDebugCanvas> CWldSession::GetTickDebugCanvas() const
  {
    return mDebugCanvas.clone_retained();
  }

  /**
   * Address: 0x007F63C0 (FUN_007F63C0, Moho::CWldSession::GetBeatDebugCanvas)
   *
   * IDA signature:
   * boost::shared_ptr_CDebugCanvas *__usercall Moho::CWldSession::GetBeatDebugCanvas(
   *   boost::shared_ptr_CDebugCanvas *result, Moho::CWldSession *this);
   *
   * What it does:
   * Returns a retained copy of `mBeatDebugCanvas` (+0x041C/+0x0420).
   */
  boost::SharedPtrRaw<CDebugCanvas> CWldSession::GetBeatDebugCanvas() const
  {
    return mBeatDebugCanvas.clone_retained();
  }

  /**
   * Address: 0x00894530 (FUN_00894530,
   * ?DoBeat@CWldSession@Moho@@QAEXV?$auto_ptr@USSyncData@Moho@@@std@@@Z)
   *
   * IDA signature:
   * void __stdcall Moho::CWldSession::DoBeat(Moho::CWldSession *this, std::auto_ptr<SSyncData> sdata);
   *
   * What it does:
   * Applies one sim beat to the client world, in the packet's own lane order.
   * This is the sole consumer of the driver's sync queue - without it the queue
   * fills, the issue thread stops issuing, and the game clock never advances.
   */
  void CWldSession::DoBeat(msvc8::auto_ptr<SSyncData> syncData)
  {
    const CTimeBarSection beatSection("Sync");

    RCamManager* const cameraManager = CAM_GetManager();
    CameraImpl* const worldCamera = cameraManager->GetCamera("WorldCamera");
    IWldTerrainRes* const terrainRes = mWldMap->mTerrainRes;

    const SSyncData& beat = *syncData;

    mGameTick = beat.mCurTick;
    mLastBeatWasTick = beat.mAdvanced;

    // A focus-army change moves the listener, and the outgoing selection belongs
    // to an army we may no longer be allowed to see - so it is dropped wholesale.
    if (beat.mFocusArmy != FocusArmy) {
      FocusArmy = beat.mFocusArmy;
      USER_GetSound()->SetListenerArmy(ArmyAtIndexOrNull(userArmies, FocusArmy));

      ScopedLocalSelectionSet clearedSelection;
      SetSelection(clearedSelection.get());
    }

    USER_GetSound()->UpdateSoundRequests(beat.mAudioRequests);

    if (beat.mAdvanced) {
      sWorldParticles.AdvancementBeat();
    }
    if (beat.mParticleBuffer) {
      sWorldParticles.AddParticles(*static_cast<const SParticleBuffer*>(beat.mParticleBuffer.get()));
    }

    auto* const decalManager = static_cast<CDecalManager*>(terrainRes->GetDecalManager());
    decalManager->AddDecals(beat.mAddDecals);
    decalManager->RemoveDecals(beat.mRemoveDecals);
    decalManager->ProcessRemovals(beat.mCurTick);

    // Camera shakes reach every live camera, not just the world one.
    {
      const msvc8::vector<CameraImpl*> allCameras = CAM_GetAllRCamCameras();
      for (const SCamShakeParams& shake : beat.mCamShakeParams) {
        for (CameraImpl* const camera : allCameras) {
          if (camera != nullptr) {
            camera->CameraShake(shake);
          }
        }
      }
    }

    if (worldCamera != nullptr) {
      terrainRes->UpdateWaveSystem(worldCamera->CameraGetView(), worldCamera->CameraGetTargetZoom(), mGameTick);
    }

    for (const gpg::Rect2i& playableRect : beat.mPlayableRectUpdates) {
      terrainRes->NotifyMapChange(playableRect);
    }

    // A new army grid means new armies; each lands in its own index slot, and
    // the listener is re-seated afterwards because the focus army may now exist.
    if (!beat.mNewGrids.empty()) {
      for (const SSTIArmyConstantData& armyConstantData : beat.mNewGrids) {
        UserArmy* const army = new UserArmy(this, armyConstantData);
        userArmies[static_cast<std::size_t>(army->mArmyIndex)] = army;
      }
      USER_GetSound()->SetListenerArmy(ArmyAtIndexOrNull(userArmies, FocusArmy));
    }

    // Army updates are positional: the Nth record belongs to the Nth army.
    {
      std::size_t armyIndex = 0;
      for (const SSTIArmyVariableData& armyUpdate : beat.mArmyUpdates) {
        (void)AssignArmyVariableData(armyUpdate, &userArmies[armyIndex]->mVarDat);
        ++armyIndex;
      }
    }

    for (const SCreateEntityParams& createParams : beat.mNewEntities) {
      AddEntity(new UserEntity(*this, createParams));
    }

    for (const SCreateUnitParams& createParams : beat.mNewUnits) {
      AddEntity(new UserUnit(this, createParams));
    }

    for (const SSTICommandConstantData& commandConstantData : beat.mPublishedCommandDescriptors) {
      (void)FindOrCreateCommandIssueHelper(*mCommandManager, commandConstantData, 0u, 0);
    }

    for (const SUnitVariableUpdateEntry& unitUpdate : beat.mUnitUpdates) {
      auto* const unit = static_cast<UserUnit*>(LookupEntityId(unitUpdate.mEntityId));
      unit->UpdateUnitData(unitUpdate.mVariableData, unitUpdate.mReconFlags);
    }

    for (const SEntityVariableUpdateEntry& entityUpdate : beat.mEntityUpdates) {
      LookupEntityId(entityUpdate.mEntityId)->UpdateEntityData(entityUpdate.mVariableData);
    }

    // Erase means "the sim is done with this entity but the client may still be
    // animating it": drop it from the id map and park it in the orphan set.
    for (const EntId erasedId : beat.mEraseIds) {
      OrphanEntity(LookupEntityId(erasedId));
    }

    for (const SEntityPoseUpdateEntry& poseUpdate : beat.mPoseUpdates) {
      UserEntity* const entity = LookupEntityId(poseUpdate.mEntityId);
      if (entity == nullptr) {
        gpg::Logf("CWldSession::DoBeat() unknown entity id (0x%08x) supplied in a pose update.", poseUpdate.mEntityId);
        continue;
      }
      entity->SetPose(poseUpdate.mPose);
    }

    // Delete means gone for good.
    for (const EntId deletedId : beat.mDeleteIds) {
      UserEntity* const entity = LookupEntityId(deletedId);
      RemoveEntity(entity);
      delete entity;
    }

    for (const SSyncPublishedCommandPacket& commandPacket : beat.mPublishedCommandPackets) {
      UserCommandIssueHelper* const helper = FindCommandIssueHelper(*mCommandManager, commandPacket.commandId);
      helper->mVariableData = commandPacket.variableData;
      helper->mVariableDataDirty = 1u;
    }

    for (const CmdId removedCommandId : beat.mPendingCommandEventRemovals) {
      delete FindCommandIssueHelper(*mCommandManager, removedCommandId);
    }

    DeleteCommandIssueHelpers(*mCommandManager, beat.mPendingReleasedCommandIds);

    // The command graph only gets marked here; the mesh rebuild it implies runs
    // back in `SessionFrame`.
    if (const boost::SharedPtrRaw<UICommandGraph> commandGraph = GetCommandGraph(false); commandGraph.px != nullptr) {
      commandGraph.px->MarkDirty();
    }

    if (worldCamera != nullptr) {
      for (const SCamFollowParams& follow : beat.mFollowCameras) {
        worldCamera->CameraFollow(follow);
      }
    }

    // Hand the sim's Lua payload to the UI: last beat's table becomes
    // `PreviousSync`, this beat's stream becomes `Sync`, then `OnSync()` runs.
    {
      const LuaPlus::LuaObject previousSync = SCR_Copy(mState->GetGlobal("Sync"), mState);
      mState->GetGlobals().SetObject("PreviousSync", previousSync);

      // The binary takes the stream by reference and never checks it, because
      // its `Sim::Sync` always publishes one. Ours is still a partial lift that
      // leaves `mStream` null, so the deserialize is skipped until it does -
      // otherwise every beat faults in `BinaryReader::Read`.
      if (beat.mStream != nullptr) {
        gpg::BinaryReader syncReader(beat.mStream);
        LuaPlus::LuaObject currentSync;
        currentSync.SCR_FromByteStream(currentSync, mState, &syncReader);
        mState->GetGlobals().SetObject("Sync", currentSync);
      }
    }
    (void)SCR_LuaDoString("OnSync()", mState);

    mSessionPauseStateA = static_cast<std::uint8_t>(beat.mPausedBy != -1);
    ReseatSharedLane(mDebugCanvas, beat.mTickDebugCanvas);
    ReseatSharedLane(mBeatDebugCanvas, beat.mBeatDebugCanvas);
    ren_FogOfWar = beat.mFogOfWar;
    terrainRes->SyncTerrain(beat.mTerrainUpdate.px);
    ReseatSharedLane(mSimResources, beat.mSimResources);
    AssignSyncInlineVectors(mSyncInlineVectors, beat.mInlineScratchVectors);

    for (const msvc8::string& printLine : beat.mPrintField) {
      CON_Printf("%s", printLine.c_str());
    }

    if (!beat.mDesyncs.empty()) {
      msvc8::vector<msvc8::string> desyncArmyNames(beat.mDesyncs.size());

      std::size_t desyncIndex = 0;
      for (const SDesyncInfo& desync : beat.mDesyncs) {
        desyncArmyNames[desyncIndex].assign(
          cmdSources[static_cast<std::size_t>(desync.army)].mName, 0, msvc8::string::npos
        );
        GPGNET_ReportDesync(desync.beat, desync.army, desync.hash2.ToString(), desync.hash1.ToString());
        ++desyncIndex;
      }

      UI_ShowDesyncDialog(mGameTick, desyncArmyNames);
    }

    if (beat.mGameOver && IsGameOver == 0u) {
      IsGameOver = 1u;
      UI_NoteGameOver();
      if (CFG_GetArgOption("/exitongameover", 0u, nullptr)) {
        wxTheApp->ExitMainLoop();
      }
    }

    if (mPendingSaveData) {
      ApplyPendingSaveData();
    }

    // Every registered unit gets its beat. The stat is what the profiler reads
    // as "how much work is one beat", so it is published even for an empty list.
    {
      // Heap-backed on purpose. `Collect` takes the vector by its
      // `gpg::fastvector<T>` base, and the base's grow path frees `start_`
      // unconditionally - it has no `originalVec_` word to test against. Hand
      // it an inline `FastVectorN` and the first push past the inline capacity
      // calls `delete[]` on the inline buffer, which here would be a stack
      // address. The binary gets away with an inline lane because its collect
      // family is templated on the concrete vector type, so the grow helper it
      // emits (sub_505BA0) reads `originalVec_` at +0x0C and skips the free.
      // Until that template is restored, the base-typed API must be handed a
      // vector that really does own its storage.
      gpg::fastvector<UserEntity*> tickers;
      auto* const spatialDb = static_cast<SpatialDB_MeshInstance*>(GetEntitySpatialDbStorage());
      (void)spatialDb->Collect(tickers, ENTITYTYPE_Unit);

      const auto tickerCount = static_cast<std::int32_t>(tickers.size());
      if (sEngineStat_UserSync_SessionTick_NumTickers == nullptr) {
        sEngineStat_UserSync_SessionTick_NumTickers =
          GetEngineStats()->GetItem("UserSync_SessionTick_NumTickers", true);
        (void)sEngineStat_UserSync_SessionTick_NumTickers->Release(0);
      }
      (void)sEngineStat_UserSync_SessionTick_NumTickers->SetInt(&tickerCount);

      for (std::int32_t i = 0; i < tickerCount; ++i) {
        tickers[static_cast<std::size_t>(i)]->Tick(beat.mCurBeat);
      }
    }

    // Both weak-set drains prune as they go. The orphan walk steps the cursor
    // before it calls out, because `OrphanUpdate` can unlink the entity it was
    // just handed; the visibility walk steps after, because `UpdateVisibility`
    // leaves the set alone.
    {
      auto* const runtimeView = reinterpret_cast<CWldSessionOrphanRuntimeView*>(this);

      SSelectionSetUserEntity& orphanSet = runtimeView->mPendingOrphanSet;
      for (auto cursor = OpenLiveWeakSetCursor(orphanSet); cursor.mNode != orphanSet.mHead;) {
        UserEntity* const entity = DecodeSelectionIndexOwner(&cursor);
        (void)cursor.Next();
        if (entity != nullptr) {
          entity->OrphanUpdate();
        }
      }

      SSelectionSetUserEntity& vizSet =
        reinterpret_cast<CWldSessionVizUpdateRuntimeView*>(this)->mVizUpdateSet;
      for (auto cursor = OpenLiveWeakSetCursor(vizSet); cursor.mNode != vizSet.mHead;) {
        if (UserEntity* const entity = DecodeSelectionIndexOwner(&cursor); entity != nullptr) {
          entity->UpdateVisibility();
        }
        (void)cursor.Next();
      }
    }

    AdvanceCommandIssueHelpersToBeat(*mCommandManager, beat.mCurBeat);

    if (mRequestingPauseState != 0u && beat.mCurBeat - mPauseRequester >= 0) {
      mRequestingPauseState = 0u;
    }

    CheckForNecessaryUIRefresh();

    if (IUIManager* const uiManager = UI_GetManager(); uiManager != nullptr) {
      (void)uiManager->DoBeat();
    }

    if (!beat.mSubmitArmyStats.empty()) {
      GPGNET_SubmitArmyStats(beat.mSubmitArmyStats);
    }

    if (dbg_Metronome && USER_GetSound() != nullptr) {
      USER_GetSound()->Play(msvc8::string("Tick", 4u), msvc8::string("TestBank", 8u));
    }
  }

  /**
   * Address: 0x00895B40 (FUN_00895B40, ?SessionFrame@CWldSession@Moho@@QAEXM@Z)
   */
  void CWldSession::SessionFrame(const float deltaSeconds)
  {
    static_cast<RRuleGameRules*>(mRules)->UpdateLuaState(mState);

    ISTIDriver* const simDriver = SIM_GetActiveDriver();

    // Interpolation between ticks. Running with the wind means "do not
    // interpolate, just consume beats", so the fraction is pinned at a whole
    // tick and the drain below never waits for the clock.
    if (mLastBeatWasTick == 0 || wld_RunWithTheWind) {
      mTimeSinceLastTick = 1.0f;
    } else {
      mTimeSinceLastTick += WLD_GetSimRate() * deltaSeconds * 10.0f;
    }

    CFormation::UpdateOrientation(AccessCursorInfo(*this).mMouseWorldPos, mCurFormation);

    const std::int32_t tickAtFrameStart = mGameTick;
    const std::int32_t targetTick = mGameTick + static_cast<std::int32_t>(std::floor(mTimeSinceLastTick));

    // Drain the driver's sync queue. Bounded at 100 beats so a burst after a
    // stall cannot make one frame arbitrarily long.
    std::int32_t beatsApplied = 0;
    for (; beatsApplied < 100; ++beatsApplied) {
      if (mReplayIsPaused) {
        // A paused replay still applies beats until it lands on a tick.
        if (mLastBeatWasTick != 0) {
          break;
        }
      } else if (mGameTick >= targetTick && !wld_RunWithTheWind) {
        break;
      }

      if (!simDriver->HasSyncData()) {
        break;
      }

      SSyncData* packet = nullptr;
      simDriver->GetSyncData(packet);
      DoBeat(msvc8::auto_ptr<SSyncData>(packet));
    }

    if (sEngineStat_Sync_Count == nullptr) {
      sEngineStat_Sync_Count = GetEngineStats()->GetItem("Sync_Count", true);
      (void)sEngineStat_Sync_Count->Release(0);
    }
    (void)sEngineStat_Sync_Count->SetInt(&beatsApplied);

    // Whatever the drain consumed comes back off the interpolation fraction, so
    // the render clock does not run ahead of the sim clock.
    if (!wld_RunWithTheWind) {
      const float remainder = mTimeSinceLastTick - static_cast<float>(mGameTick - tickAtFrameStart);
      mTimeSinceLastTick = std::max(0.0f, std::min(remainder, 1.0f));
    }

    if (const boost::SharedPtrRaw<UICommandGraph> commandGraph = GetCommandGraph(false); commandGraph.px != nullptr) {
      commandGraph.px->CreateMeshes();
    }

    // 0x00409AC0 - the binary names this `CTaskStage::DoFrame`; it is the same
    // body the rest of the tree already calls `UserFrame`.
    mCurThread->UserFrame();
  }

  /**
   * Address: 0x00896000 (FUN_00896000, ?GetSelectionUnits@CWldSession@Moho@@QBEXAAV?$WeakSet@VUserUnit@Moho@@@2@@Z)
   */
  void CWldSession::GetSelectionUnits(msvc8::vector<UserUnit*>& outUnits) const
  {
    outUnits.clear();

    const SSelectionNodeUserEntity* const head = mSelection.mHead;
    if (!head) {
      return;
    }

    for (const SSelectionNodeUserEntity* node = head->mLeft; node && node != head; node = NextTreeNode(node)) {
      UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
      if (!entity) {
        continue;
      }

      UserUnit* const userUnit = entity->IsUserUnit();
      if (!userUnit) {
        continue;
      }

      if (std::find(outUnits.begin(), outUnits.end(), userUnit) == outUnits.end()) {
        outUnits.push_back(userUnit);
      }
    }
  }

  /**
   * Address: 0x00896000 (FUN_00896000, ?GetSelectionUnits@CWldSession@Moho@@QBEXAAV?$WeakSet@VUserUnit@Moho@@@2@@Z)
   *
   * What it does:
   * Inserts every live selected `UserUnit` into `outUnits` through
   * `WeakSet<UserUnit>::Add`, walking the selection with the shared
   * tombstone-pruning `find`/`Iterator_inc` pair.
   *
   * The walk prunes tombstoned nodes out of the tree as it goes, which is why
   * the shipped `QBE` (const) member mutates the selection: the const_cast
   * below reproduces that exactly rather than papering over it.
   */
  void CWldSession::GetSelectionUnits(WeakUnitSetUserUnit& outUnits) const
  {
    SSelectionSetUserEntity& selection = const_cast<SSelectionSetUserEntity&>(mSelection);

    SSelectionNodeUserEntity* const head = selection.mHead;
    if (head == nullptr) {
      return;
    }

    SSelectionNodeUserEntity* node = head->mLeft;
    node = SSelectionSetUserEntity::find(&selection, node, &node);

    while (node != head) {
      if (UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt); entity != nullptr) {
        if (UserUnit* const unit = entity->IsUserUnit(); unit != nullptr) {
          WeakUnitSetUserUnit::AddResult added{};
          (void)WeakUnitSetUserUnit::Add(&added, &outUnits, unit);
        }
      }

      SSelectionSetUserEntity::Iterator_inc(&node);
      node = SSelectionSetUserEntity::find(&selection, node, &node);
    }
  }

  /**
   * Address: 0x00896090 (FUN_00896090, ?GetValidAttackingUnits@CWldSession@Moho@@QBEXAAV?$WeakSet@VUserUnit@Moho@@@2@@Z)
   *
   * What it does:
   * Walks selected units and keeps only those that can attack the currently
   * hovered entity.
   */
  void CWldSession::GetValidAttackingUnits(msvc8::vector<UserUnit*>& outUnits) const
  {
    outUnits.clear();

    const UserEntity* const hoveredTarget = this->GetHoveredUserEntity();
    const SSelectionNodeUserEntity* const head = mSelection.mHead;
    if (!head) {
      return;
    }

    for (const SSelectionNodeUserEntity* node = head->mLeft; node && node != head; node = NextTreeNode(node)) {
      UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt);
      if (!entity) {
        continue;
      }

      UserUnit* const userUnit = entity->IsUserUnit();
      if (!userUnit) {
        continue;
      }

      if (userUnit->CanAttackTarget(hoveredTarget, true)) {
        AppendUnitUnique(outUnits, userUnit);
      }
    }
  }

  /**
   * Address: 0x008B0C80 (FUN_008B0C80)
   * Mangled: ?ISSUE_IncreaseCommandCount@Moho@@YAXPAVUserCommand@1@H@Z
   *
   * IDA signature:
   * void __cdecl Moho::ISSUE_IncreaseCommandCount(Moho::UserCommand* helper, int count);
   *
   * What it does:
   * Re-issues one factory-build command `count` extra times. Early-outs unless the
   * helper's resolved command type is `UNITCOMMAND_BuildFactory`. Reconstructs a
   * `SSTICommandIssueData` carrying the helper's constant command index and target
   * blueprint, decodes the helper's cached cursor-entity weak-set into live
   * `UserUnit*` lanes with a tombstone-pruning tree walk, then calls `ISSUE_Command`
   * once per requested count (the command payload is passed by value each call).
   */
  void ISSUE_IncreaseCommandCount(UserCommandIssueHelper* const helper, const int count)
  {
    // Gate: only factory-build commands are re-issued this way (asm 0x008B0CA2).
    if (ResolveCommandIssueHelperCommandType(*helper) != EUnitCommandType::UNITCOMMAND_BuildFactory) {
      return;
    }

    // Rebuild the issue payload from the helper's constant command descriptor: seed
    // an empty payload, then stamp BuildFactory + the command index (+0x04) and the
    // target blueprint pointer (+0x20) straight from the constant data.
    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_None);
    commandIssueData.mCommandType = EUnitCommandType::UNITCOMMAND_BuildFactory;
    commandIssueData.mIndex = helper->mConstantData.cmd;
    commandIssueData.mBlueprint = reinterpret_cast<RUnitBlueprint*>(helper->mConstantData.blueprint);

    // Collect the helper's cached cursor entities as raw UserUnit* lanes (the
    // increase path pushes every decoded entity unconditionally, no IsUserUnit
    // filter). The set is rebuilt-if-dirty by the UserUnit-side bridge.
    gpg::fastvector<UserUnit*> selectedUnits{};
    SSelectionSetUserEntity* const cursorEntities = ResolveCommandIssueCursorEntities(*helper);
    if (cursorEntities->mSize > 0u) {
      selectedUnits.reserve(cursorEntities->mSize);
    }

    SSelectionNodeUserEntity* node = nullptr;
    cursorEntities->PruneTombstonesAndFindLive(&node, cursorEntities->mHead->mLeft);
    while (node != cursorEntities->mHead) {
      if (UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt)) {
        selectedUnits.push_back(reinterpret_cast<UserUnit*>(entity));
      }
      node = NextTreeNode(node);
      cursorEntities->PruneTombstonesAndFindLive(&node, node);
    }

    // Issue the reconstructed factory-build command once per requested count;
    // clearQueue is always false here (asm push ebx==0 at 0x008B0E12).
    for (int remaining = count; remaining > 0; --remaining) {
      ISSUE_Command(selectedUnits, commandIssueData, false);
    }
  }

  // ---------------------------------------------------------------------
  // The ISSUE_FactoryCommand / ISSUE_RemoveLastCommand /
  // ISSUE_RemoveCommandFromUnitQueue family. Both of the binary callers this
  // family exists for are now recovered and call into it by name:
  //   - Moho::SCommandModeData::HandleEvent (0x0081FCD0) is defined further
  //     down this file and calls the `WeakSet<UserEntity>` overload of
  //     ISSUE_RemoveLastCommand from its RULEUCC_Attack arm;
  //   - Moho::CUIWorldView::HandleEvent (0x008704B0, moho/ui/UiRuntimeTypes.cpp)
  //     calls ISSUE_RemoveCommandFromUnitQueue from its shift+ctrl
  //     right-button-release arm, through the declaration in CWldSession.h.
  // ---------------------------------------------------------------------

  /**
   * Address: 0x008B5B50 (FUN_008B5B50, struct_CommandManager::NextCmdId)
   *
   * Recovered in Sim.cpp as a file-scope helper (no header declaration, so
   * it cannot be called from this translation unit as written - same
   * cross-TU gap as `func_OnCommandDragEnd`/moho/ui/CommandDragger.cpp).
   * Declared here to document the real call `ISSUE_FactoryCommand` makes.
   * Allocates one next command low-id from the manager's id-pool (released
   * set first, then sequential cursor), packs the active source byte into
   * the high byte, and writes the result to `outCommandId` (also returned).
   */
  [[nodiscard]] std::uint32_t* AllocatePackedCommandIdFromManager(
    CommandManager* commandManager, std::uint32_t* outCommandId
  ) noexcept;

  /**
   * Address: 0x008B00A0 (FUN_008B00A0, func_DecodeEntIdSet)
   *
   * Recovered in Sim.cpp as a file-scope helper - same cross-TU gap as
   * `AllocatePackedCommandIdFromManager` above. Declared here to document
   * the real call `ISSUE_FactoryCommand` makes: builds an entity-id set from
   * a list of selected user units.
   */
  void func_DecodeEntIdSet(BVSet<EntId, EntIdUniverse>& out, const gpg::fastvector<UserUnit*>& units);

  /**
   * Address: 0x008B0730 (FUN_008B0730,
   * ?ISSUE_FactoryCommand@Moho@@YAXABV?$fastvector@PAVUserUnit@Moho@@@gpg@@USSTICommandIssueData@1@_N@Z)
   *
   * IDA note: the decompiler flags this function's own local-variable
   * allocation as failed ("the output may be wrong!"), so its pseudocode is
   * lower-confidence than usual. The structure below is cross-checked
   * against the already-recovered sibling `ISSUE_Command(const
   * gpg::fastvector<UserUnit*>&, SSTICommandIssueData, bool)` (Sim.cpp),
   * which shares the same no-rush gate, id-allocation, and per-unit queue
   * bookkeeping shape almost verbatim - factory commands go through
   * `GetFactoryCommandQueue()`/`IssueFactoryCommand` instead of the plain
   * command queue/`IssueCommand`. One low-confidence spot: the binary's own
   * `struct_UserUnitManager::add` call appears to pass `arg8.mIndex` as its
   * 4th argument rather than `clearQueue` - given the "variable allocation
   * failed" warning and that `UserUnitManagerAdd`'s public contract
   * (UserUnit.h) is `(manager, helper, cmdId, clearFlag)`, this recovery
   * trusts the established public signature (`clearQueue`) over the
   * uncertain decompiler artifact; flagged here for a follow-up asm-level
   * re-check before this lands.
   *
   * What it does:
   * Client/UI-side factory-command issue keystone over an explicit
   * `UserUnit*` list (factories): allocates a command id, runs the no-rush
   * gate against the resolved target, dispatches to the sim driver's
   * `IssueFactoryCommand`, publishes/reuses the command-issue helper, and
   * enqueues it into each unit's *factory* command queue (capped at 500
   * queued entries unless `clearQueue` forces a reset).
   */
  void ISSUE_FactoryCommand(
    const gpg::fastvector<UserUnit*>& units, SSTICommandIssueData commandIssueData, const bool clearQueue
  )
  {
    CWldSession* const session = WLD_GetActiveSession();
    CommandManager* const commandManager = session->mCommandManager;
    STIMap* const playableMap = reinterpret_cast<STIMap*>(session->mWldMap->mTerrainRes->mPlayableRectSource);

    std::uint32_t packedCommandId = 0u;
    commandIssueData.nextCommandId =
      static_cast<std::int32_t>(*AllocatePackedCommandIdFromManager(commandManager, &packedCommandId));
    if ((static_cast<std::uint32_t>(commandIssueData.nextCommandId) & 0xFF000000u) == 0xFF000000u) {
      return; // id-pool exhausted for this command source; nothing to issue.
    }

    // No-rush / playability gate - identical shape to ISSUE_Command's own
    // gate (Sim.cpp) and Moho::ISSUE_SetCommandTarget's (Sim.cpp).
    if (commandIssueData.mTarget.mType != EAiTargetType::AITARGET_None) {
      constexpr float kInvalidLane = std::numeric_limits<float>::quiet_NaN();
      Wm3::Vec3f targetPoint{kInvalidLane, kInvalidLane, kInvalidLane};

      if (commandIssueData.mTarget.mType == EAiTargetType::AITARGET_Entity) {
        if (UserEntity* const targetEntity = session->LookupEntityId(static_cast<EntId>(commandIssueData.mTarget.mEnt))) {
          targetPoint = targetEntity->mVariableData.mCurTransform.pos_;
        }
      } else {
        targetPoint = commandIssueData.mTarget.mPos;
      }

      const std::int32_t focusArmyIndex = session->FocusArmy;
      if (IsValidVector3f(targetPoint) && focusArmyIndex >= 0 &&
          session->userArmies[static_cast<std::size_t>(focusArmyIndex)] != nullptr) {
        const UserArmy* const focusArmy = session->GetFocusArmy();
        const bool insidePlayableArea =
          focusArmy->mVarDat.mUseWholeMap != 0u || playableMap == nullptr || playableMap->IsPlayable(targetPoint);

        if (!insidePlayableArea) {
          return;
        }
        if (focusArmy->mVarDat.mNoRushTimer > 0) {
          const float deltaX = (focusArmy->mVarDat.mArmyStart.x + focusArmy->mVarDat.mNoRushOffset.x) - targetPoint.x;
          const float deltaZ = (focusArmy->mVarDat.mArmyStart.y + focusArmy->mVarDat.mNoRushOffset.y) - targetPoint.z;
          const float noRushDistance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
          if (noRushDistance > focusArmy->mVarDat.mNoRushRadius) {
            return;
          }
        }
      }
    }

    BVSet<EntId, EntIdUniverse> issuedEntitySet{};
    func_DecodeEntIdSet(issuedEntitySet, units);
    if (ISTIDriver* const simDriver = SIM_GetActiveDriver()) {
      simDriver->IssueFactoryCommand(issuedEntitySet, commandIssueData, clearQueue);
    }

    SSTICommandConstantData commandConstantData{};
    InitializePublishedCommandDescriptorFromIssueData(&commandConstantData, &commandIssueData);

    const CmdId commandId = static_cast<CmdId>(commandIssueData.nextCommandId);
    UserCommandIssueHelper* const commandHelper =
      FindOrCreateCommandIssueHelper(*commandManager, commandConstantData, 1u, commandId);
    commandHelper->mVariableData = SSTICommandVariableData(commandIssueData);
    commandHelper->mVariableDataDirty = 1u;

    for (UserUnit* const unit : units) {
      UserCommandQueue* const factoryQueue = unit->GetFactoryCommandQueue();
      if (factoryQueue == nullptr) {
        continue;
      }

      if (GetUserUnitManagerQueueSize(factoryQueue) <= 500) {
        if (clearQueue) {
          ResetUserUnitManagerState(factoryQueue, commandId);
        }
        UserUnitManagerAdd(factoryQueue, commandHelper, commandId, clearQueue);
      } else if (clearQueue) {
        ResetUserUnitManagerState(factoryQueue, commandId);
        UserUnitManagerAdd(factoryQueue, commandHelper, commandId, clearQueue);
      }
    }

    UI_OnCommandIssued(units, commandIssueData, clearQueue);
    session->DirtyCommandGraph();
  }

  /**
   * Address: 0x008B0B30 (FUN_008B0B30,
   * ?ISSUE_FactoryCommand@Moho@@YAXABV?$WeakSet@VUserEntity@Moho@@@1@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Converts one selected weak-set of user entities into live `UserUnit*`
   * lanes (inline-buffered fastvector, capacity pre-reserved from the set
   * size) and forwards to the explicit-unit `ISSUE_FactoryCommand`
   * overload, which takes the command payload by value (copy-constructed on
   * the stack here). Identical shape to `ISSUE_Command`'s own weak-set
   * overload (CWldSession.cpp).
   */
  void ISSUE_FactoryCommand(
    const SSelectionSetUserEntity& entities, const SSTICommandIssueData& commandIssueData, const bool clearQueue
  )
  {
    gpg::fastvector_n<UserUnit*, 2> selectedUnits{};
    const std::int32_t entityCount = entities.size();
    if (entityCount > 0) {
      selectedUnits.reserve(static_cast<std::size_t>(entityCount));
    }

    SSelectionSetUserEntity* const mutableEntities = const_cast<SSelectionSetUserEntity*>(&entities);
    SSelectionNodeUserEntity* node = nullptr;
    node = SSelectionSetUserEntity::find(mutableEntities, mutableEntities->mHead->mLeft, &node);
    while (node != mutableEntities->mHead) {
      UserEntity* const selectedEntity = DecodeSelectedUserEntity(node->mEnt);
      UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
      if (selectedUnit != nullptr) {
        selectedUnits.push_back(selectedUnit);
      }

      SSelectionSetUserEntity::Iterator_inc(&node);
      node = SSelectionSetUserEntity::find(mutableEntities, node, &node);
    }

    ISSUE_FactoryCommand(selectedUnits, commandIssueData, clearQueue);
  }

  /**
   * Address: 0x008B1270 (FUN_008B1270,
   * ?ISSUE_RemoveLastCommand@Moho@@YAXABV?$fastvector@PAVUserUnit@Moho@@@gpg@@@Z)
   *
   * IDA signature:
   * void __cdecl Moho::ISSUE_RemoveLastCommand(gpg::fastvector<Moho::UserUnit *> const &);
   *
   * What it does:
   * For each unit in `units`: resolves its command queue's most-recently
   * queued command helper (backward null-skip scan via
   * `GetUserUnitManagerLastQueuedHelper`), skipping units with no queue or
   * no queued helper at all. For each match: tells the active sim driver
   * to remove that command from the unit's server-side queue (by CmdId +
   * EntId), then records the removal locally via
   * `RecordUnitManagerCommandHelperRemoval` (UserUnit.h) - see that
   * declaration's doc comment for the `unitCount` tag-value oddity both
   * call sites here share. Finally marks the session's UI command graph
   * dirty so the graph overlay redraws.
   *
   * Invocation: sole caller is the `WeakSet<UserEntity>` overload of
   * `Moho::ISSUE_RemoveLastCommand` (FUN_008B1390, below), which calls it by
   * name a few lines down; that overload is in turn called by
   * `Moho::SCommandModeData::HandleEvent` (FUN_0081FCD0, recovered in this
   * file) from its `RULEUCC_Attack` arm.
   */
  void ISSUE_RemoveLastCommand(const gpg::fastvector<UserUnit*>& units)
  {
    const std::int32_t unitCount = static_cast<std::int32_t>(units.Size());

    for (UserUnit* const unit : units) {
      if (unit == nullptr) {
        continue;
      }

      UserCommandQueue* const manager = unit->GetCommandQueue();
      UserCommandIssueHelper* const lastHelper = GetUserUnitManagerLastQueuedHelper(manager);
      if (lastHelper == nullptr) {
        continue;
      }

      const EntId entityId = unit->mParams.mEntityId;
      if (ISTIDriver* const simDriver = SIM_GetActiveDriver(); simDriver != nullptr) {
        (void)simDriver->RemoveCommandFromUnitQueue(lastHelper->mConstantData.cmd, entityId);
      }

      RecordUnitManagerCommandHelperRemoval(lastHelper, manager, unitCount);
    }

    if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
      session->DirtyCommandGraph();
    }
  }

  /**
   * Address: 0x008B1390 (FUN_008B1390,
   * ?ISSUE_RemoveLastCommand@Moho@@YAXABV?$WeakSet@VUserEntity@Moho@@@1@@Z)
   *
   * IDA signature:
   * void __usercall Moho::ISSUE_RemoveLastCommand(Moho::WeakSet_UserEntity *a1@<ebx>);
   *
   * What it does:
   * Collects every live `UserUnit` in `entities` into a
   * `gpg::fastvector<UserUnit*>` (reserving up front for the weak-set's
   * live size) and forwards to the `gpg::fastvector<UserUnit*>` overload
   * of `ISSUE_RemoveLastCommand` (FUN_008B1270, above).
   *
   * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
   * (FUN_0081FCD0, recovered in this file), from the `RULEUCC_Attack` arm
   * at 0x0081FDB9 when the event replaces a command the same drag issued.
   */
  void ISSUE_RemoveLastCommand(SSelectionSetUserEntity& entities)
  {
    gpg::fastvector<UserUnit*> units{};
    units.reserve(static_cast<std::size_t>(entities.size()));

    if (SSelectionNodeUserEntity* const head = entities.mHead; head != nullptr) {
      SSelectionNodeUserEntity* node = head->mLeft;
      node = SSelectionSetUserEntity::find(&entities, node, &node);

      while (node != head) {
        if (UserEntity* const entity = DecodeSelectedUserEntity(node->mEnt); entity != nullptr) {
          if (UserUnit* const unit = entity->IsUserUnit(); unit != nullptr) {
            units.push_back(unit);
          }
        }

        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&entities, node, &node);
      }
    }

    ISSUE_RemoveLastCommand(units);
  }

  /**
   * Address: 0x008B1220 (FUN_008B1220)
   * Mangled: ?ISSUE_RemoveCommandFromUnitQueue@Moho@@YAXPAVUserCommand@1@PAVUserUnit@1@@Z
   *
   * IDA signature:
   * void __usercall Moho::ISSUE_RemoveCommandFromUnitQueue(
   *     Moho::UserCommand *command@<ebx>, Moho::UserUnit *unit@<esi>);
   *
   * What it does:
   * Removes exactly one queued command from exactly one unit. Null-tolerant on
   * both arguments (0x008B1223 / 0x008B1228). Tells the active sim driver to
   * drop `command`'s constant command id from `unit`'s server-side queue
   * (`ISTIDriver` vtable +0x80, 0x008B123C-0x008B1247), then records the local
   * removal against the unit's own command queue.
   *
   * Two details differ from the `ISSUE_RemoveLastCommand` sibling above and are
   * preserved verbatim:
   *   - the driver pointer is dereferenced unguarded (0x008B1232 loads the
   *     global and immediately reads its vptr); the sibling's null check is a
   *     property of that function, not of this one;
   *   - the tag handed to `RecordUnitManagerCommandHelperRemoval` is the `CmdId`
   *     the driver call returned through its sret slot (read back at
   *     0x008B1249 and pushed at 0x008B124F), not a unit count. The push
   *     happens *before* `GetCommandQueue` is dispatched (0x008B1255), so the
   *     evaluation order below matches the binary's.
   *
   * Invocation: sole call site in the image is `Moho::CUIWorldView::HandleEvent`
   * (0x008704B0) at 0x00871082, inside the shift+ctrl right-button-release loop
   * that strips the hovered command from every unit under the cursor. That
   * caller is recovered in moho/ui/UiRuntimeTypes.cpp and calls this by name.
   */
  void ISSUE_RemoveCommandFromUnitQueue(UserCommandIssueHelper* const command, UserUnit* const unit)
  {
    if (command == nullptr || unit == nullptr) {
      return;
    }

    const CmdId removedCommandId =
      SIM_GetActiveDriver()->RemoveCommandFromUnitQueue(command->mConstantData.cmd, unit->mParams.mEntityId);

    UserCommandQueue* const manager = unit->GetCommandQueue();
    RecordUnitManagerCommandHelperRemoval(command, manager, removedCommandId);
  }

  /**
   * Address: 0x008B4300 (FUN_008B4300, sub_8B4300)
   *
   * What it does:
   * Header-visible bridge over `IsCandidateExcludedByCachedRelation` (the
   * anonymous-namespace body earlier in this file), so callers outside this
   * translation unit can run the command-graph relation gate without the
   * anonymous runtime-view type leaking into a header.
   *
   * Invocation: `Moho::CUIWorldView::HandleEvent` (0x008704B0) calls it at
   * 0x008706C6 while scanning the selection for a participant of the hovered
   * command.
   */
  bool IsCommandCandidateExcludedByCachedRelation(
    UserCommandIssueHelper& command,
    UserUnit* const candidateUnit
  ) noexcept
  {
    auto& anchorHistory = reinterpret_cast<CommandGraphAnchorHistoryRuntimeView&>(command);
    return IsCandidateExcludedByCachedRelation(anchorHistory, candidateUnit);
  }

  /**
   * Address: 0x0081DD00 (FUN_0081DD00, sub_81DD00)
   *
   * What it does:
   * Header-visible bridge over `CanRestartMoveCommandAsPatrol` (the
   * anonymous-namespace body earlier in this file). Both parameter types are
   * already public, so this only lifts the linkage.
   *
   * Invocation: `Moho::CUIWorldView::HandleEvent` (0x008704B0) calls it at
   * 0x008707FC to gate the "convert moves into patrol" cursor banner; the
   * in-file caller `SCommandModeData::HandleEvent` keeps calling the
   * anonymous-namespace body directly.
   */
  bool CanRestartSelectionMoveCommandAsPatrol(
    SSelectionSetUserEntity& selection,
    UserCommandIssueHelper* const helper
  )
  {
    return CanRestartMoveCommandAsPatrol(selection, helper);
  }

  namespace
  {
    /// The `EntId` sentinel every ground-targeted command payload carries
    /// (`mov [target+4], 0F0000000h` at every ground-target site in
    /// `SCommandModeData::HandleEvent`).
    constexpr std::uint32_t kGroundTargetEntityId = 0xF0000000u;

    /// Cursor-banner lifetime shared by both banners this dispatcher raises
    /// (`flt_E4F718`, pushed at 0x0081FEC6 and 0x008207FC).
    constexpr float kCursorBannerSeconds = 3.0f;
    /// ARGB red (0x0081FED2).
    constexpr std::uint32_t kCoordinatedAttackBannerColor = 0xFFFF0000u;
    /// ARGB green (0x0082080B).
    constexpr std::uint32_t kPatrolInitiatedBannerColor = 0xFF00FF00u;

    /**
     * A `CmdId` packs the issuing command source into its high byte, and the
     * `(MouseInfo, modifiers)` command-mode constructor (0x0081CEA0) seeds
     * `mIsDragged` with an all-ones id. `HandleEvent` therefore tests only the
     * source byte for the "this drag is not editing a live command" sentinel
     * (0x0081FEA6 and 0x0082078E), not the whole word.
     */
    [[nodiscard]] bool HasDraggedCommand(const CommandModeData& commandMode) noexcept
    {
      constexpr std::uint32_t kCommandSourceMask = 0xFF000000u;
      return (static_cast<std::uint32_t>(commandMode.mIsDragged) & kCommandSourceMask) != kCommandSourceMask;
    }

    /// `SCommandModeData::mModifiers` bit lanes, unpacked in one block at
    /// 0x0081FD00-0x0081FD24 before the mode switch runs.
    enum ECommandModeModifier : std::int32_t
    {
      /// Append to the existing command queue instead of replacing it.
      COMMODMOD_Queue = 0x1,
      /// Force the formation ("form") variant of the issued command.
      COMMODMOD_Formation = 0x2,
      /// Turn a plain move order into an aggressive-move order.
      COMMODMOD_AttackMove = 0x4,
    };

    /**
     * The drag snapshot stores the cursor in screen space as a plain
     * `Wm3::Vector2f`; the cursor-banner API names the same two floats
     * `SMauiMousePos` (the binary just hands `&mMouseScreenPos` over in `ecx`
     * at 0x0081FEDA / 0x00820813).
     */
    [[nodiscard]] SMauiMousePos ToMauiMousePos(const Wm3::Vector2f& screenPos) noexcept
    {
      return SMauiMousePos{screenPos.x, screenPos.y};
    }

    void SetEntityTarget(SSTICommandIssueData& data, const UserEntity& target) noexcept
    {
      data.mTarget.mType = EAiTargetType::AITARGET_Entity;
      data.mTarget.mEntityId = static_cast<std::uint32_t>(target.mParams.mEntityId);
      data.mTarget.mPos = Wm3::Vec3f(0.0f, 0.0f, 0.0f);
    }

    void SetGroundTarget(SSTICommandIssueData& data, const Wm3::Vector3f& worldPos) noexcept
    {
      data.mTarget.mType = EAiTargetType::AITARGET_Ground;
      data.mTarget.mEntityId = kGroundTargetEntityId;
      data.mTarget.mPos = worldPos;
    }

    /**
     * Copies the drag formation's chosen script index, heading quaternion and
     * spacing scale into the payload's formation lanes - the same
     * `unk38`/`mOri`/`unk4C` triple `CPlatoon`'s own Form* command builders
     * fill (CPlatoon.cpp).
     */
    void ApplyFormationLanes(SSTICommandIssueData& data, const CFormation& formation) noexcept
    {
      data.unk38 = formation.mBestFormation;
      data.mOri = formation.mDirection;
      data.unk4C = formation.mDirectionScale;
    }

    /// The drag formation has settled on a usable script and stopped ticking.
    [[nodiscard]] bool IsFormationSettled(const CFormation& formation) noexcept
    {
      return formation.mReady && formation.mTimeLeft == 0.0f;
    }

    /// Issues `commandType` at the hovered entity for the whole selection.
    void IssueOrderAtEntity(
      SSelectionSetUserEntity& selection,
      const EUnitCommandType commandType,
      const UserEntity& target,
      const bool clearQueue
    )
    {
      SSTICommandIssueData commandData(commandType);
      SetEntityTarget(commandData, target);
      ISSUE_Command(selection, commandData, clearQueue);
    }

    /// Issues `commandType` at a world position for the whole selection.
    void IssueOrderAtGround(
      SSelectionSetUserEntity& selection,
      const EUnitCommandType commandType,
      const Wm3::Vector3f& worldPos,
      const bool clearQueue
    )
    {
      SSTICommandIssueData commandData(commandType);
      SetGroundTarget(commandData, worldPos);
      ISSUE_Command(selection, commandData, clearQueue);
    }

    /**
     * The "snap the group anchor to the terrain, then re-issue at the drag
     * position" tail both the `RULEUCC_Patrol` and `RULEUCC_Ferry` arms run
     * when their anchor resolver reports the group is not already doing this
     * exact thing. The second issue always passes `clearQueue == false` so it
     * appends behind the first.
     */
    template <typename TIssueFn>
    void IssueAnchoredThenDragPosition(
      SSTICommandIssueData& commandData,
      const CWldSession& session,
      const Wm3::Vector3f& groupAnchor,
      const Wm3::Vector3f& dragWorldPos,
      const bool clearQueue,
      TIssueFn&& issue
    )
    {
      const float anchorSurface = session.GetSTIMap()->GetSurface(groupAnchor);
      SetGroundTarget(commandData, Wm3::Vector3f(groupAnchor.x, anchorSurface, groupAnchor.z));
      issue(commandData, clearQueue);

      SetGroundTarget(commandData, dragWorldPos);
      issue(commandData, false);
    }

    /**
     * Address: 0x0081FF17-0x0082012A (the `RULEUCC_Attack` no-hover arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Splits the selection into units eligible for an attack-move
     * (mobile + `FIRESTATE_ReturnFire`) and everything else, then issues an
     * AggressiveMove at the drag position to the first group and a plain
     * ground Attack to the second.
     */
    void IssueAttackMoveToGround(
      CWldSession& session,
      SSelectionSetUserEntity& selection,
      const Wm3::Vector3f& dragWorldPos,
      const bool formationModifier,
      const bool clearQueue
    )
    {
      ScopedLocalSelectionSet otherGuard{};
      ScopedLocalSelectionSet aggressiveMoveGuard{};
      SSelectionSetUserEntity& otherUnits = otherGuard.get();
      SSelectionSetUserEntity& aggressiveMoveUnits = aggressiveMoveGuard.get();
      SplitSelectionForAggressiveMove(selection, aggressiveMoveUnits, otherUnits);

      if (!aggressiveMoveUnits.IsEmptyFromHeadFind()) {
        const CFormation& formation = *session.mCurFormation;
        SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_AggressiveMove);
        ApplyFormationLanes(commandData, formation);

        Wm3::Vector3f destination = dragWorldPos;
        if (aggressiveMoveUnits.size() > 1 && formationModifier) {
          commandData.mCommandType = EUnitCommandType::UNITCOMMAND_FormAggressiveMove;
          destination = formation.mFinish;
        }

        SetGroundTarget(commandData, destination);
        ISSUE_Command(aggressiveMoveUnits, commandData, clearQueue);
      }

      if (!otherUnits.IsEmptyFromHeadFind()) {
        IssueOrderAtGround(otherUnits, EUnitCommandType::UNITCOMMAND_Attack, dragWorldPos, clearQueue);
      }
    }

    /**
     * Address: 0x00820661-0x00820B37 (the `RULEUCC_Move` arm of
     * `Moho::SCommandModeData::HandleEvent`, also entered from the
     * `RULEUCC_Guard` arm once the drag formation has settled)
     *
     * What it does:
     * Splits the selection into rally-point holders and everything else, then
     * issues Move/AggressiveMove (or their Form* variants once the drag
     * formation has settled and more than one unit is moving) to the plain
     * units and the same order as a *factory* command to the rally-point
     * holders. Before issuing the plain order it offers the "keep dragging an
     * already-queued move to convert it into a patrol" shortcut: when the drag
     * is editing a live command whose queue passes
     * `CanRestartMoveCommandAsPatrol`, the queued commands are restarted as
     * Patrol/FormPatrol in place, a cursor banner is shown and **nothing** is
     * issued - not even the rally-point half.
     */
    void IssueMoveOrderForDrag(
      CommandModeData& commandMode,
      CWldSession& session,
      SSelectionSetUserEntity& selection,
      const bool attackMoveModifier,
      const bool queueModifier,
      const bool clearQueue
    )
    {
      const Wm3::Vector3f& dragWorldPos = commandMode.mMouseDragStart.mMouseWorldPos;

      ScopedLocalSelectionSet rallyPointGuard{};
      ScopedLocalSelectionSet otherGuard{};
      SSelectionSetUserEntity& rallyPointUnits = rallyPointGuard.get();
      SSelectionSetUserEntity& otherUnits = otherGuard.get();
      SplitSelectionByRallyPointCategory(selection, rallyPointUnits, otherUnits);

      const EUnitCommandType moveCommand = attackMoveModifier
        ? EUnitCommandType::UNITCOMMAND_AggressiveMove
        : EUnitCommandType::UNITCOMMAND_Move;
      const EUnitCommandType formMoveCommand = attackMoveModifier
        ? EUnitCommandType::UNITCOMMAND_FormAggressiveMove
        : EUnitCommandType::UNITCOMMAND_FormMove;

      if (!otherUnits.IsEmptyFromHeadFind()) {
        const CFormation& formation = *session.mCurFormation;
        SSTICommandIssueData commandData(moveCommand);
        ApplyFormationLanes(commandData, formation);

        Wm3::Vector3f destination = dragWorldPos;
        // The stock build short-circuits this on the formation modifier the
        // way the RULEUCC_Attack arm above does; in the shipped FAF binary the
        // `jnz` that did so is NOP'd out at 0x0082074D-0x0082074E, leaving only
        // the settled-formation test. Recovered as shipped.
        if (otherUnits.size() > 1 && IsFormationSettled(formation)) {
          commandData.mCommandType = formMoveCommand;
          destination = formation.mFinish;
        }
        SetGroundTarget(commandData, destination);

        if (HasDraggedCommand(commandMode)) {
          UserCommandIssueHelper* const draggedCommand =
            FindCommandIssueHelperInSession(&session, commandMode.mIsDragged);
          if (CanRestartMoveCommandAsPatrol(selection, draggedCommand)) {
            RestartMoveCommandAsPatrol(selection, draggedCommand);
            UI_StartCursorText(
              ToMauiMousePos(commandMode.mMouseDragStart.mMouseScreenPos),
              "<LOC Engine0012>Patrol Initiated to location!",
              kPatrolInitiatedBannerColor,
              kCursorBannerSeconds,
              true
            );
            return;
          }
        }

        ISSUE_Command(otherUnits, commandData, clearQueue);
      }

      if (!rallyPointUnits.IsEmptyFromHeadFind()) {
        SSTICommandIssueData rallyCommandData(moveCommand);
        SetGroundTarget(rallyCommandData, dragWorldPos);
        ISSUE_FactoryCommand(rallyPointUnits, rallyCommandData, clearQueue);
      }
    }

    /**
     * Address: 0x008203CE-0x0082065C (the `RULEUCC_Guard` arm of
     * `Moho::SCommandModeData::HandleEvent`, reached once the drag formation
     * is *not* settled)
     *
     * What it does:
     * Guarding a hovered unit targets it directly, except when it is a
     * STRUCTURE: then the selection is split by the REBUILDER category so the
     * rebuilders are aimed at the structure's own world position (they can
     * rebuild the wreck in place) while everybody else guards the entity, both
     * halves carrying the structure's blueprint. With nothing hovered the
     * order becomes a guard-this-spot for every mobile selected entity, in
     * formation when more than one of them takes it.
     */
    void IssueGuardOrderForDrag(
      CommandModeData& commandMode,
      CWldSession& session,
      SSelectionSetUserEntity& selection,
      UserEntity* const hovered,
      const bool queueModifier,
      const bool clearQueue
    )
    {
      const Wm3::Vector3f& dragWorldPos = commandMode.mMouseDragStart.mMouseWorldPos;
      const EUnitCommandType guardCommand = UnitCommandCapToCommandType(commandMode.mCommandCaps);

      if (UserUnit* const hoveredUnit = hovered != nullptr ? hovered->IsUserUnit() : nullptr;
          hoveredUnit != nullptr) {
        const RUnitBlueprint* const hoveredBlueprint = GetIUnitBridge(hoveredUnit)->GetBlueprint();

        bool hoveredIsStructure = false;
        if (hoveredBlueprint != nullptr) {
          const msvc8::string structureCategory("STRUCTURE");
          hoveredIsStructure = hovered->IsInCategory(structureCategory);
        }

        if (!hoveredIsStructure) {
          IssueOrderAtEntity(selection, guardCommand, *hovered, clearQueue);
          return;
        }

        ScopedLocalSelectionSet nonRebuilderGuard{};
        ScopedLocalSelectionSet rebuilderGuard{};
        SSelectionSetUserEntity& nonRebuilders = nonRebuilderGuard.get();
        SSelectionSetUserEntity& rebuilders = rebuilderGuard.get();
        SplitSelectionByRebuilderCategory(selection, nonRebuilders, rebuilders);

        {
          SSTICommandIssueData commandData(guardCommand);
          SetEntityTarget(commandData, *hovered);
          commandData.mBlueprint = const_cast<RUnitBlueprint*>(hoveredBlueprint);
          ISSUE_Command(nonRebuilders, commandData, clearQueue);
        }
        {
          SSTICommandIssueData commandData(UnitCommandCapToCommandType(commandMode.mCommandCaps));
          SetGroundTarget(commandData, hovered->mVariableData.mCurTransform.pos_);
          commandData.mBlueprint = const_cast<RUnitBlueprint*>(hoveredBlueprint);
          ISSUE_Command(rebuilders, commandData, clearQueue);
        }
        return;
      }

      ScopedLocalUnitSet formationUnitsGuard{};
      ScopedLocalSelectionSet guardTargetGuard{};
      WeakUnitSetUserUnit& formationUnits = formationUnitsGuard.get();
      SSelectionSetUserEntity& guardTargets = guardTargetGuard.get();

      SSelectionSetUserEntity::FindResult cursor{};
      (void)selection.First(&cursor);
      SSelectionSetUserEntity::Index iterator{&selection, cursor.mRes};
      while (iterator.mNode != selection.mHead) {
        UserEntity* const entity = DecodeSelectionIndexOwner(&iterator);
        const REntityBlueprint* const blueprint = entity != nullptr ? entity->mParams.mBlueprint : nullptr;
        if (blueprint != nullptr && blueprint->IsMobile()) {
          SSelectionSetUserEntity::AddResult targetAdd{};
          (void)SSelectionSetUserEntity::Add(&targetAdd, &guardTargets, entity);

          if (UserUnit* const unit = entity->IsUserUnit(); unit != nullptr) {
            WeakUnitSetUserUnit::AddResult participantAdd{};
            (void)WeakUnitSetUserUnit::Add(&participantAdd, &formationUnits, unit);
          }
        }

        (void)iterator.Next();
      }

      CFormation& formation = *session.mCurFormation;
      if (guardTargets.size() > 1) {
        formation.ChooseFormation(dragWorldPos, formationUnits, queueModifier);
        if (formation.mBestFormation >= 0) {
          SSTICommandIssueData commandData(UnitCommandCapToCommandType(commandMode.mCommandCaps));
          SetGroundTarget(commandData, dragWorldPos);
          ApplyFormationLanes(commandData, formation);
          ISSUE_Command(guardTargets, commandData, clearQueue);
          formation.Reset();
        }
        return;
      }

      if (!guardTargets.IsEmptyFromHeadFind()) {
        IssueOrderAtGround(
          guardTargets, UnitCommandCapToCommandType(commandMode.mCommandCaps), dragWorldPos, clearQueue
        );
      }
    }

    /**
     * Address: 0x00820923-0x00820B37 (the `RULEUCC_Patrol` arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Splits the selection into rally-point holders and everybody else, picks
     * Patrol or FormPatrol (the latter only once the drag formation has
     * settled; otherwise a fresh formation is chosen from the selected units
     * around the hovered unit, or around the drag position when nothing is
     * hovered, and the whole arm is abandoned if no formation script fits),
     * then issues that command to both halves. Each half first asks
     * `ResolveGroupMoveAnchorOrDetectPatrol` whether the group is already
     * patrolling: if it is, the drag position is used as-is; if not, the
     * resolved group anchor is snapped to the terrain and issued first so the
     * patrol runs anchor -> drag position.
     */
    void IssuePatrolOrderForDrag(
      CommandModeData& commandMode,
      CWldSession& session,
      SSelectionSetUserEntity& selection,
      UserEntity* const hovered,
      const bool queueModifier,
      const bool clearQueue
    )
    {
      const Wm3::Vector3f& dragWorldPos = commandMode.mMouseDragStart.mMouseWorldPos;

      ScopedLocalSelectionSet rallyPointGuard{};
      ScopedLocalSelectionSet otherGuard{};
      SSelectionSetUserEntity& rallyPointUnits = rallyPointGuard.get();
      SSelectionSetUserEntity& otherUnits = otherGuard.get();
      SplitSelectionByRallyPointCategory(selection, rallyPointUnits, otherUnits);

      CFormation& formation = *session.mCurFormation;
      SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_Patrol);
      SetGroundTarget(commandData, dragWorldPos);

      if (selection.size() > 1) {
        if (IsFormationSettled(formation)) {
          commandData.mCommandType = EUnitCommandType::UNITCOMMAND_FormPatrol;
          ApplyFormationLanes(commandData, formation);
        } else {
          ScopedLocalUnitSet formationUnitsGuard{};
          WeakUnitSetUserUnit& formationUnits = formationUnitsGuard.get();

          SSelectionSetUserEntity::FindResult cursor{};
          (void)selection.First(&cursor);
          SSelectionSetUserEntity::Index iterator{&selection, cursor.mRes};
          while (iterator.mNode != selection.mHead) {
            UserEntity* const entity = DecodeSelectionIndexOwner(&iterator);
            if (UserUnit* const unit = entity != nullptr ? entity->IsUserUnit() : nullptr; unit != nullptr) {
              WeakUnitSetUserUnit::AddResult participantAdd{};
              (void)WeakUnitSetUserUnit::Add(&participantAdd, &formationUnits, unit);
            }

            (void)iterator.Next();
          }

          const Wm3::Vector3f& formationAnchor =
            hovered != nullptr ? hovered->mVariableData.mCurTransform.pos_ : dragWorldPos;
          formation.ChooseFormation(formationAnchor, formationUnits, queueModifier);
          if (formation.mBestFormation < 0) {
            return;
          }

          ApplyFormationLanes(commandData, formation);
          formation.Reset();
        }
      }

      if (!otherUnits.IsEmptyFromHeadFind()) {
        Wm3::Vector3f groupAnchor(0.0f, 0.0f, 0.0f);
        if (ResolveGroupMoveAnchorOrDetectPatrol(selection, groupAnchor, !queueModifier)) {
          ISSUE_Command(otherUnits, commandData, clearQueue);
        } else {
          IssueAnchoredThenDragPosition(
            commandData, session, groupAnchor, dragWorldPos, clearQueue,
            [&otherUnits](const SSTICommandIssueData& data, const bool clear) {
              ISSUE_Command(otherUnits, data, clear);
            }
          );
        }
      }

      if (!rallyPointUnits.IsEmptyFromHeadFind()) {
        Wm3::Vector3f groupAnchor(0.0f, 0.0f, 0.0f);
        if (ResolveGroupMoveAnchorOrDetectPatrol(selection, groupAnchor, !queueModifier)) {
          ISSUE_FactoryCommand(rallyPointUnits, commandData, clearQueue);
        } else {
          IssueAnchoredThenDragPosition(
            commandData, session, groupAnchor, dragWorldPos, clearQueue,
            [&rallyPointUnits](const SSTICommandIssueData& data, const bool clear) {
              ISSUE_FactoryCommand(rallyPointUnits, data, clear);
            }
          );
        }
      }
    }

    /**
     * Address: 0x008215FD-0x008217CA (the `RULEUCC_Ferry` arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Keeps only the air transports out of the selection and gives them a
     * ferry route. When every one of them is already ferrying, the drag
     * position is appended as-is; otherwise their averaged current route
     * anchor is snapped to the terrain and issued first so the ferry runs
     * anchor -> drag position. The land-unit half of the split is built (the
     * binary builds it too) but this arm never consumes it.
     */
    void IssueFerryOrderForDrag(
      CWldSession& session,
      SSelectionSetUserEntity& selection,
      const Wm3::Vector3f& dragWorldPos,
      const bool clearQueue
    )
    {
      ScopedLocalSelectionSet airTransportGuard{};
      ScopedLocalSelectionSet landUnitGuard{};
      SSelectionSetUserEntity& airTransports = airTransportGuard.get();
      SSelectionSetUserEntity& landUnits = landUnitGuard.get();
      SplitSelectionForFerryCommand(selection, airTransports, landUnits);

      if (airTransports.IsEmptyFromHeadFind()) {
        return;
      }

      SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_Ferry);
      SetGroundTarget(commandData, dragWorldPos);

      Wm3::Vector3f groupAnchor(0.0f, 0.0f, 0.0f);
      if (ResolveGroupFerryAnchorOrDetectFerry(airTransports, groupAnchor)) {
        ISSUE_Command(airTransports, commandData, clearQueue);
        return;
      }

      IssueAnchoredThenDragPosition(
        commandData, session, groupAnchor, dragWorldPos, clearQueue,
        [&airTransports](const SSTICommandIssueData& data, const bool clear) {
          ISSUE_Command(airTransports, data, clear);
        }
      );
    }

    /**
     * Address: 0x00821014-0x008215BC (the `RULEUCC_Transport` arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Four separate transport gestures, in the order the binary tests them:
     *   1. drop on a TELEPORTBEACON while a teleport-capable unit is selected
     *      -> unload onto the beacon;
     *   2. drop on a unit that itself has the CallTransport capability
     *      -> reverse-load into it;
     *   3. otherwise, when the session's extra-select list names specific
     *      units, unload exactly those at the drag position (as a plain Move
     *      when every one of them is a POD, since pods are not cargo);
     *   4. otherwise split the selection into air transports and land units:
     *      if either half is empty the whole selection is told to unload at
     *      the drag position, else the transports are folded into the land
     *      group and the group is given an AssistMove there.
     * Every path ends by re-applying the current selection, which is what
     * refreshes the extra-select overlay.
     */
    void IssueTransportOrderForDrag(
      CWldSession& session,
      SSelectionSetUserEntity& selection,
      UserEntity* const hovered,
      const Wm3::Vector3f& dragWorldPos,
      const bool clearQueue
    )
    {
      if (hovered != nullptr) {
        const msvc8::string teleportBeaconCategory("TELEPORTBEACON");
        if (hovered->IsInCategory(teleportBeaconCategory) && SelectionContainsTeleportationUnit(selection)) {
          IssueOrderAtEntity(
            selection, EUnitCommandType::UNITCOMMAND_TransportUnloadUnits, *hovered, clearQueue
          );
          return;
        }
      }

      if (UserUnit* const hoveredUnit = hovered != nullptr ? hovered->IsUserUnit() : nullptr;
          hoveredUnit != nullptr) {
        const std::uint32_t hoveredCaps = GetIUnitBridge(hoveredUnit)->GetAttributes().commandCapsMask;
        if ((hoveredCaps & static_cast<std::uint32_t>(RULEUCC_CallTransport)) != 0u) {
          IssueOrderAtEntity(
            selection, EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits, *hovered, clearQueue
          );
          return;
        }
      }

      ScopedCopiedSelectionSet extraSelectionGuard{};
      SSelectionSetUserEntity& extraSelection = extraSelectionGuard.get();
      extraSelection = session.GetExtraSelectList();

      if (!extraSelection.IsEmptyFromHeadFind()) {
        ScopedCopiedSelectionSet unloadGuard{};
        SSelectionSetUserEntity& unloadTargets = unloadGuard.get();
        (void)CopySelectionSetFromOther(&unloadTargets, &selection);

        bool onlyPods = true;
        SSelectionSetUserEntity::FindResult cursor{};
        (void)extraSelection.First(&cursor);
        SSelectionSetUserEntity::Index iterator{&extraSelection, cursor.mRes};
        while (iterator.mNode != extraSelection.mHead) {
          UserEntity* const entity = DecodeSelectionIndexOwner(&iterator);
          if (entity != nullptr && entity->mVariableData.mIsDead == 0u && entity->IsUserUnit() != nullptr) {
            SSelectionSetUserEntity::AddResult addResult{};
            (void)SSelectionSetUserEntity::Add(&addResult, &unloadTargets, entity);

            const msvc8::string podCategory("POD");
            if (!entity->IsInCategory(podCategory)) {
              onlyPods = false;
            }
          }

          (void)iterator.Next();
        }

        const EUnitCommandType unloadCommand = onlyPods
          ? EUnitCommandType::UNITCOMMAND_Move
          : EUnitCommandType::UNITCOMMAND_TransportUnloadSpecificUnits;
        IssueOrderAtGround(unloadTargets, unloadCommand, dragWorldPos, clearQueue);
      } else {
        ScopedLocalSelectionSet airTransportGuard{};
        ScopedLocalSelectionSet landUnitGuard{};
        SSelectionSetUserEntity& airTransports = airTransportGuard.get();
        SSelectionSetUserEntity& landUnits = landUnitGuard.get();
        SplitSelectionForFerryCommand(selection, airTransports, landUnits);

        if (airTransports.IsEmptyFromHeadFind() || landUnits.IsEmptyFromHeadFind()) {
          IssueOrderAtGround(
            selection, EUnitCommandType::UNITCOMMAND_TransportUnloadUnits, dragWorldPos, clearQueue
          );
        } else {
          SSelectionSetUserEntity::FindResult cursor{};
          (void)airTransports.First(&cursor);
          SSelectionSetUserEntity::Index iterator{&airTransports, cursor.mRes};
          while (iterator.mNode != airTransports.mHead) {
            UserEntity* const entity = DecodeSelectionIndexOwner(&iterator);
            if (entity != nullptr && entity->mVariableData.mIsDead == 0u && entity->IsUserUnit() != nullptr) {
              SSelectionSetUserEntity::AddResult addResult{};
              (void)SSelectionSetUserEntity::Add(&addResult, &landUnits, entity);
            }

            (void)iterator.Next();
          }

          IssueOrderAtGround(landUnits, EUnitCommandType::UNITCOMMAND_AssistMove, dragWorldPos, clearQueue);
        }
      }

      session.SetSelection(selection);
    }

    /**
     * Address: 0x00820E01-0x0082100F (the `RULEUCC_CallTransport` arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Tells the selection to load into the hovered transport, splitting the
     * rally-point holders off into a factory command as every other move-like
     * arm does. The hovered transport is added to whichever half is being
     * ordered unless it is a ferry beacon or an air staging platform - a
     * carrier overrides that and is always loaded along with its cargo.
     */
    void IssueCallTransportOrderForDrag(
      SSelectionSetUserEntity& selection,
      UserEntity& hovered,
      const bool clearQueue
    )
    {
      const bool hoveredIsAirStaging = hovered.IsInCategory(msvc8::string("AIRSTAGINGPLATFORM"));
      const bool hoveredIsCarrier = hovered.IsInCategory(msvc8::string("CARRIER"));
      const bool hoveredIsFerryBeacon = hovered.IsInCategory(msvc8::string("FERRYBEACON"));

      SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_TransportLoadUnits);
      SetEntityTarget(commandData, hovered);

      ScopedLocalSelectionSet rallyPointGuard{};
      ScopedLocalSelectionSet otherGuard{};
      SSelectionSetUserEntity& rallyPointUnits = rallyPointGuard.get();
      SSelectionSetUserEntity& otherUnits = otherGuard.get();
      SplitSelectionByRallyPointCategory(selection, rallyPointUnits, otherUnits);

      const bool loadHoveredTransportToo = (!hoveredIsFerryBeacon && !hoveredIsAirStaging) || hoveredIsCarrier;

      if (!otherUnits.IsEmptyFromHeadFind()) {
        if (loadHoveredTransportToo) {
          SSelectionSetUserEntity::AddResult addResult{};
          (void)SSelectionSetUserEntity::Add(&addResult, &otherUnits, &hovered);
        }
        ISSUE_Command(otherUnits, commandData, clearQueue);
      }

      if (!rallyPointUnits.IsEmptyFromHeadFind()) {
        if (loadHoveredTransportToo) {
          SSelectionSetUserEntity::AddResult addResult{};
          (void)SSelectionSetUserEntity::Add(&addResult, &rallyPointUnits, &hovered);
        }
        ISSUE_FactoryCommand(rallyPointUnits, commandData, clearQueue);
      }
    }

    /**
     * Address: 0x00821AC0-0x00821CFA (the `RULEUCC_Script` arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Hands the pending script command to
     * `/lua/user/UserScriptCommand.lua:VerifyScriptCommand` and, when the
     * script sets `UserValidated`, re-issues it to exactly the units the
     * script listed in `AuthorizedUnits`. The verified descriptor rides along
     * on the payload's Lua-object lane (minus `AuthorizedUnits`, which is
     * nilled out first so the sim never sees it).
     */
    void IssueScriptCommandForDrag(
      SSelectionSetUserEntity& selection,
      UserEntity* const hovered,
      const Wm3::Vector3f& dragWorldPos,
      const bool clearQueue
    )
    {
      SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_Script);
      if (hovered != nullptr) {
        SetEntityTarget(commandData, *hovered);
      } else {
        SetGroundTarget(commandData, dragWorldPos);
      }

      LuaPlus::LuaObject verifyResult = UI_VerifyScriptCommand(selection, commandData, clearQueue);
      if (!verifyResult["UserValidated"].GetBoolean()) {
        return;
      }

      commandData.mObject = verifyResult;
      LuaPlus::LuaState* const state = verifyResult.m_state;

      gpg::fastvector_n<UserUnit*, 1> authorizedUnits{};
      {
        // The binary lets the `operator[]` temporary die right after the
        // iterator is constructed (0x00821C2D) and keeps iterating the freed
        // slot; the table object is held for the whole walk here instead,
        // which is the same traversal without the dangling read.
        LuaPlus::LuaObject authorizedTable = verifyResult["AuthorizedUnits"];
        for (LuaPlus::LuaTableIterator entry(authorizedTable, 1); !entry.m_isDone; entry.Next()) {
          authorizedUnits.push_back(SCR_FromLua_UserUnit(entry.GetValue(), state));
        }
      }

      verifyResult.SetNil("AuthorizedUnits");
      ISSUE_Command(authorizedUnits, commandData, clearQueue);
    }

    /**
     * Address: 0x00821DEE-0x00821EA2 (the `COMMOD_Build`/`COMMOD_BuildAnchored`
     * arm of `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * While the session is previewing invalid build placements, validates the
     * drag spot (an anchored build additionally has to be inside the builder's
     * build radius). A legal spot - or a session that is not previewing at all
     * - just notifies the UI script layer that a command was issued; an
     * illegal one instead takes one build off an order this selection already
     * has queued on that same footprint, which is what makes dragging a
     * queued structure back onto itself cancel it.
     */
    void DispatchBuildCommandMode(CommandModeData& commandMode, CWldSession& session, const bool clearQueue)
    {
      SSelectionSetUserEntity& selection = session.mSelection;
      const Wm3::Vector3f& dragWorldPos = commandMode.mMouseDragStart.mMouseWorldPos;
      const auto* const buildBlueprint = static_cast<const RUnitBlueprint*>(commandMode.mBlueprint);

      if (session.mShowInvalidBuildPlacementPreview) {
        const SCoordsVec2 buildPosition{dragWorldPos.x, dragWorldPos.z};

        const bool withinBuildDistance = commandMode.mMode != COMMOD_BuildAnchored
          || USERUNIT_WithinBuildDistance(session, buildBlueprint, buildPosition);

        bool placeable = false;
        if (withinBuildDistance) {
          SOccupationResult occupation{};
          placeable = USERUNIT_CanBeBuiltAt(session, buildBlueprint, buildPosition, false, &occupation, nullptr);
        }

        if (!placeable) {
          if (UserCommandIssueHelper* const queuedOrder =
                FindColocatedQueuedBuildOrder(selection, dragWorldPos, buildBlueprint);
              queuedOrder != nullptr) {
            ISSUE_DecreaseCommandCount(queuedOrder, 1);
          }
          return;
        }
      }

      SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_None);
      UI_OnCommandIssued(selection, commandData, clearQueue);
    }

    /**
     * Address: 0x0081FD6D-0x00821CFA plus the shared tails (the `COMMOD_Order`
     * arm of `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * The command-capability switch: one arm per `ERuleBPUnitCommandCaps`
     * value the world view can put the cursor into. Everything that is not
     * called out below reduces to "issue this capability's command at the drag
     * position", and `RULEUCC_Invalid` is swallowed outright.
     */
    void DispatchOrderCommandMode(
      CommandModeData& commandMode,
      CWldSession& session,
      UserEntity* const hovered,
      const bool isDragUpdate,
      const bool formationModifier,
      const bool attackMoveModifier,
      const bool queueModifier,
      const bool clearQueue
    )
    {
      SSelectionSetUserEntity& selection = session.mSelection;
      const Wm3::Vector3f& dragWorldPos = commandMode.mMouseDragStart.mMouseWorldPos;

      switch (commandMode.mCommandCaps) {
        case RULEUCC_Move:
          IssueMoveOrderForDrag(commandMode, session, selection, attackMoveModifier, queueModifier, clearQueue);
          return;

        case RULEUCC_Attack: {
          // A drag that re-targets the order it already issued withdraws that
          // order first, so the queue never grows while the cursor moves.
          if (isDragUpdate) {
            ISSUE_RemoveLastCommand(selection);
          }

          if (hovered == nullptr) {
            IssueAttackMoveToGround(session, selection, dragWorldPos, formationModifier, clearQueue);
            return;
          }

          const CFormation& formation = *session.mCurFormation;
          SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_Attack);
          ApplyFormationLanes(commandData, formation);
          if (selection.size() > 1 && (formationModifier || IsFormationSettled(formation))) {
            commandData.mCommandType = EUnitCommandType::UNITCOMMAND_FormAttack;
          }
          SetEntityTarget(commandData, *hovered);

          // Several players attacking the same target with one drag get the
          // "coordinated attack" banner and share the dragged order's id.
          if (isDragUpdate && HasDraggedCommand(commandMode)
              && CanStartCoordinatedAttack(session, commandMode.mIsDragged)) {
            UI_StartCursorText(
              ToMauiMousePos(commandMode.mMouseDragStart.mMouseScreenPos),
              "<LOC Engine0011>Coordinated Attack!",
              kCoordinatedAttackBannerColor,
              kCursorBannerSeconds,
              true
            );
            commandData.unk04 = commandMode.mIsDragged;
          }

          ISSUE_Command(selection, commandData, clearQueue);
          return;
        }

        case RULEUCC_Guard:
          // A settled drag formation turns a guard gesture into a formation
          // move (0x0082013F-0x0082014F).
          if (IsFormationSettled(*session.mCurFormation)) {
            IssueMoveOrderForDrag(commandMode, session, selection, attackMoveModifier, queueModifier, clearQueue);
            return;
          }
          IssueGuardOrderForDrag(commandMode, session, selection, hovered, queueModifier, clearQueue);
          return;

        case RULEUCC_Patrol:
          IssuePatrolOrderForDrag(commandMode, session, selection, hovered, queueModifier, clearQueue);
          return;

        case RULEUCC_Ferry:
          IssueFerryOrderForDrag(session, selection, dragWorldPos, clearQueue);
          return;

        case RULEUCC_Transport:
          IssueTransportOrderForDrag(session, selection, hovered, dragWorldPos, clearQueue);
          return;

        case RULEUCC_CallTransport:
          if (hovered == nullptr) {
            return;
          }
          IssueCallTransportOrderForDrag(selection, *hovered, clearQueue);
          return;

        case RULEUCC_Script:
          IssueScriptCommandForDrag(selection, hovered, dragWorldPos, clearQueue);
          return;

        case RULEUCC_Reclaim: {
          if (hovered == nullptr) {
            return;
          }

          bool reclaimable = false;
          {
            const msvc8::string reclaimableCategory("RECLAIMABLE");
            reclaimable = hovered->IsInCategory(reclaimableCategory) || hovered->IsBeingBuilt();
          }
          if (!reclaimable) {
            return;
          }

          IssueOrderAtEntity(
            selection, UnitCommandCapToCommandType(commandMode.mCommandCaps), *hovered, clearQueue
          );
          return;
        }

        // Sacrifice is its own emitted block in the binary (0x008217CF) but the
        // same source shape as the repair/capture/overcharge group below.
        case RULEUCC_Sacrifice:
        case RULEUCC_Repair:
        case RULEUCC_Capture:
        case RULEUCC_Overcharge:
          if (hovered == nullptr) {
            return;
          }
          IssueOrderAtEntity(
            selection, UnitCommandCapToCommandType(commandMode.mCommandCaps), *hovered, clearQueue
          );
          return;

        case RULEUCC_Nuke:
        case RULEUCC_Tactical:
        case RULEUCC_SpecialAction:
          if (hovered != nullptr) {
            IssueOrderAtEntity(
              selection, UnitCommandCapToCommandType(commandMode.mCommandCaps), *hovered, clearQueue
            );
          } else {
            IssueOrderAtGround(
              selection, UnitCommandCapToCommandType(commandMode.mCommandCaps), dragWorldPos, clearQueue
            );
          }
          return;

        case RULEUCC_Invalid:
          return;

        default:
          IssueOrderAtGround(
            selection, UnitCommandCapToCommandType(commandMode.mCommandCaps), dragWorldPos, clearQueue
          );
          return;
      }
    }
  } // namespace

  /**
   * Address: 0x0081FCD0 (FUN_0081FCD0, Moho::SCommandModeData::HandleEvent)
   *
   * IDA signature:
   * void __thiscall Moho::SCommandModeData::HandleEvent(
   *     Moho::SCommandModeData *this, Moho::CWldSession *a2, char a3);
   *
   * What it does:
   * Turns one committed world-view mouse gesture into command traffic for the
   * session's current selection. The drag snapshot this object carries
   * (`mMouseDragStart`) supplies both the world position and the hovered
   * entity; `mModifiers` supplies the three keyboard modifier lanes; `mMode`
   * and `mCommandCaps` select the arm:
   *
   *   - `COMMOD_Order` -> `DispatchOrderCommandMode`, one arm per command
   *     capability (move / attack / guard / patrol / ferry / transport /
   *     call-transport / reclaim / sacrifice+repair+capture+overcharge /
   *     nuke+tactical+special-action / script), each of them documented on its
   *     own helper above;
   *   - `COMMOD_Build`, `COMMOD_BuildAnchored` -> `DispatchBuildCommandMode`,
   *     the build-placement validator;
   *   - `COMMOD_Ping` (and the unnamed mode 7 the binary's jump table routes
   *     to the same entry) -> just leave command mode;
   *   - `COMMOD_Move` and `COMMOD_Reclaim` are *not* handled here (the jump
   *     table sends them to the default arm): those modes are cursor states
   *     the world view resolves into a `COMMOD_Order` before committing.
   *
   * Every arm shares one derived flag: `clearQueue` is the inverse of the
   * queue modifier, so holding shift appends the new order instead of
   * replacing the queue.
   */
  void CommandModeData::HandleEvent(CWldSession& session, const bool isDragUpdate)
  {
    const bool queueModifier = (mModifiers & COMMODMOD_Queue) != 0;
    const bool formationModifier = (mModifiers & COMMODMOD_Formation) != 0;
    const bool attackMoveModifier = (mModifiers & COMMODMOD_AttackMove) != 0;
    const bool clearQueue = !queueModifier;

    UserEntity* const hovered = DecodeHoveredDragEntity(mMouseDragStart);

    switch (mMode) {
      case COMMOD_Order:
        DispatchOrderCommandMode(
          *this, session, hovered, isDragUpdate, formationModifier, attackMoveModifier, queueModifier, clearQueue
        );
        return;

      case COMMOD_Build:
      case COMMOD_BuildAnchored:
        DispatchBuildCommandMode(*this, session, clearQueue);
        return;

      case COMMOD_Ping:
      // The jump table at 0x00821F04 routes mode 7 to the same entry as
      // `COMMOD_Ping`; the recovered enum has no name for it.
      case static_cast<ECommandMode>(COMMOD_Ping + 1):
        UI_EndCommandMode();
        return;

      default:
        return;
    }
  }

  /**
   * Address: 0x0083E150 (FUN_0083E150, func_UserScriptCommandObj)

  /**
   * Address: 0x0083E150 (FUN_0083E150, func_UserScriptCommandObj)
   *
   * What it does:
   * Builds one Lua command-issue descriptor table (`Units`, `Blueprint`,
   * `Target`, optional `LuaParams`, `CommandType`, `Clear`) used by UI script
   * command callbacks.
   */
  LuaPlus::LuaObject* BuildUserScriptCommandObject(
    LuaPlus::LuaObject* const outCommandObject,
    LuaPlus::LuaState* const state,
    const gpg::fastvector<UserUnit*>& units,
    const SSTICommandIssueData& commandIssueData,
    const bool doClear
  )
  {
    if (outCommandObject == nullptr || state == nullptr) {
      return outCommandObject;
    }

    outCommandObject->AssignNewTable(state, 0, 0);

    LuaPlus::LuaObject unitsTable;
    unitsTable.AssignNewTable(state, 0, 0);
    std::int32_t unitIndex = 1;
    for (UserUnit* const unit : units) {
      if (unit == nullptr) {
        ++unitIndex;
        continue;
      }

      IUnit* const iunitBridge = GetIUnitBridge(unit);
      if (iunitBridge == nullptr) {
        ++unitIndex;
        continue;
      }

      const LuaPlus::LuaObject unitLuaObject = iunitBridge->GetLuaObject();
      unitsTable.SetObject(unitIndex, unitLuaObject);
      ++unitIndex;
    }
    outCommandObject->SetObject("Units", unitsTable);

    const char* blueprintId = "";
    if (commandIssueData.mBlueprint != nullptr) {
      blueprintId = commandIssueData.mBlueprint->mBlueprintId.c_str();
    }
    outCommandObject->SetString("Blueprint", blueprintId);

    LuaPlus::LuaObject targetTable;
    targetTable.AssignNewTable(state, 0, 0);

    ESTITargetType targetType = static_cast<ESTITargetType>(static_cast<std::int32_t>(commandIssueData.mTarget.mType));
    gpg::RRef targetTypeRef{};
    gpg::RRef_ESTITargetType(&targetTypeRef, &targetType);
    const msvc8::string targetTypeLexical = targetTypeRef.GetLexical();
    targetTable.SetString("Type", targetTypeLexical.c_str());

    if (commandIssueData.mTarget.mType == EAiTargetType::AITARGET_Entity) {
      const EntId targetEntityId = static_cast<EntId>(commandIssueData.mTarget.mEntityId);
      if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
        if (UserEntity* const targetEntity = session->LookupEntityId(targetEntityId); targetEntity != nullptr) {
          const msvc8::string entityIdLexical = gpg::STR_Printf("%d", static_cast<std::int32_t>(targetEntityId));
          targetTable.SetString("EntityId", entityIdLexical.c_str());

          const LuaPlus::LuaObject targetPositionObject =
            SCR_ToLua<Wm3::Vector3<float>>(state, targetEntity->mVariableData.mCurTransform.pos_);
          targetTable.SetObject("Position", targetPositionObject);
        }
      }
    } else {
      const LuaPlus::LuaObject targetPositionObject =
        SCR_ToLua<Wm3::Vector3<float>>(state, commandIssueData.mTarget.mPos);
      targetTable.SetObject("Position", targetPositionObject);
    }

    outCommandObject->SetObject("Target", targetTable);

    if (commandIssueData.mObject.m_state != nullptr) {
      const LuaPlus::LuaObject luaParams = SCR_Copy(commandIssueData.mObject, state);
      outCommandObject->SetObject("LuaParams", luaParams);
    }

    EUnitCommandType commandType = commandIssueData.mCommandType;
    gpg::RRef commandTypeRef{};
    gpg::RRef_EUnitCommandType(&commandTypeRef, &commandType);
    const msvc8::string commandTypeLexical = commandTypeRef.GetLexical();
    outCommandObject->SetString("CommandType", commandTypeLexical.c_str());
    outCommandObject->SetBoolean("Clear", doClear);
    return outCommandObject;
  }

  /**
   * Address: 0x0083E640 (FUN_0083E640,
   * ?UI_VerifyScriptCommand@Moho@@YA?AVLuaObject@LuaPlus@@ABV?$fastvector@PAVUserUnit@Moho@@@gpg@@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Builds one script command descriptor from explicit `UserUnit*` lanes,
   * calls `/lua/user/UserScriptCommand.lua:VerifyScriptCommand`, and returns
   * the Lua result object (or the command descriptor on callback failure).
   */
  LuaPlus::LuaObject UI_VerifyScriptCommand(
    const gpg::fastvector<UserUnit*>& units,
    const SSTICommandIssueData& commandIssueData,
    const bool doClear
  )
  {
    CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
    LuaPlus::LuaState* const state = (uiManager != nullptr) ? uiManager->mLuaState : nullptr;
    LuaPlus::LuaObject commandObject{};
    (void)BuildUserScriptCommandObject(&commandObject, state, units, commandIssueData, doClear);

    if (state == nullptr) {
      return commandObject;
    }

    LuaPlus::LuaObject commandModule = SCR_Import(state, "/lua/user/UserScriptCommand.lua");
    LuaPlus::LuaObject verifyScriptCommand = commandModule["VerifyScriptCommand"];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> verifyScriptCommandFn(verifyScriptCommand);
    try {
      return verifyScriptCommandFn.Call_Object_Obj(commandObject);
    } catch (const std::exception& exception) {
      gpg::Warnf(
        "Error running '/lua/user/UserScriptCommand.lua:VerifyScriptCommand': %s",
        exception.what() != nullptr ? exception.what() : "<unknown>"
      );
    } catch (...) {
      gpg::Warnf("Error running '/lua/user/UserScriptCommand.lua:VerifyScriptCommand': %s", "<unknown>");
    }

    return commandObject;
  }

  /**
   * Address: 0x0083E500 (FUN_0083E500,
   * ?UI_VerifyScriptCommand@Moho@@YA?AVLuaObject@LuaPlus@@ABV?$WeakSet@VUserEntity@Moho@@@1@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Converts one selected weak-set of user entities into live `UserUnit*`
   * lanes and forwards to the explicit-unit `UI_VerifyScriptCommand` overload.
   */
  LuaPlus::LuaObject UI_VerifyScriptCommand(
    const SSelectionSetUserEntity& entities,
    const SSTICommandIssueData& commandIssueData,
    const bool doClear
  )
  {
    gpg::fastvector_n<UserUnit*, 2> selectedUnits{};
    const std::int32_t entityCount = entities.size();
    if (entityCount > 0) {
      selectedUnits.reserve(static_cast<std::size_t>(entityCount));
    }

    SSelectionSetUserEntity* const mutableEntities = const_cast<SSelectionSetUserEntity*>(&entities);
    SSelectionNodeUserEntity* node = nullptr;
    node = SSelectionSetUserEntity::find(mutableEntities, mutableEntities->mHead->mLeft, &node);
    while (node != mutableEntities->mHead) {
      UserEntity* const selectedEntity = DecodeSelectedUserEntity(node->mEnt);
      UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
      if (selectedUnit != nullptr) {
        selectedUnits.push_back(selectedUnit);
      }

      SSelectionSetUserEntity::Iterator_inc(&node);
      node = SSelectionSetUserEntity::find(mutableEntities, node, &node);
    }

    return UI_VerifyScriptCommand(selectedUnits, commandIssueData, doClear);
  }

  /**
   * Address: 0x0083E770 (FUN_0083E770,
   * ?UI_OnCommandIssued@Moho@@YAXABV?$fastvector@PAVUserUnit@Moho@@@gpg@@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Builds one Lua command descriptor table from explicit `UserUnit*` lanes and
   * invokes `/lua/ui/game/commandmode.lua:OnCommandIssued`.
   */
  void UI_OnCommandIssued(
    const gpg::fastvector<UserUnit*>& units,
    const SSTICommandIssueData& commandIssueData,
    const bool doClear
  )
  {
    CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
    LuaPlus::LuaState* const state = (uiManager != nullptr) ? uiManager->mLuaState : nullptr;
    if (state == nullptr) {
      return;
    }

    LuaPlus::LuaObject commandObject{};
    (void)BuildUserScriptCommandObject(&commandObject, state, units, commandIssueData, doClear);

    LuaPlus::LuaObject commandModeModule = SCR_Import(state, "/lua/ui/game/commandmode.lua");
    LuaPlus::LuaObject onCommandIssued = commandModeModule["OnCommandIssued"];
    LuaPlus::LuaFunction callback(onCommandIssued);

    try {
      callback.Call_Object(commandObject);
    } catch (const std::exception& exception) {
      gpg::Warnf(
        "Error running '/lua/ui/game/commandmode.lua:OnCommandIssued': %s",
        exception.what() != nullptr ? exception.what() : "<unknown>"
      );
    } catch (...) {
      gpg::Warnf("Error running '/lua/ui/game/commandmode.lua:OnCommandIssued': %s", "<unknown>");
    }
  }

  /**
   * Address: 0x0083E870 (FUN_0083E870,
   * ?UI_OnCommandIssued@Moho@@YAXABV?$WeakSet@VUserEntity@Moho@@@1@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Converts one selected weak-set of user entities into live `UserUnit*`
   * lanes and forwards to the explicit-unit `UI_OnCommandIssued` overload.
   */
  void UI_OnCommandIssued(
    const SSelectionSetUserEntity& entities,
    const SSTICommandIssueData& commandIssueData,
    const bool doClear
  )
  {
    gpg::fastvector_n<UserUnit*, 2> selectedUnits{};
    const std::int32_t entityCount = entities.size();
    if (entityCount > 0) {
      selectedUnits.reserve(static_cast<std::size_t>(entityCount));
    }

    SSelectionSetUserEntity* const mutableEntities = const_cast<SSelectionSetUserEntity*>(&entities);
    SSelectionNodeUserEntity* node = nullptr;
    node = SSelectionSetUserEntity::find(mutableEntities, mutableEntities->mHead->mLeft, &node);
    while (node != mutableEntities->mHead) {
      UserEntity* const selectedEntity = DecodeSelectedUserEntity(node->mEnt);
      UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
      if (selectedUnit != nullptr) {
        selectedUnits.push_back(selectedUnit);
      }

      SSelectionSetUserEntity::Iterator_inc(&node);
      node = SSelectionSetUserEntity::find(mutableEntities, node, &node);
    }

    UI_OnCommandIssued(selectedUnits, commandIssueData, doClear);
  }

  /**
   * Address: 0x008B05E0 (FUN_008B05E0,
   * ?ISSUE_Command@Moho@@YAXABV?$WeakSet@VUserEntity@Moho@@@1@ABUSSTICommandIssueData@1@_N@Z)
   *
   * IDA signature:
   * void __usercall Moho::ISSUE_Command(WeakSet_UserEntity *entities@<ebx>,
   *     SSTICommandIssueData *data, BOOL clearQueue);
   *
   * What it does:
   * Converts one selected weak-set of user entities into live `UserUnit*` lanes
   * (inline-buffered fastvector, capacity pre-reserved from the set size) and
   * forwards to the explicit-unit `ISSUE_Command(fastvector)` overload, which
   * takes the command payload by value (copy-constructed on the stack here).
   */
  void ISSUE_Command(
    const SSelectionSetUserEntity& entities,
    const SSTICommandIssueData& commandIssueData,
    const bool clearQueue
  )
  {
    gpg::fastvector_n<UserUnit*, 2> selectedUnits{};
    const std::int32_t entityCount = entities.size();
    if (entityCount > 0) {
      selectedUnits.reserve(static_cast<std::size_t>(entityCount));
    }

    SSelectionSetUserEntity* const mutableEntities = const_cast<SSelectionSetUserEntity*>(&entities);
    SSelectionNodeUserEntity* node = nullptr;
    node = SSelectionSetUserEntity::find(mutableEntities, mutableEntities->mHead->mLeft, &node);
    while (node != mutableEntities->mHead) {
      UserEntity* const selectedEntity = DecodeSelectedUserEntity(node->mEnt);
      UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
      if (selectedUnit != nullptr) {
        selectedUnits.push_back(selectedUnit);
      }

      SSelectionSetUserEntity::Iterator_inc(&node);
      node = SSelectionSetUserEntity::find(mutableEntities, node, &node);
    }

    ISSUE_Command(selectedUnits, commandIssueData, clearQueue);
  }

  /**
   * Address: 0x00822270 (FUN_00822270, sub_822270)
   *
   * IDA signature:
   * Moho::WeakSet_UserUnit_FindResBool *__userpurge sub_822270@<eax>(
   *     Moho::WeakSet_UserUnit_FindResBool *result@<esi>,
   *     Moho::WeakSet_UserUnit *set,
   *     Moho::UserUnit *unit);
   *
   * What it does:
   * Inserts one unit key into a `WeakSet<UserUnit>` and returns the
   * `{iterator, inserted}` pair through the caller-supplied sret slot
   * (`[esi+0]=set`, `[esi+4]=node`, `[esi+8]=inserted`, 0x00822306..0x0082230C).
   *
   * The map insert is bracketed by an intrusive weak guard so the unit cannot
   * be destroyed out from under the tree while it rebalances: a stack
   * `WeakPtr<UserUnit>` is pushed onto the unit's weak-owner use-list before
   * the insert (0x008222A9-0x008222B3, reaching the `WeakObject` sub-object
   * with the same `+ 8` adjust `WeakSet<UserEntity>::Add` uses at 0x007AE1DA)
   * and spliced back out afterwards by walking the chain until the slot that
   * points at it is found (0x008222DF-0x008222F8). The splice also runs on the
   * throwing path, through the EH funclet at 0x00B94260 - which is why the
   * guard is expressed as an RAII object here.
   *
   * `unit` is reinterpreted rather than statically upcast because `UserUnit`
   * has no reconstructed definition in this tree yet; the binary itself does
   * no adjustment either - both `Add` emissions derive the `WeakObject`
   * sub-object from the raw element pointer with the identical `add eax, 8`,
   * which is only possible if `UserUnit`'s `UserEntity` sub-object sits at
   * offset zero.
   */
  WeakUnitSetUserUnit::AddResult* WeakUnitSetUserUnit::Add(
    AddResult* const outResult,
    WeakUnitSetUserUnit* const set,
    UserUnit* const unit
  )
  {
    outResult->mOwnerSet = set;
    outResult->mNode = (set != nullptr) ? set->mHead : nullptr;
    outResult->mWasInserted = 0u;

    UserEntity* const entity = reinterpret_cast<UserEntity*>(unit);
    ScopedSelectionOwnerLinkGuard ownerLinkGuard(entity);

    SelectionInsertFindResult insertResult{};
    (void)FindOrInsertSelectionNodeByUserEntity(&insertResult, set, entity);

    outResult->mNode = insertResult.node;
    outResult->mWasInserted = insertResult.inserted ? 1u : 0u;
    return outResult;
  }

  /**
   * Address: 0x00894280 (FUN_00894280, ?LookupEntityId@CWldSession@Moho@@QAEPAVUserEntity@2@VEntId@2@@Z)
   *
   * What it does:
   * Performs one ordered entity-id lookup in the world-session entity map and
   * returns the live `UserEntity*` when the key is present.
   */
  UserEntity* CWldSession::LookupEntityId(const EntId entityId)
  {
    SessionEntityMap& entityMap = GetSessionEntityMap(this);
    SessionEntityMapNode* const head = entityMap.mHead;
    SessionEntityMapNode* probe = head->mParent;
    const std::uint32_t key = static_cast<std::uint32_t>(entityId);

    while (probe != nullptr && probe != head && probe->mIsSentinel == 0u) {
      if (key < probe->mEntityId) {
        probe = probe->mLeft;
      } else if (probe->mEntityId < key) {
        probe = probe->mRight;
      } else {
        return probe->mEntity;
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x00896140 (FUN_00896140, ?SetSelection@CWldSession@Moho@@QAEXABV?$WeakSet@VUserEntity@Moho@@@2@@Z)
   *
   * What it does:
   * Replaces the active selection set from `selection`, broadcasts one
   * `{previous,current,added,removed}` selection-event payload, updates
   * max-selection bookkeeping, and refreshes sync-filter mask B when changed.
   */
  void CWldSession::SetSelection(const SSelectionSetUserEntity& selection)
  {
    SSelectionSetUserEntity addedEntities{};
    addedEntities.mAllocProxy = nullptr;
    addedEntities.mHead = AllocateWeakEntitySetHead();
    addedEntities.mSize = 0u;
    addedEntities.mSizeMirrorOrUnused = 0u;

    SSelectionSetUserEntity removedEntities{};
    removedEntities.mAllocProxy = nullptr;
    removedEntities.mHead = AllocateWeakEntitySetHead();
    removedEntities.mSize = 0u;
    removedEntities.mSizeMirrorOrUnused = 0u;

    bool selectionChanged = false;

    msvc8::vector<UserEntity*> nextSelectionEntities{};
    CollectSelectionEntities(selection, nextSelectionEntities);
    for (UserEntity* const entity : nextSelectionEntities) {
      if (entity == nullptr) {
        continue;
      }

      SSelectionSetUserEntity::FindResult found{};
      (void)FindSelectionNodeByEntityGuarded(&found, &mSelection, entity);
      if (found.mRes == mSelection.mHead) {
        selectionChanged = true;
        SSelectionSetUserEntity::AddResult addResult{};
        (void)SSelectionSetUserEntity::Add(&addResult, &addedEntities, entity);
      }
    }

    msvc8::vector<UserEntity*> currentSelectionEntities{};
    CollectSelectionEntities(mSelection, currentSelectionEntities);
    SSelectionSetUserEntity* const incomingSelection = const_cast<SSelectionSetUserEntity*>(&selection);
    for (UserEntity* const entity : currentSelectionEntities) {
      if (entity == nullptr || incomingSelection == nullptr) {
        continue;
      }

      SSelectionSetUserEntity::FindResult found{};
      (void)FindSelectionNodeByEntityGuarded(&found, incomingSelection, entity);
      if (found.mRes == incomingSelection->mHead) {
        selectionChanged = true;
        SSelectionSetUserEntity::AddResult addResult{};
        (void)SSelectionSetUserEntity::Add(&addResult, &removedEntities, entity);
      }
    }

    BroadcastSelectionEventListeners(
      SelectionEventHead(*this),
      SelectionEventLaneFromPointer(&mSelection),
      SelectionEventLaneFromPointer(incomingSelection),
      SelectionEventLaneFromPointer(&addedEntities),
      SelectionEventLaneFromPointer(&removedEntities)
    );

    if (&mSelection != incomingSelection && mSelection.mHead != nullptr && incomingSelection != nullptr &&
      incomingSelection->mHead != nullptr) {
      SSelectionNodeUserEntity* eraseCursor = mSelection.mHead->mLeft;
      (void)mSelection.EraseRange(&eraseCursor, mSelection.mHead->mLeft, mSelection.mHead);
      (void)CloneSelectionTreeFromStorage(&mSelection, incomingSelection);
    }

    reinterpret_cast<CWldSessionSelectionStatsRuntimeView*>(this)->maxSelectionSize = mSelection.size();

    if (selectionChanged) {
      if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
        SSyncFilterMaskBlock selectionMask{};
        BuildSelectionSyncMask(mSelection, selectionMask);
        activeDriver->SetSyncFilterMaskB(selectionMask);
      }

      UI_EndCommandMode();
    }

    (void)removedEntities.ReleaseStorage();
    (void)addedEntities.ReleaseStorage();
  }

  void CWldSession::SetSelectionUnits(const msvc8::vector<UserUnit*>& units)
  {
    SSelectionSetUserEntity nextSelection{};
    nextSelection.mAllocProxy = nullptr;
    nextSelection.mHead = AllocateWeakEntitySetHead();
    nextSelection.mSize = 0u;
    nextSelection.mSizeMirrorOrUnused = 0u;

    for (UserUnit* const unit : units) {
      if (unit == nullptr) {
        continue;
      }

      UserEntity* const entity = reinterpret_cast<UserEntity*>(unit);
      SSelectionSetUserEntity::AddResult addResult{};
      (void)SSelectionSetUserEntity::Add(&addResult, &nextSelection, entity);
    }

    SetSelection(nextSelection);
    (void)nextSelection.ReleaseStorage();
  }

  /**
   * Address: 0x00865830 (FUN_00865830, ?CanSelectUnit@CWldSession@Moho@@QBE_NPAVUserUnit@2@@Z)
   */
  bool CWldSession::CanSelectUnit(UserUnit* const unit) const
  {
    const UserEntity* const entity = reinterpret_cast<const UserEntity*>(unit);
    const bool selectableByArmy = entity != nullptr && entity->IsSelectable() && entity->mArmy == GetFocusUserArmy();
    return selectableByArmy || (UI_SelectAnything && this != nullptr && IsCheatsEnabled);
  }

  /**
   * Address: 0x00865920 (FUN_00865920, ?ReleaseDrag@CWldSession@Moho@@QAEXW4EMauiEventModifier@2@@Z)
   */
  void CWldSession::ReleaseDrag(const EMauiEventModifier modifiers)
  {
    constexpr std::uint32_t kShiftMask = static_cast<std::uint32_t>(MEM_Shift);
    constexpr std::uint32_t kCtrlMask = static_cast<std::uint32_t>(MEM_Ctrl);
    constexpr std::uint32_t kAltMask = static_cast<std::uint32_t>(MEM_Alt);
    constexpr std::uint32_t kShiftCtrlMask = kShiftMask | kCtrlMask;

    const std::uint32_t modifierBits = static_cast<std::uint32_t>(modifiers);
    msvc8::vector<UserUnit*> nextSelection{};

    UserEntity* const hoveredEntity = this->GetHoveredUserEntity();
    UserUnit* const hoveredUnit = hoveredEntity != nullptr ? hoveredEntity->IsUserUnit() : nullptr;

    if (ui_DebugAltClick && (modifierBits & kAltMask) != 0u && hoveredEntity != nullptr) {
      UserArmy* const hoveredArmy = hoveredEntity->mArmy;
      if (hoveredArmy != nullptr && hoveredArmy != GetFocusUserArmy()) {
        SetSelectionUnits(nextSelection);
        RequestFocusArmy(static_cast<int>(hoveredArmy->mArmyIndex));
        return;
      }
    }

    if (!CanSelectUnit(hoveredUnit)) {
      if ((modifierBits & kShiftCtrlMask) == 0u) {
        SetSelectionUnits(nextSelection);
      }
      return;
    }

    if ((modifierBits & kCtrlMask) != 0u) {
      msvc8::vector<UserUnit*> currentSelection{};
      GetSelectionUnits(currentSelection);

      const IUnit* const hoveredBridge = GetIUnitBridge(hoveredUnit);
      const RUnitBlueprint* const targetBlueprint = hoveredBridge != nullptr ? hoveredBridge->GetBlueprint() : nullptr;

      if ((modifierBits & kShiftMask) != 0u) {
        if (ContainsUnitPtr(currentSelection, hoveredUnit)) {
          for (UserUnit* const selectedUnit : currentSelection) {
            const IUnit* const selectedBridge = GetIUnitBridge(selectedUnit);
            if (selectedBridge == nullptr || selectedBridge->GetBlueprint() != targetBlueprint) {
              AppendUnitUnique(nextSelection, selectedUnit);
            }
          }

          SetSelectionUnits(nextSelection);
          return;
        }

        nextSelection = currentSelection;
      }

      msvc8::vector<UserUnit*> allSessionUnits{};
      CollectSessionUserUnits(this, allSessionUnits);
      const UserArmy* const focusArmy = GetFocusUserArmy();
      for (UserUnit* const sessionUnit : allSessionUnits) {
        if (sessionUnit == nullptr || sessionUnit->IsBeingBuilt()) {
          continue;
        }

        const IUnit* const sessionBridge = GetIUnitBridge(sessionUnit);
        if (sessionBridge == nullptr || sessionBridge->IsDead()) {
          continue;
        }

        const UserEntity* const sessionEntity = reinterpret_cast<const UserEntity*>(sessionUnit);
        if (sessionEntity == nullptr || sessionEntity->mArmy != focusArmy) {
          continue;
        }

        if (sessionBridge->GetBlueprint() != targetBlueprint) {
          continue;
        }

        AppendUnitUnique(nextSelection, sessionUnit);
      }

      SetSelectionUnits(nextSelection);
      return;
    }

    if ((modifierBits & kShiftMask) != 0u) {
      GetSelectionUnits(nextSelection);
      if (ContainsUnitPtr(nextSelection, hoveredUnit)) {
        RemoveUnitIfPresent(nextSelection, hoveredUnit);
      } else {
        AppendUnitUnique(nextSelection, hoveredUnit);
      }
    } else {
      AppendUnitUnique(nextSelection, hoveredUnit);
    }

    SetSelectionUnits(nextSelection);
  }

  /**
   * Address: 0x00865E20 (FUN_00865E20, ?HandleDoubleClickSelection@CWldSession@Moho@@QAEXPAVCameraImpl@2@@Z)
   */
  void CWldSession::HandleDoubleClickSelection(CameraImpl* const camera)
  {
    UserEntity* const hoveredEntity = this->GetHoveredUserEntity();
    if (hoveredEntity == nullptr) {
      return;
    }

    UserUnit* const hoveredUnit = hoveredEntity->IsUserUnit();
    if (hoveredUnit == nullptr) {
      return;
    }

    if (hoveredEntity->IsInCategory(msvc8::string("WALL"))) {
      return;
    }

    if (hoveredEntity->mArmy != GetFocusUserArmy()) {
      return;
    }

    const IUnit* const hoveredBridge = GetIUnitBridge(hoveredUnit);
    if (hoveredBridge == nullptr) {
      return;
    }

    const RUnitBlueprint* const targetBlueprint = hoveredBridge->GetBlueprint();
    msvc8::vector<UserUnit*> nextSelection{};
    GetSelectionUnits(nextSelection);

    CameraFrustumUserEntityList* const frustumUnits = camera != nullptr ? camera->GetArmyUnitsInFrustum() : nullptr;
    if (frustumUnits != nullptr) {
      for (CameraUserEntityWeakRef* weakRef = frustumUnits->mStart;
           weakRef != nullptr && weakRef != frustumUnits->mFinish;
           ++weakRef) {
        UserEntity* const entity = DecodeCameraFrustumWeakRef(*weakRef);
        if (entity == nullptr) {
          continue;
        }

        UserUnit* const unit = entity->IsUserUnit();
        if (unit == nullptr || unit == hoveredUnit) {
          continue;
        }

        IUnit* const unitBridge = GetIUnitBridge(unit);
        if (unitBridge == nullptr || unitBridge->IsDead() || unitBridge->DestroyQueued()) {
          continue;
        }

        if (!CanSelectUnit(unit)) {
          continue;
        }

        if (unitBridge->GetBlueprint() != targetBlueprint) {
          continue;
        }

        if (unitBridge->IsUnitState(UNITSTATE_BeingUpgraded)) {
          continue;
        }

        AppendUnitUnique(nextSelection, unit);
      }
    }

    SetSelectionUnits(nextSelection);
  }

  /**
   * Address: 0x00896900 (FUN_00896900, ?GetDelayToNextBeat@CWldSession@Moho@@QBEMXZ)
   */
  float CWldSession::GetDelayToNextBeat() const
  {
    if (mReplayIsPaused != 0u && mLastBeatWasTick != 0) {
      return (std::numeric_limits<float>::infinity)();
    }

    if (mTimeSinceLastTick < 1.0f) {
      return (1.0f - mTimeSinceLastTick) / (WLD_GetSimRate() * 10.0f);
    }

    return 0.0f;
  }

  /**
   * Address: 0x00895FD0 (FUN_00895FD0, ?GetGameTime@CWldSession@Moho@@QBEMXZ)
   *
   * What it does:
   * Returns current game time in seconds.
   */
  float CWldSession::GetGameTime() const
  {
    return (static_cast<float>(mGameTick) + mTimeSinceLastTick) * 0.1f;
  }

  /**
   * Address: 0x00896960 (FUN_00896960, ?SyncPlayableRect@CWldSession@Moho@@QAEXABV?$Rect2@H@gpg@@@Z)
   *
   * What it does:
   * Applies one playable rectangle to terrain and updates user-entity mesh
   * hidden flags to match whether each entity lies inside that rectangle.
   */
  void CWldSession::SyncPlayableRect(const gpg::Rect2i& playableRect)
  {
    if (mWldMap != nullptr && mWldMap->mTerrainRes != nullptr) {
      (void)ApplyTerrainPlayableRect(mWldMap->mTerrainRes, playableRect);
    }

    SessionEntityMap& entityMap = GetSessionEntityMap(this);
    SessionEntityMapNode* const head = entityMap.mHead;
    if (head == nullptr || head->mLeft == head) {
      return;
    }

    for (SessionEntityMapNode* node = head->mLeft; node != nullptr && node != head; node = NextTreeNode(node)) {
      UserEntity* const entity = node->mEntity;
      if (entity == nullptr) {
        continue;
      }

      MeshInstance* const meshInstance = entity->mMeshInstance;
      if (meshInstance == nullptr) {
        continue;
      }

      const int mapX = static_cast<int>(entity->mVariableData.mCurTransform.pos_.x);
      const int mapZ = static_cast<int>(entity->mVariableData.mCurTransform.pos_.z);
      const bool insidePlayableRect = mapX >= playableRect.x0 && mapX < playableRect.x1 && mapZ >= playableRect.z0 &&
        mapZ < playableRect.z1;
      meshInstance->isHidden = insidePlayableRect ? 0u : 1u;
    }
  }

  /**
    * Alias of FUN_00896F00 (non-canonical helper lane).
   * ?GetSaveData@CWldSession@Moho@@QBE?AV?$shared_ptr@USSessionSaveData@Moho@@@boost@@XZ)
   */
  boost::shared_ptr<SSessionSaveData> CWldSession::GetSaveData() const
  {
    boost::shared_ptr<SSessionSaveData> saveData{new SSessionSaveData()};
    SessionSaveSourceNode* const sourceHead = GetSaveSourceTreeHead(this);
    if (!sourceHead) {
      return saveData;
    }

    for (SessionSaveSourceNode* sourceNode = sourceHead->mLeft; sourceNode && sourceNode != sourceHead;
         sourceNode = NextTreeNode(sourceNode)) {
      auto* const provider = static_cast<ISessionSaveSourceProvider*>(sourceNode->mProvider);
      if (!provider) {
        continue;
      }

      auto* const owner = static_cast<SessionSaveNodeOwnerView*>(provider->GetSaveNodeOwner());
      if (!owner || !owner->mTagTreeHead) {
        continue;
      }

      SessionSaveTagNode* const tagHead = owner->mTagTreeHead;
      for (SessionSaveTagNode* tagNode = tagHead->mLeft; tagNode && tagNode != tagHead;
           tagNode = NextTreeNode(tagNode)) {
        saveData->InsertNodeLabel(sourceNode->mCommandSourceId, tagNode->mTagName);
      }
    }

    return saveData;
  }

  /**
   * Address: 0x0087FC90 (FUN_0087FC90,
   * ?GetScenarioInfo@CWldSession@Moho@@QBE?AVLuaObject@LuaPlus@@XZ)
   *
   * What it does:
   * Returns one value-copy of the session scenario-info Lua object.
   */
  LuaPlus::LuaObject CWldSession::GetScenarioInfo() const
  {
    return LuaPlus::LuaObject(mScenarioInfo);
  }

  /**
   * Address: 0x0081F7B0 (FUN_0081F7B0,
   * ?GetLeftMouseButtonAction@CWldSession@Moho@@QAEAAUCommandModeData@2@PAU32@PBUstruct_MouseInfo@@H@Z)
   */
  CommandModeData* CWldSession::GetLeftMouseButtonAction(
    CommandModeData* const outMode, const MouseInfo* const mouseInfo, const int modifiers
  )
  {
    if (!outMode) {
      return nullptr;
    }

    CommandModeData mode{};
    mode.mMode = COMMOD_None;
    mode.mCommandCaps = RULEUCC_None;
    mode.mBlueprint = nullptr;
    mode.mModifiers = modifiers;
    mode.mIsDragged = -1;
    mode.mReserved5C = -1;
    mode.mMouseDragEnd = MouseInfo{};
    mode.mMouseDragEnd.mIsDragger = -1;

    if (mouseInfo) {
      mode.mMouseDragStart = *mouseInfo;
      mode.mIsDragged = mouseInfo->mIsDragger;

      if (mouseInfo->mHitValid != 0u) {
        bool resolvedByUi = false;
        if (mState && FocusArmy >= 0) {
          const std::size_t focusIndex = static_cast<std::size_t>(FocusArmy);
          if (focusIndex < userArmies.size() && userArmies[focusIndex] != nullptr) {
            UICommandModeData uiMode{};
            if (TryGetUICommandMode(mState, uiMode)) {
              if (uiMode.mMode.empty()) {
                resolvedByUi = false;
              } else if (uiMode.mMode == "order") {
                resolvedByUi = true;
                mode.mMode = COMMOD_Order;

                LuaPlus::LuaObject commandName = moho::SCR_GetLuaTableField(mState, uiMode.mPayload, "name");
                if (commandName && commandName.IsString()) {
                  const char* const commandCapsName = commandName.GetString();
                  if (commandCapsName && std::strcmp(commandCapsName, "Transport") == 0) {
                    mode.mCommandCaps = RULEUCC_Transport;
                  } else if (commandCapsName && std::strcmp(commandCapsName, "CallTransport") == 0) {
                    mode.mCommandCaps = RULEUCC_CallTransport;
                  }
                }
              } else if (uiMode.mMode == "build" || uiMode.mMode == "buildanchored") {
                resolvedByUi = true;
                LuaPlus::LuaObject blueprintNameField = moho::SCR_GetLuaTableField(mState, uiMode.mPayload, "name");
                if (blueprintNameField && blueprintNameField.IsString()) {
                  const char* const blueprintName = blueprintNameField.GetString();
                  RResId blueprintId{};
                  blueprintId.name = blueprintName ? blueprintName : "";

                  void* const blueprint =
                    mRules ? static_cast<RRuleGameRules*>(mRules)->GetUnitBlueprint(blueprintId) : nullptr;
                  if (blueprint) {
                    mode.mMode = (uiMode.mMode == "build") ? COMMOD_Build : COMMOD_BuildAnchored;
                    mode.mBlueprint = blueprint;
                  }
                }
              } else if (uiMode.mMode == "ping") {
                resolvedByUi = true;
                mode.mMode = COMMOD_Ping;
              } else if (!uiMode.mMode.empty()) {
                resolvedByUi = true;
                gpg::Warnf("CWldSession::GetLeftMouseButtonAction invalid command mode: %s", uiMode.mMode.c_str());
              }
            }
          }
        }

        if (!resolvedByUi) {
          mode.mMode = DefaultModeFromDrag(mouseInfo->mIsDragger);
        }
      }
    }

    *outMode = mode;
    return outMode;
  }

  namespace
  {
    /** `TELEPORTBEACON` category the teleport-beacon splat/icon branch tests for (0x00851C5D). */
    const msvc8::string kCommandSplatTeleportBeaconCategory("TELEPORTBEACON", 14u);

    /** Default (non-teleport) command-splat line colour, `0x80800000` (0x00851D22). */
    constexpr std::uint32_t kCommandSplatDefaultColor = 0x80800000u;

    /** Same-army teleport-beacon command-splat line colour, `0x809040A0` (0x00851CF1). */
    constexpr std::uint32_t kCommandSplatTeleportColor = 0x809040A0u;

    /** Half-width of the beveled command-splat line ribbon, in world units (`0.1`, 0x00851B9E..0x00851BA6). */
    constexpr float kCommandSplatLineHalfWidth = 0.1f;

    /** Half-extent of the flat command-splat icon billboard, in world units (`1.0`, 0x00851E38..0x00851E42). */
    constexpr float kCommandSplatIconHalfExtent = 1.0f;

    /**
     * Resolves the world-space anchor `CWldSession::DrawCommandSplats` draws
     * one command-link line endpoint from/to for `entity`: either its own
     * interpolated position (`boneIndex < 0`, 0x008519D9..0x00851A11) or the
     * composite-transform position of bone `boneIndex` on its freshly
     * refreshed debug pose (0x00851929..0x00851994, the same
     * `MeshInstance::ComputeDebugPose` + `CAniPoseBone::GetCompositeTransform`
     * chain `MeshRenderer::RenderSkeleton` issues for the skeleton-debug
     * overlay). The interpolation alpha is `0.0f`: the incoming stack slot
     * the binary reads for it is never written by the sole call site (which
     * pushes only the session, camera and prim-batcher), so it resolves
     * whatever was left on the caller's frame - the same "phantom
     * interpolant" shape already documented and resolved to a hard `0.0f`
     * on the sibling `DrawEconomyOverlay` above.
     *
     * The binary calls `CAniPoseBone::GetCompositeTransform` unconditionally
     * even when `boneIndex` is out of range for the refreshed pose's bone
     * array, leaving the bone pointer null (0x00851961..0x00851971) - a
     * latent null-dereference crash on out-of-range data. Preserved here as
     * a defensive `false` return instead of reproducing the crash.
     */
    [[nodiscard]] bool ResolveCommandSplatAnchorPosition(
      UserEntity& entity, const std::int32_t boneIndex, Wm3::Vector3f& outPosition
    )
    {
      if (boneIndex < 0) {
        outPosition = entity.GetInterpolatedTransform(0.0f).pos_;
        return true;
      }

      if (entity.mMeshInstance == nullptr) {
        return false;
      }

      const boost::shared_ptr<CAniPose> pose = entity.mMeshInstance->ComputeDebugPose();
      if (!pose) {
        return false;
      }

      const std::ptrdiff_t boneCount = pose->mBones.end() - pose->mBones.begin();
      if (boneIndex >= boneCount) {
        return false;
      }

      outPosition = pose->mBones.begin()[boneIndex].GetCompositeTransform().pos_;
      return true;
    }

    /**
     * Binds one texture resource by path for the command-splat icon
     * batches, matching 0x00851DB8..0x00851DF1 (attack icon) /
     * 0x00851F3C..0x00851FAA (teleport icon):
     * `CD3DDevice::GetResources()->GetTexture(handle, path, nullptr, true)`
     * followed by `CD3DPrimBatcher::SetTexture` on the dynamic-sheet
     * overload (the resolved `TextureResourceHandle` - a
     * `shared_ptr<RD3DTextureResource>` - upcasts to the
     * `shared_ptr<ID3DTextureSheet>` the overload wants, since
     * `RD3DTextureResource` derives from `ID3DTextureSheet`).
     */
    void BindCommandSplatIconTexture(CD3DPrimBatcher& batcher, const char* const path)
    {
      CD3DDevice* const device = D3D_GetDevice();
      ID3DDeviceResources* const resources = device->GetResources();
      ID3DDeviceResources::TextureResourceHandle textureHandle{};
      (void)resources->GetTexture(textureHandle, path, nullptr, true);
      batcher.SetTexture(boost::shared_ptr<ID3DTextureSheet>(textureHandle));
    }

    /**
     * Draws one flat, ground-aligned 2x2-world-unit icon billboard at
     * `worldPosition` (0x00851E30..0x00851F27 / 0x00851FE0..0x008520D2 -
     * the attack- and teleport-icon batch loops share this exact shape).
     * The `+-1.0` X/Z corner offsets with no Y offset and the opaque-white
     * vertex colour (`-1`, written repeatedly at 0x00851E55..0x00851F19 and
     * its teleport-branch twin) come straight from the binary; the precise
     * corner-to-UV pairing was not independently bit-verified (the source
     * locals the binary reuses for this pass were, earlier in the same
     * function, a `std::string` and two unrelated `Vertex` scratch buffers,
     * which makes a byte-exact reconstruction of just this block
     * impractical) - the standard 0..1 UV wrap used here reproduces the
     * visible quad shape and opaque-white tint and is not expected to read
     * any differently.
     */
    void DrawCommandSplatIcon(CD3DPrimBatcher& batcher, const Wm3::Vector3f& worldPosition)
    {
      constexpr std::uint32_t kIconColor = 0xFFFFFFFFu;

      const CD3DPrimBatcher::Vertex topLeft{
        worldPosition.x - kCommandSplatIconHalfExtent, worldPosition.y, worldPosition.z + kCommandSplatIconHalfExtent,
        kIconColor, 0.0f, 0.0f};
      const CD3DPrimBatcher::Vertex topRight{
        worldPosition.x - kCommandSplatIconHalfExtent, worldPosition.y, worldPosition.z - kCommandSplatIconHalfExtent,
        kIconColor, 0.0f, 1.0f};
      const CD3DPrimBatcher::Vertex bottomRight{
        worldPosition.x + kCommandSplatIconHalfExtent, worldPosition.y, worldPosition.z - kCommandSplatIconHalfExtent,
        kIconColor, 1.0f, 1.0f};
      const CD3DPrimBatcher::Vertex bottomLeft{
        worldPosition.x + kCommandSplatIconHalfExtent, worldPosition.y, worldPosition.z + kCommandSplatIconHalfExtent,
        kIconColor, 1.0f, 0.0f};
      batcher.DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }
  } // namespace

  /**
   * Address: 0x008515B0 (FUN_008515B0, ?DrawCommandSplats@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::DrawCommandSplats(GeomCamera3* const camera, CD3DPrimBatcher* const primBatcher)
  {
    // Walk the selection weak-set and collect the distinct army indices of
    // every live selected unit (0x008515D4..0x00851696, `WeakSet_UserEntity`
    // `find`/`Iterator::inc` over `mSelection`; the per-entity value added to
    // the set is that unit's owning army index).
    BVIntSet selectedArmies{};
    if (mSelection.mHead != nullptr) {
      SSelectionNodeUserEntity* node = nullptr;
      node = SSelectionSetUserEntity::find(&mSelection, mSelection.mHead->mLeft, &node);
      while (node != mSelection.mHead) {
        if (UserEntity* const entity = ResolveWeakEntitySetNodeEntity(*node);
            entity != nullptr && entity->mArmy != nullptr) {
          (void)selectedArmies.Add(static_cast<unsigned int>(entity->mArmy->mArmyIndex));
        }

        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&mSelection, node, &node);
      }
    }

    ISTIDriver* const simDriver = SIM_GetActiveDriver();
    if (simDriver == nullptr) {
      return;
    }

    // Always publish the selection's army mask to the sync filter, even when
    // the rest of this overlay is not drawn this frame (0x008516A6..0x008516F5).
    simDriver->SetSyncFilterMaskA(selectedArmies);

    // The rest of the overlay only draws while Shift is held with no UI
    // control focused and the game window foreground - `MAUI_KeyIsDown`
    // already implements exactly that gate (0x00851704..0x00851742).
    if (!MAUI_KeyIsDown(MKEY_SHIFT)) {
      return;
    }

    primBatcher->Setup("TAlphaBlendLinearSampleNoDepth");
    primBatcher->SetViewProjMatrix(*camera);
    primBatcher->SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));

    msvc8::vector<Wm3::Vector3f> attackIconPositions{};
    msvc8::vector<Wm3::Vector3f> teleportIconPositions{};

    // `mSyncInlineVectors` is the per-beat command-link scratch buffer
    // `CWldSession::DoBeat`/`AssignSyncInlineVectors` populate every beat
    // (see its declaration above) - this is that lane's reader. Each record
    // is one source unit's queued command-link run: `inlineVec_[2]` holds
    // the source `EntId`, and the `{begin(),end()}` range holds
    // `(boneIndex, targetEntId)` int32 pairs (0x008518A4..0x0085189A).
    for (const SyncInlineVector& record : mSyncInlineVectors) {
      UserEntity* const source = LookupEntityId(record.inlineVec_[2]);
      if (source == nullptr) {
        continue;
      }

      for (const std::int32_t* pair = record.begin(); pair + 1 < record.end(); pair += 2) {
        const std::int32_t boneIndex = pair[0];
        const EntId targetId = pair[1];

        UserEntity* const target = LookupEntityId(targetId);
        if (target == nullptr) {
          continue;
        }

        Wm3::Vector3f sourcePosition{};
        if (!ResolveCommandSplatAnchorPosition(*source, boneIndex, sourcePosition)) {
          continue;
        }

        const Wm3::Vector3f targetPosition = target->GetInterpolatedTransform(0.0f).pos_;

        // Direction from source to target, normalized (zero vector when the
        // two points coincide) - 0x00851A37..0x00851AE9.
        Wm3::Vector3f direction{
          targetPosition.x - sourcePosition.x, targetPosition.y - sourcePosition.y,
          targetPosition.z - sourcePosition.z};
        const float distance =
          std::sqrt(direction.x * direction.x + direction.y * direction.y + direction.z * direction.z);
        if (distance > 0.0f) {
          const float inverseDistance = 1.0f / distance;
          direction = Wm3::Vector3f{
            direction.x * inverseDistance, direction.y * inverseDistance, direction.z * inverseDistance};
        } else {
          direction = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
        }

        // Perpendicular bevel offset: the direction rotated 90 degrees
        // about Y, scaled to the ribbon half-width (0x00851B8C..0x00851BA6).
        const Wm3::Vector3f bevel{
          direction.z * kCommandSplatLineHalfWidth, 0.0f, -direction.x * kCommandSplatLineHalfWidth};

        // The line ribbon runs from one unit short of the source to one
        // unit short of the target (0x00851AE9..0x00851C50), offset to one
        // side by `bevel`.
        const Wm3::Vector3f nearSource{
          sourcePosition.x + direction.x, sourcePosition.y + direction.y, sourcePosition.z + direction.z};
        const Wm3::Vector3f nearTarget{
          targetPosition.x - direction.x, targetPosition.y - direction.y, targetPosition.z - direction.z};

        const Wm3::Vector3f topLeft{nearSource.x + bevel.x, nearSource.y + bevel.y, nearSource.z + bevel.z};
        const Wm3::Vector3f& topRight = nearSource;
        const Wm3::Vector3f& bottomRight = nearTarget;
        const Wm3::Vector3f bottomLeft{nearTarget.x + bevel.x, nearTarget.y + bevel.y, nearTarget.z + bevel.z};

        const bool sameArmy = source->mArmy != nullptr && source->mArmy == target->mArmy;
        const bool isTeleportBeacon = sameArmy && target->IsInCategory(kCommandSplatTeleportBeaconCategory);
        const std::uint32_t lineColor = isTeleportBeacon ? kCommandSplatTeleportColor : kCommandSplatDefaultColor;

        primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft, lineColor);

        if (isTeleportBeacon) {
          teleportIconPositions.push_back(targetPosition);
        } else {
          attackIconPositions.push_back(targetPosition);
        }
      }
    }

    BindCommandSplatIconTexture(*primBatcher, "/textures/ui/common/game/waypoints/attack_btn_up.dds");
    for (const Wm3::Vector3f& iconPosition : attackIconPositions) {
      DrawCommandSplatIcon(*primBatcher, iconPosition);
    }

    BindCommandSplatIconTexture(*primBatcher, "/textures/ui/common/game/waypoints/teleport_btn_up.dds");
    for (const Wm3::Vector3f& iconPosition : teleportIconPositions) {
      DrawCommandSplatIcon(*primBatcher, iconPosition);
    }

    primBatcher->Flush();
  }

  /**
   * Address: 0x008599D0 (FUN_008599D0, ?RenderMeshPreviews@CWldSession@Moho@@QAEHXZ)
   */
  void CWldSession::RenderMeshPreviews()
  {
    // Recovered 0x008599D0 high-level flow:
    // 1) Validate current formation + instance readiness.
    // 2) Iterate formation units, query formation position/orientation.
    // 3) Sample terrain elevation from STIMap/CHeightField.
    // 4) Create "UnitFormationPreview" mesh material + mesh instances.
    // 5) Set stance/orientation and tint preview mesh instances.
    //
    // Deep lift blockers:
    // CFormation runtime layout, CAiFormationInstance accessors, MeshMaterial/MeshRenderer
    // creation chain, and preview-instance ownership container at 0x010C425C/0x010C4260.
  }

  namespace
  {
    /**
     * Gap between two stacked bars, in screen pixels (`flt_DFEB0C` added twice
     * per row at 0x0085D22F / 0x0085D23E).
     */
    constexpr float kLifebarRowGap = 2.0f;

    /** Every bar sits on an opaque black backdrop (`0FF000000h`, 0x0085D285). */
    constexpr std::uint32_t kLifebarBackdropColor = 0xFF000000u;

    /**
     * A filled bar never gets thinner than this even when the bar itself is
     * (`comiss` against `flt_DFEB0C` at 0x0085D55D / 0x0085D581).
     */
    constexpr float kLifebarMinFillHeight = 2.0f;

    /** The drop shadow under a label is offset one pixel down-right (0x0085E2A3). */
    constexpr float kLabelShadowOffset = 1.0f;

    /** Label drop shadow colour (`0FF000000h` pushed at 0x0085E2AB). */
    constexpr std::uint32_t kLabelShadowColor = 0xFF000000u;

    /**
     * Address: 0x004EAA50 (FUN_004EAA50)
     *
     * What it does:
     * Returns the shared "no screen position" sentinel - a `Wm3::Vector2f`
     * whose components are both NaN. The binary keeps it in a
     * function-local static (storage 0x010C7AB4/0x010C7AB8 behind the
     * one-bit init guard at 0x010C7ABC) and both of
     * `DrawUnitCustomNameLabel`'s early-outs hand it back: the first inlines
     * the guard (0x0085E33F), the second calls this body (0x0085E0F5).
     */
    [[nodiscard]] const Wm3::Vector2f& InvalidScreenPoint()
    {
      static const Wm3::Vector2f sentinel{
        std::numeric_limits<float>::quiet_NaN(), std::numeric_limits<float>::quiet_NaN()
      };
      return sentinel;
    }

    /**
     * Address: 0x005657B0 (FUN_005657B0, sub_5657B0)
     *
     * IDA signature:
     * BOOL __usercall sub_5657B0@<eax>(float *a1@<esi>);
     *
     * What it does:
     * Reports whether a screen point carries a real position, i.e. neither
     * component is NaN. This is the read side of `InvalidScreenPoint()`.
     */
    [[nodiscard]] bool IsValidScreenPoint(const Wm3::Vector2f& point)
    {
      return !std::isnan(point.X()) && !std::isnan(point.Y());
    }

    /**
     * Address: 0x010C4284 (the cached custom-name font)
     *
     * What it does:
     * Returns the process-wide font the custom-name labels render with,
     * creating it on first use from the `ui_CustomNameFont` /
     * `ui_CustomNameFontSize` console variables (0x0085E11B..0x0085E171).
     * The binary keeps exactly one reference for the life of the process -
     * the temporary handle `CD3DFont::Create` returns is assigned into the
     * global and then released - so the static below deliberately never
     * releases either.
     */
    [[nodiscard]] CD3DFont* CustomNameFont()
    {
      static boost::SharedPtrRaw<CD3DFont> font{};
      if (font.px == nullptr) {
        font = CD3DFont::Create(ui_CustomNameFontSize, ui_CustomNameFont.c_str());
      }
      return font.px;
    }

    /**
     * Emits one axis-aligned screen-space bar.
     *
     * All six quads in `DrawUnitLifebars` hand their corners to
     * `CD3DPrimBatcher::DrawQuad` in the same rotation - top-left, down the
     * left edge, across the bottom, back up the right edge - so the corner
     * mechanics are lifted here instead of being open-coded six times. That
     * rotation is the binary's own: at 0x0085D317 the `topLeft` argument
     * (the vector pushed first, read from the callee frame at +8 in
     * 0x00438DD0) is `(left, top)` while `topRight` (the `ecx` argument,
     * read at 0x00438DA3) is `(left, bottom)`.
     */
    void DrawLifebarQuad(
      CD3DPrimBatcher& primBatcher,
      const float left,
      const float top,
      const float right,
      const float bottom,
      const std::uint32_t color
    )
    {
      primBatcher.DrawQuad(
        Wm3::Vector3f(left, top, 0.0f),
        Wm3::Vector3f(left, bottom, 0.0f),
        Wm3::Vector3f(right, bottom, 0.0f),
        Wm3::Vector3f(right, top, 0.0f),
        color
      );
    }

    /**
     * Phase of the shared "empty fuel" blink, in [0,1)
     * (0x0085D107..0x0085D11B and the identical block at
     * 0x0085D18E..0x0085D1A2).
     *
     * Driven by the sim clock rather than the wall clock so every warning bar
     * on screen blinks in step: the whole-tick counter plus this frame's
     * sub-tick interpolant, scaled by the console rate and wrapped.
     */
    [[nodiscard]] float FuelWarningBlinkPhase(const StrategicIconAuxView& aux)
    {
      const double simTime = static_cast<double>(aux.mSession->mGameTick) + static_cast<double>(aux.mTickFraction);
      return static_cast<float>(std::fmod(simTime * static_cast<double>(ui_FuelEmptyBlinkRate), 1.0));
    }

    /**
     * Address: 0x0085CD40 (FUN_0085CD40, sub_85CD40)
     *
     * IDA signature:
     * float *__usercall sub_85CD40@<eax>(UnitIconData *icon@<eax>,
     *   Wm3::Vector2f *labelCursor, struct_IconAux *aux);
     *
     * What it does:
     * Draws one unit's stacked status bars in the strategic view and reports
     * where a text label under them would start.
     *
     * Row one is always the health bar. Row two and three are conditional: a
     * unit with a shield puts the shield on row two and fuel (or, when the
     * unit carries no fuel at all, build progress) on row three; a unit
     * without a shield collapses to a single second row showing whichever of
     * fuel and build progress is further along. Fuel at or below empty - but
     * not the "no fuel lane at all" sentinel of -1 - swaps that bar to the
     * warning colour and fills it completely on alternate blink phases.
     *
     * Each row is an opaque black backdrop with a coloured fill inset one
     * pixel, the fill running `fraction` of the way across.
     *
     * `labelCursor` receives the horizontal centre of the bar stack and the
     * bottom edge of the last row actually drawn, which is what
     * `DrawUnitCustomNameLabel` hangs its text off.
     */
    void DrawUnitLifebars(const UnitIconData& icon, Wm3::Vector2f& labelCursor, const StrategicIconAuxView& aux)
    {
      CD3DPrimBatcher& primBatcher = *aux.mBatcher;
      primBatcher.SetTexture(aux.mWhiteTexture);

      const GeomCamera3& camera = *aux.mCamera;
      const REntityBlueprint& blueprint = *icon.mBlueprint;
      const Wm3::Vector3f worldPosition{icon.mWorldX, icon.mWorldY, icon.mWorldZ};

      // Row 2 of the viewport matrix is the perspective-correct width factor;
      // dividing by it keeps the bar a constant on-screen size as the camera
      // pulls back (0x0085CD6A..0x0085CDAF).
      const float widthScale = camera.viewport.ProjectViewportWidthRow2(worldPosition);

      // A blueprint may override either bar extent; a non-positive value means
      // "use the console default" (0x0085CDA8 / 0x0085CDC6).
      const float barWidthSource = (blueprint.mLifeBarSize > 0.0f) ? blueprint.mLifeBarSize : ui_LifebarWidth;
      const float barHeightSource = (blueprint.mLifeBarHeight > 0.0f) ? blueprint.mLifeBarHeight : ui_lifebarHeight;
      const float barWidth = (1.0f / widthScale) * barWidthSource;
      const float barHeight = (1.0f / widthScale) * barHeightSource;

      // The anchor is not the unit's screen position: the world point is taken
      // into VIEW space first so the stack can be dropped straight down the
      // camera's own up axis by the blueprint's lifebar offset, and only then
      // projected. That is why this cannot go through `GeomCamera3::Project` -
      // the offset is applied mid-pipeline (0x0085CDFF..0x0085CFA1).
      const VMatrix4& view = camera.view;
      const float viewX = (view.r[0].x * worldPosition.X()) + (view.r[1].x * worldPosition.Y()) +
        (view.r[2].x * worldPosition.Z()) + view.r[3].x;
      const float viewY = (view.r[0].y * worldPosition.X()) + (view.r[1].y * worldPosition.Y()) +
        (view.r[2].y * worldPosition.Z()) + view.r[3].y;
      const float viewZ = (view.r[0].z * worldPosition.X()) + (view.r[1].z * worldPosition.Y()) +
        (view.r[2].z * worldPosition.Z()) + view.r[3].z;
      const float viewW = (view.r[0].w * worldPosition.X()) + (view.r[1].w * worldPosition.Y()) +
        (view.r[2].w * worldPosition.Z()) + view.r[3].w;

      const float inverseViewW = 1.0f / viewW;
      const float anchorX = viewX * inverseViewW;
      const float anchorY = (viewY * inverseViewW) - (blueprint.mLifeBarOffset + ui_LifebarOffset);
      const float anchorZ = viewZ * inverseViewW;

      const VMatrix4& projection = camera.projection;
      const float clipX = (projection.r[0].x * anchorX) + (projection.r[1].x * anchorY) +
        (projection.r[2].x * anchorZ) + projection.r[3].x;
      const float clipY = (projection.r[0].y * anchorX) + (projection.r[1].y * anchorY) +
        (projection.r[2].y * anchorZ) + projection.r[3].y;
      const float clipW = (projection.r[0].w * anchorX) + (projection.r[1].w * anchorY) +
        (projection.r[2].w * anchorZ) + projection.r[3].w;

      // NDC to whole pixels, Y flipped, same mapping the resource splats use.
      const float inverseClipW = 1.0f / clipW;
      const float anchorScreenX =
        std::floor(((clipX * inverseClipW) - -1.0f) * aux.mViewportWidth * 0.5f);
      const float anchorScreenY = std::floor(
        ((((clipY * inverseClipW) - -1.0f) * (-0.0f - aux.mViewportHeight)) * 0.5f) + aux.mViewportHeight
      );

      const float halfBarWidth = barWidth * 0.5f;
      const float barLeft = anchorScreenX - halfBarWidth;
      const float barRight = barLeft + barWidth;
      const float barTop = anchorScreenY - (barHeight * 0.5f);

      const UserEntity& entity = *icon.mUnit;
      float healthFraction = entity.mVariableData.mHealth / entity.mVariableData.mMaxHealth;
      // Written as the binary's inverted compares so a NaN ratio (a unit with
      // zero max health) clamps to full rather than propagating.
      if (!(1.0f > healthFraction)) {
        healthFraction = 1.0f;
      }
      if (0.0f > healthFraction) {
        healthFraction = 0.0f;
      }

      std::uint32_t healthColor = ui_LifeBarBadColor;
      if (healthFraction > ui_LifeBarGoodCutoff) {
        healthColor = ui_LifeBarGoodColor;
      } else if (healthFraction > ui_LifeBarBadCutoff) {
        healthColor = ui_LifeBarMedColor;
      }

      // Rows two and three stay at zero for anything that is not a unit, which
      // is what suppresses them below.
      float secondRowFraction = 0.0f;
      float thirdRowFraction = 0.0f;
      std::uint32_t secondRowColor = 0u;
      std::uint32_t thirdRowColor = 0u;

      // Slot 3 (`[vftable+0x0C]`, the non-const overload) is the one the
      // binary dispatches at 0x0085D091, matching the caller's own test.
      if (const UserUnit* const unit = icon.mUnit->IsUserUnit(); unit != nullptr) {
        const float fuelRatio = unit->mUnitVarDat.mFuelRatio;
        const float shieldRatio = unit->mUnitVarDat.mShieldRatio;
        const float workProgress = unit->mUnitVarDat.mWorkProgress;

        // -1 is the "this unit has no fuel lane" sentinel, distinct from an
        // empty tank at 0 (0x0085D0D3 / 0x0085D180).
        constexpr float kNoFuelLaneSentinel = -1.0f;

        if (shieldRatio > 0.0f) {
          secondRowColor = ui_ShieldBarColor;
          secondRowFraction = shieldRatio;

          if (!(fuelRatio > kNoFuelLaneSentinel)) {
            thirdRowColor = ui_ProgressBarColor;
            thirdRowFraction = workProgress;
          } else {
            thirdRowColor = ui_FuelBarColor;
            thirdRowFraction = fuelRatio;
            if (!(0.0f < fuelRatio) && FuelWarningBlinkPhase(aux) > 0.5f) {
              thirdRowColor = ui_FuelWarningColor;
              thirdRowFraction = 1.0f;
            }
          }
        } else {
          if (fuelRatio > workProgress) {
            secondRowColor = ui_FuelBarColor;
            secondRowFraction = fuelRatio;
          } else {
            secondRowColor = ui_ProgressBarColor;
            secondRowFraction = workProgress;
          }

          if (fuelRatio > kNoFuelLaneSentinel && !(0.0f < fuelRatio) && FuelWarningBlinkPhase(aux) > 0.5f) {
            secondRowColor = ui_FuelWarningColor;
            secondRowFraction = 1.0f;
          }
        }

        if (!(1.0f > secondRowFraction)) {
          secondRowFraction = 1.0f;
        }
        if (0.0f > secondRowFraction) {
          secondRowFraction = 0.0f;
        }
        if (!(1.0f > thirdRowFraction)) {
          thirdRowFraction = 1.0f;
        }
        if (0.0f > thirdRowFraction) {
          thirdRowFraction = 0.0f;
        }
      }

      const float secondRowTop = barTop + (barHeight + kLifebarRowGap);
      const float thirdRowTop = secondRowTop + (barHeight + kLifebarRowGap);

      // Backdrops first, one row at a time, each row gated on the row above
      // having something to show.
      DrawLifebarQuad(primBatcher, barLeft, barTop, barRight, barTop + barHeight, kLifebarBackdropColor);

      float lastRowTop = barTop;
      if (secondRowFraction > 0.0f) {
        DrawLifebarQuad(
          primBatcher, barLeft, secondRowTop, barRight, secondRowTop + barHeight, kLifebarBackdropColor
        );
        lastRowTop = secondRowTop;

        if (thirdRowFraction > 0.0f) {
          DrawLifebarQuad(
            primBatcher, barLeft, thirdRowTop, barRight, thirdRowTop + barHeight, kLifebarBackdropColor
          );
          lastRowTop = thirdRowTop;
        }
      }

      labelCursor = Wm3::Vector2f(barLeft + halfBarWidth, lastRowTop + barHeight);

      // Then the coloured fills, inset one pixel inside their backdrops.
      const float fillTrackWidth = barWidth - 1.0f;
      const float fillHeight = (barHeight - kLifebarRowGap) + 1.0f;
      const float fillBottomOffset = (fillHeight < kLifebarMinFillHeight) ? kLifebarMinFillHeight : fillHeight;

      DrawLifebarQuad(
        primBatcher,
        barLeft + 1.0f,
        barTop + 1.0f,
        barLeft + (healthFraction * fillTrackWidth),
        barTop + fillBottomOffset,
        healthColor
      );

      if (secondRowFraction > 0.0f) {
        DrawLifebarQuad(
          primBatcher,
          barLeft + 1.0f,
          secondRowTop + 1.0f,
          barLeft + (secondRowFraction * fillTrackWidth),
          secondRowTop + fillBottomOffset,
          secondRowColor
        );

        if (thirdRowFraction > 0.0f) {
          DrawLifebarQuad(
            primBatcher,
            barLeft + 1.0f,
            thirdRowTop + 1.0f,
            barLeft + (thirdRowFraction * fillTrackWidth),
            thirdRowTop + fillBottomOffset,
            thirdRowColor
          );
        }
      }
    }

    /**
     * Address: 0x0085E0A0 (FUN_0085E0A0, sub_85E0A0)
     *
     * IDA signature:
     * Wm3::Vector2f *__cdecl sub_85E0A0(Wm3::Vector2f *result, UnitIconData *icon,
     *   struct_IconAux *aux, Wm3::Vector2f *labelCursor, char isMiniMap);
     *
     * What it does:
     * Draws one unit's player-assigned custom name under its status bars and
     * returns where the text was placed, so the next label down can stack
     * beneath it. Returns `InvalidScreenPoint()` when nothing was drawn -
     * labels are off, this is the minimap, or the unit has no custom name -
     * which is the caller's signal to leave its cursor untouched.
     *
     * The label is centred on `labelCursor` when the bar pass gave it one;
     * otherwise it falls back to projecting the unit itself and applying the
     * same blueprint + console lifebar offset the bars use. Either way the
     * text is snapped to whole pixels and drawn twice, an opaque black copy
     * one pixel down-right first so it stays readable over terrain.
     */
    [[nodiscard]] Wm3::Vector2f DrawUnitCustomNameLabel(
      const UnitIconData& icon,
      const StrategicIconAuxView& aux,
      const Wm3::Vector2f& labelCursor,
      const bool isMiniMap
    )
    {
      if (!ui_RenderCustomNames || isMiniMap) {
        return InvalidScreenPoint();
      }

      UserUnit* const unit = icon.mUnit->IsUserUnit();

      // `UserUnit::GetCustomName` (vtable slot 24, `[vftable+0x60]`) hands back
      // the address of the unit's `msvc8::string`, not a C string - the binary
      // reads `_Mysize` at +0x14 and picks the inline buffer or heap pointer off
      // `_Myres` at +0x18. Same reinterpret the console command family uses.
      const auto& customName = *reinterpret_cast<const msvc8::string*>(unit->GetCustomName());
      if (customName.empty()) {
        return InvalidScreenPoint();
      }

      CD3DFont* const font = CustomNameFont();

      // The second `GetAdvance` argument is not materialised at this call site
      // (0x0085E196 sets up only the string); zero is the neutral flag value.
      const float textWidth = font->GetAdvance(customName.c_str(), 0);
      const float lineHeight = font->mHeight;

      float textLeft = 0.0f;
      float textBaseline = 0.0f;
      if (IsValidScreenPoint(labelCursor)) {
        textLeft = labelCursor.X() - (textWidth * 0.5f);
        textBaseline = labelCursor.Y();
      } else {
        const Wm3::Vector2f projected = aux.mCamera->Project(
          Wm3::Vector3f(icon.mWorldX, icon.mWorldY, icon.mWorldZ),
          0.0f,
          aux.mViewportWidth,
          aux.mViewportHeight,
          0.0f
        );
        textLeft = projected.X() - (textWidth * 0.5f);
        textBaseline = (icon.mBlueprint->mLifeBarOffset + projected.Y()) + ui_LifebarOffset;
      }
      textBaseline += lineHeight;

      const float snappedLeft = std::floor(textLeft);
      const float snappedBaseline = std::floor(textBaseline);

      const Wm3::Vector2f shadowOrigin{snappedLeft + kLabelShadowOffset, snappedBaseline + kLabelShadowOffset};
      const Wm3::Vector2f textOrigin{snappedLeft, snappedBaseline};

      // The trailing glyph-scale / max-advance pair is not passed at either
      // call site - `Render2D` materialises its own axis constants on entry
      // (0x00426583..0x004265AB) - so both draws use the file's established
      // unscaled / unclipped defaults.
      font->Render2D(
        customName.c_str(),
        aux.mBatcher,
        shadowOrigin,
        kLabelShadowColor,
        1.0f,
        std::numeric_limits<float>::quiet_NaN()
      );
      font->Render2D(
        customName.c_str(),
        aux.mBatcher,
        textOrigin,
        ui_CustomNameColor,
        1.0f,
        std::numeric_limits<float>::quiet_NaN()
      );

      return textOrigin;
    }
  } // namespace

  /**
   * Address: 0x0085B6E0 (FUN_0085B6E0,
   * ?RenderStrategicIcons@CWldSession@Moho@@QAEXPAVCameraImpl@2@PAVCD3DPrimBatcher@2@PAVCWldMap@2@@Z)
   *
   * What it does:
   * Lazily builds the process-global icon-aux singleton, re-seats its
   * per-frame camera/batcher state and screen projection, then walks every
   * unit `CameraImpl::GetAllUnitsInFrustum()` currently sees and classifies
   * each one carrying a strategic-icon name into one of four runs (ground /
   * air / high-priority / selected), picking its icon texture through
   * `PickUnitStrategicIconTexture`.
   *
   * Blockers this pass resolved (see cited evidence at each site):
   *  - `CameraImpl` vtable slot mixup: the dispatch at 0x0085BA71 (byte
   *    offset 0xA0 from the vtable head) is slot 40 = `GetAllUnitsInFrustum`,
   *    not `GetArmyUnitsInFrustum` (slot 41, +0xA4) as an earlier pass's
   *    comment guessed - confirmed by reading the shipped vtable directly
   *    out of `bin/2025.7.1/ForgedAlliance.exe` (see `CameraImpl.h`).
   *  - `REntityBlueprint::mStrategicIconSortPriority` retyped from a 32-bit
   *    `mStrategicIconRuntimeWord` to the real single byte the classifier
   *    compares against `'A'`.
   *  - `CWldSession`'s `EntId -> UserEntity*` map was already modelled
   *    (`SessionEntityMap` / `LookupEntityId`) by a prior pass - no new work
   *    needed there.
   *  - `StrategicIconAuxView`'s constructor and `LoadGenericIcons` recovered
   *    (0x0085B2A0 / 0x0085E7F0); `gStrategicIconAuxiliary` retyped from a
   *    never-defined `StrategicIconAuxRuntimeView` forward declaration to
   *    the real, complete type.
   *  - `PickUnitStrategicIconTexture` / `PickGenericStrategicIconTexture`
   *    recovered (0x0085D880 / 0x0085CBD0), which required retyping
   *    `REntityBlueprint`'s four cached icon fields from `boost::weak_ptr`
   *    to `boost::shared_ptr` (see the evidence note on those fields).
   *
   * Deferred to a follow-up pass - not drawn by this function yet:
   *  - The actual draw calls (`RenderUnitIcon`, 0x0085D9A0): the icon-quad
   *    geometry, the `Moho::teamcolors` per-army palette
   *    (`+0x0128F1C0`, read when `mTeamColorMode` is on), the blink timer,
   *    and the single dedicated "hovered unit" slot (this function's local
   *    `v148.playableRectX1` in the original - hovered units are excluded
   *    from all four runs below, matching the binary, but nothing consumes
   *    them yet).
   *  - The "toggled off a scripted ability" half of the paused-overlay flag
   *    below, which currently reflects only `mUnitVarDat.mIsPaused`.
   *  - The selection-set name label (0x0085E3A0), which stacks under the
   *    custom name using the same cursor protocol.
   *  - The formation-ghost pass ("TStrategicFormationIcon"): needs
   *    `IFormationInstance::Contains`, not modelled yet - a separate,
   *    already-tracked blocker (see the `CFormationInstance` split notes).
   */
  void CWldSession::RenderStrategicIcons(
    CameraImpl* const camera, CD3DPrimBatcher* const primBatcher, CWldMap* const map, const bool isMiniMap
  )
  {
    // Read once per frame, before the singleton is even built (0x0085B719).
    // An "attached" unit - one riding a transport or docked - normally has its
    // lifebar suppressed; this option puts it back.
    const bool showAttachedUnitLifebars = OPTIONS_GetBool("show_attached_unit_lifebars");

    // --- Phase 1: lazy singleton build --------------------------------
    if (gStrategicIconAuxiliary == nullptr) {
      gStrategicIconAuxiliary = new StrategicIconAuxView();
      gStrategicIconAuxiliary->LoadGenericIcons(this);
      gStrategicIconAuxiliary->LoadPauseAndStunnedRestTextures(this);
    }
    StrategicIconAuxView& aux = *gStrategicIconAuxiliary;

    // --- Phase 2: re-seat per-frame camera/batcher state, clear the four
    // implemented runs, push the pixel-exact screen projection ----------
    const GeomCamera3& view = camera->CameraGetView();
    aux.mViewportX = view.viewport.r[3].x;
    aux.mViewportY = view.viewport.r[3].y;
    aux.mViewportWidth = view.viewport.r[3].z;
    aux.mViewportHeight = view.viewport.r[3].w;
    aux.mSession = this;
    aux.mBatcher = primBatcher;
    aux.mCamera = &view;
    // aux.mTickFraction re-seat deferred alongside the lifebar pass, its
    // only reader - see the class comment above `mTickFraction`.

    aux.mGroundIcons.clear();
    aux.mAirIcons.clear();
    aux.mHighPriorityIcons.clear();
    aux.mSelectedIcons.clear();
    // aux.mLifebarIcons collection deferred alongside the lifebar draw pass.

    primBatcher->SetProjectionMatrix(MakeViewportPixelProjection(view));
    primBatcher->SetViewMatrix(VMatrix4::Identity());

    // The binary reads this parameter's raw bits as a float sub-tick
    // interpolation fraction for `GetInterpolatedTransform()` below,
    // despite the mangled signature typing it `CWldMap*` - confirmed
    // end-to-end via float-register (`fld`/`fstp`/`movss`) moves, both here
    // (0x0085B85C, storing `[esp+argC]`) and at the real caller
    // (`CRenderWorldView::Render`, 0x0086EE58/0x0086EE63, `fld [ebp+map]`).
    // Preserved exactly rather than "fixed", per this project's
    // binary-fidelity mandate.
    const float tickFraction = std::bit_cast<float>(map);

    // "Current zoom" scalar used below as the mesh-fade-in comparison
    // baseline: the camera target position projected through row 1 of the
    // viewport matrix (0x0085BA1E..0x0085BA93 in the binary).
    const Wm3::Vector3f targetPosition = camera->GetTargetPosition();
    const float currentZoomValue = (view.viewport.r[1].x * targetPosition.x) +
      (view.viewport.r[1].y * targetPosition.y) + (view.viewport.r[1].z * targetPosition.z) + view.viewport.r[1].w;

    // --- Phase 3: classify every unit in frustum ------------------------
    UserArmy* const focusArmy = GetFocusArmy();
    CameraFrustumUserEntityList* const allUnits = camera->GetAllUnitsInFrustum();

    for (CameraUserEntityWeakRef* ref = allUnits->mStart; ref != allUnits->mFinish; ++ref) {
      UserEntity* const entity = DecodeCameraFrustumWeakRef(*ref);
      if (entity == nullptr || entity->mVariableData.mIsDead) {
        continue;
      }

      UserUnit* const asUnit = entity->IsUserUnit();

      // `mIntelStateFlags` bit 0x20: this unit renders through some other
      // path already and its strategic icon is suppressed outright
      // (`(v26->mSelectionMaskUsed & 0x20) == 0` gates entry at 0x0085BAC3).
      constexpr std::uint32_t kStrategicIconEntitySuppressedMask = 0x20u;
      if (asUnit != nullptr && (asUnit->mIntelStateFlags & kStrategicIconEntitySuppressedMask) != 0u) {
        continue;
      }

      const REntityBlueprint* const blueprint = entity->mParams.mBlueprint;
      if (blueprint == nullptr || blueprint->mStrategicIconName.empty()) {
        continue;
      }

      UnitIconData iconData{};
      iconData.mUnit = entity;
      iconData.mBlueprint = blueprint;

      const VTransform interpolated = entity->GetInterpolatedTransform(tickFraction);
      iconData.mWorldX = interpolated.pos_.x;
      iconData.mWorldY = interpolated.pos_.y;
      iconData.mWorldZ = interpolated.pos_.z;

      // `mIntelStateFlags` bit 0x08 ("health-valid") / bit 0x10
      // ("has-data"): both default true for non-`UserUnit` entities
      // (wrecks, props, ...), matching `isBusy_60`/`v49`'s init at
      // 0x0085BB60..0x0085BB74.
      constexpr std::uint32_t kIntelHealthValidMask = 0x08u;
      constexpr std::uint32_t kHasBlueprintIconDataMask = 0x10u;
      const bool selectedVariantEligible =
        asUnit == nullptr || (asUnit->mIntelStateFlags & kIntelHealthValidMask) != 0u;
      const bool hasFullBlueprintIconData =
        asUnit == nullptr || (asUnit->mIntelStateFlags & kHasBlueprintIconDataMask) != 0u;

      iconData.mIsFriendly =
        focusArmy == nullptr || focusArmy->IsAlly(static_cast<std::uint32_t>(entity->mArmy->mArmyIndex));

      iconData.mShowStunnedOverlay = asUnit != nullptr && asUnit->mUnitVarDat.mStunTicks != 0;
      iconData.mShowPausedOverlay = asUnit != nullptr && asUnit->mUnitVarDat.mIsPaused;

      if (focusArmy == nullptr || entity->mArmy == focusArmy) {
        if (mWldMap != nullptr && mWldMap->mTerrainRes != nullptr &&
            !mWldMap->mTerrainRes->IsInPlayableRect(interpolated.pos_)) {
          continue;
        }
      }

      if (iconData.mIsFriendly) {
        UserEntity* const attachmentParent = entity->GetAttachmentParent();
        if (attachmentParent != nullptr && attachmentParent->IsInCategory(msvc8::string("CARRIER"))) {
          continue;
        }
      } else if (asUnit != nullptr && asUnit->mUnitVarDat.mIsBusy && asUnit->GetBlueprint()->Air.CanFly) {
        continue;
      }

      // --- Lifebar collection gate (0x0085BFDB..0x0085C09F) -------------
      // The one producer of `mLifebarIcons`. Everything below is read in the
      // binary's own order; each early-out lands on the same 0x0085C0A4
      // continue as the icon test that follows.
      if (ui_RenderUnitBars && ui_LifebarLOD > currentZoomValue && !entity->mVariableData.mIsDead &&
          blueprint->mLifeBarRender != 0) {
        // Enemy units only get bars when their health is actually known
        // (`selectedVariantEligible`, intel bit 0x08), and then only if the
        // player forced enemy bars on or is hovering this unit. Friendly units
        // skip all three tests.
        bool eligible = iconData.mIsFriendly;
        if (!eligible && selectedVariantEligible) {
          eligible = ui_ForceLifbarsOnEnemy || entity == GetHoveredUserEntity();
        }

        if (eligible && asUnit != nullptr) {
          // A unit mid-upgrade is drawn by the upgrade progress UI instead
          // (slot 15, dispatched with `push 25h` at 0x0085C06B).
          const IUnit* const unitBridge = GetIUnitBridge(asUnit);
          const bool attachedAndHidden = !showAttachedUnitLifebars && asUnit->mUnitVarDat.mIsBusy;
          if (!unitBridge->IsUnitState(UNITSTATE_BeingUpgraded) && !attachedAndHidden &&
              unitBridge->GetBlueprint()->Display.HideLifebars == 0) {
            aux.mLifebarIcons.push_back(iconData);
          }
        }
      }

      if (!ui_NisRenderIcons || (!ui_RenderIcons && !iconData.mShowPausedOverlay) || entity->IsBeingBuilt()) {
        continue;
      }

      // When the unit's own mesh is already close enough to be visible
      // without help, skip the icon entirely for units that have full
      // intel data (or belong to an immobile blueprint under a focus
      // army) and aren't paused - everyone else still gets an icon.
      const bool skipWhenMeshVisible =
        (hasFullBlueprintIconData || (focusArmy != nullptr && !blueprint->IsMobile())) &&
        !iconData.mShowPausedOverlay;

      const RMeshBlueprint* const mesh = entity->mVariableData.mMeshBlueprint;
      if (mesh != nullptr && !ui_AlwaysRenderStrategicIcons) {
        const float fadeThreshold = std::min(mesh->mIconFadeInZoom, camera->GetMaxZoom() * 0.89f);
        if (fadeThreshold <= currentZoomValue) {
          if (skipWhenMeshVisible) {
            continue;
          }
          iconData.mSuppressBaseIcon = iconData.mShowPausedOverlay || iconData.mShowStunnedOverlay;
        }
      }

      const bool isHovered = entity == GetHoveredUserEntity();

      SSelectionSetUserEntity::FindResult selectionFind{};
      const bool isSelected =
        FindSelectionNodeByEntityGuarded(&selectionFind, &mSelection, entity)->mRes != mSelection.mHead;

      boost::shared_ptr<CD3DBatchTexture> icon =
        PickUnitStrategicIconTexture(aux, iconData, isSelected, selectedVariantEligible, isHovered);
      if (!icon) {
        continue;
      }
      iconData.mIconTexture = std::move(icon);

      if (iconData.mShowPausedOverlay) {
        iconData.mPausedTexture = aux.mPauseRestTexture;
      }
      if (iconData.mShowStunnedOverlay) {
        iconData.mStunnedTexture = aux.mStunnedRestTexture;
      }

      // The single dedicated "hovered unit" slot is part of the deferred
      // draw pass (see the function comment) - hovered units are excluded
      // from all four runs here, matching the binary, but nothing consumes
      // them yet.
      if (isHovered) {
        continue;
      }

      if (isSelected) {
        aux.mSelectedIcons.push_back(iconData);
        continue;
      }

      // Sort-priority byte < 'A' always wins the high-priority run
      // (0x0085C2C0..0x0085C2C7). At/above 'A' the binary default-
      // constructs a `WeakPtr_CD3DBatchTexture` and tests it - a
      // no-argument constructor is unconditionally empty, so that branch
      // is provably always false and always falls through to ground/air.
      if (blueprint->mStrategicIconSortPriority < static_cast<std::uint8_t>('A')) {
        aux.mHighPriorityIcons.push_back(iconData);
        continue;
      }

      if (asUnit != nullptr && asUnit->GetBlueprint()->Air.CanFly) {
        aux.mAirIcons.push_back(iconData);
      } else {
        aux.mGroundIcons.push_back(iconData);
      }
    }

    // --- Phase 4: draw the lifebar / label stack ------------------------
    // The icon-quad runs collected above are still drawn by the deferred
    // 0x0085D9A0 pass; this is the bar-and-label stack that follows it in
    // the binary (0x0085C890..0x0085C9DB).
    (void)primBatcher->Setup("TLifeBar");

    for (UnitIconData& lifebarIcon : aux.mLifebarIcons) {
      // The bar pass always writes both components before returning, on every
      // path; it is the label pass that may decline.
      Wm3::Vector2f labelCursor{};
      DrawUnitLifebars(lifebarIcon, labelCursor, aux);

      // Props and wrecks get bars but never labels - only a real unit can
      // carry a custom name or belong to a named selection set
      // (0x0085C915..0x0085C923).
      if (lifebarIcon.mUnit->IsUserUnit() == nullptr) {
        continue;
      }

      // A label that declined to draw returns the NaN sentinel, which leaves
      // the cursor where the bars left it so the next label still stacks
      // correctly (the caller-side isnan pair at 0x0085C973/0x0085C989).
      const Wm3::Vector2f afterCustomName = DrawUnitCustomNameLabel(lifebarIcon, aux, labelCursor, isMiniMap);
      if (IsValidScreenPoint(afterCustomName)) {
        labelCursor = afterCustomName;
      }

      // The selection-set name label (0x0085E3A0) stacks under this one and
      // is still deferred - see the function comment above.
    }

    primBatcher->Flush();
  }

  /**
   * Address: 0x008621B0 (FUN_008621B0,
   * ?RenderProjectileIcons@CWldSession@Moho@@QAEXPAVCameraImpl@2@PAVCRenderWorldView@2@PAVCD3DPrimBatcher@2@PAVCWldMap@2@M@Z)
   */
  void CWldSession::RenderProjectileIcons(
    CameraImpl* const camera,
    CRenderWorldView* const /*worldView*/,
    CD3DPrimBatcher* const primBatcher,
    CWldMap* const /*map*/,
    const float deltaSeconds
  )
  {
    const GeomCamera3& view = camera->CameraGetView();

    // Zoomed in past the strategic threshold the projectiles are drawn as real
    // meshes, so the icon pass is skipped entirely.
    if (camera->CameraGetTargetZoom() < UI_StrategicProjectileLOD) {
      return;
    }

    const float viewportWidth = static_cast<float>(static_cast<std::int32_t>(view.viewport.r[3].z));
    const float viewportHeight = static_cast<float>(static_cast<std::int32_t>(view.viewport.r[3].w));

    primBatcher->SetProjectionMatrix(MakeViewportPixelProjection(view));
    primBatcher->SetViewMatrix(VMatrix4::Identity());

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("primbatcher");
    device->SelectTechnique(kProjectileIconTechnique);
    CD3DPrimBatcherRuntimeView::FromBatcher(primBatcher)->mRebuildComposite = 0;

    const CategoryWordRangeView* const projectileCategory = mRules->GetEntityCategory("PROJECTILE");
    UserArmy* const focusArmy = GetFocusArmy();

    // The binary collects into a stack fastvector with a large inline buffer;
    // the heap-backed lane is behaviourally identical for a scratch list.
    gpg::fastvector<UserEntity*> visibleEntities{};
    auto* const spatialStorage = reinterpret_cast<SpatialDB_MeshInstance*>(GetEntitySpatialDbStorage());
    (void)spatialStorage->CollectInView(const_cast<GeomCamera3*>(&view), visibleEntities, ENTITYTYPE_Entity);

    for (UserEntity* const entity : visibleEntities) {
      if (entity == nullptr || entity->mVariableData.mIsDead) {
        continue;
      }

      // Entity ids are family-tagged in their top nibble; only the projectile
      // family gets an icon, which is cheaper than a category test per entity.
      if ((entity->mParams.mEntityId & kEntityFamilyMask) != kEntityFamilyProjectile) {
        continue;
      }

      const auto* const blueprint = reinterpret_cast<const RProjectileBlueprint*>(entity->mParams.mBlueprint);
      if (blueprint == nullptr) {
        continue;
      }
      if (projectileCategory == nullptr || !projectileCategory->mBits.Contains(blueprint->mCategoryBitIndex)) {
        continue;
      }

      const Wm3::Vec3f worldPosition = entity->GetInterpolatedTransform(deltaSeconds).pos_;

      // Own and allied projectiles are always drawn; everyone else's have to be
      // under recon cover, and an underwater projectile is checked against the
      // fog grid rather than the explored grid.
      if (focusArmy != nullptr && !focusArmy->IsAlly(static_cast<std::uint32_t>(entity->mArmy->mArmyIndex))
          && !focusArmy->CanSeePoint(
               worldPosition,
               (entity->mVariableData.mLayerMask & kLayerUnderwaterMask) != 0 ? UserArmy::EReconGridMask::Fog
                                                                 : UserArmy::EReconGridMask::Explored
             )) {
        continue;
      }

      boost::shared_ptr<CD3DBatchTexture> icon{};
      float halfWidth = 0.0f;
      float halfHeight = 0.0f;
      bool usesIconTexture = false;

      if (!blueprint->mStrategicIconName.empty()) {
        if (!UI_RenProjectileIcons) {
          continue;
        }
        icon = CD3DBatchTexture::FromFile(blueprint->mStrategicIconName.c_str(), 0u);
        if (!icon) {
          continue;
        }
        // Sized from the texture itself, so an icon is drawn at its authored
        // pixel size regardless of zoom.
        halfWidth = static_cast<float>(icon->mWidth >> 1u);
        halfHeight = static_cast<float>(icon->mHeight >> 1u);
        usesIconTexture = true;
        if (UI_RenProjectileGlow) {
          primBatcher->Flush();
          (void)primBatcher->Setup(kProjectileIconTechnique);
        }
      } else {
        UserArmy* const owningArmy = entity->mArmy;
        if (owningArmy == nullptr) {
          continue;
        }
        icon = CD3DBatchTexture::FromSolidColor(
          UI_forceWeaponsToYellow ? kProjectileForcedColor : owningArmy->mVarDat.mPlayerColorBgra
        );
        if (!icon) {
          continue;
        }
        halfWidth = blueprint->Display.StrategicIconSize * 0.5f;
        halfHeight = halfWidth;
      }

      primBatcher->SetTexture(icon);

      const Wm3::Vector2f projected = view.Project(worldPosition, 0.0f, viewportWidth, viewportHeight, 0.0f);
      // Snapped to whole pixels so the icon samples its texels 1:1.
      const float centerX = std::floor(projected.x);
      const float centerY = std::floor(projected.y);

      const float left = centerX - halfWidth;
      const float right = centerX + halfWidth;
      const float top = centerY - halfHeight;
      const float bottom = centerY + halfHeight;

      const CD3DPrimBatcher::Vertex topLeft{left, top, 1.0f, kProjectileIconColor, 0.0f, 1.0f};
      const CD3DPrimBatcher::Vertex topRight{left, bottom, 1.0f, kProjectileIconColor, 0.0f, 0.0f};
      const CD3DPrimBatcher::Vertex bottomRight{right, bottom, 1.0f, kProjectileIconColor, 1.0f, 0.0f};
      const CD3DPrimBatcher::Vertex bottomLeft{right, top, 1.0f, kProjectileIconColor, 1.0f, 1.0f};
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);

      if (!usesIconTexture || !UI_RenProjectileGlow) {
        continue;
      }

      // Glow pass: a second quad over the icon whose alpha pulses on a shared
      // global timer, so every projectile icon on screen pulses in step.
      primBatcher->Flush();
      (void)primBatcher->Setup("TCommandGlow");

      UI_CurGlowTime =
        (UI_CurGlowTime <= UI_RenProjectileGlowPeriod) ? UI_CurGlowTime + deltaSeconds : 0.0f;

      const float halfPeriod = UI_RenProjectileGlowPeriod * 0.5f;
      float glowFrom = UI_RenProjectileGlowMax;
      float glowTo = UI_RenProjectileGlowMin;
      float glowElapsed = UI_CurGlowTime;
      if (glowElapsed > halfPeriod) {
        glowFrom = UI_RenProjectileGlowMin;
        glowTo = UI_RenProjectileGlowMax;
        glowElapsed -= halfPeriod;
      }

      const float glow = (((glowFrom - glowTo) / halfPeriod) * glowElapsed) + glowTo;
      const std::uint32_t glowColor = static_cast<std::uint32_t>(static_cast<std::uint8_t>(glow * 255.0f)) << 24u;

      const CD3DPrimBatcher::Vertex glowTopLeft{right, top, 1.0f, glowColor, 1.0f, 1.0f};
      const CD3DPrimBatcher::Vertex glowTopRight{left, top, 1.0f, glowColor, 0.0f, 1.0f};
      const CD3DPrimBatcher::Vertex glowBottomRight{left, bottom, 1.0f, glowColor, 0.0f, 0.0f};
      const CD3DPrimBatcher::Vertex glowBottomLeft{right, bottom, 1.0f, glowColor, 1.0f, 0.0f};
      primBatcher->DrawQuad(glowTopLeft, glowTopRight, glowBottomRight, glowBottomLeft);
      primBatcher->Flush();
    }

    primBatcher->Flush();
  }

  namespace
  {
    /** "/env/common/splats/mass_strategic.dds" - literal at 0x00E47488. */
    constexpr const char* kMassStrategicSplat = "/env/common/splats/mass_strategic.dds";

    /** "/env/common/splats/hydrocarbon_strategic.dds" - literal at 0x00E474B0. */
    constexpr const char* kHydrocarbonStrategicSplat = "/env/common/splats/hydrocarbon_strategic.dds";

    /**
     * Splat quads are drawn unmodulated (`or eax, 0FFFFFFFFh` at 0x00862F63 /
     * 0x00863361 feeds all four vertex colour lanes); the tint lives in the
     * texture.
     */
    constexpr std::uint32_t kResourceSplatColor = 0xFFFFFFFFu;

    /**
     * A splat quad is half the texture's pixel size: both extents are the
     * dimension shifted right by two, i.e. width/4 either side of the centre
     * (`shr eax, 2` at 0x0086309D / 0x008630B9, and again at 0x00863298 /
     * 0x008632B4). The `fild` + negative fixup around each shift is the
     * unsigned-to-float conversion of the `std::uint32_t` dimension.
     */
    constexpr std::uint32_t kResourceSplatHalfExtentShift = 2u;

    /**
     * Address: 0x010C4340 (`shaderVarPrimBatcherTime`)
     *
     * What it does:
     * Returns the process-global `primbatcher` effect's `"time"` shader
     * variable. The binary registers it from a CRT static initialiser,
     * `register_ShaderVarPrimBatcherTime` (0x00BE6050,
     * `func_register_ShaderVar("time", &shaderVarPrimBatcherTime,
     * "primbatcher")`), and tears it down through the `atexit` hook at
     * 0x00C07480.
     *
     * The canonical home for this slot is `ShaderVar.cpp` next to
     * `register_ShaderVarPrimBatcherCompositeMatrix` / `...Texture1` /
     * `...AlphaMultiplier`; it is defined here as a function-local static
     * because this translation unit is its only reader so far. The lazy
     * registration is equivalent to the binary's CRT initialiser: nothing can
     * observe the slot before the first `RenderResources` call.
     */
    [[nodiscard]] ShaderVar& PrimBatcherTimeShaderVar()
    {
      static ShaderVar slot;
      static const bool registered = (RegisterShaderVar("time", &slot, "primbatcher"), true);
      (void)registered;
      return slot;
    }

    /**
     * Address: 0x0086309A..0x0086325A (mass splat run, inlined)
     * Address: 0x00863295..0x00863455 (hydrocarbon splat run, inlined)
     *
     * What it does:
     * Binds one strategic-resource splat texture and emits one screen-space
     * quad per collected deposit centre. The compiler emitted this twice, once
     * per resource kind, from what was plainly one helper: both runs compute
     * the same half-extents, bind through the same `SetTexture` overload and
     * build the same four vertices, differing only in which stack slots the
     * scheduler picked for them.
     *
     * A missing texture skips the whole run (`test ecx, ecx` / `jz` at
     * 0x00863092 and 0x0086328D), but an empty point list still binds the
     * texture - the count test comes after `SetTexture` in both runs.
     */
    void DrawResourceSplats(
      CD3DPrimBatcher& primBatcher,
      const boost::shared_ptr<CD3DBatchTexture>& splat,
      const gpg::fastvector<Wm3::Vector2f>& screenPoints
    )
    {
      if (!splat) {
        return;
      }

      const float halfWidth = static_cast<float>(splat->mWidth >> kResourceSplatHalfExtentShift);
      const float halfHeight = static_cast<float>(splat->mHeight >> kResourceSplatHalfExtentShift);
      primBatcher.SetTexture(splat);

      for (const Wm3::Vector2f& centre : screenPoints) {
        const float left = centre.X() - halfWidth;
        const float right = centre.X() + halfWidth;
        const float top = centre.Y() - halfHeight;
        const float bottom = centre.Y() + halfHeight;

        const CD3DPrimBatcher::Vertex topLeft{left, top, 0.0f, kResourceSplatColor, 0.0f, 0.0f};
        const CD3DPrimBatcher::Vertex bottomLeft{left, bottom, 0.0f, kResourceSplatColor, 0.0f, 1.0f};
        const CD3DPrimBatcher::Vertex bottomRight{right, bottom, 0.0f, kResourceSplatColor, 1.0f, 1.0f};
        const CD3DPrimBatcher::Vertex topRight{right, top, 0.0f, kResourceSplatColor, 1.0f, 0.0f};
        primBatcher.DrawQuad(topLeft, bottomLeft, bottomRight, topRight);
      }
    }
  } // namespace

  /**
   * Address: 0x00862A80 (FUN_00862A80, ?RenderResources@CWldSession@Moho@@QAEXPAVGeomCamera3@2@PAVCD3DPrimBatcher@2@@Z)
   *
   * IDA signature:
   * void __usercall Moho::CWldSession::RenderResources(Moho::CWldSession *this,
   *   Moho::GeomCamera3 *camera@<ecx>, Moho::CD3DPrimBatcher *primBatcher);
   *
   * What it does:
   * Draws the strategic-view mass and hydrocarbon splats. Binds the
   * `TResourceIcon` technique of the `primbatcher` effect, pushes the wall
   * clock into that effect's `time` variable, switches the batcher to the
   * pixel-exact screen projection, then asks the sim's resource registry for
   * every deposit whose terrain AABB intersects the camera's second frustum
   * solid. Each deposit that lies wholly inside the playable rect and whose
   * terrain-height centre is nearer than `UI_ResourceLODCutoff` is projected
   * to a whole screen pixel and bucketed by resource kind; the two buckets are
   * then drawn with their respective splat textures and flushed.
   *
   * Locals map, from the frame slots the disassembly actually uses (IDA's own
   * frame naming past 0x00862D3A is shifted 0x10 low because it does not model
   * the indirect `DepositCollides` call's argument purge, which is why the
   * decompile aliases unrelated slots onto one another):
   *   ebp-0x7F8 `gpg::fastvector_n<Wm3::Vector2f, 16>` hydrocarbon points
   *             (inline window ebp-0x7E8 .. ebp-0x768 = 0x80 bytes)
   *   ebp-0x768 `gpg::fastvector_n<Wm3::Vector2f, 64>` mass points
   *             (inline window ebp-0x758 .. ebp-0x558 = 0x200 bytes)
   *   ebp-0x558 `gpg::fastvector_n<ResourceDeposit, 64>` query output
   *             (inline window ebp-0x548 .. ebp-0x48  = 0x500 bytes)
   *   ebp-0x898 .. ebp-0x88C  the playable rect, copied out of `STIMap`
   *   ebp-0x8B0 .. ebp-0x8A8  the deposit centre (x, terrain height, z)
   *   ebp-0x8B8 / ebp-0x8B4   the floored screen pixel
   *   ebp-0x848 / ebp-0x850   the mass / hydrocarbon splat handles
   */
  void CWldSession::RenderResources(GeomCamera3* const camera, CD3DPrimBatcher* const primBatcher)
  {
    // 0x00862AA6..0x00862ACC: `D3D_GetDevice()->SelectFxFile("primbatcher")`,
    // `SelectTechnique("TResourceIcon")` and the composite-matrix invalidation
    // are `CD3DPrimBatcher::Setup` (0x00438560) inlined verbatim.
    (void)primBatcher->Setup("TResourceIcon");

    // The resource-icon shader animates off the process wall clock, not off a
    // sim tick - `gpg::time::GetSystemTimer().ElapsedSeconds()` at
    // 0x00862AD3/0x00862ADA.
    ShaderVar& timeShaderVar = PrimBatcherTimeShaderVar();
    const float shaderTime = gpg::time::GetSystemTimer().ElapsedSeconds();
    if (timeShaderVar.Exists()) {
      timeShaderVar.SetFloat(shaderTime);
    }

    // Raw viewport extents, not the whole-pixel truncation the projection
    // matrix below uses: 0x00862B18/0x00862B20 keep the untruncated floats and
    // 0x00862F42/0x00862F56 map NDC onto them.
    const float viewportWidth = camera->viewport.r[3].z;
    const float viewportHeight = camera->viewport.r[3].w;

    // `mWldMap->mTerrainRes` + 0x04 is the active `STIMap`; its playable rect
    // sits at +0x08 (0x00862B09..0x00862B4D reads all four bounds).
    const VisibilityRect& playableRect = mWldMap->mTerrainRes->mPlayableRectSource->mPlayableRect;

    primBatcher->SetProjectionMatrix(MakeViewportPixelProjection(*camera));
    primBatcher->SetViewMatrix(VMatrix4::Identity());

    IResources* const resources = mSimResources.px;
    CHeightField* const heightField = mWldMap->mTerrainRes->GetHeightField();

    // Declaration order is the binary's: the tail destroys the query output
    // first (0x008634DB), then the hydrocarbon bucket (0x00863512), then the
    // mass bucket (0x00863549).
    gpg::fastvector_n<Wm3::Vector2f, 64> massPoints;
    gpg::fastvector_n<Wm3::Vector2f, 16> hydrocarbonPoints;

    // The binary hands `DepositCollides` a 64-deposit inline fastvector. This
    // tree's `CSimResources::DepositCollides` takes the plain
    // `gpg::fastvector<T>` base and appends through that base's `PushBack`,
    // whose grow path frees `start_` unconditionally, so an inline window
    // cannot be handed across the call - heap-backed on purpose, same as the
    // projectile-arc `Collect` site.
    gpg::fastvector<ResourceDeposit> deposits;

    // Virtual dispatch through `IResources` slot 7 (`[vftable+0x1C]` at
    // 0x00862D2D..0x00862D3A). `kNone` asks for every deposit kind.
    resources->DepositCollides(&camera->solid2, heightField, &deposits, kNone);

    for (const ResourceDeposit& deposit : deposits) {
      const gpg::Rect2i& footprint = deposit.footprintRect;

      // Centre of the integer footprint, computed the binary's way: the extent
      // is differenced in integers first, then halved and re-based
      // (0x00862D8A..0x00862DC5).
      const float centreX =
        (static_cast<float>(footprint.x1 - footprint.x0) * 0.5f) + static_cast<float>(footprint.x0);
      const float centreZ =
        (static_cast<float>(footprint.z1 - footprint.z0) * 0.5f) + static_cast<float>(footprint.z0);

      // A deposit that pokes out of the playable rect is dropped whole, not
      // clipped (four signed compares at 0x00862DB1..0x00862DF4).
      if (footprint.x0 < playableRect.minX || playableRect.maxX < footprint.x1 ||
          footprint.z0 < playableRect.minZ || playableRect.maxZ < footprint.z1) {
        continue;
      }

      const Wm3::Vector3f centre{centreX, heightField->GetElevation(centreX, centreZ), centreZ};

      // Row 1 of the viewport matrix carries the renderer's LOD depth; splats
      // stop drawing past the cutoff (0x00862E15..0x00862E6F).
      if (camera->viewport.ProjectViewportDepthRow1(centre) <= UI_ResourceLODCutoff) {
        continue;
      }

      // 0x00862E75..0x00862F5F is `GeomCamera3::Project` (0x00470F60) inlined
      // over a viewport anchored at the origin with a flipped Y axis: x maps
      // onto [0, width] and y onto [height, -0]. The two zero terms fold away
      // in the emission, which is why no `sub`/`add` against them survives.
      const Wm3::Vector2f projected = camera->Project(centre, 0.0f, viewportWidth, viewportHeight, -0.0f);

      // Splats snap to whole pixels so the texture samples 1:1 (two `floor`
      // calls at 0x00862F81 / 0x00862F91).
      const Wm3::Vector2f screenPoint{std::floor(projected.X()), std::floor(projected.Y())};

      if (deposit.depositType == kMass) {
        massPoints.push_back(screenPoint);
      } else {
        hydrocarbonPoints.push_back(screenPoint);
      }
    }

    // Both handles stay alive until after the flush - the binary releases the
    // hydrocarbon one at 0x00863469 and the mass one at 0x008634A6, both past
    // `Flush`. The `1` border argument asks `FromFile` for a one-texel guard
    // band so the atlas neighbours cannot bleed into the splat.
    const boost::shared_ptr<CD3DBatchTexture> massSplat = CD3DBatchTexture::FromFile(kMassStrategicSplat, 1u);
    DrawResourceSplats(*primBatcher, massSplat, massPoints);

    const boost::shared_ptr<CD3DBatchTexture> hydrocarbonSplat =
      CD3DBatchTexture::FromFile(kHydrocarbonStrategicSplat, 1u);
    DrawResourceSplats(*primBatcher, hydrocarbonSplat, hydrocarbonPoints);

    primBatcher->Flush();
  }

  namespace
  {
    // The economy lanes below are per-tick rates and the overlay shows them per
    // second; the sim runs ten ticks a second (0x00DFF31C).
    constexpr float kEconOverlayTicksPerSecond = 10.0f;

    // Inside this magnitude the rate is printed with one decimal, outside it as
    // a whole number (0x008591FA / 0x0085927B against 0x00DFF31C / 0x00E4F910).
    constexpr float kEconOverlayDecimalCutoff = 10.0f;

    // Opaque black - the drop-shadow pass (pushed at 0x008597B9 / 0x008598A8).
    constexpr std::uint32_t kEconOverlayShadowColor = 0xFF000000u;

    // Unmodulated white - the bar slices carry their own texture colour.
    constexpr std::uint32_t kEconOverlayBarColor = 0xFFFFFFFFu;

    // The shadow pass is offset one pixel right and down (0x00DFEC20 == 1.0f).
    constexpr float kEconOverlayShadowOffset = 1.0f;

    // `/lua/ui/game/econoverlayparams.lua` lanes, in the order the import reads
    // them. Each is left at its previous value when the key is absent.
    std::uint32_t gEconOverlayPositiveColor = 0;                    // 0x00F57C00
    std::uint32_t gEconOverlayNegativeColor = 0;                    // 0x00F57BFC
    boost::shared_ptr<CD3DBatchTexture> gEconOverlayLeftTexture{};  // 0x010C4230
    boost::shared_ptr<CD3DBatchTexture> gEconOverlayRightTexture{}; // 0x010C4238
    boost::shared_ptr<CD3DBatchTexture> gEconOverlayMidTexture{};   // 0x010C4244
    msvc8::string gEconOverlayFontName{};                           // 0x00F5B210
    std::int32_t gEconOverlayFontSize = 0;                          // 0x00F57C04
    float gEconOverlayEnergyTopOffset = 0.0f;                       // 0x010A6458
    float gEconOverlayMassTopOffset = 0.0f;                         // 0x00F57C08

    bool gEconOverlayParamsImported = false;                        // 0x010A6449
    CD3DFont* gEconOverlayFont = nullptr;                           // 0x010C4228

    /**
     * Address: 0x00858850 (FUN_00858850, Moho::func_ImportEconOverlayParams)
     *
     * IDA signature:
     * void __cdecl func_ImportEconOverlayParams();
     *
     * What it does:
     * Imports `/lua/ui/game/econoverlayparams.lua` and copies the nine optional
     * `EconOverlayParams` fields into the lanes above. Every field is looked up
     * twice exactly as the binary does it: once for an `IsNil` probe on a
     * throwaway object, and again to read the value, so a missing key leaves
     * the previous value untouched.
     */
    void ImportEconOverlayParams()
    {
      LuaPlus::LuaState* const state = static_cast<CUIManager*>(UI_GetManager())->mLuaState;

      LuaPlus::LuaObject module = SCR_Import(state, "/lua/ui/game/econoverlayparams.lua");
      if (module.IsNil()) {
        return;
      }

      LuaPlus::LuaObject params = module["EconOverlayParams"];
      if (!params.IsTable()) {
        return;
      }

      if (!params["positiveColor"].IsNil()) {
        gEconOverlayPositiveColor = SCR_DecodeColor(state, params["positiveColor"]);
      }
      if (!params["negativeColor"].IsNil()) {
        gEconOverlayNegativeColor = SCR_DecodeColor(state, params["negativeColor"]);
      }
      if (!params["leftTexture"].IsNil()) {
        gEconOverlayLeftTexture = CD3DBatchTexture::FromFile(params["leftTexture"].GetString(), 1u);
      }
      if (!params["midTexture"].IsNil()) {
        gEconOverlayMidTexture = CD3DBatchTexture::FromFile(params["midTexture"].GetString(), 1u);
      }
      if (!params["rightTexture"].IsNil()) {
        gEconOverlayRightTexture =
          CD3DBatchTexture::FromFile(params["rightTexture"].GetString(), 1u);
      }
      if (!params["fontName"].IsNil()) {
        const char* const fontName = params["fontName"].GetString();
        (void)gEconOverlayFontName.assign(fontName, std::strlen(fontName));
      }
      if (!params["fontSize"].IsNil()) {
        gEconOverlayFontSize = static_cast<std::int32_t>(params["fontSize"].GetNumber());
      }
      if (!params["energyTopOffset"].IsNil()) {
        gEconOverlayEnergyTopOffset = static_cast<float>(params["energyTopOffset"].GetNumber());
      }
      if (!params["massTopOffset"].IsNil()) {
        gEconOverlayMassTopOffset = static_cast<float>(params["massTopOffset"].GetNumber());
      }
    }

    /**
     * What it does:
     * Formats one per-second resource rate into `out` the way the overlay does
     * it at 0x008591E3 and 0x00859275: one decimal while the magnitude stays
     * inside +/-10, a whole number outside it. NaN takes the whole-number path,
     * because the binary branches on an unordered `comiss`.
     *
     * The binary prints into a temporary and then assigns that temporary into
     * the caller's string; kept in that shape so the temporary's storage is
     * released before the draw, as in the binary.
     */
    void FormatEconomyRateInto(
      msvc8::string& out,
      const float ratePerSecond,
      const char* const wholeFormat,
      const char* const decimalFormat
    )
    {
      const bool useDecimals =
        kEconOverlayDecimalCutoff > ratePerSecond && ratePerSecond > -kEconOverlayDecimalCutoff;
      const msvc8::string formatted =
        useDecimals ? gpg::STR_Printf(decimalFormat, static_cast<double>(ratePerSecond))
                    : gpg::STR_Printf(wholeFormat, static_cast<std::int32_t>(ratePerSecond));
      (void)out.assign(formatted, 0, msvc8::string::npos);
    }

    /**
     * What it does:
     * Emits one axis-aligned, fully-mapped quad of the economy bar. The three
     * slice draws at 0x0085952E, 0x00859659 and 0x0085977F write byte-identical
     * vertex blocks apart from the x range, so they share this helper.
     */
    void DrawEconomyOverlaySlice(
      CD3DPrimBatcher& primBatcher, const float x0, const float y0, const float x1, const float y1
    )
    {
      const CD3DPrimBatcher::Vertex topLeft{x0, y0, 0.0f, kEconOverlayBarColor, 0.0f, 0.0f};
      const CD3DPrimBatcher::Vertex topRight{x1, y0, 0.0f, kEconOverlayBarColor, 1.0f, 0.0f};
      const CD3DPrimBatcher::Vertex bottomRight{x1, y1, 0.0f, kEconOverlayBarColor, 1.0f, 1.0f};
      const CD3DPrimBatcher::Vertex bottomLeft{x0, y1, 0.0f, kEconOverlayBarColor, 0.0f, 1.0f};
      primBatcher.DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }

    /**
     * What it does:
     * Draws one economy number. `Render2D`'s two trailing floats are not
     * materialised at the binary's call sites (0x008597FB, 0x00859877,
     * 0x008598E5 and 0x00859961 push only this/text/colour and hand the origin
     * over in `eax`), and the recovered `Render2D` ignores `maxAdvance` while
     * `Render` ignores `glyphScale`, so both are passed as zero here.
     */
    void DrawEconomyOverlayLabel(
      CD3DFont& font,
      CD3DPrimBatcher& primBatcher,
      const msvc8::string& text,
      const float x,
      const float y,
      const std::uint32_t color
    )
    {
      const Wm3::Vector2f origin{x, y};
      font.Render2D(text.c_str(), &primBatcher, origin, color, 0.0f, 0.0f);
    }
  } // namespace

  /**
   * Address: 0x00858D80 (FUN_00858D80, Moho::CWldSession::DrawEconomyOverlay)
   *
   * IDA signature:
   * void __usercall Moho::CWldSession::DrawEconomyOverlay(
   *   CWldSession *session, CD3DPrimBatcher *batcher, CWldMap *map,
   *   CameraImpl *camera@<ecx>);
   *
   * What it does:
   * Draws the net energy/mass rate readout over every army unit in the camera
   * frustum - see the header for the full description.
   */
  void CWldSession::DrawEconomyOverlay(
    CameraImpl* const camera, CD3DPrimBatcher* const primBatcher, [[maybe_unused]] CWldMap* const map
  )
  {
    if (!DisplayEconomyOverlay) {
      return;
    }

    if (!gEconOverlayParamsImported) {
      ImportEconOverlayParams();
      gEconOverlayParamsImported = true;
    }

    if (gEconOverlayFont == nullptr) {
      // `Create` hands back a borrowed shared lane; the overlay keeps its own
      // intrusive reference on the font and releases the lane straight away.
      boost::SharedPtrRaw<CD3DFont> created =
        CD3DFont::Create(gEconOverlayFontSize, gEconOverlayFontName.c_str());
      CD3DFont* const font = created.px;
      if (gEconOverlayFont != font) {
        if (gEconOverlayFont != nullptr) {
          (void)gEconOverlayFont->ReleaseReference();
        }
        gEconOverlayFont = font;
        if (font != nullptr) {
          font->AddReference();
        }
      }
      created.release();
    }

    (void)primBatcher->Setup("TAlphaBlendLinearSampleNoDepth");

    const GeomCamera3& view = camera->CameraGetView();

    // The binary inlines the same pixel-exact screen projection here that
    // RenderProjectileArcs inlines at 0x0086010B; it lives on GeomCamera3 now.
    const float viewportWidth = static_cast<float>(static_cast<std::int32_t>(view.viewport.r[3].z));
    const float viewportHeight = static_cast<float>(static_cast<std::int32_t>(view.viewport.r[3].w));

    primBatcher->SetProjectionMatrix(MakeViewportPixelProjection(view));
    primBatcher->SetViewMatrix(VMatrix4::Identity()); // 0x00858FE6 (sIdentity)

    CameraFrustumUserEntityList* const frustumUnits = camera->GetArmyUnitsInFrustum();
    for (CameraUserEntityWeakRef* weakRef = frustumUnits->mStart; weakRef != frustumUnits->mFinish;
         ++weakRef) {
      UserEntity* const entity = DecodeCameraFrustumWeakRef(*weakRef);
      if (entity == nullptr) {
        continue;
      }

      UserUnit* const unit = entity->IsUserUnit();
      if (unit == nullptr) {
        continue;
      }

      IUnit* const unitBridge = GetIUnitBridge(unit);
      if (unitBridge->IsDead() || unitBridge->DestroyQueued()) {
        continue;
      }

      // Only units still drawn as meshes get the readout: past the mesh's
      // icon-fade-in depth the unit is a strategic icon and the bar would
      // clutter the map.
      const RMeshBlueprint* const meshBlueprint = unit->mVariableData.mMeshBlueprint;
      if (meshBlueprint == nullptr) {
        continue;
      }
      if (view.viewport.ProjectViewportDepthRow1(unitBridge->GetPosition())
          >= meshBlueprint->mIconFadeInZoom) {
        continue;
      }

      // The binary dispatches through the blueprint accessor here and discards
      // the result (0x008590CF); kept because the virtual call is observable.
      (void)unitBridge->GetBlueprint();

      const SSTIUnitEconomyPair& produced = unit->mUnitVarDat.mProduced;
      const SSTIUnitEconomyPair& upkeep = unit->mUnitVarDat.mMaintainenceCost;
      const float energyRate = produced.ENERGY - upkeep.ENERGY;
      const float massRate = produced.MASS - upkeep.MASS;
      if (energyRate == 0.0f && massRate == 0.0f) {
        continue;
      }

      const float energyPerSecond = energyRate * kEconOverlayTicksPerSecond;
      const float massPerSecond = massRate * kEconOverlayTicksPerSecond;

      // Not a parameter: the binary reads a frame local at -4 that is stored
      // once from a zeroed ebx (0x00858DAF -> 0x00858E0E) and never rewritten,
      // so the overlay always samples the untick-interpolated position.
      const Wm3::Vector3f worldPosition = entity->GetInterpolatedPosition(0.0f);
      const Wm3::Vector2f screenPosition =
        view.Project(worldPosition, 0.0f, viewportWidth, viewportHeight, 0.0f);

      msvc8::string energyText{};
      msvc8::string massText{};
      FormatEconomyRateInto(energyText, energyPerSecond, "%+4i ", "%+4.1f ");
      FormatEconomyRateInto(massText, massPerSecond, "%+4i", "%+4.1f");

      // The bar is as wide as the wider of the two numbers and as tall as the
      // middle slice, centred on the projected position and snapped to whole
      // pixels.
      const float energyAdvance = gEconOverlayFont->GetAdvance(energyText.c_str(), 0);
      const float massAdvance = gEconOverlayFont->GetAdvance(massText.c_str(), 0);
      const float barWidth = massAdvance > energyAdvance ? massAdvance : energyAdvance;
      const float barHeight = static_cast<float>(gEconOverlayMidTexture->mHeight);

      const float barLeft = std::floor(screenPosition.x - (barWidth * 0.5f));
      const float barTop = std::floor(screenPosition.y - (barHeight * 0.5f));
      const float barRight = barLeft + barWidth;
      const float barBottom = barTop + barHeight;

      primBatcher->SetTexture(gEconOverlayMidTexture);
      DrawEconomyOverlaySlice(*primBatcher, barLeft, barTop, barRight, barBottom);

      primBatcher->SetTexture(gEconOverlayLeftTexture);
      const float leftCapWidth = static_cast<float>(gEconOverlayLeftTexture->mWidth);
      DrawEconomyOverlaySlice(*primBatcher, barLeft - leftCapWidth, barTop, barLeft, barBottom);

      primBatcher->SetTexture(gEconOverlayRightTexture);
      const float rightCapWidth = static_cast<float>(gEconOverlayRightTexture->mWidth);
      DrawEconomyOverlaySlice(*primBatcher, barRight, barTop, barRight + rightCapWidth, barBottom);

      // Each number is drawn twice: an opaque black shadow one pixel down and
      // right, then the value itself in the sign colour.
      const float fontHeight = gEconOverlayFont->mHeight;
      const float energyBaseline = std::floor(gEconOverlayEnergyTopOffset) + fontHeight + barTop;
      const float massBaseline = std::floor(gEconOverlayMassTopOffset) + fontHeight + barTop;
      const std::uint32_t energyColor =
        energyPerSecond < 0.0f ? gEconOverlayNegativeColor : gEconOverlayPositiveColor;
      const std::uint32_t massColor =
        massPerSecond < 0.0f ? gEconOverlayNegativeColor : gEconOverlayPositiveColor;

      DrawEconomyOverlayLabel(
        *gEconOverlayFont,
        *primBatcher,
        energyText,
        barLeft + kEconOverlayShadowOffset,
        energyBaseline + kEconOverlayShadowOffset,
        kEconOverlayShadowColor
      );
      DrawEconomyOverlayLabel(
        *gEconOverlayFont, *primBatcher, energyText, barLeft, energyBaseline, energyColor
      );
      DrawEconomyOverlayLabel(
        *gEconOverlayFont,
        *primBatcher,
        massText,
        barLeft + kEconOverlayShadowOffset,
        massBaseline + kEconOverlayShadowOffset,
        kEconOverlayShadowColor
      );
      DrawEconomyOverlayLabel(
        *gEconOverlayFont, *primBatcher, massText, barLeft, massBaseline, massColor
      );
    }

    primBatcher->Flush();
  }

  namespace
  {
    /**
     * Address: 0x0088BEE0 (FUN_0088BEE0, Moho::func_DoPreload)
     *
     * IDA signature:
     * void func_DoPreload();
     *
     * What it does:
     * Drives the world-session `Preload` frame action: tears down any active
     * world-session runtime, saves user preferences, restarts the in-game UI
     * lane on the active Lua state, opens the world UI provider's loading
     * dialog, asks the session loader to prefetch the pending session's
     * scenario, installs the no-op `IClientMgrUIInterface` bootstrap on the
     * pending session's client manager, and transitions the world-frame
     * dispatch lane to `Loading`. The bracketing ` DoPreload 1` / ` DoPreload
     * 2` `std::string` temporaries match the binary's profiler-marker shape
     * (built and immediately destroyed with no consumer in the retail body).
     */
    void WLD_DoPreload()
    {
      // ` DoPreload 1` bracket marker: the retail binary constructs one
      // 12-byte `std::string` literal here purely as a profiler/log marker
      // and discards it immediately. Preserved 1:1 to keep observable
      // string-allocation side effects (operator new/delete pair when the
      // SSO threshold would be exceeded) identical to the binary.
      {
        const std::string marker(" DoPreload 1", 12u);
        (void)marker;
      }

      WLD_Teardown();
      USER_SavePreferences();

      LuaPlus::LuaState* const state = USER_GetLuaState();
      (void)UI_StartGameUI(state);

      if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
        wldUIProvider->StartLoadingDialog();
      }

      CWldSessionLoaderImpl* const loader = GetWldSessionLoader();
      SWldSessionInfo* const pendingSession = gPendingWldSessionInfo;
      if (loader != nullptr && pendingSession != nullptr) {
        LaunchInfoBase* const launchInfo = pendingSession->mLaunchInfo.get();
        if (launchInfo != nullptr) {
          // Binary slot 2 dispatch on `IWldSessionLoader` is
          // `GetScenarioInfo(mapName, &mGameMods, setGameData)`. The retail
          // call site at 0x0088BF52 only pushes 2 args; the third dword
          // consumed by the callee's `retn 0Ch` is whatever stale stack
          // value sits at `[esp+8]`. Recover as a 3-arg invocation with the
          // setGameData lane wired to the prefetch-then-mark semantics the
          // preload action needs (mark the requested scenario as the active
          // game-data target before the `Loading` action begins iterating
          // on it).
          (void)loader->GetScenarioInfo(
            pendingSession->mMapName.raw_data_unsafe(), &launchInfo->mGameMods, true
          );
        }
      }

      if (pendingSession != nullptr && pendingSession->mClientManager != nullptr) {
        pendingSession->mClientManager->SetUIInterface(GetClientMgrUiInterfaceBootstrap());
      }

      gWldFrameAction = EWldFrameAction::Loading;

      // ` DoPreload 2` bracket marker (paired with the opening marker
      // above): same profiler/log-string discard pattern.
      {
        const std::string marker(" DoPreload 2", 12u);
        (void)marker;
      }
    }

    /**
     * Address: 0x0088C000 (FUN_0088C000, func_DoLoading)
     *
     * IDA signature:
     * void __cdecl func_DoLoading(bool *outContinue);
     *
     * What it does:
     * Drives the world-session `Loading` frame action. Every frame it beats the
     * client manager; once the loader reports the scenario in hand it takes
     * ownership of the loaded Lua state / game rules / map, builds the session,
     * gives the launch info its own copy of the playable map and the player's
     * language, opens the replay sink when the session is recorded, creates the
     * sim driver, and hands the frame machine on to `Initialize`.
     *
     * This transition is the whole point of the function. Until it was
     * recovered, `Loading` fell through to `CreateSession` - a state that in
     * the binary only exists for an explicit restart request - and
     * `WLD_CreateSessionInfo` bounced straight back to `Preload`, so a skirmish
     * cycled Preload -> Loading -> CreateSession forever, restarting the
     * in-game UI and reopening the loading movie on every lap.
     *
     * The bracketing ` DoLoading N` `std::string` temporaries are the binary's
     * profiler markers: built and immediately discarded, kept for the identical
     * allocation side effects.
     */
    void WLD_DoLoading(bool* const outContinue)
    {
      {
        const std::string marker(" DoLoading 1", 12u);
        (void)marker;
      }

      SWldSessionInfo* const sessionInfo = gPendingWldSessionInfo;
      if (sessionInfo != nullptr && sessionInfo->mClientManager != nullptr) {
        sessionInfo->mClientManager->DoBeat();
      }

      CWldSessionLoaderImpl* const loader = GetWldSessionLoader();
      if (loader == nullptr || !loader->IsLoaded()) {
        return;
      }

      {
        const std::string marker(" DoLoading 2", 12u);
        (void)marker;
      }

      SWldGameData gameData{};
      (void)loader->LoadGameData(&gameData);

      if (gameData.mGameRules == nullptr) {
        gpg::Warnf("map %s failed.  aborting session.", sessionInfo->mMapName.c_str());
        if (gWldFrameAction != EWldFrameAction::Inactive) {
          gWldFrameAction = EWldFrameAction::Exit;
        }
        if (outContinue != nullptr) {
          *outContinue = true;
        }
        ReleaseWldGameDataHandles(&gameData);
        return;
      }

      // The replay sink, when this session records one. A sink that cannot be
      // opened is not fatal - the session simply stops being a recorded one.
      msvc8::auto_ptr<gpg::Stream> replayStream(nullptr);
      if (sessionInfo->mIsBeingRecorded) {
        const msvc8::string defaultReplayName = Loc(USER_GetLuaState(), "<LOC Engine0030>LastGame");
        replayStream = VCR_CreateReplay(sessionInfo, defaultReplayName.c_str());
        if (replayStream.get() == nullptr) {
          sessionInfo->mIsBeingRecorded = false;
        }
      }

      {
        const std::string marker(" DoLoading 3");
        (void)marker;
      }

      msvc8::auto_ptr<LuaPlus::LuaState> stateOwner(gameData.mState);
      msvc8::auto_ptr<RRuleGameRules> rulesOwner(gameData.mGameRules);
      msvc8::auto_ptr<CWldMap> mapOwner(gameData.mWldMap);
      gameData = SWldGameData{};
      CWldSession* const wldSession = WLD_CreateSession(stateOwner, rulesOwner, mapOwner, *sessionInfo);

      // The launch info keeps its own copy of the playable map so a restart can
      // rebuild the session without the terrain resource still being alive.
      auto* const playableMap =
        reinterpret_cast<STIMap*>(wldSession->mWldMap->mTerrainRes->mPlayableRectSource);
      STIMap* const launchMap = new STIMap(playableMap);

      LaunchInfoBase* const launchInfo = sessionInfo->mLaunchInfo.get();
      launchInfo->mGameRules = wldSession->mRules;
      if (launchMap != launchInfo->mMap && launchInfo->mMap != nullptr) {
        delete launchInfo->mMap;
      }
      launchInfo->mMap = launchMap;

      launchInfo->mLanguage.assign_owned(wldSession->mState->GetGlobal("__language").ToString());

      if (!wldSession->IsMultiplayer && !wldSession->IsReplay) {
        // Single player: the session takes a shared owner on a fresh clone of
        // the launch info, which is what a mid-game save serializes.
        boost::SharedPtrRaw<void> createdLaunchInfo{};
        launchInfo->Create(createdLaunchInfo);

        boost::SharedPtrRaw<LaunchInfoBase> createdTyped{};
        createdTyped.px = static_cast<LaunchInfoBase*>(createdLaunchInfo.px);
        createdTyped.pi = createdLaunchInfo.pi;
        wldSession->mLaunchInfo = boost::SharedPtrFromRawRetained(createdTyped);
        createdLaunchInfo.release();
      }

      {
        const std::string marker(" DoLoading 4");
        (void)marker;
      }

      if (LaunchInfoNew* const newLaunchInfo = launchInfo->GetNew(); newLaunchInfo != nullptr) {
        newLaunchInfo->mProps = wldSession->mWldMap->mProps;
      }

      {
        const std::string marker(" DoLoading 5");
        (void)marker;
      }

      // Ownership of both the client manager and the replay sink moves into the
      // driver; the session info gives its client manager up here.
      IClientManager* const clientManager = sessionInfo->mClientManager;
      sessionInfo->mClientManager = nullptr;
      ISTIDriver* const previousDriver = SIM_GetActiveDriver();
      // `SIM_CreateDriver` publishes the new driver into the same global lane
      // the binary assigns here, so the previous one is released afterwards.
      (void)SIM_CreateDriver(
        static_cast<CClientManagerImpl*>(clientManager),
        replayStream.release(),
        sessionInfo->mLaunchInfo,
        sessionInfo->mSourceId
      );
      if (previousDriver != nullptr) {
        delete previousDriver;
      }

      gWldFrameAction = EWldFrameAction::Initialize;
      if (outContinue != nullptr) {
        *outContinue = true;
      }

      {
        const std::string marker(" DoLoading 6");
        (void)marker;
      }

      ReleaseWldGameDataHandles(&gameData);
    }

    /**
     * Address: 0x0088C3F0 (FUN_0088C3F0, func_DoInitializing)
     *
     * What it does:
     * Waits for the sim to publish its first sync data, then performs the whole
     * loading-to-playing handover: starts the game Lua UI, takes down the
     * loading dialog, builds the in-game interface, drops the now-consumed
     * session info, runs the loader's teardown callbacks, and finally tells the
     * client manager that this client has finished loading.
     */
    void WLD_DoInitializing(bool* const outContinue)
    {
      ISTIDriver* const simDriver = SIM_GetActiveDriver();
      if (simDriver == nullptr) {
        if (outContinue != nullptr) {
          *outContinue = false;
        }
        gWldFrameAction = EWldFrameAction::Exit;
        return;
      }

      simDriver->Dispatch();
      if (!simDriver->HasSyncData()) {
        return;
      }

      CWldSession* const session = gActiveWldSession;
      if (session != nullptr && session->mState != nullptr) {
        (void)UI_StartGameUI(session->mState);
      }

      // Apply the first sync payload. This has to happen before
      // `CreateGameInterface` below: the packet carries the initial armies and
      // entities, and the in-game UI reads them as it builds.
      if (session != nullptr) {
        SSyncData* syncData = nullptr;
        simDriver->GetSyncData(syncData);
        session->DoBeat(msvc8::auto_ptr<SSyncData>(syncData));
      }

      IWldUIProvider* const wldUIProvider = ResolveWldUIProvider();
      if (wldUIProvider != nullptr) {
        wldUIProvider->StopLoadingDialog();
      }

      if (wldUIProvider != nullptr) {
        wldUIProvider->CreateGameInterface(gPendingWldSessionInfo != nullptr && gPendingWldSessionInfo->mIsReplay);
      }

      // The session info existed only to carry launch parameters into the
      // session; the session owns everything it needed by now.
      if (SWldSessionInfo* const consumedSessionInfo = gPendingWldSessionInfo; consumedSessionInfo != nullptr) {
        consumedSessionInfo->~SWldSessionInfo();
        ::operator delete(consumedSessionInfo);
      }
      gPendingWldSessionInfo = nullptr;

      (void)WLD_DispatchOnTeardownCallbacksCoreFromGlobalList();

      // Declare this client ready. `CClientManagerImpl::Cleanup` is the only
      // writer of `mWeAreReady`, which `DoBeat` needs before it will ever set
      // `mEveryoneIsReady` - so without this the session sits in Waiting
      // forever showing "waiting for other players", local game or not.
      if (CClientManagerImpl* const clientManager = simDriver->GetClientManager(); clientManager != nullptr) {
        clientManager->Cleanup();
      }

      if (outContinue != nullptr) {
        *outContinue = false;
      }
      gWldFrameAction = EWldFrameAction::PostInitialize;
    }

    /**
     * Address: 0x0088BFD0 (FUN_0088BFD0)
     *
     * What it does:
     * Signals one trailing post-init sim-driver lane, transitions world-frame
     * dispatch to `Playing`, and notifies the active world-UI provider through
     * `OnStart` when present.
     */
    int WLD_EnterPlayingAndNotifyUIProvider()
    {
      int dispatchResult = 0;
      if (ISTIDriver* const simDriver = SIM_GetActiveDriver(); simDriver != nullptr) {
        simDriver->DecrementOutstandingRequestsAndSignal();
      }

      gWldFrameAction = EWldFrameAction::Playing;

      if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
        wldUIProvider->OnStart();
      }

      return dispatchResult;
    }

    /**
     * Address: 0x0088C6D0 (FUN_0088C6D0, func_DoPostInitializing)
     *
     * What it does:
     * Dispatches post-init sim/network work, transitions to playing once every
     * client is ready, and toggles waiting-dialog UI lanes during the handoff.
     */
    void WLD_DoPostInitializing(bool* const outContinue)
    {
      if (outContinue != nullptr) {
        *outContinue = false;
      }

      ISTIDriver* const simDriver = SIM_GetActiveDriver();
      if (simDriver == nullptr) {
        gWldFrameAction = EWldFrameAction::Exit;
        return;
      }

      simDriver->Dispatch();
      CClientManagerImpl* const clientManager = simDriver->GetClientManager();
      if (clientManager != nullptr && clientManager->IsEveryoneReady()) {
        simDriver->DecrementOutstandingRequestsAndSignal();
        gWldFrameAction = EWldFrameAction::Playing;
        if (outContinue != nullptr) {
          *outContinue = true;
        }
        if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
          wldUIProvider->OnStart();
        }
      } else {
        if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
          wldUIProvider->StartWaitingDialog();
        }
        gWldFrameAction = EWldFrameAction::Waiting;
      }
    }

    /**
     * Address: 0x0088C750 (FUN_0088C750, func_DoWaiting)
     *
     * What it does:
     * Dispatches waiting-state sim/network work, transitions to playing when
     * all peers are ready, and fires waiting-dialog stop/start UI callbacks.
     */
    void WLD_DoWaiting(bool* const outContinue)
    {
      if (outContinue != nullptr) {
        *outContinue = false;
      }

      ISTIDriver* const simDriver = SIM_GetActiveDriver();
      if (simDriver == nullptr) {
        gWldFrameAction = EWldFrameAction::Exit;
        return;
      }

      simDriver->Dispatch();
      CClientManagerImpl* const clientManager = simDriver->GetClientManager();
      if (clientManager != nullptr && clientManager->IsEveryoneReady()) {
        if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
          wldUIProvider->StopWaitingDialog();
        }

        simDriver->DecrementOutstandingRequestsAndSignal();
        gWldFrameAction = EWldFrameAction::Playing;

        if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
          wldUIProvider->OnStart();
        }

        if (outContinue != nullptr) {
          *outContinue = true;
        }
      } else {
        (void)UI_UpdateDisconnectDialogCallback();
      }
    }

    /**
     * Address: 0x0088C7C0 (FUN_0088C7C0, func_DoPlayingAction)
     *
     * What it does:
     * Dispatches one sim-driver tick, hands the current world camera set to
     * the sim driver, runs one world-session frame, fires the trailing
     * sim-driver post-frame slot, and pumps the disconnect dialog callback.
     */
    void WLD_DoPlayingAction(const float deltaSeconds)
    {
      if (ISTIDriver* const simDriver = SIM_GetActiveDriver(); simDriver != nullptr) {
        simDriver->Dispatch();

        // Snapshot every active GeomCamera and forward to the sim driver so
        // visibility/projection state matches the upcoming session frame.
        const msvc8::vector<GeomCamera3> cameras = CAM_GetAllCameras();
        simDriver->SetGeomCams(cameras);
      }

      if (CWldSession* const activeSession = WLD_GetActiveSession(); activeSession != nullptr) {
        activeSession->SessionFrame(deltaSeconds);
      }

      if (ISTIDriver* const simDriver = SIM_GetActiveDriver(); simDriver != nullptr) {
        // Trailing sim-driver post-frame slot (Func1 in IDA): currently
        // a NoOp until full ISTIDriver vtable slot ownership is recovered.
        simDriver->NoOp();
      }

      (void)UI_UpdateDisconnectDialogCallback();
    }

    void WLD_CreateSessionInfo()
    {
      // Full `FUN_0088C9D0` session-info recreation still depends on
      // unrecovered LaunchInfoNew/session bootstrap ownership lanes.
      gWldFrameAction = EWldFrameAction::Preload;
    }
  } // namespace

  /**
   * Address: 0x0088BD20 (FUN_0088BD20, ?WLD_SetUIProvider@Moho@@YAXPAVIWldUIProvider@1@@Z)
   *
   * What it does:
   * Replaces the process-global world-UI provider ownership lane, deleting the
   * previous provider when it differs from the new one.
   */
  void WLD_SetUIProvider(IWldUIProvider* const provider)
  {
    if (sWldUIProvider != provider && sWldUIProvider != nullptr) {
      delete sWldUIProvider;
    }

    sWldUIProvider = provider;
  }

  EWldFrameAction WLD_GetFrameAction()
  {
    return gWldFrameAction;
  }

  void WLD_SetFrameAction(const EWldFrameAction action)
  {
    gWldFrameAction = action;
  }

  /**
   * Address: 0x0088BE80 (FUN_0088BE80, ?WLD_IsSessionActive@Moho@@YA_NXZ)
   *
   * What it does:
   * Returns whether world-frame dispatch is currently active.
   */
  bool WLD_IsSessionActive()
  {
    return gWldFrameAction != EWldFrameAction::Inactive;
  }

  /**
   * Address: 0x0088BE90 (FUN_0088BE90, world-frame playing-state probe)
   *
   * What it does:
   * Returns whether world-frame dispatch is currently in the `Playing` state.
   */
  bool WLD_IsSessionPlaying()
  {
    return gWldFrameAction == EWldFrameAction::Playing;
  }

  /**
   * Address: 0x0088BEA0 (FUN_0088BEA0, ?WLD_RequestEndSession@Moho@@YAXXZ)
   *
   * What it does:
   * Requests world-session exit when frame dispatch is currently active.
   */
  void WLD_RequestEndSession()
  {
    if (gWldFrameAction != EWldFrameAction::Inactive) {
      gWldFrameAction = EWldFrameAction::Exit;
    }
  }

  /**
   * Address: 0x0088E6F0 (FUN_0088E6F0)
   *
   * What it does:
   * Console-command callback that requests world-session exit when frame
   * dispatch is currently active.
   */
  void CON_WLD_RequestEndSession(void* const commandArgs)
  {
    (void)commandArgs;

    if (gWldFrameAction != EWldFrameAction::Inactive) {
      gWldFrameAction = EWldFrameAction::Exit;
    }
  }

  /**
   * Address: 0x0088BEC0 (FUN_0088BEC0, ?WLD_RequestRestartSession@Moho@@YAXXZ)
   *
   * What it does:
   * Requests world-session recreation when frame dispatch is active and the
   * active session carries restart launch info.
   */
  void WLD_RequestRestartSession()
  {
    if (gWldFrameAction == EWldFrameAction::Inactive) {
      return;
    }

    CWldSession* const activeSession = WLD_GetActiveSession();
    if (activeSession != nullptr && activeSession->mLaunchInfo) {
      gWldFrameAction = EWldFrameAction::CreateSession;
    }
  }

  /**
   * Address: 0x0088C9C0 (FUN_0088C9C0)
   *
   * What it does:
   * Tears down the current world session and then enters the front-end flow.
   */
  [[nodiscard]] bool WLD_TeardownAndStartFrontEnd()
  {
    WLD_Teardown();
    return UI_StartFrontEnd();
  }

  /**
   * Address: 0x0088CAE0 (FUN_0088CAE0, ?WLD_Frame@Moho@@YA_NM@Z)
   */
  bool WLD_Frame(const float deltaSeconds)
  {
    if (CWldSessionLoaderImpl* const loader = GetWldSessionLoader(); loader != nullptr) {
      loader->Update();
    }

    for (;;) {
      bool continueDispatch = false;
      switch (gWldFrameAction) {
        case EWldFrameAction::Inactive:
          if (CWldSessionLoaderImpl* const loader = GetWldSessionLoader(); loader != nullptr) {
            loader->SetCreated();
          }
          return true;
        case EWldFrameAction::Preload:
          WLD_DoPreload();
          return true;
        case EWldFrameAction::Loading:
          WLD_DoLoading(&continueDispatch);
          break;
        case EWldFrameAction::Initialize:
          WLD_DoInitializing(&continueDispatch);
          break;
        case EWldFrameAction::PostInitialize:
          WLD_DoPostInitializing(&continueDispatch);
          break;
        case EWldFrameAction::Waiting:
          WLD_DoWaiting(&continueDispatch);
          break;
        case EWldFrameAction::Playing:
          WLD_DoPlayingAction(deltaSeconds);
          return true;
        case EWldFrameAction::CreateSession:
          WLD_CreateSessionInfo();
          return true;
        case EWldFrameAction::Exit:
          (void)WLD_TeardownAndStartFrontEnd();
          return true;
        default:
          return true;
      }

      if (continueDispatch) {
        continue;
      }

      return true;
    }
  }

  /**
   * Address: 0x00869810 (FUN_00869810, func_WldSessionLoader_GetOnTeardownCallbacks)
   */
  WldTeardownCallbackVector* WLD_GetOnTeardownCallbacks()
  {
    if ((gWldTeardownCallbacksInitMask & 1u) == 0u) {
      gWldTeardownCallbacksInitMask |= 1u;
      gWldTeardownCallbacks.clear();
      (void)std::atexit(&CleanupWldTeardownCallbacks);
    }

    return &gWldTeardownCallbacks;
  }

  /**
   * Address: 0x008699A0 (FUN_008699A0)
   *
   * What it does:
   * Resolves the process-global teardown-callback vector and dispatches its
   * core callback lane.
   */
  std::int32_t WLD_DispatchOnTeardownCallbacksCoreFromGlobalList()
  {
    WldTeardownCallbackVector* const callbacks = WLD_GetOnTeardownCallbacks();
    return static_cast<std::int32_t>(DispatchTeardownCallbacksCoreAndReturnLastResult(callbacks));
  }

  /**
   * Address: 0x008699B0 (FUN_008699B0)
   *
   * What it does:
   * Resolves the process-global teardown-callback vector and runs the normal
   * teardown callback dispatch entry point.
   */
  [[nodiscard]] std::intptr_t WLD_RunTeardownCallbacksFromGlobalList()
  {
    WldTeardownCallbackVector* const callbacks = WLD_GetOnTeardownCallbacks();
    return DoTeardownCallbacks(callbacks);
  }

  /**
   * Address: 0x00869A80 (FUN_00869A80)
   *
   * What it does:
   * Releases global world-session teardown-callback vector storage and rewires
   * all three storage lanes to null -- VC8's `vector<T>::_Tidy()`, which is
   * what move-assigning an empty vector compiles to.
   */
  void WLD_ResetOnTeardownCallbackStorage()
  {
    gWldTeardownCallbacks = WldTeardownCallbackVector{};
  }

  /**
   * Address: 0x00869950 (FUN_00869950)
   *
   * What it does:
   * Appends one teardown-callback pointer to the process-global callback
   * vector and returns that vector.
   */
  WldTeardownCallbackVector* WLD_AddOnTeardownCallback(IWldTeardownCallback* const callback)
  {
    WldTeardownCallbackVector* const callbacks = WLD_GetOnTeardownCallbacks();
    if (callbacks == nullptr) {
      return nullptr;
    }

    callbacks->push_back(callback);
    return callbacks;
  }

  /**
   * Address: 0x0088C860 (FUN_0088C860, ?WLD_Teardown@Moho@@YAXXZ)
   */
  void WLD_Teardown()
  {
    if (ISTIDriver* const simDriver = SIM_DetachActiveDriver(); simDriver != nullptr) {
      simDriver->ShutDown();
      delete simDriver;
    }

    if (IUIManager* const uiManager = UI_GetManager(); uiManager != nullptr) {
      (void)uiManager->SetNewLuaState(nullptr);
    }

    if (IUserSoundManager* const userSound = USER_GetSound(); userSound != nullptr) {
      userSound->StopAllSounds();
    }

    (void)DoTeardownCallbacks(WLD_GetOnTeardownCallbacks());
    WLD_DestroySession();

    gWldFrameAction = EWldFrameAction::Inactive;
  }

  /**
   * Address: 0x0088BD40 (FUN_0088BD40)
   */
  LuaPlus::LuaObject WLD_LoadScenarioInfo(const msvc8::string& scenarioFile, LuaPlus::LuaState* const state)
  {
    if (state == nullptr) {
      return {};
    }

    LuaPlus::LuaObject scenarioEnv(state);
    if (FILE_GetFileInfo(scenarioFile.c_str(), nullptr, false)) {
      // Both scripts run with `scenarioEnv` as their globals table, so the
      // scenario file's top-level `ScenarioInfo = {...}` lands in it rather
      // than in _G. This is the engine's own loader (VFS resolution + hook
      // concatenation + setfenv); routing it through the Lua-level `doscript`
      // binding instead loses the C++ error propagation the caller relies on.
      scenarioEnv.AssignNewTable(state, 0, 0);
      (void)SCR_LuaDoScript(state, "/lua/dataInit.lua", &scenarioEnv);
      (void)SCR_LuaDoScript(state, scenarioFile.c_str(), &scenarioEnv);
    }

    if (scenarioEnv.IsNil()) {
      return scenarioEnv;
    }

    return scenarioEnv["ScenarioInfo"];
  }

  /**
   * Address: 0x00897220 (FUN_00897220, ?WLD_CreateSession@Moho@@YAPAVCWldSession@1@AAV?$auto_ptr@VLuaState@LuaPlus@@@std@@AAV?$auto_ptr@VRRuleGameRules@Moho@@@4@AAV?$auto_ptr@VCWldMap@Moho@@@4@AAUSWldSessionInfo@1@@Z)
   *
   * What it does:
   * Allocates one world-session object, constructs it from transferred
   * auto_ptr lanes, and updates the global active-session pointer.
   */
  CWldSession* WLD_CreateSession(
    msvc8::auto_ptr<LuaPlus::LuaState>& state,
    msvc8::auto_ptr<RRuleGameRules>& gameRules,
    msvc8::auto_ptr<CWldMap>& wldMap,
    SWldSessionInfo& sessionInfo
  )
  {
    void* const sessionStorage = ::operator new(sizeof(CWldSession), std::nothrow);
    if (sessionStorage == nullptr) {
      gActiveWldSession = nullptr;
      return nullptr;
    }

    CWldSession* session = nullptr;
    try {
      session = new (sessionStorage) CWldSession(state, gameRules, wldMap, sessionInfo);
    } catch (...) {
      ::operator delete(sessionStorage);
      throw;
    }

    gActiveWldSession = session;
    return session;
  }

  /**
   * Address: 0x008972D0 (FUN_008972D0)
   *
   * What it does:
   * Runs one deleting teardown path for `CWldSession` and returns the original
   * pointer lane.
   */
  CWldSession* DeleteWldSessionAndReturn(CWldSession* const session) noexcept
  {
    session->~CWldSession();
    ::operator delete(session);
    return session;
  }

  /**
   * Address: 0x008972A0 (FUN_008972A0, ?WLD_DestroySession@Moho@@YAXXZ)
   *
   * What it does:
   * Destroys the active world-session object when present and clears the
   * process-global active-session pointer.
   */
  void WLD_DestroySession()
  {
    CWldSession* const activeSession = gActiveWldSession;
    if (activeSession != nullptr) {
      (void)DeleteWldSessionAndReturn(activeSession);
    }

    gActiveWldSession = nullptr;
  }

  /**
   * Address: 0x008972F0 (FUN_008972F0, ?WLD_GetSession@Moho@@YAPAVCWldSession@1@XZ)
   *
   * What it does:
   * Returns the process-global active world-session pointer.
   */
  CWldSession* WLD_GetSession()
  {
    return gActiveWldSession;
  }

  /**
   * Address: 0x0088D060 (FUN_0088D060, ?WLD_BeginSession@Moho@@YAXV?$auto_ptr@USWldSessionInfo@Moho@@@std@@@Z)
   *
   * What it does:
   * Replaces pending world-session bootstrap info and schedules preload.
   */
  void WLD_BeginSession(msvc8::auto_ptr<SWldSessionInfo> sessionInfo)
  {
    SWldSessionInfo* nextSessionInfo = sessionInfo.release();
    (void)RebindPendingWldSessionInfoFromReleasedSlot(&nextSessionInfo);
    gWldFrameAction = EWldFrameAction::Preload;
  }

  /**
   * Address: 0x0088D0B0 (FUN_0088D0B0, ?WLD_GetSimRate@Moho@@YAMXZ)
   */
  float WLD_GetSimRate()
  {
    extern float wld_SkewRateAdjustBase;
    extern float wld_SkewRateAdjustMax;

    ISTIDriver* const simDriver = SIM_GetActiveDriver();
    if (simDriver == nullptr) {
      return 1.0f;
    }

    CClientManagerImpl* const clientManager = simDriver->GetClientManager();
    if (clientManager == nullptr) {
      return 1.0f;
    }

    const float requestedSimScale =
      static_cast<float>(std::pow(10.0, static_cast<double>(clientManager->GetSimRate()) * 0.1));

    const float skewRateMin = 1.0f / wld_SkewRateAdjustMax;
    const float skewRateSample =
      static_cast<float>(std::pow(static_cast<double>(wld_SkewRateAdjustBase), -simDriver->GetSimSpeed()));
    const float clampedSkewRate = std::max(skewRateMin, std::min(wld_SkewRateAdjustMax, skewRateSample));
    return clampedSkewRate * requestedSimScale;
  }

  /**
   * Address: 0x0088D170 (FUN_0088D170, session sim-rate permission probe)
   *
   * What it does:
   * Returns whether the active session context may issue local sim-rate
   * changes (`replay`, focused local army, or non-multiplayer).
   */
  bool WLD_CanAdjustSimRate()
  {
    CWldSession* const activeSession = WLD_GetActiveSession();
    if (activeSession == nullptr) {
      return false;
    }

    if (activeSession->IsReplay) {
      return true;
    }

    const int focusArmy = activeSession->FocusArmy;
    if (focusArmy >= 0 && activeSession->userArmies[static_cast<std::size_t>(focusArmy)] != nullptr) {
      return true;
    }

    return !activeSession->IsMultiplayer;
  }

  /**
   * Address: 0x0088D1B0 (FUN_0088D1B0, ?WLD_IncreaseSimRate@Moho@@YAXXZ)
   *
   * What it does:
   * Raises requested sim rate by one step (up to +50) for authorized local
   * session contexts.
   */
  void WLD_IncreaseSimRate()
  {
    ISTIDriver* const simDriver = SIM_GetActiveDriver();
    if (simDriver == nullptr || !WLD_CanAdjustSimRate()) {
      return;
    }

    CClientManagerImpl* const clientManager = simDriver->GetClientManager();
    const int requestedSimRate = clientManager->GetSimRateRequested();
    if (requestedSimRate < 50) {
      clientManager->SetSimRate(requestedSimRate + 1);
    }
  }

  /**
   * Address: 0x0088D220 (FUN_0088D220, ?WLD_ResetSimRate@Moho@@YAXXZ)
   *
   * What it does:
   * Resets requested sim rate back to neutral (`0`) for authorized local
   * session contexts.
   */
  void WLD_ResetSimRate()
  {
    ISTIDriver* const simDriver = SIM_GetActiveDriver();
    if (simDriver == nullptr || !WLD_CanAdjustSimRate()) {
      return;
    }

    CClientManagerImpl* const clientManager = simDriver->GetClientManager();
    if (clientManager->GetSimRateRequested() != 0) {
      clientManager->SetSimRate(0);
    }
  }

  /**
   * Address: 0x0088D280 (FUN_0088D280, ?WLD_DecreaseSimRate@Moho@@YAXXZ)
   *
   * What it does:
   * Lowers requested sim rate by one step (down to `-10`) for authorized
   * local session contexts.
   */
  void WLD_DecreaseSimRate()
  {
    ISTIDriver* const simDriver = SIM_GetActiveDriver();
    if (simDriver == nullptr || !WLD_CanAdjustSimRate()) {
      return;
    }

    CClientManagerImpl* const clientManager = simDriver->GetClientManager();
    const int requestedSimRate = clientManager->GetSimRateRequested();
    if (requestedSimRate > -10) {
      clientManager->SetSimRate(requestedSimRate - 1);
    }
  }

  /**
   * Address: 0x0088D2F0 (FUN_0088D2F0, ?WLD_SetGameSpeed@Moho@@YAXH@Z)
   *
   * What it does:
   * Sets one requested sim-rate lane after clamping the provided game-speed
   * value to the legacy `[-10, 10]` bounds.
   */
  void WLD_SetGameSpeed(int gameSpeed)
  {
    ISTIDriver* const simDriver = SIM_GetActiveDriver();
    if (simDriver == nullptr) {
      return;
    }

    CClientManagerImpl* const clientManager = simDriver->GetClientManager();
    int clampedGameSpeed = gameSpeed;
    if (gameSpeed >= 10) {
      clampedGameSpeed = 10;
    }

    if (clampedGameSpeed < -10) {
      clampedGameSpeed = -10;
    }

    clientManager->SetSimRate(clampedGameSpeed);
  }

  /**
   * Address: 0x0088D330 (FUN_0088D330, ?WLD_GetDriver@Moho@@YAPAVISTIDriver@1@XZ)
   *
   * What it does:
   * Returns the process-global active sim-driver pointer.
   */
  ISTIDriver* WLD_GetDriver()
  {
    return SIM_GetActiveDriver();
  }

  /**
   * Address context:
   * - global `Moho::sWldSession` consumed by save/load request paths.
   */
  CWldSession* WLD_GetActiveSession()
  {
    return gActiveWldSession;
  }
} // namespace moho


/**
 * Address: 0x0081EC00 (FUN_0081EC00, func_GetRightMouseButtonAction)
 * Mangled: ?func_GetRightMouseButtonAction@@... (referenced at global scope)
 *
 * IDA signature:
 * Moho::SCommandModeData *__cdecl func_GetRightMouseButtonAction(
 *     Moho::SCommandModeData *commandData, Moho::UICursorInfo *mouseInfo,
 *     int modifiers, Moho::CWldSession *wldSession);
 *
 * What it does:
 * Resolves the command a right-mouse click issues for the current selection
 * given the cursor state (hover target, drag id, modifiers). Walks the selected
 * set to accumulate the union of command-caps, then applies the attack /
 * capture / reclaim / transport / repair / guard / move precedence against the
 * hovered entity (or the pending command-manager helper when there is no hover)
 * and writes the resolved SCommandModeData into `out`. This symbol is
 * referenced by the linker at global scope (not inside namespace moho), so the
 * definition stays at global scope.
 */
moho::CommandModeData* func_GetRightMouseButtonAction(
  moho::CommandModeData* out, moho::MouseInfo* mouseInfo, int modifiers, moho::CWldSession* wldSession)
{
  using namespace moho;

  // Seed defaults from the cursor snapshot + modifiers (FUN_0081CEA0).
  CommandModeData commandModeData(*mouseInfo, modifiers);

  // No valid focus army (observer) -> return the default (empty) command mode.
  if (wldSession->FocusArmy < 0 || wldSession->userArmies[wldSession->FocusArmy] == nullptr) {
    *out = commandModeData;
    return out;
  }

  // An active UI command mode (e.g. a placement mode already engaged) suppresses
  // right-click command resolution; leave `out` untouched and bail.
  UICommandModeData commandMode{};
  TryGetUICommandMode(wldSession->mState, commandMode);
  if (!commandMode.mMode.empty()) {
    return out;
  }

  // Accumulate the union of command caps over every live selected user-unit.
  // `categoryOrdinals` collects each selected blueprint's category-bit index;
  // the binary keeps this side effect but never reads the set for a decision
  // (dead accumulation), so it is built and then destructed at scope end.
  BVIntSet categoryOrdinals;
  ERuleBPUnitCommandCaps selectionCommandCaps = RULEUCC_None;
  {
    SSelectionSetUserEntity& selection = wldSession->mSelection;
    SSelectionNodeUserEntity* node = selection.mHead->mLeft;
    node = SSelectionSetUserEntity::find(&selection, node, &node);
    while (node != selection.mHead) {
      UserEntity* const selectedEntity = DecodeSelectedUserEntity(node->mEnt);
      (void)categoryOrdinals.Add(static_cast<unsigned int>(selectedEntity->mParams.mBlueprint->mCategoryBitIndex));
      if (UserUnit* const selectedUnit = selectedEntity->IsUserUnit()) {
        selectionCommandCaps = static_cast<ERuleBPUnitCommandCaps>(
          selectionCommandCaps | GetIUnitBridge(selectedUnit)->GetAttributes().commandCapsMask
        );
      }
      SSelectionSetUserEntity::Iterator_inc(&node);
      node = SSelectionSetUserEntity::find(&selection, node, &node);
    }
  }

  UserEntity* const hoverEntity = mouseInfo->mUnitHover;

  if (hoverEntity == nullptr) {
    // No hover: consult the pending right-click command-manager helper. An
    // attack/form-attack pending command with an attack-capable selection
    // resolves to an Order+Attack; otherwise fall through to the move tail.
    RightClickCommandIssueHelperView* const helper =
      FindRightClickCommandIssueHelper(wldSession, static_cast<std::uint32_t>(mouseInfo->mIsDragger));
    if (helper != nullptr
        && (helper->commandType == EUnitCommandType::UNITCOMMAND_Attack
            || helper->commandType == EUnitCommandType::UNITCOMMAND_FormAttack)
        && (selectionCommandCaps & RULEUCC_Attack) != 0) {
      commandModeData.mMode = COMMOD_Order;
      commandModeData.mCommandCaps = RULEUCC_Attack;
    } else if ((selectionCommandCaps & RULEUCC_Move) != 0) {
      commandModeData.mMode = COMMOD_Order;
      commandModeData.mCommandCaps = RULEUCC_Move;
    }
    commandModeData.mIsDragged = mouseInfo->mIsDragger;
    *out = commandModeData;
    return out;
  }

  // --- Hover branch --------------------------------------------------------
  const bool isBeingBuilt = hoverEntity->IsBeingBuilt();
  const bool isFerryBeacon = hoverEntity->IsInCategory(msvc8::string("FERRYBEACON"));
  const bool isCampaignGate = hoverEntity->IsInCategory(msvc8::string("CAMPAIGNGATE"));

  // Reclaim eligibility: RECLAIMABLE (or under-construction) targets are
  // reclaim-valid; everything else is not.
  bool reclaimTargetValid = true;
  if (hoverEntity->mParams.mBlueprint != nullptr) {
    const bool reclaimable =
      hoverEntity->IsInCategory(msvc8::string("RECLAIMABLE")) || hoverEntity->IsBeingBuilt();
    if (!reclaimable) {
      reclaimTargetValid = false;
    }
  } else {
    reclaimTargetValid = false;
  }

  bool mCapturable = false;
  if (UserUnit* const hoverUnitForCaps = hoverEntity->IsUserUnit()) {
    mCapturable = GetIUnitBridge(hoverUnitForCaps)->GetAttributes().mCapturable;
    // When the unit is busy it is neither reclaimable nor capturable via
    // right-click.
    if (hoverEntity->IsUserUnit()->mUnitVarDat.mIsBusy) {
      reclaimTargetValid = false;
      mCapturable = false;
    }
  }

  bool isEnemy = false;
  bool isAlly = false;
  UserArmy* const focusArmy =
    (wldSession->FocusArmy < 0) ? nullptr : wldSession->userArmies[wldSession->FocusArmy];
  UserArmy* const hoverArmy = hoverEntity->mArmy;
  if (hoverArmy != nullptr && focusArmy != nullptr) {
    isEnemy = focusArmy->IsEnemy(hoverArmy->mArmyIndex);
    isAlly = focusArmy->IsAlly(hoverArmy->mArmyIndex);
  }

  UserUnit* const hoverUnit = hoverEntity->IsUserUnit();

  bool resolved = false;

  if (!(isEnemy && (selectionCommandCaps & RULEUCC_Attack) != 0
        && AnySelectedUnitCanAttackHover(hoverEntity, wldSession))) {
    // Capture: a non-allied, finished, capturable target with capture-capable
    // selection resolves to Order+Capture.
    if (!isAlly && !isBeingBuilt && mCapturable && (selectionCommandCaps & RULEUCC_Capture) != 0) {
      commandModeData.mMode = COMMOD_Order;
      commandModeData.mCommandCaps = RULEUCC_Capture;
      resolved = true;
    }

    // Reclaim: enemy / ownerless / reclaim-friendly targets that are reclaim
    // valid with reclaim-capable selection resolve to Order+Reclaim.
    if (!resolved) {
      const bool reclaimEligible =
        (isEnemy || hoverArmy == nullptr || hoverEntity->IsInCategory(msvc8::string("RECLAIMFRIENDLY")))
        && reclaimTargetValid && (selectionCommandCaps & RULEUCC_Reclaim) != 0;
      if (reclaimEligible) {
        commandModeData.mMode = COMMOD_Order;
        commandModeData.mCommandCaps = RULEUCC_Reclaim;
        resolved = true;
      }
    }

    // Transport chains only apply when the hover target belongs to the focus army.
    if (!resolved && hoverArmy == focusArmy) {
      if ((selectionCommandCaps & RULEUCC_CallTransport) != 0
          && SelectionHasTransportForTarget(&wldSession->mSelection, hoverEntity)) {
        commandModeData.mMode = COMMOD_Order;
        commandModeData.mCommandCaps = RULEUCC_CallTransport;
        resolved = true;
      } else if (hoverUnit != nullptr
                 && (GetIUnitBridge(hoverUnit)->GetAttributes().commandCapsMask & RULEUCC_CallTransport) != 0
                 && HoverTransportAcceptsSelection(&wldSession->mSelection, hoverEntity)) {
        commandModeData.mMode = COMMOD_Order;
        commandModeData.mCommandCaps = RULEUCC_Transport;
        resolved = true;
      } else if (isFerryBeacon && AllSelectedAreFactories(&wldSession->mSelection, wldSession)) {
        commandModeData.mMode = COMMOD_Order;
        commandModeData.mCommandCaps = RULEUCC_CallTransport;
        resolved = true;
      }
    }

    const ERuleBPUnitCommandCaps selectionCommandCapsTail = selectionCommandCaps;

    if (!resolved) {
      if (isEnemy) {
        // Attack-capable but nothing in the selection can actually attack the
        // hover -> mark the order invalid (immediate 0x01000000 = RULEUCC_Invalid).
        if ((selectionCommandCaps & RULEUCC_Attack) != 0
            && !AnySelectedUnitCanAttackHover(hoverEntity, wldSession)) {
          commandModeData.mMode = COMMOD_Order;
          commandModeData.mCommandCaps = RULEUCC_Invalid;
          resolved = true;
        }
        // else: fall through to the move tail.
      } else {
        const std::int32_t guardCap = selectionCommandCaps & RULEUCC_Guard;

        if (!OPTIONS_GetBool("switch_right_click_behavior")) {
          // Normal right-click behavior.
          const std::int32_t repairCap = selectionCommandCapsTail & RULEUCC_Repair;

          // Repair-if-under-construction: repair-capable selection over an
          // under-construction target that is mobile, or neither factory nor silo.
          bool repairUnderConstruction = false;
          if (repairCap != 0 && hoverEntity->IsBeingBuilt()) {
            if (UserUnit* const builtUnit = hoverEntity->IsUserUnit()) {
              if (GetIUnitBridge(builtUnit)->IsMobile()
                  || (!hoverEntity->IsInCategory(msvc8::string("FACTORY"))
                      && !hoverEntity->IsInCategory(msvc8::string("SILO")))) {
                repairUnderConstruction = true;
              }
            }
          }
          if (repairUnderConstruction) {
            commandModeData.mMode = COMMOD_Order;
            commandModeData.mCommandCaps = RULEUCC_Repair;
            resolved = true;
          }

          // Guard: guard-capable selection over a non-campaign-gate hovered unit
          // that is not the first selection member, while a formation is active.
          if (!resolved && guardCap != 0 && !isCampaignGate && hoverUnit != nullptr
              && !wldSession->UnitFirstInSelection(hoverUnit)
              && wldSession->mCurFormation->mTimeLeft > 0.0f) {
            commandModeData.mMode = COMMOD_Order;
            commandModeData.mCommandCaps = RULEUCC_Guard;
            resolved = true;
          }

          // Repair (finished target): allied damaged target, or a hovered unit
          // that reports the upgrading unit-state.
          if (!resolved && repairCap != 0
              && ((isAlly && hoverEntity->mVariableData.mMaxHealth > hoverEntity->mVariableData.mHealth)
                  || (hoverUnit != nullptr
                      && GetIUnitBridge(hoverUnit)->IsUnitState(UNITSTATE_Upgrading)))) {
            commandModeData.mMode = COMMOD_Order;
            commandModeData.mCommandCaps = RULEUCC_Repair;
            resolved = true;
          }
          // else: fall through to the move tail.
        } else {
          // Switched right-click behavior: repair is prioritised over guard.
          if ((selectionCommandCapsTail & RULEUCC_Repair) != 0
              && ((isAlly && hoverEntity->mVariableData.mMaxHealth > hoverEntity->mVariableData.mHealth)
                  || (hoverUnit != nullptr
                      && GetIUnitBridge(hoverUnit)->IsUnitState(UNITSTATE_Upgrading)))) {
            commandModeData.mMode = COMMOD_Order;
            commandModeData.mCommandCaps = RULEUCC_Repair;
            resolved = true;
          } else if (guardCap != 0) {
            commandModeData.mMode = COMMOD_Order;
            commandModeData.mCommandCaps = RULEUCC_Guard;
            resolved = true;
          }
          // else: fall through to the move tail.
        }
      }
    }

    // Move tail: a move-capable selection defaults to Order+Move.
    if (!resolved) {
      if ((selectionCommandCapsTail & RULEUCC_Move) != 0) {
        commandModeData.mMode = COMMOD_Order;
        commandModeData.mCommandCaps = RULEUCC_Move;
      }
      resolved = true;
    }
  } else {
    // Enemy target, attack-capable selection that can attack it -> Order+Attack.
    commandModeData.mMode = COMMOD_Order;
    commandModeData.mCommandCaps = RULEUCC_Attack;
    resolved = true;
  }

  // Finalize: stamp the drag id and copy the resolved state out.
  commandModeData.mIsDragged = mouseInfo->mIsDragger;
  *out = commandModeData;
  return out;
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_RMultiMapType_EntId_string_933d97, preregister_RMultiMapType_EntId_string)
