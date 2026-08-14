#include "CWldSession.h"

#include <algorithm>
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

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "moho/audio/IUserSoundManager.h"
#include "moho/containers/BVIntSet.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/UserEntity.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/mesh/Mesh.h"
#include "moho/lua/SCR_Color.h"
#include "moho/lua/SCR_String.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/IClientManager.h"
#include "moho/net/IClientMgrUIInterface.h"
#include "moho/resource/RResId.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/camera/VTransform.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "gpg/core/streams/BinaryReader.h"
#include "moho/console/CConCommand.h"
#include "moho/sim/COGrid.h"
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
#include "moho/sim/SSTICommandSource.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/ESTITargetTypeTypeInfo.h"
#include "moho/sim/UserArmy.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "moho/ui/CUIManager.h"
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

  struct StrategicIconAuxRuntimeView;
  StrategicIconAuxRuntimeView* gStrategicIconAuxiliary = nullptr;

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
  [[maybe_unused]] [[nodiscard]] std::uintptr_t* StoreFormationPreviewSharedPairsBeginLane(
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
  [[maybe_unused]] [[nodiscard]] std::uintptr_t* StoreFormationPreviewSharedPairsEndLane(
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
  [[maybe_unused]] [[nodiscard]] std::int32_t GetFormationPreviewSharedPairCountLane() noexcept
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
  [[maybe_unused]] [[nodiscard]] void* GetFormationPreviewSharedPairsOwnerLanePrimary(const int /*unused*/) noexcept
  {
    return &gFormationPreviewSharedPairsOwnerLane;
  }

  /**
   * Address: 0x0085A630 (FUN_0085A630)
   *
   * What it does:
   * Secondary entrypoint returning the formation-preview shared-pair owner lane.
   */
  [[maybe_unused]] [[nodiscard]] void* GetFormationPreviewSharedPairsOwnerLaneSecondary() noexcept
  {
    return &gFormationPreviewSharedPairsOwnerLane;
  }

  /**
   * Address: 0x0085EFE0 (FUN_0085EFE0)
   *
   * What it does:
   * Returns the global strategic-icon auxiliary object lane.
   */
  [[maybe_unused]] [[nodiscard]] StrategicIconAuxRuntimeView* GetStrategicIconAuxiliaryLaneA() noexcept
  {
    return gStrategicIconAuxiliary;
  }

  /**
   * Address: 0x0085EFF0 (FUN_0085EFF0)
   *
   * What it does:
   * Secondary entrypoint returning the strategic-icon auxiliary object lane.
   */
  [[maybe_unused]] [[nodiscard]] StrategicIconAuxRuntimeView* GetStrategicIconAuxiliaryLaneB() noexcept
  {
    return gStrategicIconAuxiliary;
  }

  /**
   * Address: 0x0085F000 (FUN_0085F000)
   *
   * What it does:
   * Third entrypoint returning the strategic-icon auxiliary object lane.
   */
  [[maybe_unused]] [[nodiscard]] StrategicIconAuxRuntimeView* GetStrategicIconAuxiliaryLaneC() noexcept
  {
    return gStrategicIconAuxiliary;
  }

  /**
   * Address: 0x00860F90 (FUN_00860F90)
   *
   * What it does:
   * Reads one dword through the strategic-icon scratch data-pointer lane and
   * stores it into `outValue`.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* StoreStrategicIconScratchValueLane(
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
  [[maybe_unused]] [[nodiscard]] std::uintptr_t* StoreStrategicIconScratchDataPointerLane(
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
  [[maybe_unused]] [[nodiscard]] std::uintptr_t GetStrategicIconScratchDataPointerLaneValue() noexcept
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
  [[maybe_unused]] [[nodiscard]] StrategicIconScratchTreeNodeRuntimeView* RotateStrategicIconScratchTreeLeft(
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
  [[maybe_unused]] [[nodiscard]] StrategicIconScratchTreeNodeRuntimeView* RotateStrategicIconScratchTreeRight(
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
  [[maybe_unused]] [[nodiscard]] std::uint32_t GetStrategicIconScratchCountLaneValue() noexcept
  {
    return gStrategicIconScratchCountLane;
  }

  /**
   * Address: 0x00861CA0 (FUN_00861CA0)
   *
   * What it does:
   * Returns the strategic-icon scratch owner lane slot.
   */
  [[maybe_unused]] [[nodiscard]] void* GetStrategicIconScratchOwnerLaneEntryA(const int /*unused*/) noexcept
  {
    return &gStrategicIconScratchOwnerLane;
  }

  /**
   * Address: 0x00861EB0 (FUN_00861EB0)
   *
   * What it does:
   * Secondary entrypoint returning the strategic-icon scratch owner lane slot.
   */
  [[maybe_unused]] [[nodiscard]] void* GetStrategicIconScratchOwnerLaneEntryB(const int /*unused*/) noexcept
  {
    return &gStrategicIconScratchOwnerLane;
  }

  /**
   * Address: 0x00861F60 (FUN_00861F60)
   *
   * What it does:
   * Third entrypoint returning the strategic-icon scratch owner lane slot.
   */
  [[maybe_unused]] [[nodiscard]] void* GetStrategicIconScratchOwnerLaneEntryC(const int /*unused*/) noexcept
  {
    return &gStrategicIconScratchOwnerLane;
  }

  /**
   * Address: 0x00862080 (FUN_00862080)
   *
   * What it does:
   * Fourth entrypoint returning the strategic-icon scratch owner lane slot.
   */
  [[maybe_unused]] [[nodiscard]] void* GetStrategicIconScratchOwnerLaneEntryD(const int /*unused*/) noexcept
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
  [[maybe_unused]] [[nodiscard]] SelectionEventListenerRuntimeLane* InitializeSelectionEventListenerLane(
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
  [[maybe_unused]] [[nodiscard]] PauseEventListenerRuntimeLane* InitializePauseEventListenerLane(
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
  [[maybe_unused]] void DeserializeSessionSaveDataSerializerCallback(
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
  [[maybe_unused]] void SerializeSessionSaveDataSerializerCallback(
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
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSessionSaveDataSerializerHelperPrimary() noexcept
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
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSessionSaveDataSerializerHelperSecondary() noexcept
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
  [[maybe_unused]] void ReleaseFormationPreviewSharedPairRuntime(
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
  [[maybe_unused]] void ReleaseFormationPreviewSharedPairRangeForward(
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
  [[maybe_unused]] std::uintptr_t ReleaseOneFormationPreviewSharedPairFromTailRuntime() noexcept
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

  /**
   * Address: 0x00899880 (FUN_00899880, sub_899880)
   *
   * What it does:
   * Acquires contiguous `UserArmy*` vector storage for `count` lanes and
   * fills each lane with one caller-supplied pointer value.
   */
  bool InitializeUserArmyPointerVector(
    msvc8::vector<moho::UserArmy*>& target,
    const std::uint32_t count,
    moho::UserArmy* const* const fillValueSlot
  )
  {
    auto& runtime = msvc8::AsVectorRuntimeView(target);
    runtime.begin = nullptr;
    runtime.end = nullptr;
    runtime.capacityEnd = nullptr;

    if (count == 0u) {
      return false;
    }

    constexpr std::uint32_t kElementWidth = static_cast<std::uint32_t>(sizeof(moho::UserArmy*));
    if (count > (std::numeric_limits<std::uint32_t>::max() / kElementWidth)) {
      throw std::length_error("vector<T> too long");
    }

    auto* const begin = static_cast<moho::UserArmy**>(
      ::operator new(static_cast<std::size_t>(count) * sizeof(moho::UserArmy*))
    );
    moho::UserArmy* const fillValue = (fillValueSlot != nullptr) ? *fillValueSlot : nullptr;
    for (std::uint32_t index = 0u; index < count; ++index) {
      begin[index] = fillValue;
    }

    runtime.begin = begin;
    runtime.end = begin + count;
    runtime.capacityEnd = begin + count;
    return true;
  }

  /**
   * Address: 0x00898EC0 (FUN_00898EC0)
   *
   * What it does:
   * Adapter lane that initializes one `vector<UserArmy*>` storage with
   * `count` entries and a null fill value, then returns the destination vector
   * pointer for chaining.
   */
  [[nodiscard]] msvc8::vector<moho::UserArmy*>* InitializeUserArmyPointerVectorNullFillAdapter(
    msvc8::vector<moho::UserArmy*>* const target,
    const std::uint32_t count
  )
  {
    if (target == nullptr) {
      return target;
    }

    moho::UserArmy* fillValue = nullptr;
    (void)InitializeUserArmyPointerVector(*target, count, &fillValue);
    return target;
  }
} // namespace

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
   *
   * What it does:
   * Initializes command mode from one cursor snapshot and one modifier lane:
   * clears mode/caps/blueprint, copy-constructs drag-start, resets drag-end,
   * and sets both trailing sentinel lanes to `-1`.
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
  bool UI_RenProjectileIcons = false;       // 0x00F57A8F
  bool UI_RenProjectileGlow = false;        // 0x00F57B24
  bool UI_forceWeaponsToYellow = false;     // 0x00F57B25
  float UI_RenProjectileGlowMin = 0.0f;     // 0x00F57B28
  float UI_RenProjectileGlowMax = 0.0f;     // 0x00F57B2C
  float UI_RenProjectileGlowPeriod = 0.0f;  // 0x00F57B30
  float UI_CurGlowTime = 0.0f;              // 0x010A6460

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
     * control lanes for orderline/waypoint/arrowhead textures.
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
      std::uint32_t field_0x28;            // +0x28
      float field_0x2C;                    // +0x2C
      float field_0x30;                    // +0x30
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

    struct HashBucketVector
    {
      void* mAllocProxy; // +0x00
      void** mStart;     // +0x04
      void** mFinish;    // +0x08
      void** mEnd;       // +0x0C
    };

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

  private:
    static void ReleaseIntrusive(CD3DFont*& font);
    static void AssignIntrusive(CD3DFont*& dst, CD3DFont* src);
    static void DestroyBuckets(HashBucketVector& buckets);
    static void InitBuckets(HashBucketVector& buckets, void* sentinel);

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
     * Address: 0x0082F110 (FUN_0082F110)
     */
    static void InitMapABBuckets(HashBucketVector& buckets, void* sentinel);

    /**
     * Address: 0x0082F680 (FUN_0082F680)
     */
    static void InitMapCBuckets(HashBucketVector& buckets, void* sentinel);

    /**
     * Address: 0x0082FB80 (FUN_0082FB80)
     */
    static void InitMapDBuckets(HashBucketVector& buckets, void* sentinel);

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
     * Address: 0x008300D0 (FUN_008300D0)
     */
    static CommandGraphTreeNode* AllocateTreeSentinelNode();

    static void InitTree(CommandGraphTree& tree);

    /**
     * Address: 0x00824B50 (FUN_00824B50, sub_824B50)
     *
     * What it does:
     * Destroys one command-graph runtime tree (nodes + head sentinel) and
     * clears head/size lanes.
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
        mOrderlineTexture.pi->weak_release();
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
        mWaypointTexture.pi->weak_release();
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
        mArrowheadTexture.pi->weak_release();
      }
      mArrowheadTexture.pi = incomingControl;
    }

    return this;
  }

  /**
   * Address: 0x00825570 (FUN_00825570)
   * Mangled: ?LoadTextures@UICommandGraphNode@Moho@@QAEXPAVLuaObject@LuaPlus@@PBDPAVLuaState@3@@Z
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

    const auto assignWeakSharedLane = [](
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
          destination.pi->weak_release();
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
          assignWeakSharedLane(mOrderlineTexture, loadedRaw.px, loadedRaw.pi);
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
      assignWeakSharedLane(mWaypointTexture, loadedRaw.px, loadedRaw.pi);
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
      assignWeakSharedLane(mArrowheadTexture, loadedRaw.px, loadedRaw.pi);
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
    [[maybe_unused]] [[nodiscard]] std::uint32_t ReadCommandGraphHelperLane0(const void* const value) noexcept
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
    [[maybe_unused]] [[nodiscard]] std::uint32_t ReadCommandGraphHelperLane64(const void* const value) noexcept
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
    [[maybe_unused]] [[nodiscard]] std::uint32_t ReadCommandGraphHelperLane458(const void* const value) noexcept
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
    [[maybe_unused]] [[nodiscard]] WeakOwnerLinkNodeRuntimeView* InitWeakOwnerLinkNodeFromHead(
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
    [[maybe_unused]] [[nodiscard]] std::uint32_t ReadCommandGraphHelperLane0Alt(const void* const value) noexcept
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
    [[maybe_unused]] [[nodiscard]] std::uint32_t* CopyRuntimeLane4ToDword(
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
    [[maybe_unused]] [[nodiscard]] DwordPairRuntimeView* InitDwordPairRuntimeLane(
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
    [[maybe_unused]] [[nodiscard]] CommandGraphIssueRuntimeView*
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
    [[maybe_unused]] [[nodiscard]] std::uint8_t* SetByteLaneTrue(std::uint8_t* const destination) noexcept
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

      const auto& runtime = msvc8::AsVectorRuntimeView(*callbacks);
      std::intptr_t result = reinterpret_cast<std::intptr_t>(runtime.begin);

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
    [[maybe_unused]] SBuildTemplateBuffer* RebindAndCopyBuildTemplateBufferInline(
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
    [[maybe_unused]] [[nodiscard]] std::uint32_t ReadBuildTemplateHelperLane0(const void* const value) noexcept
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
    [[maybe_unused]] [[nodiscard]] std::uint32_t ReadBuildTemplateHelperLane4(const void* const value) noexcept
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
    [[maybe_unused]] [[nodiscard]] std::uint32_t ApplyBuildTemplatePlacementPreviewStatus(
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
    [[maybe_unused]] [[nodiscard]] VTransform* ApplyCommandModeBuildPlacementPreviewStatus(
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

    struct StrategicIconAuxView
    {
      std::uint8_t mUnknown00[0x38];
      boost::shared_ptr<CD3DBatchTexture> mPauseRestTexture;   // +0x38
      boost::shared_ptr<CD3DBatchTexture> mStunnedRestTexture; // +0x40

      /**
       * Address: 0x0085EA60 (FUN_0085EA60, struct_IconAux::GetStunIcons)
       *
       * What it does:
       * Imports strategic icon Lua tables and refreshes pause/stunned overlay
       * rest textures for one icon-aux runtime object.
       */
      void LoadPauseAndStunnedRestTextures(CWldSession* session);
    };

    static_assert(
      offsetof(StrategicIconAuxView, mPauseRestTexture) == 0x38,
      "StrategicIconAuxView::mPauseRestTexture offset must be 0x38"
    );
    static_assert(
      offsetof(StrategicIconAuxView, mStunnedRestTexture) == 0x40,
      "StrategicIconAuxView::mStunnedRestTexture offset must be 0x40"
    );

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
     * What it does:
     * Copies one shared command-graph payload into one weak lane, rebinding
     * control ownership only when the incoming control block changes.
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
          incomingControl->weak_add_ref();
        }

        if (weakControl != nullptr) {
          weakControl->weak_release();
        }

        weakControl = incomingControl;
      }
    }

    void ReleaseWeakCommandGraph(UICommandGraph*& px, boost::detail::sp_counted_base*& control)
    {
      if (control) {
        control->weak_release();
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

  void UICommandGraph::DestroyBuckets(HashBucketVector& buckets)
  {
    if (buckets.mStart) {
      ::operator delete(buckets.mStart);
    }

    buckets.mAllocProxy = nullptr;
    buckets.mStart = nullptr;
    buckets.mFinish = nullptr;
    buckets.mEnd = nullptr;
  }

  void UICommandGraph::InitBuckets(HashBucketVector& buckets, void* const sentinel)
  {
    buckets.mAllocProxy = nullptr;
    buckets.mStart = static_cast<void**>(::operator new(9u * sizeof(void*)));
    buckets.mFinish = buckets.mStart;
    buckets.mEnd = buckets.mStart + 9;
    for (void** it = buckets.mStart; it != buckets.mEnd; ++it) {
      *it = sentinel;
    }
    buckets.mFinish = buckets.mEnd;
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
   * Address: 0x0082F110 (FUN_0082F110)
   */
  void UICommandGraph::InitMapABBuckets(HashBucketVector& buckets, void* const sentinel)
  {
    InitBuckets(buckets, sentinel);
  }

  /**
   * Address: 0x0082F680 (FUN_0082F680)
   */
  void UICommandGraph::InitMapCBuckets(HashBucketVector& buckets, void* const sentinel)
  {
    InitBuckets(buckets, sentinel);
  }

  /**
   * Address: 0x0082FB80 (FUN_0082FB80)
   */
  void UICommandGraph::InitMapDBuckets(HashBucketVector& buckets, void* const sentinel)
  {
    InitBuckets(buckets, sentinel);
  }

  /**
   * Address: 0x0082BF40 (FUN_0082BF40)
   */
  void UICommandGraph::InitMapAB(HashTable<HashListNode88>& table, const UICommandGraph* const owner)
  {
    table.mOwnerByte = static_cast<std::uint8_t>(reinterpret_cast<std::uintptr_t>(owner) & 0xFFu);
    table.mListHead = AllocateMapABListSentinel();
    table.mListSize = 0u;
    InitMapABBuckets(table.mBuckets, table.mListHead);
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
    InitMapCBuckets(table.mBuckets, table.mListHead);
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
    InitMapDBuckets(table.mBuckets, table.mListHead);
    table.mBucketMask = 1u;
    table.mBucketCount = 1u;
  }

  /**
   * Address: 0x0082FAB0 (FUN_0082FAB0, MSVC8 `std::list<T>::clear` inline expansion for
   *                      trivial-destructor hash-list nodes)
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

    DestroyBuckets(table.mBuckets);
    table.mBucketMask = 1u;
    table.mBucketCount = 1u;
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
   * Address: 0x00824B50 (FUN_00824B50, sub_824B50)
   *
   * What it does:
   * Destroys command-graph runtime tree nodes rooted at `mHead->mParent`,
   * then releases the head sentinel and clears head/size lanes.
   */
  void UICommandGraph::DestroyTree(CommandGraphTree& tree)
  {
    auto destroySubtree = [&](auto&& self, CommandGraphTreeNode* node) -> void {
      if (node == nullptr || node == tree.mHead || node->mIsSentinel != 0u) {
        return;
      }

      self(self, node->mRight);
      CommandGraphTreeNode* const left = node->mLeft;
      ::operator delete(node);
      self(self, left);
    };

    if (tree.mHead) {
      destroySubtree(destroySubtree, tree.mHead->mParent);
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
    [[maybe_unused]] [[nodiscard]] UserEntity*
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

    [[nodiscard]] UserEntity* DecodeUserEntityWeakRef(const CameraUserEntityWeakRef& weakRef)
    {
      constexpr std::uintptr_t kUserEntityWeakOwnerOffset = offsetof(UserEntity, mIUnitChainHead);
#if defined(MOHO_ABI_MSVC8_COMPAT)
      static_assert(kUserEntityWeakOwnerOffset == 0x08, "UserEntity weak-ref owner offset must stay 0x08");
#endif

      const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(weakRef.mOwnerLinkSlot);
      if (raw == 0u || raw == kUserEntityWeakOwnerOffset || raw < kUserEntityWeakOwnerOffset) {
        return nullptr;
      }

      return reinterpret_cast<UserEntity*>(raw - kUserEntityWeakOwnerOffset);
    }

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

    [[nodiscard]] UserEntity* GetHoveredUserEntity(const CWldSession* const session) noexcept
    {
      if (session == nullptr) {
        return nullptr;
      }

      const auto* const sessionView = reinterpret_cast<const CWldSessionCursorRuntimeView*>(session);
      return DecodeUserEntityWeakLinkSlot(sessionView->mCursorInfo.mUnitHover);
    }

    [[nodiscard]] const IUnit* ResolveIUnitBridge(const UserUnit* const userUnit) noexcept
    {
      return userUnit ? static_cast<const IUnit*>(userUnit) : nullptr;
    }

    [[nodiscard]] IUnit* ResolveIUnitBridge(UserUnit* const userUnit) noexcept
    {
      return userUnit ? static_cast<IUnit*>(userUnit) : nullptr;
    }

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
    [[maybe_unused]] [[nodiscard]] bool SelectionContainsTeleportationUnit(SSelectionSetUserEntity& selection)
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
     */
    [[maybe_unused]] [[nodiscard]] bool CanStartCoordinatedAttack(CWldSession& session, const CmdId commandId)
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
        IUnit* const iunit = ResolveIUnitBridge(userUnit);
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

    [[maybe_unused]] [[nodiscard]] SSelectionNodeUserEntity*
    EraseSelectionNodeAndAdvance(WeakEntitySetUserEntity& selection, SSelectionNodeUserEntity* node);

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

      outMask.rawWord = selectionIds.mFirstWordIndex;
      outMask.maskVectorAuxWord = selectionIds.mReservedMetaWord;
      outMask.masks.ResetFrom(selectionIds.mWords);
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
    [[maybe_unused]] [[nodiscard]] SSelectionNodeUserEntity* InitializeSelectionCloneNodeFromSource(
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
    [[maybe_unused]] [[nodiscard]] SSelectionNodeUserEntity* AllocateSelectionCloneNodeFromSource(
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
    [[maybe_unused]] [[nodiscard]] SSelectionNodeUserEntity* CloneSelectionSubtreeIntoSet(
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
    [[maybe_unused]] [[nodiscard]] SSelectionNodeUserEntity* CloneSelectionTreeFromStorage(
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

    struct SelectionFindResBool
    {
      SSelectionSetUserEntity::FindResult res;
      bool found;
    };

    /**
     * Address: 0x007B25C0 (FUN_007B25C0)
     *
     * What it does:
     * Initializes one weak-set storage header with a fresh sentinel node and
     * resets its live-node count to zero.
     */
    [[maybe_unused]] [[nodiscard]] SSelectionSetUserEntity* InitializeSelectionSetHeadStorage(
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
    [[maybe_unused]] [[nodiscard]] SSelectionSetUserEntity::FindResult* BuildSelectionFindResultFromHeadLeft(
      SSelectionSetUserEntity* const set,
      SSelectionSetUserEntity::FindResult* const outResult
    )
    {
      SSelectionNodeUserEntity* node = set->mHead->mLeft;
      (void)set->PruneTombstonesAndFindLive(&node, node);
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
    [[maybe_unused]] [[nodiscard]] SSelectionSetUserEntity::FindResult* BuildSelectionFindResultFromNextCursor(
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
    [[maybe_unused]] [[nodiscard]] SSelectionNodeUserEntity*
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
    [[maybe_unused]] [[nodiscard]] SSelectionNodeUserEntity* InitSelectionNodeValueAndWeakLink(
      SSelectionNodeUserEntity* const node,
      SSelectionSetUserEntity* const set,
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
    [[maybe_unused]] [[nodiscard]] SSelectionNodeUserEntity*
    AllocateAndInitSelectionNode(SSelectionSetUserEntity* const set, UserEntity* const entity)
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
    [[maybe_unused]] [[nodiscard]] SelectionInsertFindResult* InsertSelectionNodeAndRebalance(
      SelectionInsertFindResult* const outResult,
      SSelectionSetUserEntity* const set,
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
     */
    [[maybe_unused]] [[nodiscard]] SelectionInsertFindResult* FindOrInsertSelectionNodeByUserEntity(
      SelectionInsertFindResult* const outResult,
      SSelectionSetUserEntity* const set,
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
    [[maybe_unused]] [[nodiscard]] std::int32_t EraseSelectionEntityGuardedByOwnerLink(
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
    [[maybe_unused]] [[nodiscard]] std::int32_t EraseSelectionKeyRangeAndCount(
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
    [[maybe_unused]] [[nodiscard]] SSelectionSetUserEntity::FindResult* FindSelectionNodeWithHintGuardedByOwnerLink(
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
    [[maybe_unused]] [[nodiscard]] SSelectionNodeUserEntity** FindOrInsertSelectionNodeWithHint(
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
     * Address: 0x00822270 (FUN_00822270, sub_822270)
     *
     * What it does:
     * Inserts one unit key into a weak-set under a scoped weak-owner guard and
     * writes one `{set,node,found}` result payload.
     */
    [[maybe_unused]] [[nodiscard]] SelectionFindResBool* InsertSelectionUnitWithWeakGuard(
      SelectionFindResBool* const outResult,
      SSelectionSetUserEntity* const set,
      UserUnit* const unit
    )
    {
      outResult->res.mSet = set;
      outResult->res.mRes = (set != nullptr) ? set->mHead : nullptr;
      outResult->found = false;

      UserEntity* const entity = reinterpret_cast<UserEntity*>(unit);
      ScopedSelectionOwnerLinkGuard ownerLinkGuard(entity);

      SelectionInsertFindResult insertResult{};
      (void)FindOrInsertSelectionNodeByUserEntity(&insertResult, set, entity);
      outResult->res.mRes = insertResult.node;
      outResult->found = insertResult.inserted;
      return outResult;
    }

    /**
     * Address: 0x00822C50 (FUN_00822C50, sub_822C50)
     *
     * What it does:
     * Initializes one destination weak-set from one source iterator range by
     * copying live user-entity keys into a fresh RB-tree head/sentinel shape.
     */
    [[maybe_unused]] [[nodiscard]] SSelectionSetUserEntity* InitSelectionSetFromIteratorRange(
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
    [[maybe_unused]] [[nodiscard]] SSelectionSetUserEntity* InitSelectionSetFromIteratorRangePruningSourceTombstones(
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
    [[maybe_unused]] [[nodiscard]] SSelectionSetUserEntity* CopySelectionSetFromOther(
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
    [[maybe_unused]] [[nodiscard]] std::int32_t
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
    [[maybe_unused]] void ReleaseSelectionWeakSetStorageRange(
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
    [[maybe_unused]] [[nodiscard]] SSelectionSetUserEntity* AssignSelectionSetFromOther(
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
    [[maybe_unused]] [[nodiscard]] SSelectionSetUserEntity* AssignSelectionSetFromStorageLane(
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
    [[maybe_unused]] [[nodiscard]] SSelectionSetUserEntity* AssignSelectionSetFromSetLane(
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
    [[maybe_unused]] void ReleaseSelectionWeakSetStorageVector(
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
    [[maybe_unused]] void ReleaseSelectionWeakSetStorageVectorAndReset(
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
    [[maybe_unused]] [[nodiscard]] SelectionWeakSetStorageRuntimeView* CopySelectionWeakSetStorageRangeForward(
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
    [[maybe_unused]] [[nodiscard]] std::int32_t ReleaseSelectionWeakSetStorageRangeEmptyAdapter(
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
    [[maybe_unused]] [[nodiscard]] SelectionWeakSetStorageRuntimeView*
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
    [[maybe_unused]] [[nodiscard]] SelectionWeakSetStorageRuntimeView**
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
    [[maybe_unused]] [[nodiscard]] SelectionWeakSetStorageRuntimeView* FillSelectionWeakSetStorageRange(
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
    [[maybe_unused]] [[nodiscard]] SelectionWeakSetStorageRuntimeView* CopySelectionWeakSetStorageRangeBackward(
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
    [[maybe_unused]] void ReleaseSelectionWeakSetStorageRangeAdapter(
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
    [[maybe_unused]] [[nodiscard]] SelectionWeakSetStorageRuntimeView* FillSelectionWeakSetStorageRangeAdapter(
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
    [[maybe_unused]] [[nodiscard]] SelectionWeakSetStorageRuntimeView*
    CopySelectionWeakSetStorageRangeBackwardNullSourceAdapter(
      [[maybe_unused]] const SelectionWeakSetStorageRuntimeView* const unusedLaneA,
      [[maybe_unused]] const SelectionWeakSetStorageRuntimeView* const unusedLaneB,
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
    [[maybe_unused]] [[nodiscard]] std::int32_t ReleaseSelectionWeakSetStorageAndReturnStatus(
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
    [[maybe_unused]] [[nodiscard]] SelectionWeakSetStorageRuntimeView* ReleaseSelectionWeakSetStorageAndReturnStorage(
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
    [[maybe_unused]] [[nodiscard]] std::uint32_t ReadSelectionRuntimeLane0(const void* const value) noexcept
    {
      return ReadRuntimeDwordAt0(value);
    }

    /**
     * Address: 0x00822260 (FUN_00822260, sub_822260)
     *
     * What it does:
     * Returns one first-dword runtime lane from one selection helper payload.
     */
    [[maybe_unused]] [[nodiscard]] std::uint32_t ReadSelectionRuntimeLane0Alt(const void* const value) noexcept
    {
      return ReadRuntimeDwordAt0(value);
    }

    /**
     * Address: 0x00822340 (FUN_00822340, sub_822340)
     *
     * What it does:
     * Returns one first-dword runtime lane from one command helper payload.
     */
    [[maybe_unused]] [[nodiscard]] std::uint32_t ReadCommandRuntimeLane0(const void* const value) noexcept
    {
      return ReadRuntimeDwordAt0(value);
    }

    /**
     * Address: 0x00822350 (FUN_00822350, sub_822350)
     *
     * What it does:
     * Returns one second-dword runtime lane from one command helper payload.
     */
    [[maybe_unused]] [[nodiscard]] std::uint32_t ReadCommandRuntimeLane4(const void* const value) noexcept
    {
      return ReadRuntimeDwordAt4(value);
    }

    /**
     * Address: 0x00822390 (FUN_00822390, sub_822390)
     *
     * What it does:
     * Returns one first-dword runtime lane from one command helper payload.
     */
    [[maybe_unused]] [[nodiscard]] std::uint32_t ReadCommandRuntimeLane0Alt(const void* const value) noexcept
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
    [[maybe_unused]] [[nodiscard]] UserUnit**
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
    [[maybe_unused]] [[nodiscard]] RawPointerTripletRuntimeView*
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
    [[maybe_unused]] [[nodiscard]] void* ResetRawPointerTripletToInlineLane(RawPointerTripletRuntimeView* const view)
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
    [[maybe_unused]] [[nodiscard]] RawPointerTripletRuntimeView* InitRawPointerTripletFromExternalLane(
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
    [[maybe_unused]] void NoOpSelectionHookA() noexcept
    {}

    /**
     * Address: 0x008229B0 (FUN_008229B0, sub_8229B0)
     *
     * What it does:
     * Performs one selection-cursor decrement and returns the updated cursor lane.
     */
    [[maybe_unused]] [[nodiscard]] SSelectionNodeUserEntity* StepSelectionCursorBackward(
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
    [[maybe_unused]] [[nodiscard]] DwordByteRuntimeView* CopyDwordByteRuntimeLane(
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
    [[maybe_unused]] [[nodiscard]] std::uint32_t GetLegacyMapSetMaxSizeGuard() noexcept
    {
      return 0x15555555u;
    }

    /**
     * Address: 0x00822A10 (FUN_00822A10, nullsub_2793)
     *
     * What it does:
     * No-op hook lane retained for binary parity.
     */
    [[maybe_unused]] void NoOpSelectionHookB() noexcept
    {}

    /**
     * Address: 0x00822A40 (FUN_00822A40, sub_822A40)
     *
     * What it does:
     * Returns one legacy map/set maximum-size guard constant lane.
     */
    [[maybe_unused]] [[nodiscard]] std::uint32_t GetLegacyMapSetMaxSizeGuardAlt() noexcept
    {
      return 0x15555555u;
    }

    /**
     * Address: 0x00822D70 (FUN_00822D70, sub_822D70)
     *
     * What it does:
     * Writes one `{first,second,flag}` payload into destination runtime storage.
     */
    [[maybe_unused]] [[nodiscard]] TwoDwordByteRuntimeView* InitTwoDwordByteRuntimeLane(
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
    [[maybe_unused]] [[nodiscard]] TwoDwordByteRuntimeView* CopyTwoDwordByteRuntimeLane(
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
    [[maybe_unused]] [[nodiscard]] void* UpcastRRefToUserUnitObject(gpg::RRef* const sourceRef)
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
    [[maybe_unused]] void NoOpSelectionHookC() noexcept
    {}

    /**
     * Address: 0x00822E60 (FUN_00822E60, sub_822E60)
     *
     * What it does:
     * Returns the high-byte lane from one packed 32-bit value.
     */
    [[maybe_unused]] [[nodiscard]] std::uint8_t ReadHighByteLaneA(const std::uint32_t value) noexcept
    {
      return static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
    }

    /**
     * Address: 0x00822E90 (FUN_00822E90, nullsub_2795)
     *
     * What it does:
     * No-op hook lane retained for binary parity.
     */
    [[maybe_unused]] void NoOpSelectionHookD() noexcept
    {}

    /**
     * Address: 0x00822EA0 (FUN_00822EA0, sub_822EA0)
     *
     * What it does:
     * Returns the high-byte lane from one packed 32-bit value.
     */
    [[maybe_unused]] [[nodiscard]] std::uint8_t ReadHighByteLaneB(const std::uint32_t value) noexcept
    {
      return static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
    }

    /**
     * Address: 0x00822ED0 (FUN_00822ED0, sub_822ED0)
     *
     * What it does:
     * Returns one first-dword runtime lane from one packed payload.
     */
    [[maybe_unused]] [[nodiscard]] std::uint32_t ReadPackedRuntimeLane0(const void* const value) noexcept
    {
      return ReadRuntimeDwordAt0(value);
    }

    /**
     * Address: 0x00822EE0 (FUN_00822EE0, sub_822EE0)
     *
     * What it does:
     * Copies one `{word0,word2}` pair from one three-word packed source lane.
     */
    [[maybe_unused]] [[nodiscard]] PackedTwoWordRuntimeView* CopyPackedWordPairSkippingMiddle(
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
    [[maybe_unused]] [[nodiscard]] std::uint32_t* CopyPackedFloat2Lane(
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
    [[maybe_unused]] [[nodiscard]] SSelectionWeakRefUserEntity**
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
    [[maybe_unused]] [[nodiscard]] SSelectionWeakRefUserEntity**
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
      std::uint8_t mUnknown08_23[0x1C]{};
      CommandGraphAnchorSampleRuntimeView mAnchorSample{}; // +0x24
    };
    static_assert(
      offsetof(CommandGraphAnchorHistoryEntryRuntimeView, mEntryType) == 0x04,
      "CommandGraphAnchorHistoryEntryRuntimeView::mEntryType offset must be 0x04"
    );
    static_assert(
      offsetof(CommandGraphAnchorHistoryEntryRuntimeView, mAnchorSample) == 0x24,
      "CommandGraphAnchorHistoryEntryRuntimeView::mAnchorSample offset must be 0x24"
    );

    struct CommandGraphAnchorHistoryRuntimeView
    {
      std::uint8_t mUnknown00_5B[0x5C]{};
      CommandGraphAnchorSampleRuntimeView mFallbackSample{}; // +0x5C
      std::uint8_t mUnknown74_BB[0x48]{};
      CommandGraphAnchorHistoryEntryRuntimeView** mEntries = nullptr; // +0xBC
      std::uint32_t mEntryBase = 0; // +0xC0
      std::uint32_t mEntryStart = 0; // +0xC4
      std::uint32_t mEntryCount = 0; // +0xC8
    };
    static_assert(
      offsetof(CommandGraphAnchorHistoryRuntimeView, mFallbackSample) == 0x5C,
      "CommandGraphAnchorHistoryRuntimeView::mFallbackSample offset must be 0x5C"
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
    [[maybe_unused]] [[nodiscard]] CommandGraphAnchorSampleRuntimeView* CopyCommandGraphAnchorSampleWithRelink(
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
    [[maybe_unused]] [[nodiscard]] CommandGraphAnchorSampleRuntimeView* ResolveFallbackCommandGraphAnchorSample(
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
    [[maybe_unused]] [[nodiscard]] CommandGraphAnchorSampleRuntimeView* ResolveCommandGraphAnchorSampleFromHistory(
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
     * Alias of FUN_008BED50.
     *
     * What it does:
     * Resolves one anchor sample to world position: owner-linked entity
     * position for kind `1`, inline position for kind `2`, otherwise invalid.
     */
    [[maybe_unused]] [[nodiscard]] Wm3::Vector3f* ResolveCommandGraphAnchorSamplePositionAlias(
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
    [[maybe_unused]] [[nodiscard]] Wm3::Vector3f* ResolveCommandGraphAnchorHistoryWorldPosition(
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
    [[maybe_unused]] void UnlinkSelectionWeakOwnerRefRangeNoReset(
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

    /**
     * Address: 0x0066A550 (FUN_0066A550, Moho::WeakSet_UserEntity::next)
     *
     * What it does:
     * Erases one `UserEntity` weak-set node from the selection RB-tree, unlinks
     * its intrusive weak-owner chain lane, and returns the next in-order node.
     */
    [[maybe_unused]] [[nodiscard]] SSelectionNodeUserEntity*
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
    [[maybe_unused]] [[nodiscard]] UserEntity* ResolveEntityFromCommandIssueOwner(const void* const commandOwner)
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
    [[maybe_unused]] SSessionSaveNodeMap* InitializeSessionSaveNodeMapHeader(
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
        IUnit* const hoverBridge = ResolveIUnitBridge(hoverUnit);
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
          IUnit* const transporterBridge = ResolveIUnitBridge(transporter);
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
      IUnit* const hoverBridge = ResolveIUnitBridge(hoverUnit);
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
   * entries (null/`(void*)8` owner-link slots) as it goes.
   */
  SSelectionNodeUserEntity** SSelectionSetUserEntity::PruneTombstonesAndFindLive(
    SSelectionNodeUserEntity** const outNode,
    SSelectionNodeUserEntity* const start
  )
  {
    SSelectionNodeUserEntity* node = start;
    if (mHead == nullptr) {
      *outNode = nullptr;
      return outNode;
    }

    while (node != mHead) {
      void* const ownerLinkSlot = node->mEnt.mOwnerLinkSlot;
      if (ownerLinkSlot != nullptr && ownerLinkSlot != reinterpret_cast<void*>(8)) {
        break;
      }

      node = EraseSelectionNodeAndAdvance(*this, node);
    }

    *outNode = node;
    return outNode;
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
    SSelectionSetUserEntity* const set,
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
    (void)set->PruneTombstonesAndFindLive(&node, node);
    *outNode = node;
    return node;
  }

  /**
   * Address: 0x0066A060 (FUN_0066A060, Moho::WeakSet_UserEntity::First)
   *
   * What it does:
   * Starts weak-set iteration from the head-left node and stores one
   * `{set,node}` cursor pair into `outResult`.
   */
  SSelectionSetUserEntity::FindResult* SSelectionSetUserEntity::First(FindResult* const outResult)
  {
    return BuildSelectionFindResultFromHeadLeft(this, outResult);
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
      (void)InitializeUserArmyPointerVectorNullFillAdapter(
        &userArmies,
        static_cast<std::uint32_t>(launchInfo->mArmyLaunchInfo.size())
      );

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
      const IUnit* const selectedBridge = ResolveIUnitBridge(selectedUnit);
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
      IUnit* const selectedBridge = ResolveIUnitBridge(selectedUnit);
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

      IUnit* const iunitBridge = ResolveIUnitBridge(unit);
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
   * Address: 0x00896090 (FUN_00896090, ?GetValidAttackingUnits@CWldSession@Moho@@QBEXAAV?$WeakSet@VUserUnit@Moho@@@2@@Z)
   *
   * What it does:
   * Walks selected units and keeps only those that can attack the currently
   * hovered entity.
   */
  void CWldSession::GetValidAttackingUnits(msvc8::vector<UserUnit*>& outUnits) const
  {
    outUnits.clear();

    const UserEntity* const hoveredTarget = GetHoveredUserEntity(this);
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

      IUnit* const iunitBridge = ResolveIUnitBridge(unit);
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
   * What it does:
   * Inserts one unit into a user-entity selection/weak-set under a scoped
   * weak-owner guard, discarding the `{set,node,found}` payload. Thin void
   * wrapper over the file-static `InsertSelectionUnitWithWeakGuard`; exposed
   * (declared in CWldSession.h) so the command-issue update-event path (Sim.cpp)
   * can insert into an event weak-set without naming the private result type.
   */
  void InsertUnitIntoCommandIssueWeakSet(SSelectionSetUserEntity* const set, UserUnit* const unit)
  {
    SelectionFindResBool discardedResult{};
    (void)InsertSelectionUnitWithWeakGuard(&discardedResult, set, unit);
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

    UserEntity* const hoveredEntity = GetHoveredUserEntity(this);
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

      const IUnit* const hoveredBridge = ResolveIUnitBridge(hoveredUnit);
      const RUnitBlueprint* const targetBlueprint = hoveredBridge != nullptr ? hoveredBridge->GetBlueprint() : nullptr;

      if ((modifierBits & kShiftMask) != 0u) {
        if (ContainsUnitPtr(currentSelection, hoveredUnit)) {
          for (UserUnit* const selectedUnit : currentSelection) {
            const IUnit* const selectedBridge = ResolveIUnitBridge(selectedUnit);
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

        const IUnit* const sessionBridge = ResolveIUnitBridge(sessionUnit);
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
    UserEntity* const hoveredEntity = GetHoveredUserEntity(this);
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

    const IUnit* const hoveredBridge = ResolveIUnitBridge(hoveredUnit);
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
        UserEntity* const entity = DecodeUserEntityWeakRef(*weakRef);
        if (entity == nullptr) {
          continue;
        }

        UserUnit* const unit = entity->IsUserUnit();
        if (unit == nullptr || unit == hoveredUnit) {
          continue;
        }

        IUnit* const unitBridge = ResolveIUnitBridge(unit);
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

  /**
   * Address: 0x008515B0 (FUN_008515B0, ?DrawCommandSplats@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::DrawCommandSplats()
  {
    // Recovered 0x008515B0 high-level flow:
    // 1) Walk selection RB-tree/map and build unique source-entity set.
    // 2) For each selected user entity with a bone-animated mesh instance,
    //    refresh its debug pose via `MeshInstance::ComputeDebugPose`
    //    (0x007DE7A0) so command-splat bone anchors (teleport beacon
    //    quads) track the interpolated pose of that mesh instance in
    //    the current frame. The skeleton-overlay path in
    //    `MeshRenderer::RenderSkeleton` (0x007E2290) issues the same
    //    pose-refresh call and is wired in this SDK pass.
    // 3) Pull sim links and build line/teleport beacon quad batches.
    // 4) Bind primbatcher textures:
    //    "/textures/ui/common/game/waypoints/attack_btn_up.dds"
    //    "/textures/ui/common/game/waypoints/teleport_btn_up.dds"
    // 5) Emit quads and flush primbatcher.
    //
    // Deep lift blockers (typed dependencies still missing in SDK):
    // CD3DDevice/CD3DDeviceResources/CD3DPrimBatcher/CD3DBatchTexture render API,
    // full UserEntity selection-link iteration helpers, and CAniPoseBone
    // debug-pose chain accessors.
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

  /**
   * Address: 0x0085B6E0 (FUN_0085B6E0,
   * ?RenderStrategicIcons@CWldSession@Moho@@QAEXPAVCameraImpl@2@PAVCD3DPrimBatcher@2@PAVCWldMap@2@@Z)
   */
  void CWldSession::
    RenderStrategicIcons(CameraImpl* const /*camera*/, CD3DPrimBatcher* const /*primBatcher*/, CWldMap* const /*map*/)
  {
    // Recovered 0x0085B6E0 high-level flow:
    // 1) Lazy-create icon auxiliary cache object (0x0085B2A0/0x0085FA20).
    // 2) Classify units into icon/lifebar buckets (vec1..vec5).
    // 3) Render strategic icons via RenderUnitIcon (0x0085D9A0).
    // 4) Render formation icon pass and unit lifebar pass.
    //
    // Deep lift blockers:
    // struct_IconAux/UnitIconData concrete layouts and CD3D* render interfaces.
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

  /**
   * Address: 0x00862A80 (FUN_00862A80, ?RenderResources@CWldSession@Moho@@QAEXPAVGeomCamera3@2@PAVCD3DPrimBatcher@2@@Z)
   */
  void CWldSession::RenderResources(GeomCamera3* const /*camera*/, CD3DPrimBatcher* const /*primBatcher*/)
  {
    // Recovered 0x00862A80 high-level flow:
    // 1) Bind TResourceIcon technique and push primbatcher time shader var.
    // 2) Build strategic projection matrix from GeomCamera3 viewport.
    // 3) Query deposit collisions against camera solid, bucket mass/hydro points.
    // 4) Render strategic splats from:
    //    "/env/common/splats/mass_strategic.dds"
    //    "/env/common/splats/hydrocarbon_strategic.dds"
    // 5) Flush primbatcher and release temporary vectors/textures.
    //
    // Deep lift blockers:
    // IResources::DepositCollides typed contract, CD3DBatchTexture/CD3DPrimBatcher full API,
    // and transient fastvector wrappers used by collision query output.
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
   *   CWldSession *session, CD3DPrimBatcher *batcher, float interpolant,
   *   CameraImpl *camera@<ecx>);
   *
   * What it does:
   * Draws the net energy/mass rate readout over every army unit in the camera
   * frustum - see the header for the full description.
   */
  void CWldSession::DrawEconomyOverlay(
    CameraImpl* const camera, CD3DPrimBatcher* const primBatcher, const float interpolant
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
      UserEntity* const entity = DecodeUserEntityWeakRef(*weakRef);
      if (entity == nullptr) {
        continue;
      }

      UserUnit* const unit = entity->IsUserUnit();
      if (unit == nullptr) {
        continue;
      }

      IUnit* const unitBridge = ResolveIUnitBridge(unit);
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

      const Wm3::Vector3f worldPosition = entity->GetInterpolatedPosition(interpolant);
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
    [[maybe_unused]] int WLD_EnterPlayingAndNotifyUIProvider()
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
  [[maybe_unused]] [[nodiscard]] bool WLD_TeardownAndStartFrontEnd()
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
  [[maybe_unused]] [[nodiscard]] std::intptr_t WLD_RunTeardownCallbacksFromGlobalList()
  {
    WldTeardownCallbackVector* const callbacks = WLD_GetOnTeardownCallbacks();
    return DoTeardownCallbacks(callbacks);
  }

  namespace
  {
    void ResetWldTeardownCallbackVectorTail()
    {
      auto& runtime = msvc8::AsVectorRuntimeView(gWldTeardownCallbacks);
      runtime.end = nullptr;
      runtime.capacityEnd = nullptr;
    }
  } // namespace

  /**
   * Address: 0x00869A80 (FUN_00869A80)
   *
   * What it does:
   * Releases global world-session teardown-callback vector storage and rewires
   * all three storage lanes (`begin/end/capacityEnd`) to null.
   */
  void WLD_ResetOnTeardownCallbackStorage()
  {
    auto& runtime = msvc8::AsVectorRuntimeView(gWldTeardownCallbacks);
    if (runtime.begin != nullptr) {
      ::operator delete(runtime.begin);
    }

    runtime.begin = nullptr;
    ResetWldTeardownCallbackVectorTail();
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
  [[maybe_unused]] CWldSession* DeleteWldSessionAndReturn(CWldSession* const session) noexcept
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
          selectionCommandCaps | ResolveIUnitBridge(selectedUnit)->GetAttributes().commandCapsMask
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
    mCapturable = ResolveIUnitBridge(hoverUnitForCaps)->GetAttributes().mCapturable;
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
                 && (ResolveIUnitBridge(hoverUnit)->GetAttributes().commandCapsMask & RULEUCC_CallTransport) != 0
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
              if (ResolveIUnitBridge(builtUnit)->IsMobile()
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
                      && ResolveIUnitBridge(hoverUnit)->IsUnitState(UNITSTATE_Upgrading)))) {
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
                      && ResolveIUnitBridge(hoverUnit)->IsUnitState(UNITSTATE_Upgrading)))) {
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
