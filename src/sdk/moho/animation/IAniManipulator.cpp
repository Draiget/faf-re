#include "IAniManipulator.h"

#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "moho/animation/CAniActor.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/Sim.h"

namespace
{
  constexpr std::uint16_t kWatchBoneActiveFlag = 0x8000;
  constexpr const char* kIAniManipulatorLuaClassName = "IAniManipulator";
  constexpr const char* kIAniManipulatorSetPrecedenceName = "SetPrecedence";
  constexpr const char* kIAniManipulatorEnableName = "Enable";
  constexpr const char* kIAniManipulatorDisableName = "Disable";
  constexpr const char* kIAniManipulatorDestroyName = "Destroy";
  constexpr const char* kIAniManipulatorSetPrecedenceHelpText =
    "Manipulator:SetPrecedence(integer) -- change the precedence of this manipulator. "
    "Manipulators with higher precedence run first.";
  constexpr const char* kIAniManipulatorEnableHelpText =
    "Manipulator:Enable() -- enable a manipulator. Manipulators start out enabled so you only need this after "
    "calling Disable().";
  constexpr const char* kIAniManipulatorDisableHelpText =
    "Manipulator:Disable() -- disable a manipulator. This immediately removes it from the bone computation, which "
    "may result in the bone's position snapping.";
  constexpr const char* kIAniManipulatorDestroyHelpText = "Manipulator:Destroy() -- destroy a manipulator.";

  [[nodiscard]] gpg::RType* CachedIAniManipulatorType();

  /**
   * Address: 0x0050CCF0 (FUN_0050CCF0, sub_50CCF0)
   *
   * What it does:
   * Evaluates one x87 polynomial lane used by foot-plant solve code to
   * approximate an arccos-shaped angle from one normalized input scalar.
   */
  [[maybe_unused]] float ApproximateFootPlantAcosLane(const float value) noexcept
  {
    const float oneMinusValue = 1.0f - value;
    const float polynomial =
      value * (((value * -0.018729299f) + 0.074261002f) * value - 0.21211439f) + 1.5707288f;
    return 2.0f - std::sqrt(oneMinusValue) * polynomial;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  [[nodiscard]] moho::SAniManipBinding* InlineWatchBoneStorage(moho::IAniManipulator* const manipulator) noexcept
  {
    return &manipulator->mWatchBones.mInlineEntries[0];
  }

  [[nodiscard]] std::int32_t BindingPointerToInt32(const moho::SAniManipBinding* const binding) noexcept
  {
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(binding));
  }

  [[nodiscard]] moho::SAniManipBinding* Int32ToBindingPointer(const std::int32_t value) noexcept
  {
    return reinterpret_cast<moho::SAniManipBinding*>(static_cast<std::uintptr_t>(value));
  }

  [[maybe_unused]] moho::SAniManipBindingStorage*
  InitializeWatchBoneStorageInline(moho::SAniManipBindingStorage* storage) noexcept;

  [[maybe_unused]] moho::IAniManipulator* ManipulatorFromActorOrderLinkSlot(
    moho::TDatListItem<moho::IAniManipulator, void>* const* linkSlot
  ) noexcept;

  void InitializeWatchBoneStorage(moho::IAniManipulator* const manipulator)
  {
    (void)InitializeWatchBoneStorageInline(&manipulator->mWatchBones);
  }

  /**
   * Address: 0x0063C070 (FUN_0063C070)
   *
   * What it does:
   * Initializes one `SAniManipBindingStorage` to its inline two-element
   * storage window (`begin=end=inline`, `capacity=inline+2`).
   */
  [[maybe_unused]] moho::SAniManipBindingStorage*
  InitializeWatchBoneStorageInline(moho::SAniManipBindingStorage* const storage) noexcept
  {
    auto* const inlineStorage = &storage->mInlineEntries[0];
    storage->mBegin = inlineStorage;
    storage->mEnd = inlineStorage;
    storage->mCapacityEnd = inlineStorage + 2;
    storage->mInlineStorage = inlineStorage;
    return storage;
  }

  /**
   * Address: 0x0063C030 (FUN_0063C030)
   *
   * What it does:
   * Re-links one manipulator actor-order node immediately before `anchorNode`.
   */
  [[maybe_unused]] moho::TDatListItem<moho::IAniManipulator, void>* LinkManipulatorOrderBeforeNode(
    moho::IAniManipulator* const manipulator,
    moho::TDatListItem<moho::IAniManipulator, void>* const anchorNode
  ) noexcept
  {
    auto* const link = &manipulator->mActorOrderLink;
    link->ListLinkBefore(anchorNode);
    return link;
  }

  /**
   * Address: 0x0063C0E0 (FUN_0063C0E0)
   * Address: 0x0063C0F0 (FUN_0063C0F0)
   *
   * What it does:
   * Converts one actor-order link slot to owning `IAniManipulator*`.
   */
  [[maybe_unused]] moho::IAniManipulator* ManipulatorFromActorOrderLinkSlot(
    moho::TDatListItem<moho::IAniManipulator, void>* const* const linkSlot
  ) noexcept
  {
    auto* const link = (linkSlot != nullptr) ? *linkSlot : nullptr;
    if (link == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<moho::IAniManipulator*>(
      reinterpret_cast<std::uintptr_t>(link) - offsetof(moho::IAniManipulator, mActorOrderLink)
    );
  }

  /**
   * Address: 0x0063C100 (FUN_0063C100)
   *
   * What it does:
   * Unlinks one manipulator actor-order node and reinserts it before the node
   * referenced by `anchorSlot`.
   */
  [[maybe_unused]] moho::TDatListItem<moho::IAniManipulator, void>* RelinkManipulatorOrderBeforeSlot(
    moho::TDatListItem<moho::IAniManipulator, void>* const* const anchorSlot,
    moho::IAniManipulator* const manipulator
  ) noexcept
  {
    auto* const link = &manipulator->mActorOrderLink;
    auto* const anchorNode = (anchorSlot != nullptr) ? *anchorSlot : nullptr;
    link->ListUnlink();
    link->ListLinkBefore(anchorNode);
    return link;
  }

  struct IAniManipulatorLargeRuntimeSlotA38View
  {
    std::uint8_t mPad00A37[0xA38];
    std::uint32_t mValueA38;
  };

  static_assert(
    offsetof(IAniManipulatorLargeRuntimeSlotA38View, mValueA38) == 0xA38,
    "IAniManipulatorLargeRuntimeSlotA38View::mValueA38 offset must be 0xA38"
  );

  struct IAniManipulatorBaseRuntimeView
  {
    std::uint8_t mScriptEventPrefix[0x44];
    moho::TDatListItem<moho::IAniManipulator, void>* mActorOrderNext; // +0x44
    moho::TDatListItem<moho::IAniManipulator, void>* mActorOrderPrev; // +0x48
    bool mEnabled;                                                     // +0x4C
    std::uint8_t mEnabledPad[3]{};                                     // +0x4D
    moho::CAniActor* mOwnerActor;                                      // +0x50
    moho::Sim* mOwnerSim;                                              // +0x54
    std::int32_t mPrecedence;                                          // +0x58
    std::uint32_t mUnknown5C;                                          // +0x5C
    moho::SAniManipBinding* mWatchBonesBegin;                          // +0x60
    moho::SAniManipBinding* mWatchBonesEnd;                            // +0x64
    moho::SAniManipBinding* mWatchBonesCapacityEnd;                    // +0x68
    moho::SAniManipBinding* mWatchBonesInlineStorage;                  // +0x6C
  };

  static_assert(
    offsetof(IAniManipulatorBaseRuntimeView, mActorOrderNext) == 0x44,
    "IAniManipulatorBaseRuntimeView::mActorOrderNext offset must be 0x44"
  );
  static_assert(
    offsetof(IAniManipulatorBaseRuntimeView, mActorOrderPrev) == 0x48,
    "IAniManipulatorBaseRuntimeView::mActorOrderPrev offset must be 0x48"
  );
  static_assert(
    offsetof(IAniManipulatorBaseRuntimeView, mEnabled) == 0x4C,
    "IAniManipulatorBaseRuntimeView::mEnabled offset must be 0x4C"
  );
  static_assert(
    offsetof(IAniManipulatorBaseRuntimeView, mOwnerActor) == 0x50,
    "IAniManipulatorBaseRuntimeView::mOwnerActor offset must be 0x50"
  );
  static_assert(
    offsetof(IAniManipulatorBaseRuntimeView, mOwnerSim) == 0x54,
    "IAniManipulatorBaseRuntimeView::mOwnerSim offset must be 0x54"
  );
  static_assert(
    offsetof(IAniManipulatorBaseRuntimeView, mPrecedence) == 0x58,
    "IAniManipulatorBaseRuntimeView::mPrecedence offset must be 0x58"
  );
  static_assert(
    offsetof(IAniManipulatorBaseRuntimeView, mWatchBonesBegin) == 0x60,
    "IAniManipulatorBaseRuntimeView::mWatchBonesBegin offset must be 0x60"
  );
  static_assert(
    offsetof(IAniManipulatorBaseRuntimeView, mWatchBonesEnd) == 0x64,
    "IAniManipulatorBaseRuntimeView::mWatchBonesEnd offset must be 0x64"
  );

  struct IAniManipulatorExtendedRuntimeView
  {
    std::uint8_t mPad00A7[0xA8];
    std::int32_t mFieldA8;        // +0xA8
    std::uint8_t mPadACB3[0x8];
    bool mFlagB4;                 // +0xB4
    std::uint8_t mPadB5B7[0x3];
    float mScalarB8;              // +0xB8
    float mScalarBC;              // +0xBC
    std::uint8_t mPadC0DF[0x20];
    bool mFlagE0;                 // +0xE0
    std::uint8_t mPadE1E3[0x3];
    std::int32_t mFieldE4;        // +0xE4
    std::uint8_t mPadE8EF[0x8];
    bool mFlagF0;                 // +0xF0
    std::uint8_t mPadF1_173[0x83];
    bool mFlag174;                // +0x174
    std::uint8_t mPad175_177[0x3];
    float mVector178X;            // +0x178
    float mVector17CY;            // +0x17C
    float mVector180Z;            // +0x180
  };

  static_assert(
    offsetof(IAniManipulatorExtendedRuntimeView, mFieldA8) == 0xA8,
    "IAniManipulatorExtendedRuntimeView::mFieldA8 offset must be 0xA8"
  );
  static_assert(
    offsetof(IAniManipulatorExtendedRuntimeView, mFlagB4) == 0xB4,
    "IAniManipulatorExtendedRuntimeView::mFlagB4 offset must be 0xB4"
  );
  static_assert(
    offsetof(IAniManipulatorExtendedRuntimeView, mScalarB8) == 0xB8,
    "IAniManipulatorExtendedRuntimeView::mScalarB8 offset must be 0xB8"
  );
  static_assert(
    offsetof(IAniManipulatorExtendedRuntimeView, mScalarBC) == 0xBC,
    "IAniManipulatorExtendedRuntimeView::mScalarBC offset must be 0xBC"
  );
  static_assert(
    offsetof(IAniManipulatorExtendedRuntimeView, mFlagE0) == 0xE0,
    "IAniManipulatorExtendedRuntimeView::mFlagE0 offset must be 0xE0"
  );
  static_assert(
    offsetof(IAniManipulatorExtendedRuntimeView, mFieldE4) == 0xE4,
    "IAniManipulatorExtendedRuntimeView::mFieldE4 offset must be 0xE4"
  );
  static_assert(
    offsetof(IAniManipulatorExtendedRuntimeView, mFlagF0) == 0xF0,
    "IAniManipulatorExtendedRuntimeView::mFlagF0 offset must be 0xF0"
  );
  static_assert(
    offsetof(IAniManipulatorExtendedRuntimeView, mFlag174) == 0x174,
    "IAniManipulatorExtendedRuntimeView::mFlag174 offset must be 0x174"
  );
  static_assert(
    offsetof(IAniManipulatorExtendedRuntimeView, mVector178X) == 0x178,
    "IAniManipulatorExtendedRuntimeView::mVector178X offset must be 0x178"
  );
  static_assert(
    offsetof(IAniManipulatorExtendedRuntimeView, mVector17CY) == 0x17C,
    "IAniManipulatorExtendedRuntimeView::mVector17CY offset must be 0x17C"
  );
  static_assert(
    offsetof(IAniManipulatorExtendedRuntimeView, mVector180Z) == 0x180,
    "IAniManipulatorExtendedRuntimeView::mVector180Z offset must be 0x180"
  );

  struct RuntimeVector3LaneView
  {
    float x;
    float y;
    float z;
  };

  static_assert(sizeof(RuntimeVector3LaneView) == 0x0C, "RuntimeVector3LaneView size must be 0x0C");

  struct IAniManipulatorScalarPairRuntimeView
  {
    std::uint8_t mPad0087[0x88];
    float mScalar88; // +0x88
    float mScalar8C; // +0x8C
    std::uint8_t mPad9093[0x4];
    RuntimeVector3LaneView mVector94; // +0x94
  };

  static_assert(
    offsetof(IAniManipulatorScalarPairRuntimeView, mScalar88) == 0x88,
    "IAniManipulatorScalarPairRuntimeView::mScalar88 offset must be 0x88"
  );
  static_assert(
    offsetof(IAniManipulatorScalarPairRuntimeView, mScalar8C) == 0x8C,
    "IAniManipulatorScalarPairRuntimeView::mScalar8C offset must be 0x8C"
  );
  static_assert(
    offsetof(IAniManipulatorScalarPairRuntimeView, mVector94) == 0x94,
    "IAniManipulatorScalarPairRuntimeView::mVector94 offset must be 0x94"
  );

  struct IAniManipulatorWatchBoneRuntimeView
  {
    std::uint8_t mPad005F[0x60];
    moho::SAniManipBinding* mWatchBonesBegin; // +0x60
    moho::SAniManipBinding* mWatchBonesEnd;   // +0x64
    std::uint8_t mPad6883[0x1C];
    bool mFlag84;                             // +0x84
    bool mFlag85;                             // +0x85
  };

  static_assert(
    offsetof(IAniManipulatorWatchBoneRuntimeView, mWatchBonesBegin) == 0x60,
    "IAniManipulatorWatchBoneRuntimeView::mWatchBonesBegin offset must be 0x60"
  );
  static_assert(
    offsetof(IAniManipulatorWatchBoneRuntimeView, mWatchBonesEnd) == 0x64,
    "IAniManipulatorWatchBoneRuntimeView::mWatchBonesEnd offset must be 0x64"
  );
  static_assert(
    offsetof(IAniManipulatorWatchBoneRuntimeView, mFlag84) == 0x84,
    "IAniManipulatorWatchBoneRuntimeView::mFlag84 offset must be 0x84"
  );
  static_assert(
    offsetof(IAniManipulatorWatchBoneRuntimeView, mFlag85) == 0x85,
    "IAniManipulatorWatchBoneRuntimeView::mFlag85 offset must be 0x85"
  );

  struct RuntimeFallbackFloatVTableView
  {
    std::uint8_t mPad0077[0x78];
    float mFallbackValue;
  };

  static_assert(
    offsetof(RuntimeFallbackFloatVTableView, mFallbackValue) == 0x78,
    "RuntimeFallbackFloatVTableView::mFallbackValue offset must be 0x78"
  );

  struct RuntimeOverrideFloatLaneView
  {
    RuntimeFallbackFloatVTableView* mVTable;
    float mOverrideValue;
  };

  static_assert(
    offsetof(RuntimeOverrideFloatLaneView, mOverrideValue) == 0x04,
    "RuntimeOverrideFloatLaneView::mOverrideValue offset must be 0x04"
  );

  struct IntrusiveNodeRuntimeView
  {
    IntrusiveNodeRuntimeView* mNext;
    IntrusiveNodeRuntimeView* mPrev;
  };

  struct IntrusiveOwnerHeadRuntimeView
  {
    std::uint8_t mPad0013[0x14];
    IntrusiveNodeRuntimeView mHead;
  };

  static_assert(
    offsetof(IntrusiveOwnerHeadRuntimeView, mHead) == 0x14,
    "IntrusiveOwnerHeadRuntimeView::mHead offset must be 0x14"
  );

  struct PointerSlotRuntimeView
  {
    std::uintptr_t mValue;
  };

  constexpr std::uint32_t kWatchBoneTransientHighBitClearMask = 0xFFFEFFFFu;

  [[nodiscard]] gpg::RRef BuildFootPlantManipulatorRef(moho::CFootPlantManipulator* const object)
  {
    gpg::RRef out{};
    gpg::RRef_CFootPlantManipulator(&out, object);
    return out;
  }

  /**
   * Address: 0x00635520 (FUN_00635520, gpg::RRef_CBoneEntityManipulator wrapper lane)
   *
   * What it does:
   * Builds one reflected reference for a `CBoneEntityManipulator` instance.
   */
  [[nodiscard]] gpg::RRef BuildBoneEntityManipulatorRef(moho::CBoneEntityManipulator* const object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = gpg::LookupRType(typeid(moho::CBoneEntityManipulator));
    return out;
  }

  /**
   * Address: 0x006351D0 (FUN_006351D0, Moho::CBoneEntityManipulatorTypeInfo::NewRef)
   *
   * What it does:
   * Allocates and constructs one `CBoneEntityManipulator`, then returns it as
   * a typed `RRef` for RTTI allocation callbacks.
   */
  [[nodiscard]] gpg::RRef CreateBoneEntityManipulatorRefCallback()
  {
    return BuildBoneEntityManipulatorRef(new moho::CBoneEntityManipulator());
  }

  /**
   * Address: 0x00635270 (FUN_00635270, Moho::CBoneEntityManipulatorTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one `CBoneEntityManipulator` in caller storage and
   * returns the typed reflected reference.
   */
  [[nodiscard]] gpg::RRef ConstructBoneEntityManipulatorRefCallback(void* const storage)
  {
    moho::CBoneEntityManipulator* object = nullptr;
    if (storage != nullptr) {
      object = new (storage) moho::CBoneEntityManipulator();
    }
    return BuildBoneEntityManipulatorRef(object);
  }

  [[maybe_unused]] void DeleteBoneEntityManipulatorCallback(void* const object)
  {
    if (object != nullptr) {
      delete static_cast<moho::CBoneEntityManipulator*>(object);
    }
  }

  [[maybe_unused]] void DestructBoneEntityManipulatorCallback(void* const object)
  {
    if (object != nullptr) {
      static_cast<moho::CBoneEntityManipulator*>(object)->~CBoneEntityManipulator();
    }
  }

  [[maybe_unused]] void AddIAniManipulatorBase(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedIAniManipulatorType();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  [[nodiscard]] gpg::RRef CreateFootPlantManipulatorRefCallback();
  [[nodiscard]] gpg::RRef ConstructFootPlantManipulatorRefCallback(void* storage);
  void DeleteFootPlantManipulatorCallback(void* object);
  void DestructFootPlantManipulatorCallback(void* object);

  /**
   * Address: 0x00634AC0 (FUN_00634AC0, Moho::CBoneEntityManipulatorTypeInfo::Init)
   *
   * What it does:
   * Initializes reflected lifecycle callbacks for `CBoneEntityManipulator`,
   * adds `IAniManipulator` as base RTTI, then finalizes the type descriptor.
   */
  [[maybe_unused]] gpg::RType* InitBoneEntityManipulatorTypeInfo(gpg::RType* const typeInfo)
  {
    if (typeInfo == nullptr) {
      return nullptr;
    }

    typeInfo->size_ = sizeof(moho::CBoneEntityManipulator);
    typeInfo->newRefFunc_ = &CreateBoneEntityManipulatorRefCallback;
    typeInfo->ctorRefFunc_ = &ConstructBoneEntityManipulatorRefCallback;
    typeInfo->deleteFunc_ = &DeleteBoneEntityManipulatorCallback;
    typeInfo->dtrFunc_ = &DestructBoneEntityManipulatorCallback;
    AddIAniManipulatorBase(typeInfo);
    typeInfo->gpg::RType::Init();
    typeInfo->Finish();
    return typeInfo;
  }

  /**
   * Address: 0x00639120 (FUN_00639120, Moho::CFootPlantManipulatorTypeInfo::Init)
   *
   * What it does:
   * Initializes reflected lifecycle callbacks for `CFootPlantManipulator`,
   * adds `IAniManipulator` as base RTTI, then finalizes the type descriptor.
   */
  [[maybe_unused]] gpg::RType* InitFootPlantManipulatorTypeInfo(gpg::RType* const typeInfo)
  {
    if (typeInfo == nullptr) {
      return nullptr;
    }

    typeInfo->size_ = sizeof(moho::CFootPlantManipulator);
    typeInfo->newRefFunc_ = &CreateFootPlantManipulatorRefCallback;
    typeInfo->ctorRefFunc_ = &ConstructFootPlantManipulatorRefCallback;
    typeInfo->deleteFunc_ = &DeleteFootPlantManipulatorCallback;
    typeInfo->dtrFunc_ = &DestructFootPlantManipulatorCallback;
    AddIAniManipulatorBase(typeInfo);
    typeInfo->gpg::RType::Init();
    typeInfo->Finish();
    return typeInfo;
  }

  /**
   * Address: 0x0063A030 (FUN_0063A030, Moho::CFootPlantManipulatorTypeInfo::NewRef)
   *
   * What it does:
   * Allocates and constructs one `CFootPlantManipulator`, then returns it as a
   * typed `RRef` for RTTI allocation callbacks.
   */
  [[nodiscard]] gpg::RRef CreateFootPlantManipulatorRefCallback()
  {
    return BuildFootPlantManipulatorRef(new moho::CFootPlantManipulator());
  }

  /**
   * Address: 0x0063A0D0 (FUN_0063A0D0, Moho::CFootPlantManipulatorTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one `CFootPlantManipulator` in caller storage and
   * returns the typed reflected reference.
   */
  [[nodiscard]] gpg::RRef ConstructFootPlantManipulatorRefCallback(void* const storage)
  {
    moho::CFootPlantManipulator* object = nullptr;
    if (storage != nullptr) {
      object = new (storage) moho::CFootPlantManipulator();
    }
    return BuildFootPlantManipulatorRef(object);
  }

  void DeleteFootPlantManipulatorCallback(void* const object)
  {
    if (object != nullptr) {
      delete static_cast<moho::CFootPlantManipulator*>(object);
    }
  }

  void DestructFootPlantManipulatorCallback(void* const object)
  {
    if (object != nullptr) {
      static_cast<moho::CFootPlantManipulator*>(object)->~CFootPlantManipulator();
    }
  }

  /**
   * Address: 0x0063CA20 (FUN_0063CA20)
   *
   * What it does:
   * Copies `[sourceBegin, sourceEnd)` watch-bone bindings into `destination`
   * element-by-element and returns the destination end pointer; a null
   * destination becomes a dry-run pointer advance.
   */
  [[nodiscard]] moho::SAniManipBinding* CopyBindingRange(
    moho::SAniManipBinding* destination,
    const moho::SAniManipBinding* sourceEnd,
    const moho::SAniManipBinding* sourceBegin
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      if (destination) {
        *destination = *sourceBegin;
      }
      ++destination;
      ++sourceBegin;
    }
    return destination;
  }

  /**
   * Address: 0x0063C950 (FUN_0063C950, sub_63C950)
   *
   * What it does:
   * Allocates a new watch-bone buffer, inserts one contiguous range at
   * `insertPosition`, then updates/cleans old storage and writes the new
   * `{begin,end,capacity}` triple.
   */
  std::int32_t ReallocateWatchBoneStorageForInsert(
    moho::SAniManipBinding* const insertPosition,
    moho::SAniManipBindingStorage* const storage,
    std::int32_t newCapacity,
    const moho::SAniManipBinding* const insertBegin,
    const moho::SAniManipBinding* const insertEnd
  )
  {
    auto* const newStorage = new moho::SAniManipBinding[newCapacity];
    auto* const afterPrefix = CopyBindingRange(newStorage, insertPosition, storage->mBegin);
    auto* const afterInserted = CopyBindingRange(afterPrefix, insertEnd, insertBegin);
    auto* const newEnd = CopyBindingRange(afterInserted, storage->mEnd, insertPosition);

    if (storage->mBegin == storage->mInlineStorage) {
      // Mirrors the inline-buffer sentinel write in FUN_0063C950.
      storage->mInlineStorage->mBoneIndex = BindingPointerToInt32(storage->mCapacityEnd);
    } else {
      delete[] storage->mBegin;
    }

    storage->mBegin = newStorage;
    storage->mEnd = newEnd;
    storage->mCapacityEnd = newStorage + newCapacity;
    return newCapacity;
  }

  /**
   * Address: 0x0063C5F0 (FUN_0063C5F0, func_AppendBone)
   *
   * What it does:
   * Appends one binding and grows storage with the original doubling policy
   * when the watch-bone buffer is full.
   */
  void AppendWatchBoneBinding(moho::SAniManipBindingStorage* const storage, const moho::SAniManipBinding& binding)
  {
    auto* const end = storage->mEnd;
    if (end == storage->mCapacityEnd) {
      const auto currentSize = static_cast<std::int32_t>(storage->mEnd - storage->mBegin);
      const auto currentCapacity = static_cast<std::int32_t>(storage->mCapacityEnd - storage->mBegin);
      std::int32_t newCapacity = currentSize + 1;
      const std::int32_t doubledCapacity = currentCapacity * 2;
      if (newCapacity < doubledCapacity) {
        newCapacity = doubledCapacity;
      }

      ReallocateWatchBoneStorageForInsert(end, storage, newCapacity, &binding, &binding + 1);
      return;
    }

    if (end) {
      *end = binding;
    }
    ++storage->mEnd;
  }

  /**
   * Address: 0x0063C090 (FUN_0063C090)
   *
   * What it does:
   * Appends one watch-bone binding from `bindingSource`, growing storage with
   * the standard append helper when capacity is exhausted.
   */
  [[maybe_unused]] moho::SAniManipBinding* AppendWatchBoneBindingFromPointer(
    moho::SAniManipBindingStorage* const storage,
    const moho::SAniManipBinding* const bindingSource
  )
  {
    auto* const end = storage->mEnd;

    if (end == storage->mCapacityEnd) {
      AppendWatchBoneBinding(storage, *bindingSource);
      return end;
    }

    if (end != nullptr) {
      *end = *bindingSource;
    }
    ++storage->mEnd;
    return end;
  }

  /**
   * Address: 0x0063ACE0 (FUN_0063ACE0, sub_63ACE0)
   *
   * What it does:
   * Inserts `manipulator` into CAniActor's intrusive order list sorted by
   * ascending `mPrecedence`.
   */
  void RegisterWithOwnerActorOrderList(moho::CAniActor* const ownerActor, moho::IAniManipulator* const manipulator)
  {
    auto* const listHead =
      static_cast<moho::TDatListItem<moho::IAniManipulator, void>*>(&ownerActor->mManipulatorsByPrecedence);
    auto* insertBefore = ownerActor->mManipulatorsByPrecedence.mNext;
    while (insertBefore != listHead) {
      auto* const current = ManipulatorFromActorOrderLinkSlot(&insertBefore);
      if (manipulator->mPrecedence < current->mPrecedence) {
        break;
      }
      insertBefore = insertBefore->mNext;
    }

    manipulator->mActorOrderLink.ListLinkBefore(insertBefore);
  }

  /**
   * Address: 0x0063B740 (FUN_0063B740)
   *
   * What it does:
   * Unlinks one manipulator from actor-order lanes, updates precedence, then
   * reinserts it through `CAniActor::AddManipulator`.
   */
  [[maybe_unused]] moho::TDatListItem<moho::IAniManipulator, void>* ReinsertManipulatorAtPrecedence(
    moho::IAniManipulator* const manipulator,
    const int precedence
  )
  {
    manipulator->mActorOrderLink.ListUnlink();
    manipulator->mPrecedence = precedence;
    if (manipulator->mOwnerActor != nullptr) {
      RegisterWithOwnerActorOrderList(manipulator->mOwnerActor, manipulator);
    }
    return &manipulator->mActorOrderLink;
  }

  /**
   * Address: 0x00632C20 (FUN_00632C20)
   *
   * What it does:
   * Resolves and caches the reflected runtime type for `IAniManipulator`.
   */
  gpg::RType* CachedIAniManipulatorType()
  {
    if (!moho::IAniManipulator::sType) {
      moho::IAniManipulator::sType = gpg::LookupRType(typeid(moho::IAniManipulator));
    }
    return moho::IAniManipulator::sType;
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* object, gpg::RType* staticType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = staticType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType->IsDerivedFrom(staticType, &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  void AddCScriptEventBase(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = gpg::LookupRType(typeid(moho::CScriptEvent));
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  alignas(moho::IAniManipulatorTypeInfo)
  unsigned char gIAniManipulatorTypeInfoStorage[sizeof(moho::IAniManipulatorTypeInfo)] = {};
  bool gIAniManipulatorTypeInfoConstructed = false;

  gpg::RType* gCAniActorType = nullptr;
  gpg::RType* gSimType = nullptr;
  gpg::RType* gFastVectorSAniManipBindingType = nullptr;
  gpg::RType* gWeakPtrUnitType = nullptr;

  moho::IAniManipulatorSerializer gIAniManipulatorSerializer{};

  [[nodiscard]] gpg::RType* CachedCAniActorType()
  {
    if (!gCAniActorType) {
      gCAniActorType = gpg::LookupRType(typeid(moho::CAniActor));
    }
    return gCAniActorType;
  }

  [[nodiscard]] gpg::RType* CachedSimType()
  {
    if (!gSimType) {
      gSimType = gpg::LookupRType(typeid(moho::Sim));
      moho::Sim::sType = gSimType;
    }
    return gSimType;
  }

  [[nodiscard]] gpg::RType* CachedFastVectorSAniManipBindingType()
  {
    if (!gFastVectorSAniManipBindingType) {
      gFastVectorSAniManipBindingType = gpg::LookupRType(typeid(gpg::fastvector<moho::SAniManipBinding>));
    }
    return gFastVectorSAniManipBindingType;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    if (!gWeakPtrUnitType) {
      gWeakPtrUnitType = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = gWeakPtrUnitType;
    }
    return gWeakPtrUnitType;
  }

  [[nodiscard]] gpg::RType* CachedCScriptEventType()
  {
    if (!moho::CScriptEvent::sType) {
      moho::CScriptEvent::sType = gpg::LookupRType(typeid(moho::CScriptEvent));
    }
    return moho::CScriptEvent::sType;
  }

  [[nodiscard]] moho::IAniManipulatorTypeInfo* AcquireIAniManipulatorTypeInfo()
  {
    if (!gIAniManipulatorTypeInfoConstructed) {
      auto* const typeInfo = new (gIAniManipulatorTypeInfoStorage) moho::IAniManipulatorTypeInfo();
      gpg::PreRegisterRType(typeid(moho::IAniManipulator), typeInfo);
      gIAniManipulatorTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::IAniManipulatorTypeInfo*>(gIAniManipulatorTypeInfoStorage);
  }

  template <typename TObject>
  [[nodiscard]] TObject* ReadUnownedPointer(gpg::ReadArchive* const archive, gpg::RType* const expectedType)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, gpg::RRef{});
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    return static_cast<TObject*>(upcast.mObj);
  }

  template <typename TObject>
  void WriteUnownedPointer(gpg::WriteArchive* const archive, TObject* const object, gpg::RType* const expectedType)
  {
    gpg::RRef objectRef{};
    objectRef.mObj = object;
    objectRef.mType = expectedType;
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mNext = self;
    helper.mPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mNext != nullptr && helper.mPrev != nullptr) {
      static_cast<gpg::SerHelperBase*>(helper.mNext)->mPrev = static_cast<gpg::SerHelperBase*>(helper.mPrev);
      static_cast<gpg::SerHelperBase*>(helper.mPrev)->mNext = static_cast<gpg::SerHelperBase*>(helper.mNext);
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mPrev = self;
    helper.mNext = self;
    return self;
  }

  void cleanup_IAniManipulatorTypeInfo_00BFADC0_Impl()
  {
    if (!gIAniManipulatorTypeInfoConstructed) {
      return;
    }

    static_cast<gpg::RType*>(AcquireIAniManipulatorTypeInfo())->~RType();
    gIAniManipulatorTypeInfoConstructed = false;
  }

  [[nodiscard]] gpg::SerHelperBase* cleanup_IAniManipulatorSerializer_00BFAE20_Impl()
  {
    return UnlinkHelperNode(gIAniManipulatorSerializer);
  }

  /**
   * Address: 0x0063BA30 (FUN_0063BA30)
   *
   * What it does:
   * Initializes callback lanes for global `IAniManipulatorSerializer` helper
   * storage and returns that helper object.
   */
  [[maybe_unused]] [[nodiscard]] moho::IAniManipulatorSerializer* InitializeIAniManipulatorSerializerStartupThunk()
  {
    InitializeHelperNode(gIAniManipulatorSerializer);
    gIAniManipulatorSerializer.mSerLoadFunc = &moho::IAniManipulatorSerializer::Deserialize;
    gIAniManipulatorSerializer.mSerSaveFunc = &moho::IAniManipulatorSerializer::Serialize;
    return &gIAniManipulatorSerializer;
  }

  /**
   * Address: 0x0063BA60 (FUN_0063BA60)
   *
   * What it does:
   * Startup cleanup variant that unlinks and self-resets the global
   * IAniManipulator serializer helper node.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_IAniManipulatorSerializerStartupThunkA()
  {
    return UnlinkHelperNode(gIAniManipulatorSerializer);
  }

  /**
   * Address: 0x0063BA90 (FUN_0063BA90)
   *
   * What it does:
   * Secondary startup cleanup variant that unlinks and self-resets the global
   * IAniManipulator serializer helper node.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_IAniManipulatorSerializerStartupThunkB()
  {
    return UnlinkHelperNode(gIAniManipulatorSerializer);
  }

  void CleanupIAniManipulatorTypeInfoAtexit()
  {
    cleanup_IAniManipulatorTypeInfo_00BFADC0_Impl();
  }

  void CleanupIAniManipulatorSerializerAtexit()
  {
    (void)cleanup_IAniManipulatorSerializer_00BFAE20_Impl();
  }

  /**
   * Address: 0x0063E380 (FUN_0063E380, sub_63E380)
   *
   * What it does:
   * Loads IAniManipulator base serialization fields into an existing object.
   */
  void DeserializeIAniManipulatorState(moho::IAniManipulator* const object, gpg::ReadArchive* const archive)
  {
    if (!archive || !object) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(CachedCScriptEventType(), object, nullOwner);
    archive->ReadBool(&object->mEnabled);
    object->mOwnerActor = ReadUnownedPointer<moho::CAniActor>(archive, CachedCAniActorType());
    object->mOwnerSim = ReadUnownedPointer<moho::Sim>(archive, CachedSimType());
    archive->ReadInt(&object->mPrecedence);
    archive->Read(CachedFastVectorSAniManipBindingType(), &object->mWatchBones, nullOwner);
  }

  /**
   * Address: 0x0063E450 (FUN_0063E450, sub_63E450)
   *
   * What it does:
   * Saves IAniManipulator base serialization fields from an existing object.
   */
  void SerializeIAniManipulatorState(const moho::IAniManipulator* const object, gpg::WriteArchive* const archive)
  {
    if (!archive || !object) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(CachedCScriptEventType(), const_cast<moho::IAniManipulator*>(object), nullOwner);
    archive->WriteBool(object->mEnabled);
    WriteUnownedPointer(archive, object->mOwnerActor, CachedCAniActorType());
    WriteUnownedPointer(archive, object->mOwnerSim, CachedSimType());
    archive->WriteInt(object->mPrecedence);
    archive->Write(
      CachedFastVectorSAniManipBindingType(),
      const_cast<moho::SAniManipBindingStorage*>(&object->mWatchBones),
      nullOwner
    );
  }

  /**
   * Address: 0x0063A460 (FUN_0063A460)
   *
   * What it does:
   * Loads CFootPlantManipulator payload lanes: IAniManipulator base state,
   * goal-unit weak pointer, foot/knee/hip bones, straight-leg flag, and
   * foot-fall tuning floats.
   */
  [[maybe_unused]] void DeserializeCFootPlantManipulatorState(
    moho::CFootPlantManipulator* const object,
    gpg::ReadArchive* const archive
  )
  {
    if (!archive || !object) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(CachedIAniManipulatorType(), static_cast<moho::IAniManipulator*>(object), nullOwner);
    archive->Read(CachedWeakPtrUnitType(), &object->mGoalUnit, nullOwner);
    archive->ReadInt(&object->mFootBoneIndex);
    archive->ReadInt(&object->mKneeBoneIndex);
    archive->ReadInt(&object->mHipBoneIndex);
    archive->ReadBool(&object->mStraightLegs);
    archive->ReadFloat(&object->mMaxFootFall);
    archive->ReadFloat(&object->mHalfLegSpan);
  }

  /**
   * Address: 0x0063A540 (FUN_0063A540)
   *
   * What it does:
   * Saves CFootPlantManipulator payload lanes: IAniManipulator base state,
   * goal-unit weak pointer, foot/knee/hip bones, straight-leg flag, and
   * foot-fall tuning floats.
   */
  [[maybe_unused]] void SerializeCFootPlantManipulatorState(
    const moho::CFootPlantManipulator* const object,
    gpg::WriteArchive* const archive
  )
  {
    const gpg::RRef nullOwner{};
    archive->Write(
      CachedIAniManipulatorType(),
      const_cast<moho::IAniManipulator*>(static_cast<const moho::IAniManipulator*>(object)),
      nullOwner
    );
    archive->Write(CachedWeakPtrUnitType(), const_cast<moho::WeakPtr<moho::Unit>*>(&object->mGoalUnit), nullOwner);
    archive->WriteInt(object->mFootBoneIndex);
    archive->WriteInt(object->mKneeBoneIndex);
    archive->WriteInt(object->mHipBoneIndex);
    archive->WriteBool(object->mStraightLegs);
    archive->WriteFloat(object->mMaxFootFall);
    archive->WriteFloat(object->mHalfLegSpan);
  }

  /**
   * Address: 0x0063A2A0 (FUN_0063A2A0)
   *
   * What it does:
   * Tail-thunk alias that forwards to CFootPlantManipulator serialize body.
   */
  [[maybe_unused]] void SerializeCFootPlantManipulatorStateThunkAlias(
    const moho::CFootPlantManipulator* const object,
    gpg::WriteArchive* const archive
  )
  {
    SerializeCFootPlantManipulatorState(object, archive);
  }

  /**
   * Address: 0x0063A1C0 (FUN_0063A1C0)
   *
   * What it does:
   * Additional tail-thunk alias that forwards CFootPlantManipulator save lanes
   * into the shared serializer body.
   */
  [[maybe_unused]] void SerializeCFootPlantManipulatorStateThunkAliasB(
    const moho::CFootPlantManipulator* const object,
    gpg::WriteArchive* const archive
  )
  {
    SerializeCFootPlantManipulatorState(object, archive);
  }

  /**
   * Address: 0x0063CDD0 (FUN_0063CDD0)
   *
   * What it does:
   * First tail-thunk alias that forwards IAniManipulator save lanes into the
   * shared serializer body.
   */
  [[maybe_unused]] void SerializeIAniManipulatorStateThunkAliasA(
    const moho::IAniManipulator* const object,
    gpg::WriteArchive* const archive
  )
  {
    SerializeIAniManipulatorState(object, archive);
  }

  /**
   * Address: 0x0063D7F0 (FUN_0063D7F0)
   *
   * What it does:
   * Second tail-thunk alias that forwards IAniManipulator save lanes into the
   * shared serializer body.
   */
  [[maybe_unused]] void SerializeIAniManipulatorStateThunkAliasB(
    const moho::IAniManipulator* const object,
    gpg::WriteArchive* const archive
  )
  {
    SerializeIAniManipulatorState(object, archive);
  }
} // namespace

namespace moho
{
  gpg::RType* IAniManipulator::sType = nullptr;

  /**
   * Address: 0x0063B5D0 (FUN_0063B5D0, ??0IAniManipulator@Moho@@QAE@XZ)
   */
  IAniManipulator::IAniManipulator()
    : mOwnerActor(nullptr)
    , mOwnerSim(nullptr)
    , mPrecedence(0)
  {
    InitializeWatchBoneStorage(this);
  }

  /**
   * Address: 0x0063B640 (FUN_0063B640, ??0IAniManipulator@Moho@@QAE@PAVSim@1@PAVCAniActor@1@H@Z)
   */
  IAniManipulator::IAniManipulator(Sim* const sim, CAniActor* const ownerActor, const int precedence)
    : mOwnerActor(ownerActor)
    , mOwnerSim(sim)
    , mPrecedence(precedence)
  {
    mEnabled = true;
    InitializeWatchBoneStorage(this);
    RegisterWithOwnerActorOrderList(ownerActor, this);
  }

  bool IAniManipulator::ManipulatorUpdate()
  {
    return false;
  }

  /**
   * Address: 0x006392E0 (FUN_006392E0, ??0CFootPlantManipulator@Moho@@QAE@XZ)
   */
  CFootPlantManipulator::CFootPlantManipulator()
    : IAniManipulator()
    , mGoalUnit()
    , mFootBoneIndex(0)
    , mKneeBoneIndex(0)
    , mHipBoneIndex(0)
    , mStraightLegs(false)
    , mMaxFootFall(0.0f)
    , mHalfLegSpan(0.0f)
  {
  }

  /**
   * Address: 0x00634400 (FUN_00634400, ??0CBoneEntityManipulator@Moho@@QAE@@Z)
   */
  CBoneEntityManipulator::CBoneEntityManipulator()
    : IAniManipulator()
    , mGoalUnit()
    , mTargetEntity()
    , mReferenceBoneIndex(0)
    , mPivot(0.0f, 0.0f, 0.0f)
  {
  }

  /**
   * Address: 0x00634630 (FUN_00634630, ??1CBoneEntityManipulator@Moho@@QAE@@Z)
   */
  CBoneEntityManipulator::~CBoneEntityManipulator()
  {
    mTargetEntity.UnlinkFromOwnerChain();
    mTargetEntity.ClearLinkState();

    mGoalUnit.UnlinkFromOwnerChain();
    mGoalUnit.ClearLinkState();

    mTargetEntity.UnlinkFromOwnerChain();
    mGoalUnit.UnlinkFromOwnerChain();
  }

  bool CFootPlantManipulator::ManipulatorUpdate()
  {
    return false;
  }

  bool CBoneEntityManipulator::ManipulatorUpdate()
  {
    return false;
  }

  /**
   * Address: 0x0062FBF0 (FUN_0062FBF0)
   *
   * What it does:
   * Returns the extended runtime dword lane at offset `+0xA38`.
   */
  std::uint32_t GetRuntimeValueA38(const IAniManipulatorLargeRuntimeSlotA38View* const runtime)
  {
    return runtime->mValueA38;
  }

  /**
   * Address: 0x0062FD00 (FUN_0062FD00)
   *
   * What it does:
   * Returns the owner-actor lane from the manipulator base runtime view.
   */
  CAniActor* GetRuntimeOwnerActor(const IAniManipulatorBaseRuntimeView* const runtime)
  {
    return runtime->mOwnerActor;
  }

  /**
   * Address: 0x0062FD10 (FUN_0062FD10)
   *
   * What it does:
   * Returns the owner-sim lane from the manipulator base runtime view.
   */
  Sim* GetRuntimeOwnerSim(const IAniManipulatorBaseRuntimeView* const runtime)
  {
    return runtime->mOwnerSim;
  }

  /**
   * Address: 0x0062FD40 (FUN_0062FD40)
   *
   * What it does:
   * Returns the override scalar when non-negative, otherwise the fallback
   * scalar from the vtable lane at `+0x78`.
   */
  float ReadOverrideOrFallbackScalar(const RuntimeOverrideFloatLaneView* const runtime)
  {
    const float overrideValue = runtime->mOverrideValue;
    if (overrideValue < 0.0f) {
      return runtime->mVTable->mFallbackValue;
    }
    return overrideValue;
  }

  /**
   * Address: 0x0062FD60 (FUN_0062FD60)
   *
   * What it does:
   * Writes the extended runtime dword lane at `+0xA8`.
   */
  IAniManipulatorExtendedRuntimeView* SetRuntimeFieldA8(
    IAniManipulatorExtendedRuntimeView* const runtime, const std::int32_t value
  )
  {
    runtime->mFieldA8 = value;
    return runtime;
  }

  /**
   * Address: 0x0062FDA0 (FUN_0062FDA0)
   *
   * What it does:
   * Writes the byte lane at offset `+0x174`.
   */
  IAniManipulatorExtendedRuntimeView* SetRuntimeFlag174(
    IAniManipulatorExtendedRuntimeView* const runtime, const bool enabled
  )
  {
    runtime->mFlag174 = enabled;
    return runtime;
  }

  /**
   * Address: 0x0062FDB0 (FUN_0062FDB0)
   *
   * What it does:
   * Copies one `Vector3` payload into runtime lanes `+0x178/+0x17C/+0x180`.
   */
  const RuntimeVector3LaneView* CopyRuntimeVectorToSlot178(
    const RuntimeVector3LaneView* const source, IAniManipulatorExtendedRuntimeView* const runtime
  )
  {
    runtime->mVector178X = source->x;
    runtime->mVector17CY = source->y;
    runtime->mVector180Z = source->z;
    return source;
  }

  /**
   * Address: 0x0062FDD0 (FUN_0062FDD0)
   *
   * What it does:
   * Writes the byte lane at offset `+0xF0`.
   */
  IAniManipulatorExtendedRuntimeView* SetRuntimeFlagF0(
    IAniManipulatorExtendedRuntimeView* const runtime, const bool enabled
  )
  {
    runtime->mFlagF0 = enabled;
    return runtime;
  }

  /**
   * Address: 0x0062FDE0 (FUN_0062FDE0)
   *
   * What it does:
   * Returns the actor-order intrusive `next` pointer lane at offset `+0x44`.
   */
  TDatListItem<IAniManipulator, void>* GetActorOrderNextLink(const IAniManipulatorBaseRuntimeView* const runtime)
  {
    return runtime->mActorOrderNext;
  }

  /**
   * Address: 0x0062FE50 (FUN_0062FE50)
   *
   * What it does:
   * Returns the byte flag lane at offset `+0xE0`.
   */
  bool GetRuntimeFlagE0(const IAniManipulatorExtendedRuntimeView* const runtime)
  {
    return runtime->mFlagE0;
  }

  /**
   * Address: 0x0062FE60 (FUN_0062FE60)
   *
   * What it does:
   * Writes the dword lane at offset `+0xE4`.
   */
  IAniManipulatorExtendedRuntimeView* SetRuntimeFieldE4(
    IAniManipulatorExtendedRuntimeView* const runtime, const std::int32_t value
  )
  {
    runtime->mFieldE4 = value;
    return runtime;
  }

  /**
   * Address: 0x0062FE70 (FUN_0062FE70)
   *
   * What it does:
   * Returns the scalar lane at offset `+0xB8`.
   */
  float GetRuntimeScalarB8(const IAniManipulatorExtendedRuntimeView* const runtime)
  {
    return runtime->mScalarB8;
  }

  /**
   * Address: 0x0062FE80 (FUN_0062FE80)
   *
   * What it does:
   * Returns the scalar lane at offset `+0xBC`.
   */
  float GetRuntimeScalarBC(const IAniManipulatorExtendedRuntimeView* const runtime)
  {
    return runtime->mScalarBC;
  }

  /**
   * Address: 0x0062FE90 (FUN_0062FE90)
   *
   * What it does:
   * Writes scalar runtime lanes `+0xB8` and `+0xBC`.
   */
  IAniManipulatorExtendedRuntimeView* SetRuntimeScalarsB8AndBC(
    IAniManipulatorExtendedRuntimeView* const runtime, const float first, const float second
  )
  {
    runtime->mScalarB8 = first;
    runtime->mScalarBC = second;
    return runtime;
  }

  /**
   * Address: 0x00630750 (FUN_00630750)
   *
   * What it does:
   * Writes flag `+0xB4` and clears flag `+0xE0`.
   */
  IAniManipulatorExtendedRuntimeView* SetRuntimeFlagB4AndClearFlagE0(
    IAniManipulatorExtendedRuntimeView* const runtime, const bool enabled
  )
  {
    runtime->mFlagB4 = enabled;
    runtime->mFlagE0 = false;
    return runtime;
  }

  /**
   * Address: 0x00632CA0 (FUN_00632CA0)
   *
   * What it does:
   * Attaches an intrusive node to an owner's head lane at offset `+0x14`.
   */
  IntrusiveNodeRuntimeView* AttachNodeToOwnerHead(
    IntrusiveNodeRuntimeView* const node, IntrusiveOwnerHeadRuntimeView* const owner
  )
  {
    IntrusiveNodeRuntimeView* const head = owner ? &owner->mHead : nullptr;
    node->mNext = head;
    if (head != nullptr) {
      node->mPrev = head->mNext;
      head->mNext = node;
    } else {
      node->mPrev = nullptr;
    }
    return node;
  }

  /**
   * Address: 0x00632DF0 (FUN_00632DF0)
   *
   * What it does:
   * Unlinks one intrusive node, then restores self-links.
   */
  IntrusiveNodeRuntimeView* UnlinkNodeAndRestoreSelfLinks(IntrusiveNodeRuntimeView* const node)
  {
    node->mNext->mPrev = node->mPrev;
    node->mPrev->mNext = node->mNext;
    node->mPrev = node;
    node->mNext = node;
    return node;
  }

  /**
   * Address: 0x006346E0 (FUN_006346E0)
   *
   * What it does:
   * Copies one `Vector3` payload into runtime lane `+0x94`.
   */
  const RuntimeVector3LaneView* CopyRuntimeVectorToSlot94(
    const RuntimeVector3LaneView* const source, IAniManipulatorScalarPairRuntimeView* const runtime
  )
  {
    runtime->mVector94 = *source;
    return source;
  }

  /**
   * Address: 0x00635950 (FUN_00635950)
   *
   * What it does:
   * Returns scalar runtime lane `+0x88`.
   */
  float GetRuntimeScalar88(const IAniManipulatorScalarPairRuntimeView* const runtime)
  {
    return runtime->mScalar88;
  }

  /**
   * Address: 0x00635960 (FUN_00635960)
   *
   * What it does:
   * Returns scalar runtime lane `+0x8C`.
   */
  float GetRuntimeScalar8C(const IAniManipulatorScalarPairRuntimeView* const runtime)
  {
    return runtime->mScalar8C;
  }

  /**
   * Address: 0x00635970 (FUN_00635970)
   *
   * What it does:
   * Writes scalar runtime lanes `+0x88` and `+0x8C`.
   */
  IAniManipulatorScalarPairRuntimeView* SetRuntimeScalars88And8C(
    IAniManipulatorScalarPairRuntimeView* const runtime, const float first, const float second
  )
  {
    runtime->mScalar88 = first;
    runtime->mScalar8C = second;
    return runtime;
  }

  /**
   * Address: 0x006378B0 (FUN_006378B0)
   *
   * What it does:
   * Clears runtime flag `+0x84` and clears the transient high-halfword bit
   * across all watch-bone binding flags.
   */
  SAniManipBinding* ResetWatchBoneTransientBits(IAniManipulatorWatchBoneRuntimeView* const runtime)
  {
    runtime->mFlag84 = false;
    SAniManipBinding* entry = runtime->mWatchBonesBegin;
    while (entry != runtime->mWatchBonesEnd) {
      entry->mFlags &= kWatchBoneTransientHighBitClearMask;
      ++entry;
    }
    return entry;
  }

  /**
   * Address: 0x006378E0 (FUN_006378E0)
   *
   * What it does:
   * Writes runtime flag lane `+0x85`.
   */
  IAniManipulatorWatchBoneRuntimeView* SetRuntimeFlag85(
    IAniManipulatorWatchBoneRuntimeView* const runtime, const bool enabled
  )
  {
    runtime->mFlag85 = enabled;
    return runtime;
  }

  /**
   * Address: 0x00639F50 (FUN_00639F50)
   *
   * What it does:
   * Installs CFootPlantManipulator creation/destruction callback lanes into
   * the reflected type descriptor.
   */
  gpg::RType* InstallFootPlantManipulatorTypeCallbacks(gpg::RType* const typeInfo)
  {
    typeInfo->newRefFunc_ = &CreateFootPlantManipulatorRefCallback;
    typeInfo->ctorRefFunc_ = &ConstructFootPlantManipulatorRefCallback;
    typeInfo->deleteFunc_ = &DeleteFootPlantManipulatorCallback;
    typeInfo->dtrFunc_ = &DestructFootPlantManipulatorCallback;
    return typeInfo;
  }

  /**
   * Address: 0x0063A700 (FUN_0063A700)
   *
   * What it does:
   * Returns manipulator precedence lane `+0x58`.
   */
  std::int32_t GetRuntimePrecedence(const IAniManipulatorBaseRuntimeView* const runtime)
  {
    return runtime->mPrecedence;
  }

  /**
   * Address: 0x0063A710 (FUN_0063A710)
   *
   * What it does:
   * Writes manipulator enabled lane `+0x4C`.
   */
  IAniManipulatorBaseRuntimeView* SetRuntimeEnabledFlag(IAniManipulatorBaseRuntimeView* const runtime, const bool enabled)
  {
    runtime->mEnabled = enabled;
    return runtime;
  }

  /**
   * Address: 0x0063A720 (FUN_0063A720)
   *
   * What it does:
   * Returns manipulator enabled lane `+0x4C`.
   */
  bool GetRuntimeEnabledFlag(const IAniManipulatorBaseRuntimeView* const runtime)
  {
    return runtime->mEnabled;
  }

  /**
   * Address: 0x0063B960 (FUN_0063B960)
   *
   * What it does:
   * Returns true when one watched-bone entry has `mBoneIndex == boneIndex`.
   */
  bool HasWatchedBoneIndex(const IAniManipulatorWatchBoneRuntimeView* const runtime, const std::int32_t boneIndex)
  {
    const SAniManipBinding* entry = runtime->mWatchBonesBegin;
    while (entry != runtime->mWatchBonesEnd) {
      if (entry->mBoneIndex == boneIndex) {
        return true;
      }
      ++entry;
    }
    return false;
  }

  /**
   * Address: 0x0063BFF0 (FUN_0063BFF0)
   *
   * What it does:
   * Initializes one intrusive node with self-links.
   */
  IntrusiveNodeRuntimeView* InitializeNodeSelfLinks(IntrusiveNodeRuntimeView* const node)
  {
    node->mPrev = node;
    node->mNext = node;
    return node;
  }

  /**
   * Address: 0x0063C010 (FUN_0063C010)
   *
   * What it does:
   * Writes one single-pointer slot lane.
   */
  PointerSlotRuntimeView* SetPointerSlotValue(PointerSlotRuntimeView* const slot, const std::uintptr_t value)
  {
    slot->mValue = value;
    return slot;
  }

  /**
   * Address: 0x0062FC70 (FUN_0062FC70, ??1IAniManipulator@Moho@@UAE@XZ)
   */
  IAniManipulator::~IAniManipulator()
  {
    ResetWatchBoneStorage();
    mActorOrderLink.ListUnlink();
  }

  /**
   * Address: 0x0062FC30 (FUN_0062FC30, ?GetClass@IAniManipulator@Moho@@UBEPAVRType@gpg@@XZ)
   */
  gpg::RType* IAniManipulator::GetClass() const
  {
    return CachedIAniManipulatorType();
  }

  /**
   * Address: 0x0062FC50 (FUN_0062FC50, ?GetDerivedObjectRef@IAniManipulator@Moho@@UAE?AVRRef@gpg@@XZ)
   */
  gpg::RRef IAniManipulator::GetDerivedObjectRef()
  {
    return MakeTypedRef(this, CachedIAniManipulatorType());
  }

  /**
   * Address: 0x0063B6D0 (FUN_0063B6D0, ?AddWatchBone@IAniManipulator@Moho@@QAEHH@Z)
   */
  int IAniManipulator::AddWatchBone(const int boneIndex)
  {
    SAniManipBinding watchBone{};
    watchBone.mBoneIndex = boneIndex;
    watchBone.mFlags = kWatchBoneActiveFlag;
    (void)AppendWatchBoneBindingFromPointer(&mWatchBones, &watchBone);
    return static_cast<int>(mWatchBones.mEnd - mWatchBones.mBegin - 1);
  }

  /**
   * Address: 0x0063BAC0 (FUN_0063BAC0, cfunc_IAniManipulatorSetPrecedence)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IAniManipulatorSetPrecedenceL`.
   */
  int cfunc_IAniManipulatorSetPrecedence(lua_State* const luaContext)
  {
    return cfunc_IAniManipulatorSetPrecedenceL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0063BAE0 (FUN_0063BAE0, func_IAniManipulatorSetPrecedence_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IAniManipulator:SetPrecedence(integer)` Lua binder.
   */
  CScrLuaInitForm* func_IAniManipulatorSetPrecedence_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIAniManipulatorSetPrecedenceName,
      &moho::cfunc_IAniManipulatorSetPrecedence,
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      kIAniManipulatorLuaClassName,
      kIAniManipulatorSetPrecedenceHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0063BB40 (FUN_0063BB40, cfunc_IAniManipulatorSetPrecedenceL)
   *
   * What it does:
   * Reads `(manipulator, precedence)`, updates manipulator precedence, and
   * reinserts it into the owning actor precedence list.
   */
  int cfunc_IAniManipulatorSetPrecedenceL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kIAniManipulatorSetPrecedenceHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    IAniManipulator* const manipulator = SCR_FromLua_IAniManipulator(manipulatorObject, state);

    LuaPlus::LuaStackObject precedenceArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      precedenceArg.TypeError("integer");
    }

    const int precedence = static_cast<int>(lua_tonumber(rawState, 2));

    (void)ReinsertManipulatorAtPrecedence(manipulator, precedence);

    lua_settop(rawState, 1);
    return 1;
  }

  /**
   * Address: 0x0063BC60 (FUN_0063BC60, cfunc_IAniManipulatorEnable)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IAniManipulatorEnableL`.
   */
  int cfunc_IAniManipulatorEnable(lua_State* const luaContext)
  {
    return cfunc_IAniManipulatorEnableL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0063BC80 (FUN_0063BC80, func_IAniManipulatorEnable_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IAniManipulator:Enable()` Lua binder.
   */
  CScrLuaInitForm* func_IAniManipulatorEnable_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIAniManipulatorEnableName,
      &moho::cfunc_IAniManipulatorEnable,
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      kIAniManipulatorLuaClassName,
      kIAniManipulatorEnableHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0063BCE0 (FUN_0063BCE0, cfunc_IAniManipulatorEnableL)
   *
   * What it does:
   * Validates `IAniManipulator:Enable()`, resolves one manipulator, and marks
   * it enabled.
   */
  int cfunc_IAniManipulatorEnableL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kIAniManipulatorEnableHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    IAniManipulator* const manipulator = SCR_FromLua_IAniManipulator(manipulatorObject, state);
    if (manipulator) {
      manipulator->mEnabled = true;
    }

    return 0;
  }

  /**
   * Address: 0x0063BD90 (FUN_0063BD90, cfunc_IAniManipulatorDisable)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IAniManipulatorDisableL`.
   */
  int cfunc_IAniManipulatorDisable(lua_State* const luaContext)
  {
    return cfunc_IAniManipulatorDisableL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0063BDB0 (FUN_0063BDB0, func_IAniManipulatorDisable_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IAniManipulator:Disable()` Lua binder.
   */
  CScrLuaInitForm* func_IAniManipulatorDisable_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIAniManipulatorDisableName,
      &moho::cfunc_IAniManipulatorDisable,
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      kIAniManipulatorLuaClassName,
      kIAniManipulatorDisableHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0063BE10 (FUN_0063BE10, cfunc_IAniManipulatorDisableL)
   *
   * What it does:
   * Validates `IAniManipulator:Disable()`, resolves one manipulator, and marks
   * it disabled.
   */
  int cfunc_IAniManipulatorDisableL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kIAniManipulatorDisableHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    IAniManipulator* const manipulator = SCR_FromLua_IAniManipulator(manipulatorObject, state);
    if (manipulator) {
      manipulator->mEnabled = false;
    }

    return 0;
  }

  /**
   * Address: 0x0063BEC0 (FUN_0063BEC0, cfunc_IAniManipulatorDestroy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IAniManipulatorDestroyL`.
   */
  int cfunc_IAniManipulatorDestroy(lua_State* const luaContext)
  {
    return cfunc_IAniManipulatorDestroyL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0063BEE0 (FUN_0063BEE0, func_IAniManipulatorDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IAniManipulator:Destroy()` Lua binder.
   */
  CScrLuaInitForm* func_IAniManipulatorDestroy_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIAniManipulatorDestroyName,
      &moho::cfunc_IAniManipulatorDestroy,
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      kIAniManipulatorLuaClassName,
      kIAniManipulatorDestroyHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0063BF40 (FUN_0063BF40, cfunc_IAniManipulatorDestroyL)
   *
   * What it does:
   * Validates `IAniManipulator:Destroy()`, resolves one optional manipulator
   * pointer, and destroys the object when still alive.
   */
  int cfunc_IAniManipulatorDestroyL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kIAniManipulatorDestroyHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    IAniManipulator* const manipulator = SCR_FromLua_IAniManipulatorOpt(manipulatorObject, state);
    if (manipulator) {
      delete manipulator;
    }

    return 0;
  }

  void IAniManipulator::ResetWatchBoneStorage()
  {
    auto& storage = mWatchBones;
    auto* const inlineStorage = storage.mInlineStorage;
    if (storage.mBegin != inlineStorage) {
      delete[] storage.mBegin;
      storage.mBegin = inlineStorage;
      storage.mCapacityEnd = Int32ToBindingPointer(inlineStorage->mBoneIndex);
    }

    storage.mEnd = storage.mBegin;
  }

  /**
   * Address: 0x0063C540 (FUN_0063C540, sub_63C540)
   */
  void IAniManipulatorSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedIAniManipulatorType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mSerLoadFunc);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerSaveFunc);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x0063BA10 (FUN_0063BA10, Moho::IAniManipulatorSerializer::Deserialize)
   */
  void IAniManipulatorSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    DeserializeIAniManipulatorState(reinterpret_cast<IAniManipulator*>(objectPtr), archive);
  }

  /**
   * Address: 0x0063BA20 (FUN_0063BA20, Moho::IAniManipulatorSerializer::Serialize)
   */
  void IAniManipulatorSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    SerializeIAniManipulatorState(reinterpret_cast<const IAniManipulator*>(objectPtr), archive);
  }

  /**
   * Address: 0x0063B520 (FUN_0063B520, scalar deleting destructor thunk)
   */
  IAniManipulatorTypeInfo::~IAniManipulatorTypeInfo() = default;

  /**
   * Address: 0x0063B510 (FUN_0063B510, ?GetName@IAniManipulatorTypeInfo@Moho@@UBEPBDXZ)
   */
  const char* IAniManipulatorTypeInfo::GetName() const
  {
    return "IAniManipulator";
  }

  /**
   * Address: 0x0063B4E0 (FUN_0063B4E0, ?Init@IAniManipulatorTypeInfo@Moho@@UAEXXZ)
   */
  void IAniManipulatorTypeInfo::Init()
  {
    size_ = sizeof(IAniManipulator);
    gpg::RType::Init();
    AddCScriptEventBase(this);
    Finish();
  }

  /**
   * Address: 0x0063B480 (FUN_0063B480, sub_63B480)
   *
   * What it does:
   * Constructs/preregisters startup RTTI storage for IAniManipulator.
   */
  gpg::RType* register_IAniManipulatorTypeInfo_00()
  {
    return AcquireIAniManipulatorTypeInfo();
  }

  /**
   * Address: 0x00BFADC0 (FUN_00BFADC0, sub_BFADC0)
   *
   * What it does:
   * Releases startup-owned IAniManipulator RTTI storage.
   */
  void cleanup_IAniManipulatorTypeInfo()
  {
    cleanup_IAniManipulatorTypeInfo_00BFADC0_Impl();
  }

  /**
   * Address: 0x00BD2C20 (FUN_00BD2C20, sub_BD2C20)
   *
   * What it does:
   * Registers IAniManipulator RTTI startup ownership and installs exit cleanup.
   */
  int register_IAniManipulatorTypeInfo_AtExit()
  {
    (void)register_IAniManipulatorTypeInfo_00();
    return std::atexit(&CleanupIAniManipulatorTypeInfoAtexit);
  }

  /**
   * Address: 0x00BFAE20 (FUN_00BFAE20, Moho::IAniManipulatorSerializer::~IAniManipulatorSerializer)
   *
   * What it does:
   * Unlinks IAniManipulator serializer helper node from the intrusive helper list.
   */
  gpg::SerHelperBase* cleanup_IAniManipulatorSerializer()
  {
    return cleanup_IAniManipulatorSerializer_00BFAE20_Impl();
  }

  /**
   * Address: 0x00BD2C40 (FUN_00BD2C40, register_IAniManipulatorSerializer)
   *
   * What it does:
   * Initializes IAniManipulator serializer helper callbacks and installs exit cleanup.
   */
  void register_IAniManipulatorSerializer()
  {
    InitializeHelperNode(gIAniManipulatorSerializer);
    gIAniManipulatorSerializer.mSerLoadFunc = &IAniManipulatorSerializer::Deserialize;
    gIAniManipulatorSerializer.mSerSaveFunc = &IAniManipulatorSerializer::Serialize;
    (void)std::atexit(&CleanupIAniManipulatorSerializerAtexit);
  }
} // namespace moho

namespace
{
  struct IAniManipulatorStartupBootstrap
  {
    IAniManipulatorStartupBootstrap()
    {
      (void)moho::register_IAniManipulatorTypeInfo_AtExit();
      moho::register_IAniManipulatorSerializer();
    }
  };

  [[maybe_unused]] IAniManipulatorStartupBootstrap gIAniManipulatorStartupBootstrap;
} // namespace
