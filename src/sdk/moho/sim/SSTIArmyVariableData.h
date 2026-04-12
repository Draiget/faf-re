#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/Set.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "Wm3Vector2.h"

namespace moho
{
  /**
   * Address context:
   * - 0x006FDE70 (FUN_006FDE70)
   * - 0x00700280 (FUN_00700280)
   *
   * What it does:
   * Stores a legacy vector payload plus a trailing metadata dword used by
   * SimArmy variable-data copy helpers.
   */
  struct SArmyVectorWithMeta
  {
    msvc8::vector<std::uint32_t> mWords; // +0x00
    std::uint32_t mMetaWord;             // +0x10

    /**
     * Address: 0x007011C0 (FUN_007011C0)
     *
     * What it does:
     * Copies only the vector payload (begin/end/capacity triplet) from `source`
     * while preserving destination MSVC8 vector proxy semantics.
     */
    void CopyWordPayloadFrom(const SArmyVectorWithMeta& source);
  };

  static_assert(offsetof(SArmyVectorWithMeta, mWords) == 0x00, "SArmyVectorWithMeta::mWords offset must be 0x00");
  static_assert(offsetof(SArmyVectorWithMeta, mMetaWord) == 0x10, "SArmyVectorWithMeta::mMetaWord offset must be 0x10");
  static_assert(sizeof(SArmyVectorWithMeta) == 0x14, "SArmyVectorWithMeta size must be 0x14");

  /**
   * Address context:
   * - 0x00550920 (FUN_00550920, SSTIArmyVariableDataTypeInfo::Init)
   * - 0x00700240 (FUN_00700240)
   * - 0x00700280 (FUN_00700280)
   * - 0x00551270 (FUN_00551270, SSTIArmyVariableDataSerializer::Deserialize)
   * - 0x00551500 (FUN_00551500, SSTIArmyVariableDataSerializer::Serialize)
   *
   * What it does:
   * Network/sync variable payload for per-army runtime state.
   * Field coverage follows FA + Moho serializer/copy evidence; unresolved sub-ranges
   * remain explicit offset-scoped runtime blocks.
   */
  struct SSTIArmyVariableData
  {
    SEconTotals mEconomyTotals;             // 0x000
    std::uint8_t mIsResourceSharingEnabled; // 0x038
    std::uint8_t mPad_0039_0040[0x07]{};
    Set mNeutrals;        // 0x040
    Set mAllies;          // 0x060
    Set mEnemies;         // 0x080
    std::uint8_t mIsAlly; // 0x0A0
    std::uint8_t mPad_00A1_00A8[0x07]{};
    Set mValidCommandSources;       // 0x0A8
    std::uint32_t mPlayerColorBgra; // 0x0C8
    std::uint32_t mArmyColorBgra;   // 0x0CC
    msvc8::string mArmyType;        // 0x0D0
    std::int32_t mFaction;          // 0x0EC
    std::uint8_t mUseWholeMap;      // 0x0F0
    std::uint8_t mPad_00F1_00F4[0x03]{};
    SArmyVectorWithMeta mRuntimeWordVectorWithMeta; // 0x0F4
    std::uint8_t mShowScore;                        // 0x108
    std::uint8_t mRuntimePad_0109_0110[0x07]{};
    CategoryWordRangeView mCategoryFilterSet; // 0x110
    std::uint8_t mIsOutOfGame;                // 0x138
    std::uint8_t mPad_0139_013C[0x03]{};
    Wm3::Vector2f mArmyStart;    // 0x13C
    std::int32_t mNoRushTimer;   // 0x144
    float mNoRushRadius;         // 0x148
    Wm3::Vector2f mNoRushOffset; // 0x14C
    float mHandicapValue;        // 0x154
    float mHandicapExtra;        // 0x158
    std::uint8_t mPad_015C_0160[0x04]{};

    /**
     * Address: 0x006FD390 (FUN_006FD390, Moho::SSTIArmyVariableData::SSTIArmyVariableData)
     *
     * What it does:
     * Initializes army variable payload defaults (economy zeros, "None" army
     * type, no-rush defaults, enabled ally/show-score lanes).
     */
    SSTIArmyVariableData();

    /**
     * Address: 0x0055FF80 (FUN_0055FF80, Moho::SSTIArmyVariableData::SSTIArmyVariableData copy-ctor)
     *
     * What it does:
     * Clones army-variable runtime payload lanes, including Set/category
     * bitfields and legacy vector/string members, from one source object.
     */
    SSTIArmyVariableData(const SSTIArmyVariableData& other);

    /**
     * Address: 0x0055FEA0 (FUN_0055FEA0, Moho::SSTIArmyVariableData::~SSTIArmyVariableData)
     *
     * What it does:
     * Tears down set/vector/string member lanes for one army-variable payload.
     */
    ~SSTIArmyVariableData();

    /**
     * Address: 0x00551270 (FUN_00551270, Moho::SSTIArmyVariableDataSerializer::Deserialize)
     *
     * What it does:
     * Reads the serialized army-variable payload from `archive`.
     */
    void SerializeLoadBody(gpg::ReadArchive* archive, gpg::RRef* ownerRef);

    /**
     * Address: 0x00551500 (FUN_00551500, Moho::SSTIArmyVariableDataSerializer::Serialize)
     *
     * What it does:
     * Writes the serialized army-variable payload to `archive`.
     */
    void SerializeSaveBody(gpg::WriteArchive* archive, gpg::RRef* ownerRef) const;
  };

  static_assert(
    offsetof(SSTIArmyVariableData, mEconomyTotals) == 0x000, "SSTIArmyVariableData::mEconomyTotals offset must be 0x000"
  );
  static_assert(
    offsetof(SSTIArmyVariableData, mNeutrals) == 0x040, "SSTIArmyVariableData::mNeutrals offset must be 0x040"
  );
  static_assert(offsetof(SSTIArmyVariableData, mAllies) == 0x060, "SSTIArmyVariableData::mAllies offset must be 0x060");
  static_assert(
    offsetof(SSTIArmyVariableData, mEnemies) == 0x080, "SSTIArmyVariableData::mEnemies offset must be 0x080"
  );
  static_assert(
    offsetof(SSTIArmyVariableData, mValidCommandSources) == 0x0A8,
    "SSTIArmyVariableData::mValidCommandSources offset must be 0x0A8"
  );
  static_assert(
    offsetof(SSTIArmyVariableData, mArmyType) == 0x0D0, "SSTIArmyVariableData::mArmyType offset must be 0x0D0"
  );
  static_assert(
    offsetof(SSTIArmyVariableData, mUseWholeMap) == 0x0F0, "SSTIArmyVariableData::mUseWholeMap offset must be 0x0F0"
  );
  static_assert(
    offsetof(SSTIArmyVariableData, mRuntimeWordVectorWithMeta) == 0x0F4,
    "SSTIArmyVariableData::mRuntimeWordVectorWithMeta offset must be 0x0F4"
  );
  static_assert(
    offsetof(SSTIArmyVariableData, mShowScore) == 0x108, "SSTIArmyVariableData::mShowScore offset must be 0x108"
  );
  static_assert(
    offsetof(SSTIArmyVariableData, mCategoryFilterSet) == 0x110,
    "SSTIArmyVariableData::mCategoryFilterSet offset must be 0x110"
  );
  static_assert(
    offsetof(SSTIArmyVariableData, mIsOutOfGame) == 0x138, "SSTIArmyVariableData::mIsOutOfGame offset must be 0x138"
  );
  static_assert(
    offsetof(SSTIArmyVariableData, mArmyStart) == 0x13C, "SSTIArmyVariableData::mArmyStart offset must be 0x13C"
  );
  static_assert(
    offsetof(SSTIArmyVariableData, mNoRushTimer) == 0x144, "SSTIArmyVariableData::mNoRushTimer offset must be 0x144"
  );
  static_assert(
    offsetof(SSTIArmyVariableData, mNoRushRadius) == 0x148, "SSTIArmyVariableData::mNoRushRadius offset must be 0x148"
  );
  static_assert(
    offsetof(SSTIArmyVariableData, mNoRushOffset) == 0x14C, "SSTIArmyVariableData::mNoRushOffset offset must be 0x14C"
  );
  static_assert(
    offsetof(SSTIArmyVariableData, mHandicapValue) == 0x154, "SSTIArmyVariableData::mHandicapValue offset must be 0x154"
  );
  static_assert(
    offsetof(SSTIArmyVariableData, mHandicapExtra) == 0x158, "SSTIArmyVariableData::mHandicapExtra offset must be 0x158"
  );
  static_assert(sizeof(SSTIArmyVariableData) == 0x160, "SSTIArmyVariableData size must be 0x160");

  /**
   * VFTABLE: 0x00E17574
   * COL:  0x00E6C0A0
   */
  class SSTIArmyVariableDataSerializer
  {
  public:
    /**
     * Address: 0x00550A00 (FUN_00550A00, Moho::SSTIArmyVariableDataSerializer::Deserialize callback)
     *
     * What it does:
     * Archive callback thunk forwarding into `SSTIArmyVariableData::SerializeLoadBody`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00550A10 (FUN_00550A10, Moho::SSTIArmyVariableDataSerializer::Serialize callback)
     *
     * What it does:
     * Archive callback thunk forwarding into `SSTIArmyVariableData::SerializeSaveBody`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00550D90 (FUN_00550D90, sub_550D90)
     * Slot: 0
     *
     * What it does:
     * Binds load/save serializer callbacks into SSTIArmyVariableData RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  /**
   * Address: 0x00BC9B10 (FUN_00BC9B10, register_SSTIArmyVariableDataSerializer)
   *
   * What it does:
   * Initializes startup serializer helper links/callbacks for
   * `SSTIArmyVariableData` and schedules process-exit cleanup.
   */
  void register_SSTIArmyVariableDataSerializer();

  /**
   * VFTABLE: 0x00E17544
   * COL:  0x00E6C138
   *
   * Source hints:
   * - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  class SSTIArmyVariableDataTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005508C0 (FUN_005508C0, startup typeinfo constructor lane)
     *
     * What it does:
     * Initializes base reflection state and preregisters RTTI ownership for
     * `SSTIArmyVariableData`.
     */
    SSTIArmyVariableDataTypeInfo();

    /**
     * Address: 0x00550950 (FUN_00550950, sub_550950)
     * Slot: 2
     *
     * What it does:
     * Scalar deleting destructor thunk body for type descriptor.
     */
    ~SSTIArmyVariableDataTypeInfo() override;

    /**
     * Address: 0x00550940 (FUN_00550940, sub_550940)
     * Slot: 3
     *
     * What it does:
     * Returns RTTI registration name literal for this payload type.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00550920 (FUN_00550920, sub_550920)
     * Slot: 9
     *
     * What it does:
     * Publishes payload size and finalizes base RType initialization.
     */
    void Init() override;
  };

  /**
   * Address: 0x00BC9AF0 (FUN_00BC9AF0, register_SSTIArmyVariableDataTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `SSTIArmyVariableDataTypeInfo` storage and
   * registers process-exit teardown.
   */
  void register_SSTIArmyVariableDataTypeInfo();

  static_assert(
    offsetof(SSTIArmyVariableDataSerializer, mHelperNext) == 0x04,
    "SSTIArmyVariableDataSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SSTIArmyVariableDataSerializer, mHelperPrev) == 0x08,
    "SSTIArmyVariableDataSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SSTIArmyVariableDataSerializer, mSerLoadFunc) == 0x0C,
    "SSTIArmyVariableDataSerializer::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(SSTIArmyVariableDataSerializer, mSerSaveFunc) == 0x10,
    "SSTIArmyVariableDataSerializer::mSerSaveFunc offset must be 0x10"
  );
  static_assert(sizeof(SSTIArmyVariableDataSerializer) == 0x14, "SSTIArmyVariableDataSerializer size must be 0x14");
  static_assert(sizeof(SSTIArmyVariableDataTypeInfo) == 0x64, "SSTIArmyVariableDataTypeInfo size must be 0x64");
} // namespace moho
