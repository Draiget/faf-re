#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/render/camera/VTransform.h"
#include "Wm3Vector3.h"

namespace moho
{
  class CSndParams;
  struct RMeshBlueprint;
  class RScmResource;

  /**
   * Recovered placeholder for `Moho::SSTIEntityAttachInfo` — used by
   * `gpg::RRef_SSTIEntityAttachInfo` (FUN_00559790) and the
   * `gpg::fastvector<SSTIEntityAttachInfo>` lane embedded in
   * `SSTIEntityVariableData`. The complete-object size and field
   * layout have not yet been confirmed from binary evidence; the
   * struct is given a single `std::uintptr_t` body so it remains a
   * complete C++ type (so `typeid()` works) while keeping the
   * placeholder explicit. Replace the body with the real layout
   * once owner-side evidence is available.
   */
  struct SSTIEntityAttachInfo
  {
    static gpg::RType* sType;
    std::uintptr_t mPlaceholderState{};
  };

  static_assert(sizeof(SSTIEntityAttachInfo) == 0x04, "SSTIEntityAttachInfo size must be 0x04");
  static_assert(
    offsetof(SSTIEntityAttachInfo, mPlaceholderState) == 0x00,
    "SSTIEntityAttachInfo::mPlaceholderState offset must be 0x00"
  );

  enum class EUserEntityVisibilityMode : std::int32_t
  {
    Hidden = 1,
    MapPlayableRect = 2,
    ReconGrid = 4
  };

  inline constexpr std::uint32_t kUserEntityUnderwaterLayerMaskBits = 0x6u;

  struct SSTIIntelAttributes
  {
    std::uint32_t vision;
    std::uint32_t waterVision;
    std::uint32_t radar;
    std::uint32_t sonar;
    std::uint32_t omni;
    std::uint32_t radarStealth;
    std::uint32_t sonarStealth;
    std::uint32_t cloak;
  };

  struct SSTIInlineUIntVector
  {
    std::uint32_t* mBegin;       // 0x00
    std::uint32_t* mEnd;         // 0x04
    std::uint32_t* mCapacityEnd; // 0x08
    std::uint32_t* mInlineBegin; // 0x0C
    // Binary small-buffer quirk: this lane is inline element 0 while inline,
    // but stores the inline-capacity restore pointer while dynamic.
    std::uint32_t mInlineStorage0; // 0x10
    std::uint32_t mInlineStorage1; // 0x14

    void ResetToInlineStorage() noexcept;
    void ReleaseDynamicStorage() noexcept;
    void AssignFrom(const SSTIInlineUIntVector& rhs);

    [[nodiscard]] std::size_t Size() const noexcept;
    [[nodiscard]] std::size_t Capacity() const noexcept;
  };

  /**
   * Recovered shape for replicated user-entity variable payload.
   * Constructor/dtor/copy are lifted from:
   * - 0x00558760 (ctor)
   * - 0x00560310 (dtor)
   * - 0x0067A3E0 (operator=)
   */
  struct SSTIEntityVariableData
  {
    static gpg::RType* sType;

    /**
     * Address: 0x00558760 (FUN_00558760, ??0SSTIEntityVariableData@Moho@@QAE@XZ)
     *
     * What it does:
     * Seeds default replicated variable state for new entities.
     */
    SSTIEntityVariableData();

    /**
     * Address: 0x00560310 (FUN_00560310, ??1SSTIEntityVariableData@Moho@@QAE@XZ)
     *
     * What it does:
     * Releases shared refs and frees dynamic aux-value storage.
     */
    ~SSTIEntityVariableData();

    /**
     * Address: 0x0067A3E0 (FUN_0067A3E0, ??4SSTIEntityVariableData@Moho@@QAEAAU01@ABU01@@Z)
     *
     * What it does:
     * Copies replicated variable payload including aux-value buffer.
     */
    SSTIEntityVariableData& operator=(const SSTIEntityVariableData& rhs);

    /**
     * Address: 0x00560150 (FUN_00560150, Moho::SSTIEntityVariableData::cpy)
     *
     * What it does:
     * Copies one variable payload lane from this object into `destination`
     * and returns the destination pointer.
     */
    SSTIEntityVariableData* cpy(SSTIEntityVariableData* destination) const;

    /**
     * Address: 0x00559E00 (FUN_00559E00, Moho::SSTIEntityVariableData::MemberSerialize)
     *
     * What it does:
     * Serializes replicated variable payload lanes using reflection RTTI.
     * Rejects serializer versions older than 2.
     */
    void MemberSerialize(gpg::WriteArchive* archive, int version);

    [[nodiscard]] std::uint32_t GetVisibilityGridMask() const noexcept;
    void SetVisibilityGridMask(std::uint32_t gridMask) noexcept;
    [[nodiscard]] bool UsesUnderwaterReconGrid() const noexcept;

    boost::shared_ptr<RScmResource> mScmResource; // 0x00
    const RMeshBlueprint* mMeshBlueprint;         // 0x08
    Wm3::Vec3f mScale;                            // 0x0C
    float mHealth;                                // 0x18
    float mMaxHealth;                             // 0x1C
    std::uint8_t mIsBeingBuilt;                   // 0x20
    std::uint8_t mIsDead;                         // 0x21
    std::uint8_t mRequestRefreshUI;               // 0x22
    std::uint8_t pad_0023;                        // 0x23
    VTransform mCurTransform;                     // 0x24
    VTransform mLastTransform;                    // 0x40
    float mCurImpactValue;                        // 0x5C
    float mFractionComplete;                      // 0x60
    std::uint32_t mAttachmentParentRef;           // 0x64
    SSTIInlineUIntVector mAuxValueVector;         // 0x68
    float mScroll0U;                              // 0x80
    float mScroll0V;                              // 0x84
    float mScroll1U;                              // 0x88
    float mScroll1V;                              // 0x8C
    CSndParams* mAmbientSound;                    // 0x90
    CSndParams* mRumbleSound;                     // 0x94
    // FUN_00558760 names this lane as "mNotVisibility"; semantics are still
    // being refined but this is a visibility-suppression byte.
    std::uint8_t mVisibilityHidden; // 0x98
    std::uint8_t pad_0099_009B[0x03];
    EUserEntityVisibilityMode mVisibilityMode; // 0x9C
    std::uint32_t mLayerMask;                  // 0xA0
    std::uint8_t mUsingAltFootprint;           // 0xA4
    std::uint8_t pad_00A5_00A7[0x03];
    boost::shared_ptr<void> mUnderlayTexture; // 0xA8
    SSTIIntelAttributes mIntelAttributes;     // 0xB0
  };

  /**
   * VFTABLE: 0x00E17FA0
   * COL:  0x00E6C8FC
   */
  class SSTIEntityVariableDataSerializer
  {
  public:
    /**
     * Address: 0x00558E40 (FUN_00558E40, sub_558E40)
     * Slot: 0
     *
     * What it does:
     * Binds prebuilt load/save callbacks into `SSTIEntityVariableData` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  /**
   * VFTABLE: 0x00E17F70
   * COL:  0x00E6C994
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class SSTIEntityVariableDataTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005586B0 (FUN_005586B0, sub_5586B0)
     * Slot: 2
     */
    ~SSTIEntityVariableDataTypeInfo() override;

    /**
     * Address: 0x005586A0 (FUN_005586A0, Moho::SSTIEntityVariableDataTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00558680 (FUN_00558680, Moho::SSTIEntityVariableDataTypeInfo::Init)
     * Slot: 9
     */
    void Init() override;
  };

  /**
   * Address: 0x005581D0 (FUN_005581D0, preregister_SSTIEntityAttachInfoTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTIEntityAttachInfo`.
   */
  [[nodiscard]] gpg::RType* preregister_SSTIEntityAttachInfoTypeInfo();

  /**
   * Address: 0x00558420 (FUN_00558420, preregister_EntityAttributesTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `EntityAttributes`.
   */
  [[nodiscard]] gpg::RType* preregister_EntityAttributesTypeInfo();

  /**
   * Address: 0x00558620 (FUN_00558620, preregister_SSTIEntityVariableDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTIEntityVariableData`.
   */
  [[nodiscard]] gpg::RType* preregister_SSTIEntityVariableDataTypeInfo();

  static_assert(sizeof(SSTIIntelAttributes) == 0x20, "SSTIIntelAttributes size must be 0x20");
  static_assert(sizeof(EUserEntityVisibilityMode) == 0x04, "EUserEntityVisibilityMode size must be 0x04");

  static_assert(offsetof(SSTIInlineUIntVector, mBegin) == 0x00, "SSTIInlineUIntVector::mBegin offset must be 0x00");
  static_assert(offsetof(SSTIInlineUIntVector, mEnd) == 0x04, "SSTIInlineUIntVector::mEnd offset must be 0x04");
  static_assert(
    offsetof(SSTIInlineUIntVector, mCapacityEnd) == 0x08, "SSTIInlineUIntVector::mCapacityEnd offset must be 0x08"
  );
  static_assert(
    offsetof(SSTIInlineUIntVector, mInlineBegin) == 0x0C, "SSTIInlineUIntVector::mInlineBegin offset must be 0x0C"
  );
  static_assert(
    offsetof(SSTIInlineUIntVector, mInlineStorage0) == 0x10, "SSTIInlineUIntVector::mInlineStorage0 offset must be 0x10"
  );
  static_assert(
    offsetof(SSTIInlineUIntVector, mInlineStorage1) == 0x14, "SSTIInlineUIntVector::mInlineStorage1 offset must be 0x14"
  );
  static_assert(sizeof(SSTIInlineUIntVector) == 0x18, "SSTIInlineUIntVector size must be 0x18");
  static_assert(
    offsetof(SSTIEntityVariableData, mScmResource) == 0x00, "SSTIEntityVariableData::mScmResource offset must be 0x00"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mMeshBlueprint) == 0x08,
    "SSTIEntityVariableData::mMeshBlueprint offset must be 0x08"
  );
  static_assert(offsetof(SSTIEntityVariableData, mScale) == 0x0C, "SSTIEntityVariableData::mScale offset must be 0x0C");
  static_assert(
    offsetof(SSTIEntityVariableData, mHealth) == 0x18, "SSTIEntityVariableData::mHealth offset must be 0x18"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mMaxHealth) == 0x1C, "SSTIEntityVariableData::mMaxHealth offset must be 0x1C"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mIsBeingBuilt) == 0x20, "SSTIEntityVariableData::mIsBeingBuilt offset must be 0x20"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mIsDead) == 0x21, "SSTIEntityVariableData::mIsDead offset must be 0x21"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mRequestRefreshUI) == 0x22,
    "SSTIEntityVariableData::mRequestRefreshUI offset must be 0x22"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, pad_0023) == 0x23, "SSTIEntityVariableData::pad_0023 offset must be 0x23"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mCurTransform) == 0x24, "SSTIEntityVariableData::mCurTransform offset must be 0x24"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mLastTransform) == 0x40,
    "SSTIEntityVariableData::mLastTransform offset must be 0x40"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mCurImpactValue) == 0x5C,
    "SSTIEntityVariableData::mCurImpactValue offset must be 0x5C"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mFractionComplete) == 0x60,
    "SSTIEntityVariableData::mFractionComplete offset must be 0x60"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mAttachmentParentRef) == 0x64,
    "SSTIEntityVariableData::mAttachmentParentRef offset must be 0x64"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mAuxValueVector) == 0x68,
    "SSTIEntityVariableData::mAuxValueVector offset must be 0x68"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mScroll0U) == 0x80, "SSTIEntityVariableData::mScroll0U offset must be 0x80"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mScroll0V) == 0x84, "SSTIEntityVariableData::mScroll0V offset must be 0x84"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mScroll1U) == 0x88, "SSTIEntityVariableData::mScroll1U offset must be 0x88"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mScroll1V) == 0x8C, "SSTIEntityVariableData::mScroll1V offset must be 0x8C"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mAmbientSound) == 0x90, "SSTIEntityVariableData::mAmbientSound offset must be 0x90"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mRumbleSound) == 0x94, "SSTIEntityVariableData::mRumbleSound offset must be 0x94"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mVisibilityHidden) == 0x98,
    "SSTIEntityVariableData::mVisibilityHidden offset must be 0x98"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mVisibilityMode) == 0x9C,
    "SSTIEntityVariableData::mVisibilityMode offset must be 0x9C"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mLayerMask) == 0xA0, "SSTIEntityVariableData::mLayerMask offset must be 0xA0"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mUsingAltFootprint) == 0xA4,
    "SSTIEntityVariableData::mUsingAltFootprint offset must be 0xA4"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mUnderlayTexture) == 0xA8,
    "SSTIEntityVariableData::mUnderlayTexture offset must be 0xA8"
  );
  static_assert(
    offsetof(SSTIEntityVariableData, mIntelAttributes) == 0xB0,
    "SSTIEntityVariableData::mIntelAttributes offset must be 0xB0"
  );
  static_assert(sizeof(SSTIEntityVariableData) == 0xD0, "SSTIEntityVariableData size must be 0xD0");
  static_assert(sizeof(SSTIEntityVariableDataSerializer) == 0x14, "SSTIEntityVariableDataSerializer size must be 0x14");
  static_assert(sizeof(SSTIEntityVariableDataTypeInfo) == 0x64, "SSTIEntityVariableDataTypeInfo size must be 0x64");
} // namespace moho
