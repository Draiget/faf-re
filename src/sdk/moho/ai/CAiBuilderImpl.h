#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/ai/IAiBuilder.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class Unit;

  struct SBuilderRebuildNode
  {
    SBuilderRebuildNode* left;            // +0x00
    SBuilderRebuildNode* parent;          // +0x04
    SBuilderRebuildNode* right;           // +0x08
    std::uint32_t key;                    // +0x0C (x*10000 + z)
    const RUnitBlueprint* blueprint;      // +0x10
    std::uint8_t color;                   // +0x14
    std::uint8_t isNil;                   // +0x15
    std::uint8_t pad16[2];                // +0x16
  };

  struct SBuilderRebuildMap
  {
    std::uint32_t mMeta00;         // +0x00
    SBuilderRebuildNode* mHead;    // +0x04 (RB-tree sentinel)
    std::uint32_t mSize;           // +0x08
  };

  /**
   * VFTABLE: 0x00E1B73C
   * COL:  0x00E70E80
   */
  class CAiBuilderImpl : public IAiBuilder
  {
  public:
    /**
     * Address: 0x0059FAB0 (FUN_0059FAB0, default ctor)
     */
    CAiBuilderImpl();

    /**
     * Address: 0x0059F920 (FUN_0059F920, unit ctor)
     */
    explicit CAiBuilderImpl(Unit* unit);

    /**
     * Address: 0x0059FB50 (FUN_0059FB50, scalar deleting thunk)
     * Address: 0x0059F9C0 (FUN_0059F9C0, core dtor)
     *
     * VFTable SLOT: 0
     */
    ~CAiBuilderImpl() override;

    /**
     * Address: 0x005A2460 (FUN_005A2460, Moho::CAiBuilderImpl::MemberDeserialize)
     *
     * What it does:
     * Reads serialized builder state lanes and marks the factory queue dirty.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005A2550 (FUN_005A2550, Moho::CAiBuilderImpl::MemberSerialize)
     *
     * What it does:
     * Writes serialized builder state lanes.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x0059FAA0 (FUN_0059FAA0)
     *
     * VFTable SLOT: 1
     */
    [[nodiscard]]
    bool BuilderIsFactory() const override;

    /**
     * Address: 0x0059FA90 (FUN_0059FA90)
     *
     * VFTable SLOT: 2
     */
    void BuilderSetIsFactory(bool isFactory) override;

    /**
     * Address: 0x0059EEF0 (FUN_0059EEF0)
     *
     * VFTable SLOT: 3
     */
    void BuilderSetUpInitialRally() override;

    /**
     * Address: 0x0059F220 (FUN_0059F220)
     *
     * VFTable SLOT: 4
     */
    void BuilderValidateFactoryCommandQueue() override;

    /**
     * Address: 0x0059F440 (FUN_0059F440)
     *
     * VFTable SLOT: 5
     */
    [[nodiscard]]
    bool BuilderIsFactoryQueueEmpty() const override;

    /**
     * Address: 0x0059EED0 (FUN_0059EED0)
     *
     * VFTable SLOT: 6
     */
    [[nodiscard]]
    bool BuilderIsFactoryQueueDirty() const override;

    /**
     * Address: 0x0059EEE0 (FUN_0059EEE0)
     *
     * VFTable SLOT: 7
     */
    void BuilderSetFactoryQueueDirty(bool dirty) override;

    /**
     * Address: 0x0059F470 (FUN_0059F470)
     *
     * VFTable SLOT: 8
     */
    [[nodiscard]]
    msvc8::vector<WeakPtr<CUnitCommand>>& BuilderGetFactoryCommandQueue() override;

    /**
     * Address: 0x0059F480 (FUN_0059F480)
     *
     * VFTable SLOT: 9
     */
    [[nodiscard]]
    bool BuilderIsBusy() const override;

    /**
     * Address: 0x0059F4D0 (FUN_0059F4D0)
     *
     * VFTable SLOT: 10
     */
    void BuilderAddFactoryCommand(CUnitCommand* command, int index) override;

    /**
     * Address: 0x0059F500 (FUN_0059F500)
     *
     * VFTable SLOT: 11
     */
    [[nodiscard]]
    bool BuilderContainsCommand(CUnitCommand* command) override;

    /**
     * Address: 0x0059F540 (FUN_0059F540)
     *
     * VFTable SLOT: 12
     */
    [[nodiscard]]
    CUnitCommand* BuilderGetFactoryCommand(int index) override;

    /**
     * Address: 0x0059F580 (FUN_0059F580)
     *
     * VFTable SLOT: 13
     */
    void BuilderRemoveFactoryCommand(CUnitCommand* command) override;

    /**
     * Address: 0x0059F5A0 (FUN_0059F5A0)
     *
     * VFTable SLOT: 14
     */
    void BuilderClearFactoryCommandQueue() override;

    /**
     * Address: 0x0059F600 (FUN_0059F600)
     *
     * VFTable SLOT: 15
     */
    void BuilderSetAimTarget(Wm3::Vector3f target) override;

    /**
     * Address: 0x0059F650 (FUN_0059F650)
     *
     * VFTable SLOT: 16
     */
    [[nodiscard]]
    Wm3::Vector3f BuilderGetAimTarget() const override;

    /**
     * Address: 0x0059F670 (FUN_0059F670)
     *
     * VFTable SLOT: 17
     */
    void BuilderSetOnTarget(bool onTarget) override;

    /**
     * Address: 0x0059F680 (FUN_0059F680)
     *
     * VFTable SLOT: 18
     */
    [[nodiscard]]
    bool BuilderGetOnTarget() const override;

    /**
     * Address: 0x0059F690 (FUN_0059F690)
     *
     * VFTable SLOT: 19
     */
    void BuilderAddRebuildStructure(const SOCellPos& cellPos, const RUnitBlueprint* blueprint) override;

    /**
     * Address: 0x0059F6C0 (FUN_0059F6C0)
     *
     * VFTable SLOT: 20
     */
    void BuilderRemoveRebuildStructure(const SOCellPos& cellPos) override;

    /**
     * Address: 0x0059F710 (FUN_0059F710)
     *
     * VFTable SLOT: 21
     */
    void BuilderClearRebuildStructure() override;

    /**
     * Address: 0x0059F740 (FUN_0059F740)
     *
     * VFTable SLOT: 22
     */
    [[nodiscard]]
    const RUnitBlueprint* BuilderGetNextRebuildStructure(SOCellPos& outCellPos) override;

  public:
    static gpg::RType* sType;

    Unit* mOwnerUnit;                                       // +0x04
    std::uint8_t mIsFactory;                                // +0x08
    std::uint8_t mIsOnTarget;                               // +0x09
    std::uint8_t mFactoryQueueDirty;                        // +0x0A
    std::uint8_t mPad0B;                                    // +0x0B
    Wm3::Vector3f mAimTarget;                               // +0x0C
    SBuilderRebuildMap mRebuildStructures;                  // +0x18
    msvc8::vector<WeakPtr<CUnitCommand>> mFactoryCommands;  // +0x24
  };

  static_assert(sizeof(SBuilderRebuildNode) == 0x18, "SBuilderRebuildNode size must be 0x18");
  static_assert(offsetof(SBuilderRebuildNode, key) == 0x0C, "SBuilderRebuildNode::key offset must be 0x0C");
  static_assert(
    offsetof(SBuilderRebuildNode, blueprint) == 0x10, "SBuilderRebuildNode::blueprint offset must be 0x10"
  );
  static_assert(offsetof(SBuilderRebuildNode, color) == 0x14, "SBuilderRebuildNode::color offset must be 0x14");
  static_assert(offsetof(SBuilderRebuildNode, isNil) == 0x15, "SBuilderRebuildNode::isNil offset must be 0x15");

  static_assert(sizeof(SBuilderRebuildMap) == 0x0C, "SBuilderRebuildMap size must be 0x0C");
  static_assert(
    offsetof(SBuilderRebuildMap, mHead) == 0x04, "SBuilderRebuildMap::mHead offset must be 0x04"
  );
  static_assert(
    offsetof(SBuilderRebuildMap, mSize) == 0x08, "SBuilderRebuildMap::mSize offset must be 0x08"
  );

  static_assert(sizeof(CAiBuilderImpl) == 0x34, "CAiBuilderImpl size must be 0x34");
  static_assert(offsetof(CAiBuilderImpl, mOwnerUnit) == 0x04, "CAiBuilderImpl::mOwnerUnit offset must be 0x04");
  static_assert(offsetof(CAiBuilderImpl, mIsFactory) == 0x08, "CAiBuilderImpl::mIsFactory offset must be 0x08");
  static_assert(offsetof(CAiBuilderImpl, mIsOnTarget) == 0x09, "CAiBuilderImpl::mIsOnTarget offset must be 0x09");
  static_assert(
    offsetof(CAiBuilderImpl, mFactoryQueueDirty) == 0x0A,
    "CAiBuilderImpl::mFactoryQueueDirty offset must be 0x0A"
  );
  static_assert(offsetof(CAiBuilderImpl, mAimTarget) == 0x0C, "CAiBuilderImpl::mAimTarget offset must be 0x0C");
  static_assert(
    offsetof(CAiBuilderImpl, mRebuildStructures) == 0x18,
    "CAiBuilderImpl::mRebuildStructures offset must be 0x18"
  );
  static_assert(
    offsetof(CAiBuilderImpl, mFactoryCommands) == 0x24,
    "CAiBuilderImpl::mFactoryCommands offset must be 0x24"
  );
} // namespace moho
