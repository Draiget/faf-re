#pragma once

#include <cstddef>
#include <cstdint>

#include "../../gpg/core/utils/BoostUtils.h"
#include "../misc/StatItem.h"
#include "../misc/Stats.h"

namespace moho
{
  class CArmyStatItem;
  class CAiBrain;

  struct ArmyBlueprintNameView
  {
    std::uint8_t pad_0000[0x08];
    msvc8::string mName;
  };
  static_assert(offsetof(ArmyBlueprintNameView, mName) == 0x08, "ArmyBlueprintNameView::mName offset must be 0x08");

  struct ArmyBlueprintStatNode
  {
    ArmyBlueprintStatNode* left;                // +0x00
    ArmyBlueprintStatNode* parent;              // +0x04
    ArmyBlueprintStatNode* right;               // +0x08
    const ArmyBlueprintNameView* blueprintName; // +0x0C
    float value;                                // +0x10
    std::uint8_t color;                         // +0x14
    std::uint8_t isNil;                         // +0x15
    std::uint8_t pad_0016[2];
  };
  static_assert(sizeof(ArmyBlueprintStatNode) == 0x18, "ArmyBlueprintStatNode size must be 0x18");

  struct ArmyBlueprintStatTree
  {
    std::uint32_t meta0;         // +0x00
    ArmyBlueprintStatNode* head; // +0x04
    std::uint32_t size;          // +0x08
  };
  static_assert(sizeof(ArmyBlueprintStatTree) == 0x0C, "ArmyBlueprintStatTree size must be 0x0C");

  struct ArmyNameIndexNode
  {
    ArmyNameIndexNode* left;   // +0x00
    ArmyNameIndexNode* parent; // +0x04
    ArmyNameIndexNode* right;  // +0x08
    msvc8::string key;         // +0x0C
    CArmyStatItem* value;      // +0x28
    std::uint8_t color;        // +0x2C
    std::uint8_t isNil;        // +0x2D
    std::uint8_t pad_002E[2];
  };
  static_assert(offsetof(ArmyNameIndexNode, key) == 0x0C, "ArmyNameIndexNode::key offset must be 0x0C");
  static_assert(offsetof(ArmyNameIndexNode, value) == 0x28, "ArmyNameIndexNode::value offset must be 0x28");
  static_assert(sizeof(ArmyNameIndexNode) == 0x30, "ArmyNameIndexNode size must be 0x30");

  struct ArmyNameIndexTree
  {
    std::uint32_t meta0;     // +0x00
    ArmyNameIndexNode* head; // +0x04
    std::uint32_t size;      // +0x08
    std::uint32_t metaC;     // +0x0C
  };
  static_assert(sizeof(ArmyNameIndexTree) == 0x10, "ArmyNameIndexTree size must be 0x10");

  struct ArmyAuxListNode
  {
    ArmyAuxListNode* next;
    ArmyAuxListNode* prev;
  };
  static_assert(sizeof(ArmyAuxListNode) == 0x08, "ArmyAuxListNode size must be 0x08");

  class CArmyStatItem : public StatItem
  {
  public:
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00585B30 (FUN_00585B30, Moho::CArmyStatItem::CArmyStatItem)
     */
    explicit CArmyStatItem(const char* name);

    /**
     * Address: 0x00585BB0 (FUN_00585BB0, deleting dtor thunk)
     * Address: 0x00585C00 (FUN_00585C00, destructor core)
     *
     * VFTable SLOT: 0
     */
    ~CArmyStatItem() override;

    /**
     * Address: 0x0070B430 (FUN_0070B430, CArmyStatItem vtable slot 1)
     *
     * VFTable SLOT: 1
     */
    void ToLua(LuaPlus::LuaState* state, LuaPlus::LuaObject* outObject) override;

  private:
    void DestroyBlueprintTree();

  public:
    ArmyBlueprintStatTree mBlueprintStats; // +0xA0
  };
  static_assert(offsetof(CArmyStatItem, mBlueprintStats) == 0xA0, "CArmyStatItem::mBlueprintStats offset must be 0xA0");
  static_assert(sizeof(CArmyStatItem) == 0xAC, "CArmyStatItem size must be 0xAC");

  class CArmyStats : public Stats<CArmyStatItem>, public boost::noncopyable_::noncopyable
  {
  public:
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x006FD7C0 (FUN_006FD7C0, CArmyStats constructor)
     */
    explicit CArmyStats(CAiBrain* ownerArmy);

    /**
     * Address: 0x00704A40 (FUN_00704A40, CArmyStats destructor)
     */
    ~CArmyStats();

    /**
     * Address: 0x0070B980 (FUN_0070B980, CArmyStats vtable slot 0)
     *
     * VFTable SLOT: 0
     */
    void Delete(const char* statPath) override;

  private:
    /**
     * Address: 0x00703700 (FUN_00703700, name-index erase-iterator helper)
     */
    [[nodiscard]] ArmyNameIndexNode* EraseNameIndexNodeAndAdvance(ArmyNameIndexNode* node);

    void DestroyNameIndexTree();
    void DestroyAuxList();

  public:
    CAiBrain* mOwnerArmy;         // +0x10
    ArmyNameIndexTree mNameIndex; // +0x14
    ArmyAuxListNode* mAuxHead;    // +0x24
    std::uint32_t mAuxSize;       // +0x28
  };
  static_assert(offsetof(CArmyStats, mOwnerArmy) == 0x10, "CArmyStats::mOwnerArmy offset must be 0x10");
  static_assert(offsetof(CArmyStats, mNameIndex) == 0x14, "CArmyStats::mNameIndex offset must be 0x14");
  static_assert(offsetof(CArmyStats, mAuxHead) == 0x24, "CArmyStats::mAuxHead offset must be 0x24");
  static_assert(offsetof(CArmyStats, mAuxSize) == 0x28, "CArmyStats::mAuxSize offset must be 0x28");
  static_assert(sizeof(CArmyStats) == 0x2C, "CArmyStats size must be 0x2C");
} // namespace moho
