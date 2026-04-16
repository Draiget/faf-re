#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "../../gpg/core/utils/BoostUtils.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "../misc/StatItem.h"
#include "../misc/Stats.h"

namespace moho
{
  class CArmyStatItem;
  class CAiBrain;
  struct STrigger;
  enum ETriggerOperator : std::int32_t;

  struct ArmyBlueprintNameView
  {
    std::uint8_t pad_0000[0x08];
    msvc8::string mName;
    std::uint8_t pad_0024[0x38];
    std::int32_t mBlueprintOrdinal;
  };
  static_assert(offsetof(ArmyBlueprintNameView, mName) == 0x08, "ArmyBlueprintNameView::mName offset must be 0x08");
  static_assert(
    offsetof(ArmyBlueprintNameView, mBlueprintOrdinal) == 0x5C,
    "ArmyBlueprintNameView::mBlueprintOrdinal offset must be 0x5C"
  );

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

  struct ArmyTriggerNode
  {
    ArmyTriggerNode* next;                // +0x00
    ArmyTriggerNode* prev;                // +0x04
    boost::shared_ptr<STrigger> trigger;  // +0x08
  };
  static_assert(sizeof(ArmyTriggerNode) == 0x10, "ArmyTriggerNode size must be 0x10");

  class CArmyStatItem : public StatItem
  {
  public:
    static gpg::RType* sType;
    static gpg::RType* sPointerType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x007107E0 (FUN_007107E0, Moho::CArmyStatItem::GetPointerType)
     *
     * What it does:
     * Lazily resolves and caches reflected RTTI for `CArmyStatItem*`.
     */
    [[nodiscard]] static gpg::RType* GetPointerType();

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

    /**
     * Address: 0x0070B580 (FUN_0070B580, Moho::CArmyStatItem::SumCategory)
     *
     * What it does:
     * Sums blueprint-lane values whose blueprint ordinal is present in the
     * provided category bitset.
     */
    [[nodiscard]] float SumCategory(const EntityCategorySet* categorySet) const;

    /**
     * Address: 0x0070E2B0 (FUN_0070E2B0)
     *
     * What it does:
     * Resolves one per-blueprint float lane in `mBlueprintStats`, inserting a
     * zero-initialized node when the key is missing, and returns a writable
     * pointer to that lane.
     */
    [[nodiscard]] float* FindOrCreateBlueprintStatValue(const ArmyBlueprintNameView* blueprintName);

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

    /**
     * Address: 0x00714870 (FUN_00714870, Moho::CArmyStats::MemberDeserialize)
     *
     * gpg::ReadArchive*
     *
     * What it does:
     * Loads base stats storage, name-index map runtime lane, and trigger-list
     * runtime lane from archive using cached reflection RTTI.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00714920 (FUN_00714920, Moho::CArmyStats::MemberSerialize)
     *
     * gpg::WriteArchive*
     *
     * What it does:
     * Writes base stats storage, name-index map runtime lane, and trigger-list
     * runtime lane to archive using cached reflection RTTI.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x0070B860 (FUN_0070B860, Moho::CArmyStats::GetStat)
     *
     * What it does:
     * Resolves one army-stat item by path through cached map lanes and falls
     * back to stat-tree lookup without creating missing paths.
     */
    [[nodiscard]] CArmyStatItem* GetStat(const char* statPath);

    /**
     * Address: 0x005945E0 (FUN_005945E0, Moho::CArmyStats::GetItem)
     *
     * What it does:
     * Resolves one army-stat item by path from the name-index cache and
     * creates/caches missing items through token-table traversal.
     */
    [[nodiscard]] CArmyStatItem* GetItem(const char* statPath);

    /**
     * Address: 0x0070B820 (FUN_0070B820)
     *
     * What it does:
     * Resolves one army-stat item by path, resolves one per-blueprint float
     * lane in that item, applies `delta`, and returns the updated lane pointer.
     */
    [[nodiscard]] float* AddBlueprintStatDelta(
      const char* statPath,
      const ArmyBlueprintNameView* blueprintName,
      float delta
    );

    /**
     * Address: 0x00593260 (FUN_00593260, func_UpdateUnitStat)
     *
     * What it does:
     * Resolves one stat item by path, coerces it to integer type, and applies
     * one atomic add to the integer counter lane.
     */
    [[nodiscard]] std::int32_t UpdateUnitStat(const char* statPath, const std::int32_t* delta);

    /**
     * Address: 0x00593220 (FUN_00593220, func_SetUnitStat)
     *
     * What it does:
     * Resolves one stat item by path, coerces it to integer type, and
     * atomically replaces the integer counter lane with `*value`.
     */
    [[nodiscard]] std::int32_t SetUnitStat(const char* statPath, const std::int32_t* value);

    /**
     * Address: 0x005931E0 (FUN_005931E0, Moho::CArmyStats::SetIntStatAtomic)
     *
     * What it does:
     * Resolves one stat item by path, coerces it to integer storage, and
     * atomically replaces the counter lane with `*value`, returning the
     * previous value on success.
     */
    [[nodiscard]] std::int32_t SetIntStatAtomic(const char* statPath, const std::int32_t* value);

    /**
     * Address: 0x005932C0 (FUN_005932C0, sub_5932C0)
     *
     * What it does:
     * Sets one integer stat counter to `*candidate` only when the candidate is
     * greater than the current value, using an atomic compare-exchange loop.
     */
    [[nodiscard]] std::int32_t SetUnitStatGreaterOf(const char* statPath, const std::int32_t* candidate);

    /**
     * Address: 0x00593310 (FUN_00593310, sub_593310)
     *
     * What it does:
     * Sets one float stat counter to `max(current, *candidate)` using an
     * atomic compare-exchange loop over the bitwise float lane.
     */
    void SetUnitStatGreaterFloat(const char* statPath, const float* candidate);

    /**
     * Address: 0x0070BAB0 (FUN_0070BAB0, Moho::CArmyStats::GetTrigger)
     *
     * What it does:
     * Finds one trigger by case-insensitive name from trigger-list lanes and
     * returns one retained shared pointer in `outTrigger`.
     */
    boost::shared_ptr<STrigger>* GetTrigger(boost::shared_ptr<STrigger>* outTrigger, const char* triggerName);

    /**
     * Address: 0x0070BCA0 (FUN_0070BCA0, Moho::CArmyStats::SetArmyStatsTrigger)
     *
     * What it does:
     * Resolves trigger/stat lanes, builds one `SCondition` record, and appends
     * it to the target trigger condition vector.
     */
    static void SetArmyStatsTrigger(
      const EntityCategorySet* categorySet,
      CArmyStats* armyStats,
      const char* triggerName,
      const char* statPath,
      ETriggerOperator triggerOperator,
      float triggerValue
    );

    /**
     * Address: 0x0070BB40 (FUN_0070BB40, sub_70BB40)
     *
     * What it does:
     * Ensures one named trigger exists in the trigger-list lane, creating and
     * appending it when missing.
     */
    void EnsureTriggerExists(const char* triggerName);

    /**
     * Address: 0x0070BE50 (FUN_0070BE50, Moho::CArmyStats::RemoveArmyStatsTrigger)
     *
     * What it does:
     * Finds one trigger by case-insensitive name and removes the first match
     * from the trigger list.
     */
    void RemoveArmyStatsTrigger(const char* triggerName);

    /**
     * Address: 0x0070BEA0 (FUN_0070BEA0, Moho::CArmyStats::Update)
     *
     * What it does:
     * Evaluates all trigger conditions and dispatches `OnStatsTrigger` for
     * each trigger whose conditions all pass in this update.
     */
    void Update();

    /**
     * Address: 0x00704FD0 (FUN_00704FD0, sub_704FD0)
     *
     * What it does:
     * Resolves one string-stat path through the CArmyStats name-index cache and
     * creates/caches missing entries on demand.
     */
    [[nodiscard]] CArmyStatItem* GetStringItemCached(gpg::StrArg statPath);

    /**
     * Address: 0x00704000 (FUN_00704000, sub_704000)
     *
     * What it does:
     * Resolves one string-stat path through the cached lookup and writes one
     * string value to that stat item.
     */
    void SetStringValueByPath(gpg::StrArg statPath, const msvc8::string& value);

  private:
    /**
     * Address: 0x00703700 (FUN_00703700, name-index erase-iterator helper)
     */
    [[nodiscard]] ArmyNameIndexNode* EraseNameIndexNodeAndAdvance(ArmyNameIndexNode* node);

    /**
     * Address: 0x0070DDC0 (FUN_0070DDC0, CArmyStats name-index tree cleanup)
     *
     * What it does:
     * Destroys all name-index nodes, frees the sentinel head, and resets the
     * name-index runtime lane.
     */
    void DestroyNameIndexTree();

    /**
     * Address: 0x007015C0 (FUN_007015C0, CArmyStats auxiliary trigger-list cleanup)
     *
     * What it does:
     * Destroys all trigger-list nodes, frees the sentinel head, and resets the
     * auxiliary trigger runtime lane.
     */
    void DestroyAuxList();

  public:
    CAiBrain* mOwnerArmy;         // +0x10
    ArmyNameIndexTree mNameIndex; // +0x14
    ArmyTriggerNode* mAuxHead;    // +0x24
    std::uint32_t mAuxSize;       // +0x28
  };
  static_assert(offsetof(CArmyStats, mOwnerArmy) == 0x10, "CArmyStats::mOwnerArmy offset must be 0x10");
  static_assert(offsetof(CArmyStats, mNameIndex) == 0x14, "CArmyStats::mNameIndex offset must be 0x14");
  static_assert(offsetof(CArmyStats, mAuxHead) == 0x24, "CArmyStats::mAuxHead offset must be 0x24");
  static_assert(offsetof(CArmyStats, mAuxSize) == 0x28, "CArmyStats::mAuxSize offset must be 0x28");
  static_assert(sizeof(CArmyStats) == 0x2C, "CArmyStats size must be 0x2C");

  /**
   * Address: 0x00594720 (FUN_00594720, func_GetArmyStat2)
   *
   * What it does:
   * Resolves one army-stat item by path from the name-index cache and creates
   * and caches the lane when missing.
   */
  [[nodiscard]] CArmyStatItem* ResolveArmyStatItemCachedCreate(CArmyStats* armyStats, const char* statPath);
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00713BE0 (FUN_00713BE0, gpg::RRef_CArmyStatItem)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CArmyStatItem*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CArmyStatItem(gpg::RRef* outRef, moho::CArmyStatItem* value);
} // namespace gpg
