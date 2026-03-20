#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/mutex.h"
#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"
#include "moho/containers/TDatTreeItem.h"
#include "moho/misc/Stats.h"

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  enum class EStatType : std::uint32_t
  {
    kNone = 0,
    kFloat = 1,
    kInt = 2,
    kString = 3,
  };

  struct StatHeapBlock
  {
    void* data{nullptr};
    std::uint32_t size{0};
    std::uint32_t capacity{0};

    void Reset() noexcept;
    ~StatHeapBlock() noexcept;
  };
  static_assert(sizeof(StatHeapBlock) == 0x0C, "StatHeapBlock size must be 0x0C");

  class StatItem : public TDatTreeItem<StatItem>
  {
  public:
    /**
     * Address: 0x00408730 (FUN_00408730, Moho::StatItem::StatItem)
     */
    explicit StatItem(const char* name);

    /**
     * Address: 0x00408840 (FUN_00408840, deleting dtor thunk)
     * Address: 0x00418610 (FUN_00418610, destructor core)
     *
     * VFTable SLOT: 0
     */
    virtual ~StatItem();

    /**
     * Address: 0x00418BD0 (FUN_00418BD0, Moho::StatItem::ToLua)
     *
     * VFTable SLOT: 1
     */
    virtual void ToLua(LuaPlus::LuaState* state, LuaPlus::LuaObject* outObject);

    /**
     * Address: 0x00418750 (FUN_00418750, Moho::StatItem::GetString)
     */
    msvc8::string* GetString(bool useRealtimeValue, msvc8::string* outValue);

    /**
     * Address: 0x00418890 (FUN_00418890, Moho::StatItem::GetInt)
     */
    [[nodiscard]] int GetInt(bool useRealtimeValue);

    /**
     * Address: 0x00418990 (FUN_00418990, Moho::StatItem::GetFloat)
     */
    [[nodiscard]] float GetFloat(bool useRealtimeValue);

    /**
     * Address: 0x00417FE0 (FUN_00417FE0, Moho::StatItem::SetValue_0)
     */
    void SetValueCopy(msvc8::string* outValue);

    /**
     * Address: 0x0040D2D0 (FUN_0040D2D0, Moho::StatItem::Synchronize2)
     */
    void SynchronizeAsInt();

    /**
     * Address: 0x00415370 (FUN_00415370, Moho::StatItem::Synchronize3)
     */
    void SynchronizeAsFloat();

    static gpg::RType* sType;

  public:
    std::uint32_t mTreeMeta; // +0x20

    // Numeric slot used when `useRealtimeValue == false`.
    volatile std::int32_t mPrimaryValueBits; // +0x24

    // String value storage for `EStatType::kString`.
    msvc8::string mValue; // +0x28

    // Numeric slot used when `useRealtimeValue == true`.
    volatile std::int32_t mRealtimeValueBits; // +0x44

    msvc8::string mScratchValue; // +0x48

    std::uint32_t mHeapTag;     // +0x64
    StatHeapBlock mHeapStorage; // +0x68..+0x73

    msvc8::string mName; // +0x74

    EStatType mType{EStatType::kNone};         // +0x90
    volatile std::int32_t mUseRealtimeSlot{0}; // +0x94
    boost::mutex mLock;                        // +0x98
  };
  static_assert(offsetof(StatItem, mHeapTag) == 0x64, "StatItem::mHeapTag offset must be 0x64");
  static_assert(offsetof(StatItem, mHeapStorage) == 0x68, "StatItem::mHeapStorage offset must be 0x68");
  static_assert(offsetof(StatItem, mName) == 0x74, "StatItem::mName offset must be 0x74");
  static_assert(sizeof(StatItem) == 0xA0u, "StatItem size must be 0xA0");

  /**
   * VFTABLE: 0x00E01134
   * COL: 0x00E5D908
   */
  class StatItemSerializer
  {
  public:
    /**
     * Address: 0x004194E0 (FUN_004194E0, sub_4194E0)
     *
     * What it does:
     * Registers serializer load/save callbacks into `StatItem` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };
  static_assert(sizeof(StatItemSerializer) == 0x14, "StatItemSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E01104
   * COL: 0x00E5D9A0
   */
  class StatItemTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00418560 (FUN_00418560, sub_418560)
     * Slot: 2
     */
    ~StatItemTypeInfo() override;

    /**
     * Address: 0x00418550 (FUN_00418550, sub_418550)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00418510 (FUN_00418510, sub_418510)
     * Slot: 9
     */
    void Init() override;
  };
  static_assert(sizeof(StatItemTypeInfo) == 0x64, "StatItemTypeInfo size must be 0x64");

  /**
   * VFTABLE: 0x00E01054
   * COL: 0x00E5DBF0
   */
  template <>
  class StatsRType<StatItem> final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0041A800 (FUN_0041A800, sub_41A800)
     * Slot: 2
     */
    ~StatsRType() override;

    /**
     * Address: 0x00419550 (FUN_00419550, Moho::StatsRType_StatItem::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004195F0 (FUN_004195F0, Moho::StatsRType_StatItem::Init)
     * Slot: 9
     */
    void Init() override;
  };
  static_assert(sizeof(StatsRType<StatItem>) == 0x64, "StatsRType<StatItem> size must be 0x64");

  /**
   * Unit stat-tree lookup helpers used by Unit::GetStat* wrappers.
   *
   * Address: 0x0040C200 (FUN_0040C200, mode-based resolver)
   * Address: 0x00417B60 (FUN_00417B60, float resolver)
   * Address: 0x00417C50 (FUN_00417C50, string resolver)
   */
  [[nodiscard]] StatItem* ResolveStatByMode(void* statsRoot, gpg::StrArg name, int mode);
  [[nodiscard]] StatItem* ResolveStatFloat(void* statsRoot, gpg::StrArg name);
  [[nodiscard]] StatItem* ResolveStatString(void* statsRoot, gpg::StrArg name);
} // namespace moho
