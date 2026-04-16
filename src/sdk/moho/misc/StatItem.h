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

  enum class EPulseMode : std::int32_t
  {
    kNone = 0,
    kTick = 1,
    kFrame = 0x7FFFFFFF,
  };

  struct StatSamplePoint
  {
    std::int32_t frameIndex{0};
    float value{0.0f};
  };
  static_assert(sizeof(StatSamplePoint) == 0x08, "StatSamplePoint size must be 0x08");

  struct StatSampleBuffer
  {
    StatSamplePoint* begin{nullptr};
    StatSamplePoint* end{nullptr};
    StatSamplePoint* capacityEnd{nullptr};

    void Reset() noexcept;
    void Clear() noexcept;
    [[nodiscard]] std::size_t Size() const noexcept;
    ~StatSampleBuffer() noexcept;
  };
  static_assert(sizeof(StatSampleBuffer) == 0x0C, "StatSampleBuffer size must be 0x0C");

  struct CTimeStamp
  {
    struct SInfo
    {
      std::uint16_t year{0};    // +0x00
      std::uint8_t month{0};    // +0x02
      std::uint8_t day{0};      // +0x03
      std::uint8_t hour{0};     // +0x04
      std::uint8_t minute{0};   // +0x05
      std::uint8_t second{0};   // +0x06
      std::uint8_t weekDay{0};  // +0x07
      std::uint16_t yearDay{0}; // +0x08
    };

    /**
     * Address: 0x004E9C50 (FUN_004E9C50, ??0CTimeStamp@Moho@@QAE@XZ)
     * Mangled: ??0CTimeStamp@Moho@@QAE@XZ
     *
     * What it does:
     * Captures current wall-clock second lanes and millisecond remainder lanes
     * from CRT time/ftime calls.
     */
    CTimeStamp() noexcept;

    /**
     * Address: 0x004E9CF0 (FUN_004E9CF0, ?GetString@CTimeStamp@Moho@@QBEPBDXZ)
     * Mangled: ?GetString@CTimeStamp@Moho@@QBEPBDXZ
     *
     * What it does:
     * Formats the timestamp as ctime text, strips trailing newline, and
     * returns one process-global text buffer.
     */
    [[nodiscard]] const char* GetString() const noexcept;

    /**
     * Address: 0x004E9C90 (FUN_004E9C90, ?GetInfo@CTimeStamp@Moho@@QBE_NAAUSInfo@12@_N@Z)
     * Mangled: ?GetInfo@CTimeStamp@Moho@@QBE_NAAUSInfo@12@_N@Z
     *
     * What it does:
     * Converts one timestamp lane to local-calendar fields and stores year,
     * month/day, clock time, weekday, and yearday into the output record.
     */
    [[nodiscard]] bool GetInfo(SInfo& outInfo, bool useFineTime) const noexcept;

    /**
     * Address: 0x004E9D30 (FUN_004E9D30, ?GetDeltaSeconds@CTimeStamp@Moho@@QBENABV12@@Z)
     * Mangled: ?GetDeltaSeconds@CTimeStamp@Moho@@QBENABV12@@Z
     *
     * What it does:
     * Returns the signed second delta between this timestamp and another one
     * using fine-time seconds + millisecond lanes.
     */
    [[nodiscard]] double GetDeltaSeconds(const CTimeStamp& other) const noexcept;

    std::int64_t time{0};  // +0x00
    std::int64_t ftime{0}; // +0x08
    std::uint16_t millis{0}; // +0x10
  };
  static_assert(offsetof(CTimeStamp::SInfo, year) == 0x00, "CTimeStamp::SInfo::year offset must be 0x00");
  static_assert(offsetof(CTimeStamp::SInfo, month) == 0x02, "CTimeStamp::SInfo::month offset must be 0x02");
  static_assert(offsetof(CTimeStamp::SInfo, day) == 0x03, "CTimeStamp::SInfo::day offset must be 0x03");
  static_assert(offsetof(CTimeStamp::SInfo, hour) == 0x04, "CTimeStamp::SInfo::hour offset must be 0x04");
  static_assert(offsetof(CTimeStamp::SInfo, minute) == 0x05, "CTimeStamp::SInfo::minute offset must be 0x05");
  static_assert(offsetof(CTimeStamp::SInfo, second) == 0x06, "CTimeStamp::SInfo::second offset must be 0x06");
  static_assert(offsetof(CTimeStamp::SInfo, weekDay) == 0x07, "CTimeStamp::SInfo::weekDay offset must be 0x07");
  static_assert(offsetof(CTimeStamp::SInfo, yearDay) == 0x08, "CTimeStamp::SInfo::yearDay offset must be 0x08");
  static_assert(sizeof(CTimeStamp::SInfo) == 0x0A, "CTimeStamp::SInfo size must be 0x0A");
  static_assert(offsetof(CTimeStamp, time) == 0x00, "CTimeStamp::time offset must be 0x00");
  static_assert(offsetof(CTimeStamp, ftime) == 0x08, "CTimeStamp::ftime offset must be 0x08");
  static_assert(offsetof(CTimeStamp, millis) == 0x10, "CTimeStamp::millis offset must be 0x10");

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
     * Address: 0x00585870 (FUN_00585870, Moho::StatItem::AddFloat)
     *
     * What it does:
     * Atomically adds `*delta` to this stat's primary numeric lane using a
     * compare-and-swap retry loop over the stored float bit pattern.
     */
    [[nodiscard]] std::int32_t AddFloat(float* delta);

    /**
     * Address: 0x00751370 (FUN_00751370, Moho::StatItem::SetInt)
     *
     * What it does:
     * Atomically replaces the primary numeric lane with `*value` (or `0` when
     * `value == nullptr`) and returns the previous integer bits.
     */
    [[nodiscard]] std::int32_t SetInt(const std::int32_t* value);

    /**
     * Address: 0x00417FE0 (FUN_00417FE0, Moho::StatItem::SetValue_0)
     */
    void SetValueCopy(msvc8::string* outValue);

    /**
     * Address: 0x00415220 (FUN_00415220, Moho::StatItem::SetValue)
     */
    void SetValue(const msvc8::string& value);

    /**
     * Address: 0x004151E0 (FUN_004151E0, Moho::StatItem::Release)
     */
    [[nodiscard]] std::int32_t Release(std::int32_t value);

    /**
     * Address: 0x00418B00 (FUN_00418B00, Moho::StatItem::Clear)
     *
     * What it does:
     * Clears this stat item's current payload and optionally clears descendants.
     */
    void Clear(bool recursive);

    /**
     * Address: 0x00418A90 (FUN_00418A90, Moho::StatItem::ClearChildren)
     *
     * What it does:
     * Applies pulse-mode clear rules on this node and recursively visits child
     * nodes.
     */
    void ClearChildren(std::int32_t pulseMode);

    /**
     * Address: 0x00419090 (FUN_00419090, Moho::StatItem::SerializeList)
     *
     * What it does:
     * Serializes owned child pointers as a null-terminated list.
     */
    void SerializeList(gpg::WriteArchive* archive);

    /**
     * Address: 0x00419110 (FUN_00419110, Moho::StatItem::DeserializeList)
     *
     * What it does:
     * Loads owned child pointers until a null terminator and reattaches them.
     */
    void DeserializeList(gpg::ReadArchive* archive);

    /**
     * Address: 0x0041AD70 (FUN_0041AD70, Moho::StatItem::MemberDeserialize)
     *
     * What it does:
     * Loads stat payload lanes, name, pulse mode, and owned children from archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0041AEE0 (FUN_0041AEE0, Moho::StatItem::MemberSerialize)
     *
     * What it does:
     * Saves stat payload lanes, name, pulse mode, and owned children to archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive);

    /**
     * Address: 0x00436650 (FUN_00436650, Moho::StatItem::Synchronize)
     *
     * What it does:
     * Atomically replaces this stat-item's `mType` field with `EStatType::kInt`
     * via a load + compare-and-swap retry loop. Used to mark this stat as
     * holding an integer payload.
     */
    void Synchronize();

    /**
     * Address: 0x0040D2D0 (FUN_0040D2D0, Moho::StatItem::Synchronize2)
     */
    void SynchronizeAsInt();

    /**
     * Address: 0x00415370 (FUN_00415370, Moho::StatItem::Synchronize3)
     */
    void SynchronizeAsFloat();

    // Shared intrusive-tree helpers used by stat-path recovery code.
    void AttachChild(StatItem* child);
    [[nodiscard]] StatItem* FindDirectChildByName(const msvc8::string& token);

    static gpg::RType* sType;

  private:
    void ResetTreeLinks();
    void DetachSelfNode();

  public:
    std::uint32_t mTreeMeta; // +0x20

    // Numeric slot used when `useRealtimeValue == false`.
    volatile std::int32_t mPrimaryValueBits; // +0x24

    // String value storage for `EStatType::kString`.
    msvc8::string mValue; // +0x28

    // Numeric slot used when `useRealtimeValue == true`.
    volatile std::int32_t mRealtimeValueBits; // +0x44

    msvc8::string mScratchValue; // +0x48

    std::uint32_t mSampleTag{0};      // +0x64
    StatSampleBuffer mSampleHistory;  // +0x68..+0x73

    msvc8::string mName; // +0x74

    EStatType mType{EStatType::kNone};         // +0x90
    volatile std::int32_t mUseRealtimeSlot{0}; // +0x94
    boost::mutex mLock;                        // +0x98
  };
  static_assert(offsetof(StatItem, mSampleTag) == 0x64, "StatItem::mSampleTag offset must be 0x64");
  static_assert(offsetof(StatItem, mSampleHistory) == 0x68, "StatItem::mSampleHistory offset must be 0x68");
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
  static_assert(offsetof(StatItemSerializer, mNext) == 0x04, "StatItemSerializer::mNext offset must be 0x04");
  static_assert(offsetof(StatItemSerializer, mPrev) == 0x08, "StatItemSerializer::mPrev offset must be 0x08");
  static_assert(offsetof(StatItemSerializer, mSerLoadFunc) == 0x0C, "StatItemSerializer::mSerLoadFunc offset must be 0x0C");
  static_assert(offsetof(StatItemSerializer, mSerSaveFunc) == 0x10, "StatItemSerializer::mSerSaveFunc offset must be 0x10");

  /**
   * VFTABLE: 0x00E010B4
   * COL: 0x00E5DB04
   */
  class EStatTypePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x004192B0 (FUN_004192B0, gpg::PrimitiveSerHelper<Moho::EStatType,int>::Init)
     *
     * What it does:
     * Binds primitive enum load/save callbacks onto reflected `EStatType`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };
  static_assert(
    offsetof(EStatTypePrimitiveSerializer, mHelperNext) == 0x04,
    "EStatTypePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EStatTypePrimitiveSerializer, mHelperPrev) == 0x08,
    "EStatTypePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EStatTypePrimitiveSerializer, mSerLoadFunc) == 0x0C,
    "EStatTypePrimitiveSerializer::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(EStatTypePrimitiveSerializer, mSerSaveFunc) == 0x10,
    "EStatTypePrimitiveSerializer::mSerSaveFunc offset must be 0x10"
  );
  static_assert(sizeof(EStatTypePrimitiveSerializer) == 0x14, "EStatTypePrimitiveSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E010F4
   * COL: 0x00E5DA04
   */
  class EPulseModePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x00419350 (FUN_00419350, gpg::PrimitiveSerHelper<Moho::EPulseMode,int>::Init)
     *
     * What it does:
     * Binds primitive enum load/save callbacks onto reflected `EPulseMode`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };
  static_assert(
    offsetof(EPulseModePrimitiveSerializer, mHelperNext) == 0x04,
    "EPulseModePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EPulseModePrimitiveSerializer, mHelperPrev) == 0x08,
    "EPulseModePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EPulseModePrimitiveSerializer, mSerLoadFunc) == 0x0C,
    "EPulseModePrimitiveSerializer::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(EPulseModePrimitiveSerializer, mSerSaveFunc) == 0x10,
    "EPulseModePrimitiveSerializer::mSerSaveFunc offset must be 0x10"
  );
  static_assert(sizeof(EPulseModePrimitiveSerializer) == 0x14, "EPulseModePrimitiveSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E01104
   * COL: 0x00E5D9A0
   */
  class StatItemTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004184B0 (FUN_004184B0, Moho::StatItemTypeInfo::StatItemTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for `StatItem`.
     */
    StatItemTypeInfo();

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
   * VFTABLE: 0x00E01084
   * COL: 0x00E5DB68
   */
  class EStatTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x004181C0 (FUN_004181C0, Moho::EStatTypeTypeInfo::EStatTypeTypeInfo)
     */
    EStatTypeTypeInfo();

    /**
     * Address: 0x00418250 (FUN_00418250, Moho::EStatTypeTypeInfo::dtr)
     * Slot: 2
     */
    ~EStatTypeTypeInfo() override;

    /**
     * Address: 0x00418240 (FUN_00418240, Moho::EStatTypeTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00418220 (FUN_00418220, Moho::EStatTypeTypeInfo::Init)
     * Slot: 9
     */
    void Init() override;

  private:
    /**
     * Address: 0x00418280 (FUN_00418280, Moho::EStatTypeTypeInfo::AddEnums)
     */
    void AddEnums();
  };
  static_assert(sizeof(EStatTypeTypeInfo) == 0x78, "EStatTypeTypeInfo size must be 0x78");

  /**
   * VFTABLE: 0x00E010B4
   * COL: 0x00E5DAE0
   */
  class EPulseModeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00418340 (FUN_00418340, Moho::EPulseModeTypeInfo::EPulseModeTypeInfo)
     */
    EPulseModeTypeInfo();

    /**
     * Address: 0x004183D0 (FUN_004183D0, Moho::EPulseModeTypeInfo::dtr)
     * Slot: 2
     */
    ~EPulseModeTypeInfo() override;

    /**
     * Address: 0x004183C0 (FUN_004183C0, Moho::EPulseModeTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004183A0 (FUN_004183A0, Moho::EPulseModeTypeInfo::Init)
     * Slot: 9
     */
    void Init() override;

  private:
    /**
     * Address: 0x00418400 (FUN_00418400, Moho::EPulseModeTypeInfo::AddEnums)
     */
    void AddEnums();
  };
  static_assert(sizeof(EPulseModeTypeInfo) == 0x78, "EPulseModeTypeInfo size must be 0x78");

  /**
   * VFTABLE: 0x00E01054
   * COL: 0x00E5DBF0
   */
  template <>
  class StatsRType<StatItem> final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0041A750 (FUN_0041A750, Moho::StatsRType_StatItem::StatsRType_StatItem)
     */
    StatsRType();

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
    * Alias of FUN_0040C200 (non-canonical helper lane).
    * Alias of FUN_00417B60 (non-canonical helper lane).
    * Alias of FUN_00417C50 (non-canonical helper lane).
   */
  [[nodiscard]] StatItem* ResolveStatByMode(void* statsRoot, gpg::StrArg name, int mode);
  [[nodiscard]] StatItem* ResolveStatFloat(void* statsRoot, gpg::StrArg name);
  [[nodiscard]] StatItem* ResolveStatString(void* statsRoot, gpg::StrArg name);
} // namespace moho
