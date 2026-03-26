#include "StatItem.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "lua/LuaObject.h"

namespace
{
  struct StatIntrusiveNode
  {
    StatIntrusiveNode* prev;
    StatIntrusiveNode* next;
    moho::StatItem* parent;
    moho::StatItem* owner;
  };

  constexpr const char* kRootStatName = "Root";

  [[nodiscard]] gpg::RType* CachedStatItemType()
  {
    if (!moho::StatItem::sType) {
      moho::StatItem::sType = gpg::LookupRType(typeid(moho::StatItem));
    }
    return moho::StatItem::sType;
  }

  template <class TObject>
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

    int baseOffset = 0;
    const bool isDerived = dynamicType->IsDerivedFrom(staticType, &baseOffset);
    GPG_ASSERT(isDerived);
    if (!isDerived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  [[nodiscard]] gpg::RRef MakeStatItemRef(moho::StatItem* object)
  {
    return MakeTypedRef(object, CachedStatItemType());
  }

  [[nodiscard]] moho::StatItem* CastStatItemFromRef(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedStatItemType());
    return static_cast<moho::StatItem*>(upcast.mObj);
  }

  [[nodiscard]] moho::StatItem* ReadArchiveStatItemPointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    moho::StatItem* const item = CastStatItemFromRef(source);
    if (!item) {
      const char* const expectedName = CachedStatItemType()->GetName();
      const char* const actualName = tracked.type ? tracked.type->GetName() : "null";
      const msvc8::string msg = gpg::STR_Printf(
        "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
        "instead",
        expectedName ? expectedName : "StatItem",
        actualName ? actualName : "null"
      );
      throw std::runtime_error(msg.c_str());
    }
    return item;
  }

  /**
   * Address: 0x00419DE0 (FUN_00419DE0, func_ReadArchive_Stats_StatItem)
   */
  void DeserializeStatsStatItem(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const stats = reinterpret_cast<moho::Stats<moho::StatItem>*>(objectPtr);
    GPG_ASSERT(stats != nullptr);

    boost::mutex::scoped_lock lock(stats->mLock);
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    moho::StatItem* const loadedRoot = ReadArchiveStatItemPointer(archive, owner);

    moho::StatItem* const previousRoot = stats->mItem;
    stats->mItem = loadedRoot;
    delete previousRoot;
  }

  /**
   * Address: 0x00419E70 (FUN_00419E70, func_WriteArchive_Stats_StatItem)
   */
  void SerializeStatsStatItem(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const stats = reinterpret_cast<moho::Stats<moho::StatItem>*>(objectPtr);
    GPG_ASSERT(stats != nullptr);

    boost::mutex::scoped_lock lock(stats->mLock);
    const gpg::RRef rootRef = MakeStatItemRef(stats->mItem);
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    gpg::WriteRawPointer(archive, rootRef, gpg::TrackedPointerState::Owned, owner);
  }

  /**
   * Address: 0x00419F00 (FUN_00419F00, func_NewStats_StatItem)
   */
  void ConstructStatsStatItem(void* objectStorage)
  {
    if (!objectStorage) {
      return;
    }
    new (objectStorage) moho::Stats<moho::StatItem>();
  }

  /**
   * Address: 0x0041A4E0 (FUN_0041A4E0, func_Delete_Stats_StatItem)
   */
  void DeleteStatsStatItem(void* object)
  {
    delete static_cast<moho::Stats<moho::StatItem>*>(object);
  }

  /**
   * Address: 0x0041A0F0 (FUN_0041A0F0, sub_41A0F0)
   */
  [[nodiscard]] gpg::RRef CreateStatItemRefOwned()
  {
    auto* const item = new moho::StatItem(kRootStatName);
    return MakeStatItemRef(item);
  }

  /**
   * Address: 0x0041A170 (FUN_0041A170, sub_41A170)
   */
  void DeleteStatItemOwned(void* object)
  {
    delete static_cast<moho::StatItem*>(object);
  }

  /**
   * Address: 0x0041A190 (FUN_0041A190, sub_41A190)
   */
  [[nodiscard]] gpg::RRef ConstructStatItemRefInPlace(void* objectStorage)
  {
    auto* const item = static_cast<moho::StatItem*>(objectStorage);
    if (item) {
      new (item) moho::StatItem(kRootStatName);
    }
    return MakeStatItemRef(item);
  }

  /**
   * Address: 0x0041A210 (FUN_0041A210, sub_41A210)
   */
  void DestroyStatItemInPlace(void* object)
  {
    auto* const item = static_cast<moho::StatItem*>(object);
    if (item) {
      item->~StatItem();
    }
  }

  [[nodiscard]] StatIntrusiveNode* AsSelfNode(moho::StatItem* item) noexcept
  {
    return reinterpret_cast<StatIntrusiveNode*>(&item->head1Prev);
  }

  [[nodiscard]] StatIntrusiveNode* AsChildHead(moho::StatItem* item) noexcept
  {
    return reinterpret_cast<StatIntrusiveNode*>(&item->head2Prev);
  }

  [[nodiscard]] moho::StatItem* WalkStatPath(
    moho::StatItem* root, const msvc8::vector<msvc8::string>& tokens, const bool allowCreate, bool* const didCreate
  )
  {
    if (didCreate != nullptr) {
      *didCreate = false;
    }
    if (root == nullptr) {
      return nullptr;
    }

    const std::size_t tokenCount = tokens.size();
    if (tokenCount == 0u) {
      return root;
    }

    moho::StatItem* current = root;
    std::size_t index = 0u;
    for (; index < tokenCount; ++index) {
      moho::StatItem* const found = current->FindDirectChildByName(tokens[index]);
      if (found == nullptr) {
        break;
      }
      current = found;
    }

    if (index == tokenCount) {
      return current;
    }
    if (!allowCreate) {
      return nullptr;
    }

    if (didCreate != nullptr) {
      *didCreate = true;
    }

    moho::StatItem* parent = current;
    moho::StatItem* lastCreated = nullptr;
    for (; index < tokenCount; ++index) {
      moho::StatItem* const child = new moho::StatItem(tokens[index].c_str());
      parent->AttachChild(child);
      parent = child;
      lastCreated = child;
    }
    return lastCreated;
  }

  [[nodiscard]] std::int32_t ReadAtomicI32(volatile std::int32_t* value)
  {
#if defined(_WIN32)
    return static_cast<std::int32_t>(InterlockedCompareExchange(reinterpret_cast<volatile long*>(value), 0, 0));
#else
    return *value;
#endif
  }

  void AtomicStoreI32(volatile std::int32_t* value, const std::int32_t wanted)
  {
#if defined(_WIN32)
    for (;;) {
      const std::int32_t observed = ReadAtomicI32(value);
      const std::int32_t exchanged = static_cast<std::int32_t>(InterlockedCompareExchange(
        reinterpret_cast<volatile long*>(value), static_cast<long>(wanted), static_cast<long>(observed)
      ));
      if (exchanged == observed) {
        return;
      }
    }
#else
    *value = wanted;
#endif
  }

  [[nodiscard]] std::int32_t AtomicExchangeI32(volatile std::int32_t* value, const std::int32_t wanted)
  {
#if defined(_WIN32)
    for (;;) {
      const std::int32_t observed = ReadAtomicI32(value);
      const std::int32_t exchanged = static_cast<std::int32_t>(InterlockedCompareExchange(
        reinterpret_cast<volatile long*>(value), static_cast<long>(wanted), static_cast<long>(observed)
      ));
      if (exchanged == observed) {
        return exchanged;
      }
    }
#else
    const std::int32_t previous = *value;
    *value = wanted;
    return previous;
#endif
  }

  [[nodiscard]] std::int32_t ReadNumericSlot(moho::StatItem* item, const bool useRealtimeValue)
  {
    volatile std::int32_t* const slot = useRealtimeValue ? &item->mRealtimeValueBits : &item->mPrimaryValueBits;
    return ReadAtomicI32(slot);
  }

  [[nodiscard]] float AsFloatBits(const std::int32_t value)
  {
    float out = 0.0f;
    std::memcpy(&out, &value, sizeof(out));
    return out;
  }
} // namespace

namespace moho
{
  gpg::RType* StatItem::sType = nullptr;
  gpg::RType* Stats<StatItem>::sType = nullptr;
  EngineStats* sEngineStats = nullptr;

  void StatHeapBlock::Reset() noexcept
  {
    if (data) {
      operator delete(data);
      data = nullptr;
    }
    size = 0;
    capacity = 0;
  }

  StatHeapBlock::~StatHeapBlock() noexcept
  {
    Reset();
  }

  void StatItem::ResetTreeLinks()
  {
    StatIntrusiveNode* const selfNode = AsSelfNode(this);
    selfNode->prev = selfNode;
    selfNode->next = selfNode;
    selfNode->parent = nullptr;
    selfNode->owner = this;

    StatIntrusiveNode* const childHead = AsChildHead(this);
    childHead->prev = childHead;
    childHead->next = childHead;
    owner2 = this;
    mTreeMeta = 0;
  }

  void StatItem::DetachSelfNode()
  {
    StatIntrusiveNode* const selfNode = AsSelfNode(this);
    if (selfNode->next != nullptr && selfNode->prev != nullptr) {
      selfNode->next->prev = selfNode->prev;
      selfNode->prev->next = selfNode->next;
    }
    selfNode->prev = selfNode;
    selfNode->next = selfNode;
    selfNode->parent = nullptr;
  }

  void StatItem::AttachChild(StatItem* const child)
  {
    if (child == nullptr) {
      return;
    }

    child->DetachSelfNode();

    StatIntrusiveNode* const childNode = AsSelfNode(child);
    childNode->parent = this;

    StatIntrusiveNode* const parentHead = AsChildHead(this);
    childNode->prev = parentHead->prev;
    childNode->next = parentHead;
    parentHead->prev = childNode;
    childNode->prev->next = childNode;
  }

  StatItem* StatItem::FindDirectChildByName(const msvc8::string& token)
  {
    for (StatIntrusiveNode* node = AsChildHead(this)->next; node != nullptr; node = node->next) {
      StatItem* const child = node->owner;
      if (child == nullptr) {
        break;
      }
      if (child->mName == token) {
        return child;
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x0040A0A0 (FUN_0040A0A0, Moho::Stats_StatItem::Stats_StatItem)
   */
  Stats<StatItem>::Stats()
    : mItem(new StatItem(kRootStatName))
    , mLock()
    , pad_000D{0, 0, 0}
  {}

  /**
   * Address: 0x00406600 (FUN_00406600, Moho::Stats_StatItem::~Stats_StatItem)
   */
  Stats<StatItem>::~Stats()
  {
    delete mItem;
    mItem = nullptr;
  }

  /**
   * Address: 0x0040B2E0 (FUN_0040B2E0, Moho::Stats_StatItem::Delete)
   */
  void Stats<StatItem>::Delete(const char* statPath)
  {
    boost::mutex::scoped_lock lock(mLock);
    StatItem* const item = GetItem(statPath, false);
    if (item == mItem) {
      throw std::runtime_error("Don't be doing that, chief.");
    }
    if (item) {
      delete item;
    }
  }

  /**
   * Address: 0x0040C200 (FUN_0040C200, Moho::Stats_StatItem::GetItem)
   */
  StatItem* Stats<StatItem>::GetItem(const gpg::StrArg statPath, const bool allowCreate)
  {
    boost::mutex::scoped_lock lock(mLock);

    msvc8::vector<msvc8::string> tokens;
    gpg::STR_GetTokens(statPath, "_", tokens);

    bool didCreate = false;
    StatItem* const item = WalkStatPath(mItem, tokens, allowCreate, &didCreate);
    if (didCreate && item != nullptr) {
      item->SynchronizeAsInt();
    }
    return item;
  }

  /**
   * Address: 0x00417B60 (FUN_00417B60, Moho::EngineStats::GetItem3)
   */
  StatItem* Stats<StatItem>::GetFloatItem(const gpg::StrArg statPath)
  {
    boost::mutex::scoped_lock lock(mLock);

    msvc8::vector<msvc8::string> tokens;
    gpg::STR_GetTokens(statPath, "_", tokens);

    bool didCreate = false;
    StatItem* const item = WalkStatPath(mItem, tokens, true, &didCreate);
    if (didCreate && item != nullptr) {
      item->SynchronizeAsFloat();
    }
    return item;
  }

  /**
   * Address: 0x00417C50 (FUN_00417C50, Moho::EngineStats::GetItem_0)
   */
  StatItem* Stats<StatItem>::GetStringItem(const gpg::StrArg statPath)
  {
    boost::mutex::scoped_lock lock(mLock);

    msvc8::vector<msvc8::string> tokens;
    gpg::STR_GetTokens(statPath, "_", tokens);

    bool didCreate = false;
    StatItem* const item = WalkStatPath(mItem, tokens, true, &didCreate);
    if (didCreate && item != nullptr) {
      boost::mutex::scoped_lock itemLock(item->mLock);
      item->mType = EStatType::kString;
    }
    return item;
  }

  /**
   * Address: 0x00436290 (FUN_00436290, Moho::EngineStats::GetItem2)
   */
  StatItem* Stats<StatItem>::GetIntItem(const gpg::StrArg statPath)
  {
    return GetItem(statPath, true);
  }

  /**
   * Address: 0x004088C0 (FUN_004088C0, Moho::EngineStats::EngineStats)
   */
  EngineStats::EngineStats()
    : Stats<StatItem>()
    , mLogFileName("stats.log")
    , mResolvedLogFilePath()
    , mLogFrameCount(0)
    , mIsLogging(0)
    , mPad4D{0, 0, 0}
  {}

  /**
   * Address: 0x00407DC0 (FUN_00407DC0, Moho::EngineStats::~EngineStats)
   */
  EngineStats::~EngineStats() = default;

  /**
   * Address: 0x00417B60 (FUN_00417B60, Moho::EngineStats::GetItem3)
   */
  StatItem* EngineStats::GetItem3(const gpg::StrArg statPath)
  {
    return GetFloatItem(statPath);
  }

  /**
   * Address: 0x00417C50 (FUN_00417C50, Moho::EngineStats::GetItem_0)
   */
  StatItem* EngineStats::GetItem_0(const gpg::StrArg statPath)
  {
    return GetStringItem(statPath);
  }

  /**
   * Address: 0x00436290 (FUN_00436290, Moho::EngineStats::GetItem2)
   */
  StatItem* EngineStats::GetItem2(const gpg::StrArg statPath)
  {
    return GetIntItem(statPath);
  }

  /**
   * Address: 0x00408940 (FUN_00408940, Moho::GetEngineStats)
   */
  EngineStats* GetEngineStats()
  {
    EngineStats* result = sEngineStats;
    if (result != nullptr) {
      return result;
    }

    EngineStats* const candidate = new (std::nothrow) EngineStats();
    EngineStats* const previous = sEngineStats;
    sEngineStats = candidate;
    if (previous != nullptr) {
      delete previous;
      return sEngineStats;
    }

    return candidate;
  }

  /**
   * Address: 0x00408730 (FUN_00408730, Moho::StatItem::StatItem)
   */
  StatItem::StatItem(const char* name)
    : mPrimaryValueBits(0)
    , mValue()
    , mRealtimeValueBits(0)
    , mScratchValue()
    , mHeapStorage{}
    , mName(name ? name : "")
    , mType(EStatType::kNone)
    , mUseRealtimeSlot(0)
    , mLock()
  {
    ResetTreeLinks();
  }

  /**
   * Address: 0x00408840 (FUN_00408840, deleting dtor thunk)
   * Address: 0x00418610 (FUN_00418610, destructor core)
   */
  StatItem::~StatItem()
  {
    for (StatIntrusiveNode* node = AsChildHead(this)->next; node != nullptr;) {
      StatItem* const child = node->owner;
      if (child == nullptr) {
        break;
      }

      StatIntrusiveNode* const next = node->next;
      delete child;
      node = next;
    }

    DetachSelfNode();
    ResetTreeLinks();
  }

  /**
   * Address: 0x00417FE0 (FUN_00417FE0, Moho::StatItem::SetValue_0)
   */
  void StatItem::SetValueCopy(msvc8::string* outValue)
  {
    boost::mutex::scoped_lock lock(mLock);
    outValue->assign(mValue, 0, msvc8::string::npos);
  }

  /**
   * Address: 0x00415220 (FUN_00415220, Moho::StatItem::SetValue)
   */
  void StatItem::SetValue(const msvc8::string& value)
  {
    boost::mutex::scoped_lock lock(mLock);
    mValue.assign(value, 0, msvc8::string::npos);
  }

  /**
   * Address: 0x004151E0 (FUN_004151E0, Moho::StatItem::Release)
   */
  std::int32_t StatItem::Release(const std::int32_t value)
  {
    return AtomicExchangeI32(&mUseRealtimeSlot, value);
  }

  /**
   * Address: 0x00418750 (FUN_00418750, Moho::StatItem::GetString)
   */
  msvc8::string* StatItem::GetString(const bool useRealtimeValue, msvc8::string* outValue)
  {
    if (mType == EStatType::kFloat) {
      *outValue = gpg::STR_Printf("%.2f", AsFloatBits(ReadNumericSlot(this, useRealtimeValue)));
      return outValue;
    }

    if (mType == EStatType::kInt) {
      *outValue = gpg::STR_Printf("%i", ReadNumericSlot(this, useRealtimeValue));
      return outValue;
    }

    SetValueCopy(outValue);
    return outValue;
  }

  /**
   * Address: 0x00418890 (FUN_00418890, Moho::StatItem::GetInt)
   */
  int StatItem::GetInt(const bool useRealtimeValue)
  {
    if (mType == EStatType::kFloat) {
      return static_cast<int>(AsFloatBits(ReadNumericSlot(this, useRealtimeValue)));
    }

    if (mType == EStatType::kInt) {
      return ReadNumericSlot(this, useRealtimeValue);
    }

    msvc8::string value;
    SetValueCopy(&value);
    return std::atoi(value.c_str());
  }

  /**
   * Address: 0x00418990 (FUN_00418990, Moho::StatItem::GetFloat)
   */
  float StatItem::GetFloat(const bool useRealtimeValue)
  {
    if (mType == EStatType::kFloat) {
      return AsFloatBits(ReadNumericSlot(this, useRealtimeValue));
    }

    if (mType == EStatType::kInt) {
      return static_cast<float>(ReadNumericSlot(this, useRealtimeValue));
    }

    msvc8::string value;
    SetValueCopy(&value);
    return static_cast<float>(std::atof(value.c_str()));
  }

  /**
   * Address: 0x0040D2D0 (FUN_0040D2D0, Moho::StatItem::Synchronize2)
   */
  void StatItem::SynchronizeAsInt()
  {
    AtomicStoreI32(reinterpret_cast<volatile std::int32_t*>(&mType), static_cast<std::int32_t>(EStatType::kInt));
  }

  /**
   * Address: 0x00415370 (FUN_00415370, Moho::StatItem::Synchronize3)
   */
  void StatItem::SynchronizeAsFloat()
  {
    AtomicStoreI32(reinterpret_cast<volatile std::int32_t*>(&mType), static_cast<std::int32_t>(EStatType::kFloat));
  }

  /**
   * Address: 0x00418BD0 (FUN_00418BD0, Moho::StatItem::ToLua)
   */
  void StatItem::ToLua(LuaPlus::LuaState* /*state*/, LuaPlus::LuaObject* outObject)
  {
    outObject->SetString("Name", mName.c_str());
    if (mType == EStatType::kNone) {
      return;
    }

    const bool useRealtimeValue = (mUseRealtimeSlot == 1);
    switch (mType) {
    case EStatType::kFloat:
      outObject->SetNumber("Value", GetFloat(useRealtimeValue));
      outObject->SetString("Type", "Float");
      break;
    case EStatType::kInt:
      outObject->SetInteger("Value", GetInt(useRealtimeValue));
      outObject->SetString("Type", "Integer");
      break;
    case EStatType::kString: {
      msvc8::string value;
      GetString(useRealtimeValue, &value);
      if (!value.empty()) {
        outObject->SetString("Value", value.c_str());
      }
      outObject->SetString("Type", "String");
      break;
    }
    default:
      break;
    }
  }

  /**
   * Address: 0x004194E0 (FUN_004194E0, sub_4194E0)
   */
  void StatItemSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedStatItemType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x00418560 (FUN_00418560, sub_418560)
   */
  StatItemTypeInfo::~StatItemTypeInfo() = default;

  /**
   * Address: 0x00418550 (FUN_00418550, sub_418550)
   */
  const char* StatItemTypeInfo::GetName() const
  {
    return "StatItem";
  }

  /**
   * Address: 0x00418510 (FUN_00418510, sub_418510)
   */
  void StatItemTypeInfo::Init()
  {
    size_ = sizeof(StatItem);
    newRefFunc_ = &CreateStatItemRefOwned;
    deleteFunc_ = &DeleteStatItemOwned;
    ctorRefFunc_ = &ConstructStatItemRefInPlace;
    dtrFunc_ = &DestroyStatItemInPlace;
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0041A800 (FUN_0041A800, sub_41A800)
   */
  StatsRType<StatItem>::~StatsRType() = default;

  /**
   * Address: 0x00419550 (FUN_00419550, Moho::StatsRType_StatItem::GetName)
   */
  const char* StatsRType<StatItem>::GetName() const
  {
    static msvc8::string cachedName;
    if (cachedName.empty()) {
      cachedName = gpg::STR_Printf("Stats<%s>", CachedStatItemType()->GetName());
    }
    return cachedName.c_str();
  }

  /**
   * Address: 0x004195F0 (FUN_004195F0, Moho::StatsRType_StatItem::Init)
   */
  void StatsRType<StatItem>::Init()
  {
    size_ = sizeof(Stats<StatItem>);
    version_ = 1;
    serLoadFunc_ = &DeserializeStatsStatItem;
    serSaveFunc_ = &SerializeStatsStatItem;
    serConstructFunc_ = &ConstructStatsStatItem;
    deleteFunc_ = &DeleteStatsStatItem;
  }

  /**
   * Address: 0x0040C200 (FUN_0040C200, mode-based resolver)
   */
  StatItem* ResolveStatByMode(void* statsRoot, const gpg::StrArg name, const int mode)
  {
    auto* const stats = reinterpret_cast<Stats<StatItem>*>(statsRoot);
    if (!stats) {
      return nullptr;
    }
    return stats->GetItem(name, mode != 0);
  }

  /**
   * Address: 0x00417B60 (FUN_00417B60, float resolver)
   */
  StatItem* ResolveStatFloat(void* statsRoot, const gpg::StrArg name)
  {
    auto* const stats = reinterpret_cast<Stats<StatItem>*>(statsRoot);
    if (!stats) {
      return nullptr;
    }
    return stats->GetFloatItem(name);
  }

  /**
   * Address: 0x00417C50 (FUN_00417C50, string resolver)
   */
  StatItem* ResolveStatString(void* statsRoot, const gpg::StrArg name)
  {
    auto* const stats = reinterpret_cast<Stats<StatItem>*>(statsRoot);
    if (!stats) {
      return nullptr;
    }
    return stats->GetStringItem(name);
  }
} // namespace moho
