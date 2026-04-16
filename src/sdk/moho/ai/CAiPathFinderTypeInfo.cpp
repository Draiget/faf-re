#include "moho/ai/CAiPathFinderTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <list>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/containers/String.h"
#include "moho/ai/CAiPathFinder.h"
#include "moho/misc/Stats.h"

using namespace moho;

namespace
{
  class Rect2iListTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    void Init() override;
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int unusedTag, gpg::RRef* ownerRef);
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int unusedTag, gpg::RRef* ownerRef);
  };

  static_assert(sizeof(Rect2iListTypeInfo) == 0x64, "Rect2iListTypeInfo size must be 0x64");

  alignas(CAiPathFinderTypeInfo) unsigned char gCAiPathFinderTypeInfoStorage[sizeof(CAiPathFinderTypeInfo)] = {};
  bool gCAiPathFinderTypeInfoConstructed = false;

  alignas(Rect2iListTypeInfo) unsigned char gRect2iListTypeInfoStorage[sizeof(Rect2iListTypeInfo)] = {};
  bool gRect2iListTypeInfoConstructed = false;
  msvc8::string gRect2iListTypeName;
  bool gRect2iListTypeNameCleanupRegistered = false;

  [[maybe_unused]] [[nodiscard]] gpg::RType** StoreRuntimeTypePointer(
    gpg::RType** outType,
    gpg::RType* value
  ) noexcept;
  [[maybe_unused]] [[nodiscard]] gpg::RType** StoreRuntimeTypePointerAlias(
    gpg::RType** outType,
    gpg::RType* value
  ) noexcept;

  template <std::uintptr_t SlotAddress>
  struct StartupEngineStatsSlot
  {
    static EngineStats* value;
  };

  template <>
  EngineStats* StartupEngineStatsSlot<0x10AEE34u>::value = nullptr;

  [[nodiscard]] CAiPathFinderTypeInfo* AcquireCAiPathFinderTypeInfo()
  {
    if (!gCAiPathFinderTypeInfoConstructed) {
      auto* const typeInfo = new (gCAiPathFinderTypeInfoStorage) CAiPathFinderTypeInfo();
      gpg::PreRegisterRType(typeid(CAiPathFinder), typeInfo);
      (void)StoreRuntimeTypePointerAlias(&CAiPathFinder::sType, typeInfo);
      gCAiPathFinderTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiPathFinderTypeInfo*>(gCAiPathFinderTypeInfoStorage);
  }

  [[nodiscard]] Rect2iListTypeInfo* AcquireRect2iListTypeInfo()
  {
    if (!gRect2iListTypeInfoConstructed) {
      auto* const typeInfo = new (gRect2iListTypeInfoStorage) Rect2iListTypeInfo();
      gpg::PreRegisterRType(typeid(std::list<gpg::Rect2i>), typeInfo);
      gRect2iListTypeInfoConstructed = true;
    }

    return reinterpret_cast<Rect2iListTypeInfo*>(gRect2iListTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedRect2iType()
  {
    gpg::RType* type = gpg::Rect2i::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(gpg::Rect2i));
      gpg::Rect2i::sType = type;
    }
    return type;
  }

  void cleanup_Rect2iListTypeName()
  {
    gRect2iListTypeName.clear();
    gRect2iListTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x005AAF60 (FUN_005AAF60, sub_5AAF60)
   *
   * What it does:
   * Clears one reflected `list<Rect2i>` storage lane and releases all list
   * nodes, resetting the list into its empty sentinel state.
   */
  [[nodiscard]] std::list<gpg::Rect2i>* ClearRect2iListStorage(std::list<gpg::Rect2i>* const list)
  {
    if (list != nullptr) {
      list->clear();
    }
    return list;
  }

  /**
   * Address: 0x005AAFA0 (FUN_005AAFA0, gpg::RListType_Rect2i::GetName)
   *
   * What it does:
   * Lazily builds and caches the reflected `list<Rect2i>` type name.
   */
  const char* Rect2iListTypeInfo::GetName() const
  {
    if (gRect2iListTypeName.empty()) {
      const gpg::RType* const elementType = CachedRect2iType();
      const char* const elementName = elementType ? elementType->GetName() : "Rect2i";
      gRect2iListTypeName = gpg::STR_Printf("list<%s>", elementName ? elementName : "Rect2i");
      if (!gRect2iListTypeNameCleanupRegistered) {
        gRect2iListTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_Rect2iListTypeName);
      }
    }

    return gRect2iListTypeName.c_str();
  }

  /**
   * Address: 0x005AB060 (FUN_005AB060, gpg::RListType_Rect2i::GetLexical)
   *
   * What it does:
   * Formats the default RTTI lexical text and appends current list length.
   */
  msvc8::string Rect2iListTypeInfo::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string lexical = gpg::RType::GetLexical(ref);
    const auto* const list = static_cast<const std::list<gpg::Rect2i>*>(ref.mObj);
    const int size = list ? static_cast<int>(list->size()) : 0;
    return gpg::STR_Printf("%s, size=%d", lexical.c_str(), size);
  }

  /**
   * Address: 0x005AB040 (FUN_005AB040, gpg::RListType_Rect2i::Init)
   *
   * What it does:
   * Configures reflected `list<Rect2i>` layout/version lanes and installs
   * list serializer callbacks.
   */
  void Rect2iListTypeInfo::Init()
  {
    size_ = sizeof(std::list<gpg::Rect2i>);
    version_ = 1;
    serLoadFunc_ = &Rect2iListTypeInfo::SerLoad;
    serSaveFunc_ = &Rect2iListTypeInfo::SerSave;
  }

  /**
   * Address: 0x005AB410 (FUN_005AB410, gpg::RListType_Rect2i::SerLoad)
   *
   * What it does:
   * Clears one reflected `list<Rect2i>`, reads element count, then deserializes
   * each `Rect2i` element in archive order.
   */
  void Rect2iListTypeInfo::SerLoad(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    auto* const list = reinterpret_cast<std::list<gpg::Rect2i>*>(static_cast<std::uintptr_t>(objectPtr));
    if (archive == nullptr || list == nullptr) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);
    (void)ClearRect2iListStorage(list);

    gpg::RType* const elementType = CachedRect2iType();
    if (elementType == nullptr) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int index = 0; index < count; ++index) {
      gpg::Rect2i value{};
      archive->Read(elementType, &value, owner);
      list->push_back(value);
    }
  }

  /**
   * Address: 0x005AB4C0 (FUN_005AB4C0, gpg::RListType_Rect2i::SerSave)
   *
   * What it does:
   * Writes reflected `list<Rect2i>` element count, then serializes each
   * element in list traversal order.
   */
  void Rect2iListTypeInfo::SerSave(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    const auto* const list = reinterpret_cast<const std::list<gpg::Rect2i>*>(static_cast<std::uintptr_t>(objectPtr));
    if (archive == nullptr) {
      return;
    }

    const unsigned int count = list ? static_cast<unsigned int>(list->size()) : 0u;
    archive->WriteUInt(count);
    if (!list) {
      return;
    }

    gpg::RType* const elementType = CachedRect2iType();
    if (elementType == nullptr) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (const gpg::Rect2i& value : *list) {
      archive->Write(elementType, &value, owner);
    }
  }

  void AddBaseByTypeInfo(gpg::RType* typeInfo, const std::type_info& baseTypeInfo, const std::int32_t baseOffset)
  {
    gpg::RType* baseType = nullptr;
    try {
      baseType = gpg::LookupRType(baseTypeInfo);
    } catch (...) {
      baseType = nullptr;
    }

    if (!baseType) {
      return;
    }

    gpg::RField field{};
    field.mName = baseType->GetName();
    field.mType = baseType;
    field.mOffset = baseOffset;
    field.v4 = 0;
    field.mDesc = nullptr;
    typeInfo->AddBase(field);
  }

  /**
   * Address: 0x005AB1C0 (FUN_005AB1C0)
   *
   * What it does:
   * Binds allocation/construction/destruction callback lanes for one
   * `CAiPathFinderTypeInfo` descriptor.
   */
  [[maybe_unused]] [[nodiscard]] CAiPathFinderTypeInfo* BindCAiPathFinderTypeInfoCallbacks(
    CAiPathFinderTypeInfo* const typeInfo
  ) noexcept
  {
    if (!typeInfo) {
      return nullptr;
    }

    typeInfo->newRefFunc_ = &CAiPathFinderTypeInfo::NewRef;
    typeInfo->ctorRefFunc_ = &CAiPathFinderTypeInfo::CtrRef;
    typeInfo->deleteFunc_ = &CAiPathFinderTypeInfo::Delete;
    typeInfo->dtrFunc_ = &CAiPathFinderTypeInfo::Destruct;
    return typeInfo;
  }

  /**
   * Address: 0x005AB980 (FUN_005AB980)
   *
   * What it does:
   * Stores one runtime `RType*` lane through an output pointer.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType** StoreRuntimeTypePointer(
    gpg::RType** const outType,
    gpg::RType* const value
  ) noexcept
  {
    if (outType) {
      *outType = value;
    }
    return outType;
  }

  /**
   * Address: 0x005AB9B0 (FUN_005AB9B0)
   *
   * What it does:
   * Alias lane for storing one runtime `RType*` pointer.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType** StoreRuntimeTypePointerAlias(
    gpg::RType** const outType,
    gpg::RType* const value
  ) noexcept
  {
    return StoreRuntimeTypePointer(outType, value);
  }

  /**
   * Address: 0x005AAAA0 (FUN_005AAAA0, preregister_CAiPathFinderTypeInfo)
   *
   * What it does:
   * Constructs and preregisters startup RTTI descriptor for `CAiPathFinder`.
   */
  [[nodiscard]] gpg::RType* preregister_CAiPathFinderTypeInfo()
  {
    return AcquireCAiPathFinderTypeInfo();
  }

  /**
   * Address: 0x005ABC00 (FUN_005ABC00, preregister_Rect2iListTypeInfo)
   *
   * What it does:
   * Constructs and preregisters reflected `std::list<gpg::Rect2<int>>`
   * startup RTTI descriptor.
   */
  [[nodiscard]] gpg::RType* preregister_Rect2iListTypeInfo()
  {
    return AcquireRect2iListTypeInfo();
  }

  /**
   * Address: 0x00BF71E0 (FUN_00BF71E0, cleanup_CAiPathFinderTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `CAiPathFinderTypeInfo` reflection storage.
   */
  void cleanup_CAiPathFinderTypeInfo()
  {
    if (!gCAiPathFinderTypeInfoConstructed) {
      return;
    }

    AcquireCAiPathFinderTypeInfo()->~CAiPathFinderTypeInfo();
    gCAiPathFinderTypeInfoConstructed = false;
    (void)StoreRuntimeTypePointer(&CAiPathFinder::sType, nullptr);
  }

  /**
   * Address: 0x00BF72A0 (FUN_00BF72A0, cleanup_Rect2iListTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `std::list<gpg::Rect2<int>>` RTTI storage.
   */
  void cleanup_Rect2iListTypeInfo()
  {
    if (!gRect2iListTypeInfoConstructed) {
      return;
    }

    AcquireRect2iListTypeInfo()->~Rect2iListTypeInfo();
    gRect2iListTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BF7300 (FUN_00BF7300, cleanup_CAiPathFinderStartupStatsSlot)
   *
   * What it does:
   * Tears down one startup-owned AI path-finder stats slot.
   */
  void cleanup_CAiPathFinderStartupStatsSlot()
  {
    EngineStats*& slot = StartupEngineStatsSlot<0x10AEE34u>::value;
    if (!slot) {
      return;
    }

    delete slot;
    slot = nullptr;
  }
} // namespace

/**
 * Address: 0x005AAB60 (FUN_005AAB60, scalar deleting thunk)
 */
CAiPathFinderTypeInfo::~CAiPathFinderTypeInfo() = default;

/**
 * Address: 0x005AAB50 (FUN_005AAB50, ?GetName@CAiPathFinderTypeInfo@Moho@@UBEPBDXZ)
 *
 * What it does:
 * Returns the reflected `CAiPathFinder` type name.
 */
const char* CAiPathFinderTypeInfo::GetName() const
{
  return "CAiPathFinder";
}

/**
 * Address: 0x005AB870 (FUN_005AB870, Moho::CAiPathFinderTypeInfo::NewRef)
 *
 * What it does:
 * Allocates and constructs one `CAiPathFinder` object for reflection use,
 * then returns its typed reflection reference.
 */
gpg::RRef CAiPathFinderTypeInfo::NewRef()
{
  auto* const pathFinder = new (std::nothrow) CAiPathFinder();
  gpg::RRef out{};
  (void)gpg::RRef_CAiPathFinder(&out, pathFinder);
  return out;
}

/**
 * Address: 0x005AB8E0 (FUN_005AB8E0, Moho::CAiPathFinderTypeInfo::Delete)
 *
 * What it does:
 * Deletes one heap-owned `CAiPathFinder` object.
 */
void CAiPathFinderTypeInfo::Delete(void* const objectStorage)
{
  delete static_cast<CAiPathFinder*>(objectStorage);
}

/**
 * Address: 0x005AB900 (FUN_005AB900, Moho::CAiPathFinderTypeInfo::CtrRef)
 *
 * What it does:
 * Placement-constructs one `CAiPathFinder` object in caller-provided storage,
 * then returns its typed reflection reference.
 */
gpg::RRef CAiPathFinderTypeInfo::CtrRef(void* const objectStorage)
{
  auto* const pathFinder = static_cast<CAiPathFinder*>(objectStorage);
  if (pathFinder != nullptr) {
    new (pathFinder) CAiPathFinder();
  }

  gpg::RRef out{};
  (void)gpg::RRef_CAiPathFinder(&out, pathFinder);
  return out;
}

/**
 * Address: 0x005AB970 (FUN_005AB970, Moho::CAiPathFinderTypeInfo::Destruct)
 *
 * What it does:
 * Runs in-place destructor for one `CAiPathFinder` object without freeing
 * storage.
 */
void CAiPathFinderTypeInfo::Destruct(void* const objectStorage)
{
  auto* const pathFinder = static_cast<CAiPathFinder*>(objectStorage);
  if (pathFinder != nullptr) {
    pathFinder->~CAiPathFinder();
  }
}

/**
 * Address: 0x005AAB00 (FUN_005AAB00, ?Init@CAiPathFinderTypeInfo@Moho@@UAEXXZ)
 */
void CAiPathFinderTypeInfo::Init()
{
  size_ = sizeof(CAiPathFinder);
  (void)BindCAiPathFinderTypeInfoCallbacks(this);

  gpg::RType::Init();

  AddBaseByTypeInfo(this, typeid(IPathTraveler), 0x00);
  AddBaseByTypeInfo(this, typeid(Broadcaster), 0x0C);

  Finish();
}

/**
 * Address: 0x00BCCD50 (FUN_00BCCD50, register_CAiPathFinderTypeInfo)
 *
 * What it does:
 * Constructs/preregisters startup RTTI descriptor for `CAiPathFinder` and
 * installs process-exit cleanup.
 */
int moho::register_CAiPathFinderTypeInfo()
{
  (void)preregister_CAiPathFinderTypeInfo();
  return std::atexit(&cleanup_CAiPathFinderTypeInfo);
}

/**
 * Address: 0x00BCCDB0 (FUN_00BCCDB0, register_Rect2iListTypeInfo)
 *
 * What it does:
 * Constructs/preregisters reflected `std::list<gpg::Rect2<int>>` type-info
 * and installs process-exit cleanup.
 */
int moho::register_Rect2iListTypeInfo()
{
  (void)preregister_Rect2iListTypeInfo();
  return std::atexit(&cleanup_Rect2iListTypeInfo);
}

/**
 * Address: 0x00BCCDD0 (FUN_00BCCDD0, register_CAiPathFinderStartupStatsCleanup)
 *
 * What it does:
 * Installs process-exit cleanup for one startup-owned AI path-finder stats
 * slot.
 */
int moho::register_CAiPathFinderStartupStatsCleanup()
{
  return std::atexit(&cleanup_CAiPathFinderStartupStatsSlot);
}

namespace
{
  struct CAiPathFinderTypeInfoBootstrap
  {
    CAiPathFinderTypeInfoBootstrap()
    {
      (void)moho::register_CAiPathFinderTypeInfo();
      (void)moho::register_Rect2iListTypeInfo();
      (void)moho::register_CAiPathFinderStartupStatsCleanup();
    }
  };

  [[maybe_unused]] CAiPathFinderTypeInfoBootstrap gCAiPathFinderTypeInfoBootstrap;
} // namespace
