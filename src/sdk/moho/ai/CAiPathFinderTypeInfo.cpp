#include "moho/ai/CAiPathFinderTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <list>
#include <new>
#include <typeinfo>

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
  };

  static_assert(sizeof(Rect2iListTypeInfo) == 0x64, "Rect2iListTypeInfo size must be 0x64");

  alignas(CAiPathFinderTypeInfo) unsigned char gCAiPathFinderTypeInfoStorage[sizeof(CAiPathFinderTypeInfo)] = {};
  bool gCAiPathFinderTypeInfoConstructed = false;

  alignas(Rect2iListTypeInfo) unsigned char gRect2iListTypeInfoStorage[sizeof(Rect2iListTypeInfo)] = {};
  bool gRect2iListTypeInfoConstructed = false;
  msvc8::string gRect2iListTypeName;
  bool gRect2iListTypeNameCleanupRegistered = false;

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
      CAiPathFinder::sType = typeInfo;
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
    CAiPathFinder::sType = nullptr;
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
  newRefFunc_ = &CAiPathFinderTypeInfo::NewRef;
  ctorRefFunc_ = &CAiPathFinderTypeInfo::CtrRef;
  deleteFunc_ = &CAiPathFinderTypeInfo::Delete;
  dtrFunc_ = &CAiPathFinderTypeInfo::Destruct;

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
