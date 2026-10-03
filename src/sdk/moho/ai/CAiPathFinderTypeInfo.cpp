#include "legacy/containers/Vector.h"
#include "moho/ai/CAiPathFinderTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <list>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/RListType.h"
#include "moho/ai/CAiPathFinder.h"
#include "moho/misc/Stats.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF71E0 (FUN_00BF71E0, atexit destructor of the CAiPathFinderTypeInfo object)
   */
  [[nodiscard]] CAiPathFinderTypeInfo* AcquireCAiPathFinderTypeInfo()
  {
    static CAiPathFinderTypeInfo sInstance;
    return &sInstance;
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
    field.mFlags = 0;
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
   * Address: 0x005AAAA0 (FUN_005AAAA0, preregister_CAiPathFinderTypeInfo)
   *
   * What it does:
   * Constructs and preregisters startup RTTI descriptor for `CAiPathFinder`.
   */
  [[nodiscard]] gpg::RType* preregister_CAiPathFinderTypeInfo()
  {
    CAiPathFinderTypeInfo* const typeInfo = AcquireCAiPathFinderTypeInfo();
    gpg::PreRegisterRType(typeid(CAiPathFinder), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x005ABC00 (FUN_005ABC00, preregister_Rect2iListTypeInfo)
   * Address: 0x00BF72A0 (FUN_00BF72A0, atexit destructor of the list type object)
   *
   * What it does:
   * Constructs the `gpg::RListType<gpg::Rect2i>` static, which preregisters
   * it for `typeid(msvc8::list<gpg::Rect2i>)`, and returns it.
   *
   * `RListType<Rect2<int>>`, vtable 0x00E1C36C:
   *
   * Address: 0x005ABCA0 (FUN_005ABCA0 -- the implicit scalar deleting destructor.)
   * Address: 0x005AAFA0 (FUN_005AAFA0 -- `GetName`.)
   * Address: 0x00BF7270 (FUN_00BF7270 -- the atexit destructor of `GetName`'s name string.)
   * Address: 0x005AB060 (FUN_005AB060 -- `GetLexical`.)
   * Address: 0x005AB040 (FUN_005AB040 -- `Init`.)
   * Address: 0x005AB410 (FUN_005AB410 -- `SerLoad`. The binary zeroes the stack element first
   * (0x005AB44D..0x005AB459); `Rect2` stays a plain aggregate here, because `CUnitMotion` holds one in
   * an anonymous union, so its four words are uninitialised until `Read` writes all of them.)
   * Address: 0x005AB4C0 (FUN_005AB4C0 -- `SerSave`.)
   */
  [[nodiscard]] gpg::RType* preregister_Rect2iListTypeInfo()
  {
    static gpg::RListType<gpg::Rect2i> sInstance;
    return &sInstance;
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
  out = gpg::MakeRRef<moho::CAiPathFinder>(pathFinder);
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
  out = gpg::MakeRRef<moho::CAiPathFinder>(pathFinder);
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
 * Address: 0x005AB9F0 (FUN_005AB9F0, Moho::CAiPathFinderTypeInfo::AddBase_IPathTraveler)
 *
 * What it does:
 * Registers `IPathTraveler` as a reflected base at offset 0.
 */
void CAiPathFinderTypeInfo::AddBase_IPathTraveler(gpg::RType* const typeInfo)
{
  AddBaseByTypeInfo(typeInfo, typeid(IPathTraveler), 0x00);
}

/**
 * Address: 0x005ABA50 (FUN_005ABA50, Moho::CAiPathFinderTypeInfo::Addbase_Broadcaster_NavPath)
 *
 * What it does:
 * Registers the NavPath broadcaster as a reflected base at offset 0x0C - the
 * path finder's second base, after IPathTraveler at 0.
 */
void CAiPathFinderTypeInfo::Addbase_Broadcaster_NavPath(gpg::RType* const typeInfo)
{
  AddBaseByTypeInfo(typeInfo, typeid(Broadcaster<const SNavPath&>), gpg::BaseSubobjectOffset<CAiPathFinder, Broadcaster<const SNavPath&>>());
}

/**
 * Address: 0x005AAB00 (FUN_005AAB00, ?Init@CAiPathFinderTypeInfo@Moho@@UAEXXZ)
 */
void CAiPathFinderTypeInfo::Init()
{
  size_ = sizeof(CAiPathFinder);
  (void)BindCAiPathFinderTypeInfoCallbacks(this);

  gpg::RType::Init();

  AddBase_IPathTraveler(this);
  Addbase_Broadcaster_NavPath(this);

  Finish();
}

/**
 * Address: 0x00BCCD50 (FUN_00BCCD50, register_CAiPathFinderTypeInfo)
 *
 * What it does:
 * Constructs/preregisters startup RTTI descriptor for `CAiPathFinder`.
 */
void moho::register_CAiPathFinderTypeInfo()
{
  (void)preregister_CAiPathFinderTypeInfo();
}

/**
 * Address: 0x00BCCDB0 (FUN_00BCCDB0, register_Rect2iListTypeInfo)
 *
 * What it does:
 * Constructs/preregisters reflected `std::list<gpg::Rect2<int>>` type-info.
 */
void moho::register_Rect2iListTypeInfo()
{
  (void)preregister_Rect2iListTypeInfo();
}

namespace
{
  struct CAiPathFinderTypeInfoBootstrap
  {
    CAiPathFinderTypeInfoBootstrap()
    {
      moho::register_CAiPathFinderTypeInfo();
      moho::register_Rect2iListTypeInfo();
    }
  };

  [[maybe_unused]] CAiPathFinderTypeInfoBootstrap gCAiPathFinderTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CAiPathFinderTypeInfo_ef9477, moho::register_CAiPathFinderTypeInfo)
GPG_PREREGISTER_INIT(register_Rect2iListTypeInfo_ef9477, moho::register_Rect2iListTypeInfo)

GPG_PREREGISTER_INIT(AcquireCAiPathFinderTypeInfo_ef9477, AcquireCAiPathFinderTypeInfo)
