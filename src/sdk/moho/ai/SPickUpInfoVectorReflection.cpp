#include "moho/ai/SPickUpInfoVectorReflection.h"

#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/ai/SPickUpInfo.h"

namespace
{
  // The `vector<SPickUpInfo>` backing store is an intrusive-weak vector:
  // each 12-byte element is one `SPickUpInfo` (WeakPtr<Unit> @+0x00, float @+0x08).
  // `SPickUpInfo`'s non-trivial copy-ctor / copy-assign / dtor perform the
  // intrusive owner-chain relinks that the binary open-codes inside SerLoad's
  // per-element copy-in and destroy-old-storage loops, so a typed
  // `msvc8::vector<SPickUpInfo>` reproduces the binary's grow/relink semantics
  // (grow FUN_006275D0 dispatches to gpg::CopyWeakPtrFloatPayloadRangeStdOrder).
  using SPickUpInfoVector = msvc8::vector<moho::SPickUpInfo>;

  alignas(gpg::RVectorType_SPickUpInfo) unsigned char
    gSPickUpInfoVectorTypeStorage[sizeof(gpg::RVectorType_SPickUpInfo)];
  bool gSPickUpInfoVectorTypeConstructed = false;

  [[nodiscard]] gpg::RType* CachedSPickUpInfoType()
  {
    gpg::RType* type = moho::SPickUpInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SPickUpInfo));
      moho::SPickUpInfo::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x006275D0 (FUN_006275D0)
   *
   * IDA signature:
   * unsigned int __thiscall sub_6275D0(unsigned int *this, unsigned int a2);
   *
   * What it does:
   * Ensures one intrusive-weak `vector<SPickUpInfo>` can hold at least the
   * requested number of elements before a reflected load fills it. Growth
   * reallocates and relinks each existing weak node into its owner chain (the
   * binary dispatches the copy-with-relink to
   * `gpg::CopyWeakPtrFloatPayloadRangeStdOrder` = FUN_0062A400).
   */
  void EnsureSPickUpInfoLoadCapacity(SPickUpInfoVector& storage, const std::size_t requiredCount)
  {
    // 0x006275F1: cmp edi, 15555555h  (0x15555555 = 0x40000000 / sizeof(SPickUpInfo))
    if (requiredCount > 0x15555555u) {
      throw std::bad_alloc{};
    }

    if (requiredCount <= storage.capacity()) {
      return;
    }

    storage.reserve(requiredCount);
  }

  /**
   * Address: 0x00626E10 (FUN_00626E10)
   *
   * IDA signature:
   * int __usercall sub_626E10@<eax>(int element@<eax>, _DWORD *vector@<ecx>);
   *
   * What it does:
   * Appends one deserialized `SPickUpInfo` element to the load vector. When
   * spare capacity exists it copy-constructs the element into the tail slot
   * (relinking its weak-unit node), otherwise it delegates to the reallocating
   * single-insert grow path (FUN_00627340). Preserves the binary's typed
   * element copy-in relink of the intrusive `WeakPtr<Unit>` owner chain.
   */
  void PushBackSPickUpInfoWithRelink(SPickUpInfoVector& storage, const moho::SPickUpInfo& element)
  {
    storage.push_back(element);
  }

  [[nodiscard]] gpg::RVectorType_SPickUpInfo& AcquireSPickUpInfoVectorType()
  {
    if (!gSPickUpInfoVectorTypeConstructed) {
      new (gSPickUpInfoVectorTypeStorage) gpg::RVectorType_SPickUpInfo();
      gSPickUpInfoVectorTypeConstructed = true;
    }

    return *reinterpret_cast<gpg::RVectorType_SPickUpInfo*>(gSPickUpInfoVectorTypeStorage);
  }

  void cleanup_VectorSPickUpInfoTypeStorage()
  {
    if (!gSPickUpInfoVectorTypeConstructed) {
      return;
    }

    AcquireSPickUpInfoVectorType().~RVectorType_SPickUpInfo();
    gSPickUpInfoVectorTypeConstructed = false;
  }

  struct SPickUpInfoVectorReflectionBootstrap
  {
    SPickUpInfoVectorReflectionBootstrap()
    {
      (void)moho::register_VectorSPickUpInfoTypeAtexit();
    }
  };

  SPickUpInfoVectorReflectionBootstrap gSPickUpInfoVectorReflectionBootstrap;
} // namespace

/**
 * Address: 0x00626BA0 (FUN_00626BA0, gpg::RVectorType_SPickUpInfo::GetName)
 *
 * What it does:
 * Builds and caches lexical reflection name `vector<element>` for
 * `vector<moho::SPickUpInfo>`.
 */
const char* gpg::RVectorType_SPickUpInfo::GetName() const
{
  static msvc8::string sName{};
  if (sName.empty()) {
    const gpg::RType* const elementType = CachedSPickUpInfoType();
    const char* const elementName = elementType ? elementType->GetName() : "SPickUpInfo";
    sName = gpg::STR_Printf("vector<%s>", elementName);
  }
  return sName.c_str();
}

/**
 * Address: 0x00626C60 (FUN_00626C60, gpg::RVectorType_SPickUpInfo::GetLexical)
 *
 * What it does:
 * Returns base lexical text plus reflected vector size for one
 * `vector<moho::SPickUpInfo>` instance.
 */
msvc8::string gpg::RVectorType_SPickUpInfo::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x00626CF0 (FUN_00626CF0, gpg::RVectorType_SPickUpInfo::IsIndexed)
 */
const gpg::RIndexed* gpg::RVectorType_SPickUpInfo::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x00626C40 (FUN_00626C40, gpg::RVectorType_SPickUpInfo::Init)
 *
 * IDA signature:
 * void __thiscall gpg::RVectorType_SPickUpInfo::Init(gpg::RType *this);
 *
 * What it does:
 * Records the element byte-size (16 = sizeof(vector<SPickUpInfo>)), version 1,
 * and installs the reflected element (de)serialize callbacks
 * (`serLoadFunc_ = &SerLoad`, `serSaveFunc_ = &SerSave`). This fn-ptr install
 * is the source-level invocation that keeps SerLoad/SerSave live in the binary.
 */
void gpg::RVectorType_SPickUpInfo::Init()
{
  size_ = sizeof(SPickUpInfoVector);
  version_ = 1;
  serLoadFunc_ = &RVectorType_SPickUpInfo::SerLoad;
  serSaveFunc_ = &RVectorType_SPickUpInfo::SerSave;
}

/**
 * Address: 0x006270E0 (FUN_006270E0, gpg::RVectorType_SPickUpInfo::SerLoad)
 *
 * What it does:
 * Reads the element count, grows one staging vector, then reads each
 * `SPickUpInfo` and appends it (copy-in relinks its intrusive `WeakPtr<Unit>`
 * owner back-pointer). Move-assigns the staged vector over the destination; the
 * destroyed old-storage elements unlink themselves from their owner chains
 * (binary tail loop at loc_6271D0..loc_627217).
 */
void gpg::RVectorType_SPickUpInfo::SerLoad(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const storage = reinterpret_cast<SPickUpInfoVector*>(objectPtr);

  unsigned int count = 0u;
  archive->ReadUInt(&count);

  SPickUpInfoVector loaded{};
  EnsureSPickUpInfoLoadCapacity(loaded, static_cast<std::size_t>(count));

  gpg::RType* const elementType = CachedSPickUpInfoType();
  for (unsigned int i = 0u; i < count; ++i) {
    // The temporary element is Read into first (which links its weak-unit node
    // into the owner chain), then appended (relinking the stored copy). The
    // temporary's destruction unlinks it, matching the binary's inline relink
    // at loc_6271A2.
    moho::SPickUpInfo element{};
    gpg::RRef owner{};
    if (elementType) {
      archive->Read(elementType, &element, owner);
    }
    PushBackSPickUpInfoWithRelink(loaded, element);
  }

  *storage = std::move(loaded);
}

/**
 * Address: 0x00627240 (FUN_00627240, gpg::RVectorType_SPickUpInfo::SerSave)
 *
 * What it does:
 * Writes the vector element count, then serializes each `SPickUpInfo` payload
 * lane with reflected `WriteArchive::Write` (element stride 12).
 */
void gpg::RVectorType_SPickUpInfo::SerSave(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  if (!archive) {
    return;
  }

  const auto* const storage = reinterpret_cast<const SPickUpInfoVector*>(objectPtr);
  const unsigned int count = storage ? static_cast<unsigned int>(storage->size()) : 0u;
  archive->WriteUInt(count);

  if (!storage || count == 0u) {
    return;
  }

  gpg::RType* const elementType = CachedSPickUpInfoType();
  if (!elementType) {
    return;
  }

  const gpg::RRef emptyOwner{};
  const gpg::RRef& effectiveOwner = ownerRef ? *ownerRef : emptyOwner;
  for (const moho::SPickUpInfo& element : *storage) {
    archive->Write(elementType, &element, effectiveOwner);
  }
}

/**
 * Address: 0x00626D60 (FUN_00626D60, gpg::RVectorType_SPickUpInfo::SubscriptIndex)
 *
 * What it does:
 * Wraps `&vec[ind]` (a `moho::SPickUpInfo*` slot at stride 12) as one
 * `gpg::RRef_SPickUpInfo` reference.
 */
gpg::RRef gpg::RVectorType_SPickUpInfo::SubscriptIndex(void* const obj, const int ind) const
{
  gpg::RRef out{};

  auto* const storage = static_cast<SPickUpInfoVector*>(obj);
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  gpg::RRef_SPickUpInfo(&out, &(*storage)[static_cast<std::size_t>(ind)]);
  return out;
}

/**
 * Address: 0x00626D00 (FUN_00626D00, gpg::RVectorType_SPickUpInfo::GetCount)
 *
 * What it does:
 * Returns the vector element count `(last_ - first_) / sizeof(SPickUpInfo)`.
 */
size_t gpg::RVectorType_SPickUpInfo::GetCount(void* const obj) const
{
  const auto* const storage = static_cast<const SPickUpInfoVector*>(obj);
  return storage ? storage->size() : 0u;
}

/**
 * Address: 0x00626D30 (FUN_00626D30, gpg::RVectorType_SPickUpInfo::SetCount)
 *
 * What it does:
 * Resizes the underlying `vector<SPickUpInfo>` storage to `count` (grow-fills
 * or erase-shrinks through FUN_006276F0).
 */
void gpg::RVectorType_SPickUpInfo::SetCount(void* const obj, const int count) const
{
  if (!obj || count < 0) {
    return;
  }

  auto* const storage = static_cast<SPickUpInfoVector*>(obj);
  storage->resize(static_cast<std::size_t>(count));
}

/**
 * Address: 0x00628350 (FUN_00628350, preregister_VectorSPickUpInfoType)
 *
 * IDA signature:
 * gpg::RType *sub_628350();
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for the intrusive-weak
 * `vector<moho::SPickUpInfo>` reflected descriptor global and preregisters it
 * under `typeid(vector<moho::SPickUpInfo>)`.
 */
gpg::RType* moho::preregister_VectorSPickUpInfoType()
{
  auto* const typeInfo = &AcquireSPickUpInfoVectorType();
  gpg::PreRegisterRType(typeid(SPickUpInfoVector), typeInfo);
  return typeInfo;
}

/**
 * Address: 0x00BD1D50 (FUN_00BD1D50, CRT static-init bootstrap thunk)
 *
 * IDA signature:
 * int sub_BD1D50();  // { sub_628350(); return atexit(sub_BFA6A0); }
 *
 * What it does:
 * Runs the vector<SPickUpInfo> preregistration at process static-init and
 * registers the descriptor teardown with `atexit`. This self-roots the family
 * via the CRT static-init array (the db-note edge into CUnitLoadUnits ctor is
 * a phantom edge — the real runtime consumers look the type up by typeid).
 */
int moho::register_VectorSPickUpInfoTypeAtexit()
{
  (void)preregister_VectorSPickUpInfoType();
  return std::atexit(&cleanup_VectorSPickUpInfoTypeStorage);
}
