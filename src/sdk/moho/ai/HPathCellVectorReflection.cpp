#include "moho/ai/HPathCellVectorReflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>
#include <utility>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using HPathCellVector = msvc8::vector<moho::HPathCell>;
  using HPathCellVectorType = gpg::RVectorType<moho::HPathCell>;

  // Startup-owned reflection descriptor storage (binary global stru_1106C10 @
  // 0x01106C10). Constructed lazily by the registrar; the base gpg::RType ctor
  // plus the specialization vtable install reproduce the binary's inline setup.
  alignas(HPathCellVectorType) unsigned char gHPathCellVectorTypeStorage[sizeof(HPathCellVectorType)];
  bool gHPathCellVectorTypeConstructed = false;

  // Cached "vector<HPathCell>" lexical name (binary global stru_10C7FBC).
  msvc8::string gHPathCellVectorTypeName;
  bool gHPathCellVectorTypeNameCleanupRegistered = false;

  [[nodiscard]] HPathCellVectorType* AcquireHPathCellVectorType()
  {
    if (!gHPathCellVectorTypeConstructed) {
      new (gHPathCellVectorTypeStorage) HPathCellVectorType();
      gHPathCellVectorTypeConstructed = true;
    }
    return reinterpret_cast<HPathCellVectorType*>(gHPathCellVectorTypeStorage);
  }

  [[nodiscard]] HPathCellVectorType* PeekHPathCellVectorType() noexcept
  {
    if (!gHPathCellVectorTypeConstructed) {
      return nullptr;
    }
    return reinterpret_cast<HPathCellVectorType*>(gHPathCellVectorTypeStorage);
  }

  // Lazily resolves and caches the element RType* (binary Moho::HPathCell::sType).
  [[nodiscard]] gpg::RType* ResolveHPathCellType()
  {
    gpg::RType* type = moho::HPathCell::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::HPathCell));
      moho::HPathCell::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00C01800 (FUN_00C01800, sub_C01800)
   *
   * What it does:
   * Releases cached lexical-name storage for `RVectorType_HPathCell`.
   */
  void cleanup_HPathCellVectorTypeName()
  {
    gHPathCellVectorTypeName = msvc8::string{};
    gHPathCellVectorTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x00763760 (FUN_00763760, sub_763760)
   *
   * What it does:
   * Reads the element count, then reads that many `moho::HPathCell` values
   * (each via `ReadArchive::Read` with an empty owner reference) into a fresh
   * temporary vector and moves it into the destination `vector<HPathCell>`,
   * releasing the destination's old storage. Bound as `serLoadFunc_`;
   * `version`/`ownerRef` are unused by the binary body.
   */
  void LoadHPathCellVector(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const storage = reinterpret_cast<HPathCellVector*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    HPathCellVector loaded{};
    loaded.reserve(static_cast<std::size_t>(count));

    gpg::RType* const elementType = ResolveHPathCellType();
    const gpg::RRef emptyOwner{};
    for (unsigned int i = 0; i < count; ++i) {
      moho::HPathCell element{};
      archive->Read(elementType, &element, emptyOwner);
      loaded.push_back(element);
    }

    *storage = std::move(loaded);
  }

  /**
   * Address: 0x00763850 (FUN_00763850, sub_763850)
   *
   * What it does:
   * Writes the element count, then writes each `moho::HPathCell` value in place
   * (via `WriteArchive::Write`, forwarding the caller's owner reference). Bound
   * as `serSaveFunc_`.
   */
  void SaveHPathCellVector(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<const HPathCellVector*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    const unsigned int count = static_cast<unsigned int>(storage->size());
    archive->WriteUInt(count);

    gpg::RType* const elementType = ResolveHPathCellType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, &(*storage)[static_cast<std::size_t>(i)], owner);
    }
  }

  /**
   * Address: 0x00763AC0 (FUN_00763AC0, sub_763AC0)
   *
   * What it does:
   * Adjusts one `vector<HPathCell>` length to `requestedCount`, zero-filling
   * growth via one caller-provided fill lane and truncating shrink.
   */
  [[nodiscard]] std::size_t ResizeHPathCellVector(
    HPathCellVector& storage,
    const std::size_t requestedCount,
    const moho::HPathCell& fillValue
  )
  {
    const std::size_t currentCount = storage.size();
    if (currentCount < requestedCount) {
      storage.resize(requestedCount, fillValue);
      return requestedCount;
    }

    if (requestedCount < currentCount) {
      storage.resize(requestedCount);
    }

    return requestedCount;
  }

  /**
   * Address: 0x00C018F0 (FUN_00C018F0, sub_C018F0)
   *
   * What it does:
   * Tears down `vector<HPathCell>` reflection storage at process exit (frees the
   * RType base's field/base lanes and restores the RObject vftable, exactly as
   * the specialization's destructor does).
   */
  void cleanup_HPathCellVectorType()
  {
    HPathCellVectorType* const type = PeekHPathCellVectorType();
    if (type == nullptr) {
      return;
    }

    type->~HPathCellVectorType();
    gHPathCellVectorTypeConstructed = false;
  }

  struct HPathCellVectorReflectionBootstrap
  {
    HPathCellVectorReflectionBootstrap()
    {
      (void)moho::register_HPathCellVectorType_AtExit();
    }
  };

  HPathCellVectorReflectionBootstrap gHPathCellVectorReflectionBootstrap;
} // namespace

namespace moho
{
  gpg::RType* HPathCell::sType = nullptr;
} // namespace moho

/**
 * Address: 0x007633E0 (FUN_007633E0, gpg::RVectorType_HPathCell::GetName)
 *
 * What it does:
 * Builds and caches `"vector<HPathCell>"` from the element type name, arming a
 * one-shot `atexit` teardown for the cached string.
 */
const char* gpg::RVectorType<moho::HPathCell>::GetName() const
{
  if (gHPathCellVectorTypeName.empty()) {
    const gpg::RType* const elementType = ResolveHPathCellType();
    const char* const elementName = elementType ? elementType->GetName() : "HPathCell";
    gHPathCellVectorTypeName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "HPathCell");

    if (!gHPathCellVectorTypeNameCleanupRegistered) {
      gHPathCellVectorTypeNameCleanupRegistered = true;
      (void)std::atexit(&cleanup_HPathCellVectorTypeName);
    }
  }

  return gHPathCellVectorTypeName.c_str();
}

/**
 * Address: 0x007634A0 (FUN_007634A0, gpg::RVectorType_HPathCell::GetLexical)
 *
 * What it does:
 * Renders `"<base RType lexical>, size=<count>"`.
 */
msvc8::string gpg::RVectorType<moho::HPathCell>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x00763530 (FUN_00763530, gpg::RVectorType_HPathCell::IsIndexed)
 *
 * What it does:
 * Returns the `RIndexed` subobject (`this ? this+0x64 : nullptr`). A vector is
 * indexed but not a pointer, so only slot 6 is overridden.
 */
const gpg::RIndexed* gpg::RVectorType<moho::HPathCell>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x00763480 (FUN_00763480, gpg::RVectorType_HPathCell::Init)
 *
 * What it does:
 * Records the container byte-size (0x10 = `sizeof(msvc8::vector<HPathCell>)`),
 * version 1, and installs the element (de)serialize callbacks.
 */
void gpg::RVectorType<moho::HPathCell>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadHPathCellVector;
  serSaveFunc_ = &SaveHPathCellVector;
}

/**
 * Address: 0x00763580 (FUN_00763580, gpg::RVectorType_HPathCell::SubscriptIndex)
 *
 * What it does:
 * Wraps `&vec[ind]` (a `moho::HPathCell*` slot inside the vector storage) as one
 * `gpg::RRef_HPathCell` reference.
 */
gpg::RRef gpg::RVectorType<moho::HPathCell>::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<HPathCellVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(ind >= 0);

  gpg::RRef out{};
  gpg::RRef_HPathCell(&out, nullptr);
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  gpg::RRef_HPathCell(&out, &(*storage)[static_cast<std::size_t>(ind)]);
  return out;
}

/**
 * Address: 0x00763540 (FUN_00763540, gpg::RVectorType_HPathCell::GetCount)
 *
 * What it does:
 * Returns the element count (`(_Mylast - _Myfirst) / 4`), or 0 when unallocated.
 */
size_t gpg::RVectorType<moho::HPathCell>::GetCount(void* const obj) const
{
  if (!obj) {
    return 0u;
  }

  const auto& view = msvc8::AsVectorRuntimeView(*static_cast<const HPathCellVector*>(obj));
  if (!view.begin) {
    return 0u;
  }

  return static_cast<std::size_t>(view.end - view.begin);
}

/**
 * Address: 0x00763560 (FUN_00763560, gpg::RVectorType_HPathCell::SetCount)
 *
 * What it does:
 * Resizes the underlying `vector<HPathCell>` storage to `count`, zero-filling
 * any growth.
 */
void gpg::RVectorType<moho::HPathCell>::SetCount(void* const obj, const int count) const
{
  auto* const storage = static_cast<HPathCellVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  const moho::HPathCell zeroFill{};
  (void)ResizeHPathCellVector(*storage, static_cast<std::size_t>(count), zeroFill);
}

/**
 * Address: 0x00763EE0 (FUN_00763EE0, sub_763EE0)
 *
 * What it does:
 * Constructs (base `gpg::RType` ctor + specialization vtable install, produced
 * here by the descriptor's construction) and preregisters the startup-owned
 * `std::vector<moho::HPathCell>` reflection descriptor.
 */
gpg::RType* moho::register_HPathCellVectorType_00()
{
  HPathCellVectorType* const type = AcquireHPathCellVectorType();
  gpg::PreRegisterRType(typeid(msvc8::vector<moho::HPathCell>), type);
  return type;
}

/**
 * Address: 0x00BDC6D0 (FUN_00BDC6D0, sub_BDC6D0)
 *
 * What it does:
 * Registers `vector<HPathCell>` reflection and installs process-exit teardown
 * via `atexit`. In the binary this is the static-init aggregator that calls the
 * registrar; modeled at source level by the `HPathCellVectorReflectionBootstrap`
 * static-init instance.
 */
int moho::register_HPathCellVectorType_AtExit()
{
  (void)register_HPathCellVectorType_00();
  return std::atexit(&cleanup_HPathCellVectorType);
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_HPathCellVectorType_00_63aed0, moho::register_HPathCellVectorType_00)
