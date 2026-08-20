#include "gpg/core/containers/FastVectorSOCellPosReflection.h"

#include <cstddef>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/FastVectorUIntReflection.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"

namespace
{
  /**
   * Address: 0x00553050 / 0x005536A0 / 0x00553720 family (shared
   * `Moho::SOCellPos::sType` cache)
   *
   * What it does:
   * Reads/populates `moho::SOCellPos::sType` directly, matching the binary's
   * shared static-cache slot exactly (`moho::SOCellPos` is a real recovered
   * struct, unlike `Moho::EntId`, so no name-keyed workaround is needed
   * here). Mirrors the already-established idiom in
   * `CUnitMeleeAttackTargetTask.cpp`'s own file-local `CachedSOCellPosType()`.
   */
  [[nodiscard]] gpg::RType* CachedSOCellPosType()
  {
    gpg::RType* type = moho::SOCellPos::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SOCellPos));
      moho::SOCellPos::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x005536A0 (FUN_005536A0, gpg::RFastVectorType_SOCellPos::SerLoad)
   *
   * What it does:
   * Reads count for one reflected `fastvector<Moho::SOCellPos>`, resizes with
   * invalid-cell sentinel fill (`x = z = -32768`), then deserializes each
   * lane through `ReadArchive::Read`. The resize call (`sub_5532F0`) is the
   * same compiled body `SetCount` and `Moho::CDecoder::DecodeCells` dispatch
   * through.
   */
  void LoadFastVectorSOCellPos(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    constexpr moho::SOCellPos fill{-32768, -32768};
    gpg::FastVectorSOCellPosResize(&fill, count, storage);

    gpg::RType* const soCellPosType = CachedSOCellPosType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    auto& view = gpg::AsFastVectorRuntimeView<moho::SOCellPos>(storage);
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(soCellPosType, view.ElementAtUnchecked(i), owner);
    }
  }

  /**
   * Address: 0x00553720 (FUN_00553720, gpg::RFastVectorType_SOCellPos::SerSave)
   *
   * What it does:
   * Writes one reflected `fastvector<Moho::SOCellPos>` payload as archive
   * count plus per-lane reflected `SOCellPos` serialization.
   */
  void SaveFastVectorSOCellPos(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::SOCellPos>(storage);
    const unsigned int count = view.Data() ? static_cast<unsigned int>(view.Size()) : 0u;
    archive->WriteUInt(count);

    gpg::RType* const soCellPosType = CachedSOCellPosType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(soCellPosType, view.ElementAtUnchecked(i), owner);
    }
  }

  gpg::RFastVectorType<moho::SOCellPos> gFastVectorSOCellPosType;

  /**
   * Address: 0x00BF4B10 (FUN_00BF4B10, cleanup_RFastVectorType_SOCellPos)
   *
   * What it does:
   * Process-exit cleanup for the global `RFastVectorType<Moho::SOCellPos>`
   * descriptor's dynamic field/base storage (the same generic `gpg::RType`
   * base-class teardown every `RFastVectorType<T>` specialization shares).
   */
  void cleanup_RFastVectorType_SOCellPos()
  {
    gFastVectorSOCellPosType.fields_.clear();
    gFastVectorSOCellPosType.bases_.clear();
  }

  struct FastVectorSOCellPosReflectionBootstrap
  {
    FastVectorSOCellPosReflectionBootstrap()
    {
      gpg::register_RFastVectorType_SOCellPos();
    }
  };

  [[maybe_unused]] FastVectorSOCellPosReflectionBootstrap gFastVectorSOCellPosReflectionBootstrap;
} // namespace

/**
 * Address: 0x00BC9D60 (FUN_00BC9D60, register_RFastVectorType_SOCellPos)
 *
 * What it does:
 * Materializes startup reflection storage for `fastvector<Moho::SOCellPos>`
 * and registers process-exit teardown. Reached from the CRT static-initializer
 * table (`__xc_a`) in the binary; recovered here as the constructor of the
 * file-local `FastVectorSOCellPosReflectionBootstrap` global, matching
 * `register_RFastVectorType_uint`/`register_RFastVectorType_EntId`'s own
 * bootstrap pattern.
 */
void gpg::register_RFastVectorType_SOCellPos()
{
  (void)gFastVectorSOCellPosType;
  (void)std::atexit(&cleanup_RFastVectorType_SOCellPos);
}

/**
 * Address: 0x00553FC0 (FUN_00553FC0, gpg::RFastVectorType_SOCellPos::RFastVectorType_SOCellPos)
 */
gpg::RFastVectorType<moho::SOCellPos>::RFastVectorType()
  : gpg::RType()
  , gpg::RIndexed()
{
  gpg::PreRegisterRType(typeid(gpg::fastvector<moho::SOCellPos>), this);
}

/**
 * Address: 0x00554150 (FUN_00554150, gpg::RFastVectorType_SOCellPos::dtr)
 */
gpg::RFastVectorType<moho::SOCellPos>::~RFastVectorType() = default;

/**
 * Address: 0x00553050 (FUN_00553050, gpg::RFastVectorType_SOCellPos::GetName)
 */
const char* gpg::RFastVectorType<moho::SOCellPos>::GetName() const
{
  static msvc8::string sName;
  if (sName.empty()) {
    gpg::RType* const elementType = CachedSOCellPosType();
    const char* const elementName = elementType ? elementType->GetName() : "SOCellPos";
    sName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "SOCellPos");
  }
  return sName.c_str();
}

/**
 * Address: 0x00553110 (FUN_00553110, gpg::RFastVectorType_SOCellPos::GetLexical)
 */
msvc8::string gpg::RFastVectorType<moho::SOCellPos>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x005531A0 (FUN_005531A0, gpg::RFastVectorType_SOCellPos::IsIndexed)
 */
const gpg::RIndexed* gpg::RFastVectorType<moho::SOCellPos>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x005530F0 (FUN_005530F0, gpg::RFastVectorType_SOCellPos::Init)
 */
void gpg::RFastVectorType<moho::SOCellPos>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadFastVectorSOCellPos;
  serSaveFunc_ = &SaveFastVectorSOCellPos;
}

/**
 * Address: 0x005531F0 (FUN_005531F0, gpg::RFastVectorType_SOCellPos::SubscriptIndex)
 *
 * What it does:
 * Builds one reflected element reference for
 * `fastvector<Moho::SOCellPos>[ind]`. The retail body performs no
 * bounds/null check before indexing (matching the `EntId` sibling), so this
 * is left unconditional to match.
 */
gpg::RRef gpg::RFastVectorType<moho::SOCellPos>::SubscriptIndex(void* obj, const int ind) const
{
  auto& view = gpg::AsFastVectorRuntimeView<moho::SOCellPos>(obj);
  gpg::RRef out{};
  gpg::RRef_SOCellPos(&out, view.ElementAtUnchecked(static_cast<std::size_t>(ind)));
  return out;
}

/**
 * Address: 0x005531B0 (FUN_005531B0, gpg::RFastVectorType_SOCellPos::GetCount)
 */
size_t gpg::RFastVectorType<moho::SOCellPos>::GetCount(void* obj) const
{
  const auto& view = gpg::AsFastVectorRuntimeView<moho::SOCellPos>(obj);
  return view.Size();
}

/**
 * Address: 0x005531C0 (FUN_005531C0, gpg::RFastVectorType_SOCellPos::SetCount)
 */
void gpg::RFastVectorType<moho::SOCellPos>::SetCount(void* obj, const int count) const
{
  constexpr moho::SOCellPos fill{-32768, -32768};
  gpg::FastVectorSOCellPosResize(&fill, static_cast<unsigned int>(count), obj);
}
