#include "gpg/core/containers/FastVectorEntIdReflection.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/FastVectorUIntReflection.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"

namespace
{
  /**
   * Address: 0x00552E70 / 0x005535B0 / 0x00553630 family (shared
   * `Moho::EntId::sType` cache)
   *
   * What it does:
   * Name-keyed lazy resolver for the reflected `EntId` element type.
   * `Moho::EntId` is a plain `typedef int32_t EntId` in this recovered
   * source (moho/unit/core/IUnit.h), not a real class, so
   * `gpg::LookupRType(typeid(moho::EntId))` cannot recover the binary's
   * distinct `??_R0?AVEntId@Moho@@@8` class descriptor -- it would just
   * collide with `int`'s single `type_info`-keyed preregistration slot. This
   * mirrors `moho::preregister_EntIdTypeInfo`'s registration key exactly
   * (SSTITarget.cpp's `ResolveEntIdType()` is the same name-keyed fallback
   * for the same underlying-typedef problem).
   */
  [[nodiscard]] gpg::RType* CachedEntIdType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kEntIdTypeCandidates[] = {"EntId", "Moho::EntId", "int", "signed int"};
      for (const char* const candidate : kEntIdTypeCandidates) {
        if (!candidate) {
          continue;
        }

        cached = gpg::REF_FindTypeNamed(candidate);
        if (cached != nullptr) {
          break;
        }
      }

      if (!cached) {
        cached = gpg::LookupRType(typeid(int));
      }
    }

    return cached;
  }

  /**
   * Address: 0x005535B0 (FUN_005535B0, gpg::RFastVectorType_EntId::SerLoad)
   *
   * What it does:
   * Reads serialized lane count for one reflected `fastvector<Moho::EntId>`,
   * resizes storage with invalid-id sentinel fill (`0xF0000000`), then
   * deserializes each lane through `ReadArchive::Read`. The resize call
   * (`sub_553480`) is the exact same compiled body as
   * `gpg::FastVectorUIntResize` -- EntId storage is a flat dword array, so
   * the linker folds both `T` instantiations of the resize-fill routine
   * together.
   */
  void LoadFastVectorEntId(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    constexpr unsigned int kInvalidEntIdFill = 0xF0000000u;
    gpg::FastVectorUIntResize(&kInvalidEntIdFill, count, storage);

    gpg::RType* const entIdType = CachedEntIdType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    auto& view = gpg::AsFastVectorRuntimeView<unsigned int>(storage);
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(entIdType, view.ElementAtUnchecked(i), owner);
    }
  }

  /**
   * Address: 0x00553630 (FUN_00553630, gpg::RFastVectorType_EntId::SerSave)
   *
   * What it does:
   * Writes one reflected `fastvector<Moho::EntId>` payload as archive count
   * plus per-lane reflected `EntId` serialization.
   */
  void SaveFastVectorEntId(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<void*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<unsigned int>(storage);
    const unsigned int count = view.Data() ? static_cast<unsigned int>(view.Size()) : 0u;
    archive->WriteUInt(count);

    gpg::RType* const entIdType = CachedEntIdType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(entIdType, view.ElementAtUnchecked(i), owner);
    }
  }

  gpg::RFastVectorType<moho::EntId> gFastVectorEntIdType;

  /**
   * Address: 0x00BF4B70 (FUN_00BF4B70, cleanup_RFastVectorType_EntId)
   *
   * What it does:
   * Process-exit cleanup for the global `RFastVectorType<Moho::EntId>`
   * descriptor's dynamic field/base storage (the same generic `gpg::RType`
   * base-class teardown every `RFastVectorType<T>` specialization shares).
   */
  void cleanup_RFastVectorType_EntId()
  {
    gFastVectorEntIdType.fields_.clear();
    gFastVectorEntIdType.bases_.clear();
  }

  struct FastVectorEntIdReflectionBootstrap
  {
    FastVectorEntIdReflectionBootstrap()
    {
      gpg::register_RFastVectorType_EntId();
    }
  };

  [[maybe_unused]] FastVectorEntIdReflectionBootstrap gFastVectorEntIdReflectionBootstrap;
} // namespace

/**
 * Address: 0x00BC9D40 (FUN_00BC9D40, register_RFastVectorType_EntId)
 *
 * What it does:
 * Materializes startup reflection storage for `fastvector<Moho::EntId>` and
 * registers process-exit teardown. Reached from the CRT static-initializer
 * table (`__xc_a`) in the binary; recovered here as the constructor of the
 * file-local `FastVectorEntIdReflectionBootstrap` global, matching
 * `register_RFastVectorType_uint`'s own bootstrap pattern.
 */
void gpg::register_RFastVectorType_EntId()
{
  (void)gFastVectorEntIdType;
  (void)std::atexit(&cleanup_RFastVectorType_EntId);
}

/**
 * Address: 0x00553F50 (FUN_00553F50, gpg::RFastVectorType_EntId::RFastVectorType_EntId)
 */
gpg::RFastVectorType<moho::EntId>::RFastVectorType()
  : gpg::RType()
  , gpg::RIndexed()
{
  gpg::PreRegisterRType(typeid(gpg::fastvector<moho::EntId>), this);
}

/**
 * Address: 0x005540F0 (FUN_005540F0, gpg::RFastVectorType_EntId::dtr)
 */
gpg::RFastVectorType<moho::EntId>::~RFastVectorType() = default;

/**
 * Address: 0x00552E70 (FUN_00552E70, gpg::RFastVectorType_EntId::GetName)
 */
const char* gpg::RFastVectorType<moho::EntId>::GetName() const
{
  static msvc8::string sName;
  if (sName.empty()) {
    gpg::RType* const elementType = CachedEntIdType();
    const char* const elementName = elementType ? elementType->GetName() : "EntId";
    sName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "EntId");
  }
  return sName.c_str();
}

/**
 * Address: 0x00552F30 (FUN_00552F30, gpg::RFastVectorType_EntId::GetLexical)
 */
msvc8::string gpg::RFastVectorType<moho::EntId>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x00552FC0 (FUN_00552FC0, gpg::RFastVectorType_EntId::IsIndexed)
 */
const gpg::RIndexed* gpg::RFastVectorType<moho::EntId>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x00552F10 (FUN_00552F10, gpg::RFastVectorType_EntId::Init)
 */
void gpg::RFastVectorType<moho::EntId>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadFastVectorEntId;
  serSaveFunc_ = &SaveFastVectorEntId;
}

/**
 * Address: 0x00553010 (FUN_00553010, gpg::RFastVectorType_EntId::SubscriptIndex)
 *
 * What it does:
 * Builds one reflected element reference for `fastvector<Moho::EntId>[ind]`.
 * The retail body performs no bounds/null check before indexing (unlike the
 * `unsigned int` sibling), so this is left unconditional to match.
 */
gpg::RRef gpg::RFastVectorType<moho::EntId>::SubscriptIndex(void* obj, const int ind) const
{
  auto& view = gpg::AsFastVectorRuntimeView<unsigned int>(obj);
  gpg::RRef out{};
  gpg::RRef_EntId(&out, reinterpret_cast<std::int32_t*>(view.ElementAtUnchecked(static_cast<std::size_t>(ind))));
  return out;
}

/**
 * Address: 0x00552FD0 (FUN_00552FD0, gpg::RFastVectorType_EntId::GetCount)
 */
size_t gpg::RFastVectorType<moho::EntId>::GetCount(void* obj) const
{
  const auto& view = gpg::AsFastVectorRuntimeView<unsigned int>(obj);
  return view.Size();
}

/**
 * Address: 0x00552FE0 (FUN_00552FE0, gpg::RFastVectorType_EntId::SetCount)
 */
void gpg::RFastVectorType<moho::EntId>::SetCount(void* obj, const int count) const
{
  constexpr unsigned int kInvalidEntIdFill = 0xF0000000u;
  gpg::FastVectorUIntResize(&kInvalidEntIdFill, static_cast<unsigned int>(count), obj);
}
