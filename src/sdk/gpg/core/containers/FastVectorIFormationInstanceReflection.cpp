#include "gpg/core/containers/FastVectorIFormationInstanceReflection.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/IFormationInstanceCountedPtrReflection.h"

namespace
{
  msvc8::string gFormationInstancePtrFastVectorTypeName;
  bool gFormationInstancePtrFastVectorTypeNameCleanupRegistered = false;

  /**
   * Address: 0x00BF68C0 (FUN_00BF68C0, sub_BF68C0)
   *
   * What it does:
   * Process-exit cleanup for `RFastVectorType<Moho::IFormationInstance*>::GetName`'s
   * cached display-name string.
   */
  void CleanupFormationInstancePtrFastVectorTypeName()
  {
    gFormationInstancePtrFastVectorTypeName = msvc8::string{};
    gFormationInstancePtrFastVectorTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x0059CF00 (FUN_0059CF00, gpg::RFastVectorType_IFormationInstance_P::SerLoad)
   *
   * What it does:
   * Reads the serialized lane count for one reflected
   * `fastvector<Moho::IFormationInstance*>`, resizes storage with a null-pointer
   * fill, then deserializes each tracked pointer lane through
   * `ReadArchive::ReadPointer_IFormationInstance`. The resize call
   * (`FUN_0059CE20`) is a separate compiler-emitted inline clone of
   * `gpg::FastVectorRuntimeResizeFill` specialized for 4-byte pointer
   * elements -- see `FastVector.h`'s `Resize()` citation, which documents the
   * same address for this exact specialization.
   */
  void LoadFastVectorIFormationInstance(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(objectPtr != 0);
    if (!archive || objectPtr == 0) {
      return;
    }

    auto& vec = *reinterpret_cast<gpg::fastvector<moho::IFormationInstance*>*>(objectPtr);

    unsigned int count = 0;
    archive->ReadUInt(&count);

    vec.Resize(count);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->ReadPointer_IFormationInstance(&vec[i], &owner);
    }
  }

  /**
   * Address: 0x0059CF60 (FUN_0059CF60, gpg::RFastVectorType_IFormationInstance_P::SerSave)
   *
   * What it does:
   * Writes one reflected `fastvector<Moho::IFormationInstance*>` payload as an
   * archive count followed by per-lane `unowned` tracked-pointer writes built
   * from `gpg::RRef_IFormationInstance`.
   */
  void SaveFastVectorIFormationInstance(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(objectPtr != 0);
    if (!archive || objectPtr == 0) {
      return;
    }

    const auto& vec = *reinterpret_cast<const gpg::fastvector<moho::IFormationInstance*>*>(objectPtr);

    const unsigned int count = static_cast<unsigned int>(vec.size());
    archive->WriteUInt(count);

    for (unsigned int i = 0; i < count; ++i) {
      gpg::RRef ref{};
      gpg::RRef_IFormationInstance(&ref, vec[i]);
      gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    }
  }

  gpg::RFastVectorType<moho::IFormationInstance*> gFastVectorIFormationInstancePtrType;

  /**
   * Address: 0x00BF6980 (FUN_00BF6980, cleanup_RFastVectorType_IFormationInstance)
   *
   * What it does:
   * Process-exit cleanup for the global `RFastVectorType<Moho::IFormationInstance*>`
   * descriptor's dynamic field/base storage (the same generic `gpg::RType`
   * base-class teardown every `RFastVectorType<T>` specialization shares).
   */
  void cleanup_RFastVectorType_IFormationInstance()
  {
    gFastVectorIFormationInstancePtrType.fields_.clear();
    gFastVectorIFormationInstancePtrType.bases_.clear();
  }

  struct FastVectorIFormationInstanceReflectionBootstrap
  {
    FastVectorIFormationInstanceReflectionBootstrap()
    {
      gpg::register_RFastVectorType_IFormationInstance();
    }
  };

  [[maybe_unused]] FastVectorIFormationInstanceReflectionBootstrap gFastVectorIFormationInstanceReflectionBootstrap;
} // namespace

/**
 * Address: 0x00BCC210 (FUN_00BCC210, register_RFastVectorType_IFormationInstance)
 *
 * What it does:
 * Materializes startup reflection storage for `fastvector<Moho::IFormationInstance*>`
 * and registers process-exit teardown. Reached from the CRT static-initializer
 * table (`__xc_a`) in the binary; recovered here as the constructor of the
 * file-local `FastVectorIFormationInstanceReflectionBootstrap` global, matching
 * `register_RFastVectorType_EntId`'s own bootstrap pattern.
 */
void gpg::register_RFastVectorType_IFormationInstance()
{
  (void)gFastVectorIFormationInstancePtrType;
  (void)std::atexit(&cleanup_RFastVectorType_IFormationInstance);
}

/**
 * Address: 0x0059DED0 (FUN_0059DED0, gpg::RFastVectorType_IFormationInstance_P::RFastVectorType_IFormationInstance_P)
 */
gpg::RFastVectorType<moho::IFormationInstance*>::RFastVectorType()
  : gpg::RType()
  , gpg::RIndexed()
{
  gpg::PreRegisterRType(typeid(gpg::fastvector<moho::IFormationInstance*>), this);
}

/**
 * Address: 0x0059DFA0 (FUN_0059DFA0, gpg::RFastVectorType_IFormationInstance_P::dtr)
 *
 * What it does:
 * Standard MSVC scalar-deleting-destructor glue: frees `fields_`/`bases_`
 * heap storage, resets the vtable lane to `RObject`, and conditionally frees
 * `this`. All of that is already performed by the `gpg::RType` base
 * destructor chain, so the natural source form is a defaulted destructor --
 * see RULE ONE in CLAUDE.md and `RFastVectorType<moho::EntId>`'s identical
 * `= default` precedent.
 */
gpg::RFastVectorType<moho::IFormationInstance*>::~RFastVectorType() = default;

/**
 * Address: 0x0059C9A0 (FUN_0059C9A0, gpg::RFastVectorType_IFormationInstance_P::GetName)
 *
 * What it does:
 * Lazily formats and caches "fastvector<IFormationInstance*>" from the
 * pointer-element type's own reflected name (queried via
 * `Moho::IFormationInstance::GetPointerType()->GetName()`), guarded by a
 * once-init flag and torn down at process exit -- matches the binary's
 * `dword_10C8B50` bit0 guard + `atexit(sub_BF68C0)` shape, and the sibling
 * `RFastVectorType<moho::ReconBlip*>::GetName` recovery in
 * UnitFastVectorReflection.cpp.
 */
const char* gpg::RFastVectorType<moho::IFormationInstance*>::GetName() const
{
  if (gFormationInstancePtrFastVectorTypeName.empty()) {
    gpg::RType* const pointerType = moho::IFormationInstance::GetPointerType();
    const char* const elementName = pointerType ? pointerType->GetName() : "IFormationInstance*";
    gFormationInstancePtrFastVectorTypeName =
      gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "IFormationInstance*");
    if (!gFormationInstancePtrFastVectorTypeNameCleanupRegistered) {
      gFormationInstancePtrFastVectorTypeNameCleanupRegistered = true;
      (void)std::atexit(&CleanupFormationInstancePtrFastVectorTypeName);
    }
  }

  return gFormationInstancePtrFastVectorTypeName.c_str();
}

/**
 * Address: 0x0059CA40 (FUN_0059CA40, gpg::RFastVectorType_IFormationInstance_P::GetLexical)
 */
msvc8::string gpg::RFastVectorType<moho::IFormationInstance*>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x0059CAD0 (FUN_0059CAD0, gpg::RFastVectorType_IFormationInstance_P::IsIndexed)
 */
const gpg::RIndexed* gpg::RFastVectorType<moho::IFormationInstance*>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x0059CA20 (FUN_0059CA20, gpg::RFastVectorType_IFormationInstance_P::Init)
 */
void gpg::RFastVectorType<moho::IFormationInstance*>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadFastVectorIFormationInstance;
  serSaveFunc_ = &SaveFastVectorIFormationInstance;
}

/**
 * Address: 0x0059CB10 (FUN_0059CB10, gpg::RFastVectorType_IFormationInstance_P::SubscriptIndex)
 *
 * What it does:
 * Builds one reflected element reference for
 * `fastvector<Moho::IFormationInstance*>[ind]`. The retail body performs no
 * bounds/null check before indexing, so this is left unconditional to match.
 */
gpg::RRef gpg::RFastVectorType<moho::IFormationInstance*>::SubscriptIndex(void* obj, const int ind) const
{
  auto& vec = *static_cast<gpg::fastvector<moho::IFormationInstance*>*>(obj);
  gpg::RRef out{};
  gpg::RRef_IFormationInstance_P(&out, &vec[static_cast<std::size_t>(ind)]);
  return out;
}

/**
 * Address: 0x0059CAE0 (FUN_0059CAE0, gpg::RFastVectorType_IFormationInstance_P::GetCount)
 */
size_t gpg::RFastVectorType<moho::IFormationInstance*>::GetCount(void* obj) const
{
  const auto& vec = *static_cast<const gpg::fastvector<moho::IFormationInstance*>*>(obj);
  return vec.size();
}

/**
 * Address: 0x0059CAF0 (FUN_0059CAF0, gpg::RFastVectorType_IFormationInstance_P::SetCount)
 *
 * What it does:
 * Resizes storage to `count` elements, null-filling any grown slots. Forwards
 * directly to `fastvector::Resize`, whose pointer-element instantiation is
 * `FUN_0059CE20` (see `FastVector.h`'s `Resize()` citation for the same
 * address under this exact class).
 */
void gpg::RFastVectorType<moho::IFormationInstance*>::SetCount(void* obj, const int count) const
{
  auto& vec = *static_cast<gpg::fastvector<moho::IFormationInstance*>*>(obj);
  vec.Resize(static_cast<std::size_t>(count));
}
