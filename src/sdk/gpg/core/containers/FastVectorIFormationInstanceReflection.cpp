#include "gpg/core/containers/FastVectorIFormationInstanceReflection.h"

#include <cstddef>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/IFormationInstanceCountedPtrReflection.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x0059CF00 (FUN_0059CF00, gpg::RFastVectorType_IFormationInstance_P::SerLoad)
   *
   * What it does:
   * Reads the serialized lane count for one reflected
   * `fastvector<Moho::IFormationInstance*>`, resizes storage with a null-pointer
   * fill, then deserializes each tracked pointer lane through
   * `ReadArchive::ReadPointer_IFormationInstance`. The resize call
   * (`FUN_0059CE20`) is a separate compiler-emitted inline clone of
   * `gpg::core::FastVectorInline<T>::ResizeFill_` specialized for 4-byte pointer
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
      archive->ReadPointer(&vec[i], &owner);
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

  /**
   * Address: 0x00BF6980 (FUN_00BF6980, atexit destructor of the RFastVectorType<Moho::IFormationInstance*> object)
   */
  [[nodiscard]] gpg::RFastVectorType<moho::IFormationInstance*>* AcquireFastVectorIFormationInstancePtrType()
  {
    static gpg::RFastVectorType<moho::IFormationInstance*> sInstance;
    return &sInstance;
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
 * Constructs the `fastvector<Moho::IFormationInstance*>` reflection
 * descriptor. Reached from the CRT static-initializer table (`__xc_a`) in the
 * binary; recovered here as the constructor of the file-local
 * `FastVectorIFormationInstanceReflectionBootstrap` global, matching
 * `register_RFastVectorType_EntId`'s own bootstrap pattern.
 */
void gpg::register_RFastVectorType_IFormationInstance()
{
  (void)AcquireFastVectorIFormationInstancePtrType();
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
 * Address: 0x00BF68C0 (FUN_00BF68C0, atexit destructor of GetName's cached name)
 *
 * What it does:
 * Builds `fastvector<IFormationInstance*>` once from the pointer-element
 * type's own reflected name and returns it.
 */
const char* gpg::RFastVectorType<moho::IFormationInstance*>::GetName() const
{
  static const msvc8::string sName =
    gpg::STR_Printf("fastvector<%s>", moho::IFormationInstance::GetPointerType()->GetName());
  return sName.c_str();
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
  static_assert(sizeof(gpg::core::FastVectorInline<moho::IFormationInstance*>) == 0x10, "gpg::core::FastVectorInline<moho::IFormationInstance*> is 0x10 bytes on x86");
  size_ = sizeof(gpg::core::FastVectorInline<moho::IFormationInstance*>);
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

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RFastVectorType_IFormationInstance_59ded0, gpg::register_RFastVectorType_IFormationInstance)
