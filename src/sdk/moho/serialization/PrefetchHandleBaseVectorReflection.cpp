#include "moho/serialization/PrefetchHandleBaseVectorReflection.h"

#include <typeinfo>
#include <utility>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"

namespace
{
  [[nodiscard]] const gpg::RRef& NullOwnerRef()
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  /**
   * Address: 0x004A6480 (FUN_004A6480)
   * Address: 0x004A85E0 (FUN_004A85E0, archive-read thunk lane)
   *
   * What it does:
   * Reads vector count, deserializes each `PrefetchHandleBase` element, and
   * replaces destination vector storage.
   */
  void LoadPrefetchHandleBaseVector(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const storage = reinterpret_cast<msvc8::vector<moho::PrefetchHandleBase>*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    msvc8::vector<moho::PrefetchHandleBase> loaded{};
    loaded.resize(static_cast<std::size_t>(count));

    gpg::RType* const elementType = moho::PrefetchHandleBase::StaticGetClass();
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(elementType, &loaded[static_cast<std::size_t>(i)], NullOwnerRef());
    }

    *storage = std::move(loaded);
  }

  /**
   * Address: 0x004A65E0 (FUN_004A65E0)
   * Address: 0x004A7CE0 (FUN_004A7CE0, archive-write thunk lane)
   * Address: 0x004A8620 (FUN_004A8620, archive-write thunk lane)
   *
   * What it does:
   * Writes vector count and serializes each `PrefetchHandleBase` element.
   */
  void SavePrefetchHandleBaseVector(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<msvc8::vector<moho::PrefetchHandleBase>*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    const unsigned int count = static_cast<unsigned int>(storage->size());
    archive->WriteUInt(count);

    gpg::RType* const elementType = moho::PrefetchHandleBase::StaticGetClass();
    const gpg::RRef owner = ownerRef ? *ownerRef : NullOwnerRef();
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, &(*storage)[static_cast<std::size_t>(i)], owner);
    }
  }

  gpg::RVectorType<moho::PrefetchHandleBase> gPrefetchHandleBaseVectorType;

  struct PrefetchHandleBaseVectorRegistration
  {
    PrefetchHandleBaseVectorRegistration()
    {
      gpg::PreRegisterRType(typeid(msvc8::vector<moho::PrefetchHandleBase>), &gPrefetchHandleBaseVectorType);
    }
  };

  PrefetchHandleBaseVectorRegistration gPrefetchHandleBaseVectorRegistration;
} // namespace

gpg::RType* gpg::ResolvePrefetchHandleBaseVectorType()
{
  return gpg::LookupRType(typeid(msvc8::vector<moho::PrefetchHandleBase>));
}

/**
 * Address: 0x004A8700 (FUN_004A8700, gpg::RRef_PrefetchHandleBase)
 */
gpg::RRef* gpg::RRef_PrefetchHandleBase(gpg::RRef* outRef, moho::PrefetchHandleBase* value)
{
  if (!outRef) {
    return nullptr;
  }
  outRef->mObj = value;
  outRef->mType = moho::PrefetchHandleBase::StaticGetClass();
  return outRef;
}

/**
 * Address: 0x004A8330 (FUN_004A8330)
 */
gpg::RVectorType<moho::PrefetchHandleBase>::~RVectorType() = default;

/**
 * Address: 0x004A5D10 (FUN_004A5D10, gpg::RVectorType_PrefetchHandleBase::GetName)
 */
const char* gpg::RVectorType<moho::PrefetchHandleBase>::GetName() const
{
  static msvc8::string sName;
  if (sName.empty()) {
    const char* const elementName = moho::PrefetchHandleBase::StaticGetClass()->GetName();
    sName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "PrefetchHandleBase");
  }
  return sName.c_str();
}

/**
 * Address: 0x004A5DD0 (FUN_004A5DD0)
 */
msvc8::string gpg::RVectorType<moho::PrefetchHandleBase>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x004A5E60 (FUN_004A5E60)
 */
const gpg::RIndexed* gpg::RVectorType<moho::PrefetchHandleBase>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x004A5DB0 (FUN_004A5DB0)
 */
void gpg::RVectorType<moho::PrefetchHandleBase>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadPrefetchHandleBaseVector;
  serSaveFunc_ = &SavePrefetchHandleBaseVector;
}

/**
 * Address: 0x004A5EC0 (FUN_004A5EC0)
 */
gpg::RRef gpg::RVectorType<moho::PrefetchHandleBase>::SubscriptIndex(void* obj, const int ind) const
{
  auto* const storage = static_cast<msvc8::vector<moho::PrefetchHandleBase>*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(static_cast<std::size_t>(ind) < GetCount(obj));

  gpg::RRef out{};
  gpg::RRef_PrefetchHandleBase(&out, nullptr);
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= GetCount(obj)) {
    return out;
  }

  gpg::RRef_PrefetchHandleBase(&out, &(*storage)[static_cast<std::size_t>(ind)]);
  return out;
}

/**
 * Address: 0x004A5E70 (FUN_004A5E70)
 */
size_t gpg::RVectorType<moho::PrefetchHandleBase>::GetCount(void* obj) const
{
  if (!obj) {
    return 0u;
  }

  const auto& view = msvc8::AsVectorRuntimeView(*static_cast<const msvc8::vector<moho::PrefetchHandleBase>*>(obj));
  if (!view.begin) {
    return 0u;
  }
  return static_cast<std::size_t>(view.end - view.begin);
}

/**
 * Address: 0x004A5E90 (FUN_004A5E90)
 * Address: 0x004A6BD0 (FUN_004A6BD0, reserve/grow helper lane)
 * Address: 0x004A6CD0 (FUN_004A6CD0, resize/set-count helper lane)
 * Address: 0x004A6DE0 (FUN_004A6DE0, insert/grow helper lane)
 */
void gpg::RVectorType<moho::PrefetchHandleBase>::SetCount(void* obj, const int count) const
{
  auto* const storage = static_cast<msvc8::vector<moho::PrefetchHandleBase>*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  const moho::PrefetchHandleBase zeroFill{};
  storage->resize(static_cast<std::size_t>(count), zeroFill);
}

