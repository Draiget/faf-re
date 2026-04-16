#include "moho/serialization/SBlackListInfoVectorReflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"

namespace
{
  using SBlackListInfoVector = msvc8::vector<moho::SBlackListInfo>;
  using SBlackListInfoVectorType = gpg::RVectorType<moho::SBlackListInfo>;

  alignas(SBlackListInfoVectorType) unsigned char gSBlackListInfoVectorTypeStorage[sizeof(SBlackListInfoVectorType)];
  bool gSBlackListInfoVectorTypeConstructed = false;

  msvc8::string gSBlackListInfoVectorTypeName;
  bool gSBlackListInfoVectorTypeNameCleanupRegistered = false;

  [[nodiscard]] SBlackListInfoVectorType* AcquireSBlackListInfoVectorType()
  {
    if (!gSBlackListInfoVectorTypeConstructed) {
      new (gSBlackListInfoVectorTypeStorage) SBlackListInfoVectorType();
      gSBlackListInfoVectorTypeConstructed = true;
    }
    return reinterpret_cast<SBlackListInfoVectorType*>(gSBlackListInfoVectorTypeStorage);
  }

  [[nodiscard]] SBlackListInfoVectorType* PeekSBlackListInfoVectorType() noexcept
  {
    if (!gSBlackListInfoVectorTypeConstructed) {
      return nullptr;
    }
    return reinterpret_cast<SBlackListInfoVectorType*>(gSBlackListInfoVectorTypeStorage);
  }

  [[nodiscard]] gpg::RType* ResolveSBlackListInfoType()
  {
    gpg::RType* type = moho::SBlackListInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SBlackListInfo));
      moho::SBlackListInfo::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BFE800 (FUN_00BFE800, sub_BFE800)
   *
   * What it does:
   * Releases cached lexical-name storage for `RVectorType_SBlackListInfo`.
   */
  void cleanup_SBlackListInfoVectorTypeName()
  {
    gSBlackListInfoVectorTypeName = msvc8::string{};
    gSBlackListInfoVectorTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x006DC070 (FUN_006DC070, sub_6DC070)
   *
   * What it does:
   * Loads a `vector<SBlackListInfo>` payload and replaces destination storage.
   */
  void LoadSBlackListInfoVector(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<SBlackListInfoVector*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    SBlackListInfoVector loaded{};
    loaded.resize(static_cast<std::size_t>(count));

    gpg::RType* const elementType = ResolveSBlackListInfoType();
    if (!elementType) {
      *storage = loaded;
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(elementType, &loaded[static_cast<std::size_t>(i)], owner);
    }

    *storage = loaded;
  }

  /**
   * Address: 0x006DC1C0 (FUN_006DC1C0, sub_6DC1C0)
   *
   * What it does:
   * Writes a `vector<SBlackListInfo>` payload element-by-element.
   */
  void SaveSBlackListInfoVector(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<const SBlackListInfoVector*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    const unsigned int count = static_cast<unsigned int>(storage->size());
    archive->WriteUInt(count);

    gpg::RType* const elementType = ResolveSBlackListInfoType();
    if (!elementType) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, &(*storage)[static_cast<std::size_t>(i)], owner);
    }
  }

  /**
   * Address: 0x006DCB10 (FUN_006DCB10)
   *
   * What it does:
   * Adjusts one `vector<SBlackListInfo>` length to `requestedCount` and uses
   * one caller-provided fill lane for growth.
   */
  [[nodiscard]] std::size_t ResizeSBlackListInfoVectorWithFill(
    SBlackListInfoVector& storage,
    const std::size_t requestedCount,
    const moho::SBlackListInfo& fillValue
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
   * Address: 0x00BFE860 (FUN_00BFE860, sub_BFE860)
   *
   * What it does:
   * Tears down `vector<SBlackListInfo>` reflection storage at process exit.
   */
  void cleanup_SBlackListInfoVectorType()
  {
    SBlackListInfoVectorType* const type = PeekSBlackListInfoVectorType();
    if (type == nullptr) {
      return;
    }

    type->~SBlackListInfoVectorType();
    gSBlackListInfoVectorTypeConstructed = false;
  }

  struct SBlackListInfoVectorReflectionBootstrap
  {
    SBlackListInfoVectorReflectionBootstrap()
    {
      (void)moho::register_SBlackListInfoVectorType_AtExit();
    }
  };

  SBlackListInfoVectorReflectionBootstrap gSBlackListInfoVectorReflectionBootstrap;
} // namespace

namespace moho
{
  gpg::RType* SBlackListInfo::sType = nullptr;

  gpg::RType* SBlackListInfo::StaticGetClass()
  {
    return ResolveSBlackListInfoType();
  }
} // namespace moho

/**
 * Address: 0x006DE830 (FUN_006DE830, gpg::RRef_SBlackListInfo)
 */
gpg::RRef* gpg::RRef_SBlackListInfo(gpg::RRef* const outRef, moho::SBlackListInfo* const value)
{
  if (!outRef) {
    return nullptr;
  }

  outRef->mObj = value;
  outRef->mType = ResolveSBlackListInfoType();
  return outRef;
}

/**
 * Address: 0x006DDA30 (FUN_006DDA30)
 *
 * What it does:
 * Packs one `RRef_SBlackListInfo` lane into caller-owned output storage.
 */
[[maybe_unused]] gpg::RRef* gpg::PackRRef_SBlackListInfo(gpg::RRef* const outRef, moho::SBlackListInfo* const value)
{
  if (!outRef) {
    return nullptr;
  }

  gpg::RRef tmp{};
  (void)gpg::RRef_SBlackListInfo(&tmp, value);
  outRef->mObj = tmp.mObj;
  outRef->mType = tmp.mType;
  return outRef;
}

/**
 * Address: 0x006DB5D0 (FUN_006DB5D0, gpg::RVectorType_SBlackListInfo::GetName)
 */
const char* gpg::RVectorType<moho::SBlackListInfo>::GetName() const
{
  if (gSBlackListInfoVectorTypeName.empty()) {
    const gpg::RType* const elementType = ResolveSBlackListInfoType();
    const char* const elementName = elementType ? elementType->GetName() : "SBlackListInfo";
    gSBlackListInfoVectorTypeName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "SBlackListInfo");

    if (!gSBlackListInfoVectorTypeNameCleanupRegistered) {
      gSBlackListInfoVectorTypeNameCleanupRegistered = true;
      (void)std::atexit(&cleanup_SBlackListInfoVectorTypeName);
    }
  }

  return gSBlackListInfoVectorTypeName.c_str();
}

/**
 * Address: 0x006DB690 (FUN_006DB690, gpg::RVectorType_SBlackListInfo::GetLexical)
 */
msvc8::string gpg::RVectorType<moho::SBlackListInfo>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x006DB720 (FUN_006DB720, gpg::RVectorType_SBlackListInfo::IsIndexed)
 */
const gpg::RIndexed* gpg::RVectorType<moho::SBlackListInfo>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x006DB670 (FUN_006DB670, gpg::RVectorType_SBlackListInfo::Init)
 */
void gpg::RVectorType<moho::SBlackListInfo>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadSBlackListInfoVector;
  serSaveFunc_ = &SaveSBlackListInfoVector;
}

/**
 * Address: 0x006DB790 (FUN_006DB790, gpg::RVectorType_SBlackListInfo::SubscriptIndex)
 */
gpg::RRef gpg::RVectorType<moho::SBlackListInfo>::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<SBlackListInfoVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(storage != nullptr && static_cast<std::size_t>(ind) < storage->size());

  gpg::RRef out{};
  gpg::RRef_SBlackListInfo(&out, nullptr);
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  gpg::RRef_SBlackListInfo(&out, &(*storage)[static_cast<std::size_t>(ind)]);
  return out;
}

/**
 * Address: 0x006DB730 (FUN_006DB730, gpg::RVectorType_SBlackListInfo::GetCount)
 */
size_t gpg::RVectorType<moho::SBlackListInfo>::GetCount(void* const obj) const
{
  if (!obj) {
    return 0u;
  }

  const auto& view = msvc8::AsVectorRuntimeView(*static_cast<const SBlackListInfoVector*>(obj));
  if (!view.begin) {
    return 0u;
  }

  return static_cast<std::size_t>(view.end - view.begin);
}

/**
 * Address: 0x006DB760 (FUN_006DB760, gpg::RVectorType_SBlackListInfo::SetCount)
 */
void gpg::RVectorType<moho::SBlackListInfo>::SetCount(void* const obj, const int count) const
{
  auto* const storage = static_cast<SBlackListInfoVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  const moho::SBlackListInfo zeroFill{};
  (void)ResizeSBlackListInfoVectorWithFill(*storage, static_cast<std::size_t>(count), zeroFill);
}

/**
 * Address: 0x006DDF70 (FUN_006DDF70, sub_6DDF70)
 *
 * What it does:
 * Constructs/preregisters RTTI for `vector<SBlackListInfo>`.
 */
gpg::RType* moho::register_SBlackListInfoVectorType_00()
{
  SBlackListInfoVectorType* const type = AcquireSBlackListInfoVectorType();
  gpg::PreRegisterRType(typeid(msvc8::vector<moho::SBlackListInfo>), type);
  return type;
}

/**
 * Address: 0x00BD8BB0 (FUN_00BD8BB0, sub_BD8BB0)
 *
 * What it does:
 * Registers `vector<SBlackListInfo>` reflection and installs process-exit
 * teardown via `atexit`.
 */
int moho::register_SBlackListInfoVectorType_AtExit()
{
  (void)register_SBlackListInfoVectorType_00();
  return std::atexit(&cleanup_SBlackListInfoVectorType);
}
