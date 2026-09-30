#include "moho/serialization/SBlackListInfoVectorReflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using SBlackListInfoVectorType = gpg::RVectorType<moho::SBlackListInfo>;

  /**
   * Address: 0x00BFE860 (FUN_00BFE860, atexit destructor of the RVectorType<SBlackListInfo> object)
   */
  [[nodiscard]] SBlackListInfoVectorType* AcquireSBlackListInfoVectorType()
  {
    static SBlackListInfoVectorType sInstance;
    return &sInstance;
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
   * Address: 0x006DC070 (FUN_006DC070, sub_6DC070)
   *
   * What it does:
   * `vector<SBlackListInfo>`'s load callback. Reads the count, `reserve`s a
   * staging vector (0x006DC9F0), then per element reads one `SBlackListInfo`
   * into a temporary under an empty owner and `push_back`s it (0x006DB150);
   * the temporary's `WeakPtr<Entity>` unlinks itself at 0x006DC123. The
   * staging vector is swapped into the destination and the old elements die
   * with it. Nothing is null-tested.
   */
  void LoadSBlackListInfoVector(gpg::ReadArchive* const archive, const int objectPtr, int, gpg::RRef*)
  {
    auto& storage = *reinterpret_cast<msvc8::vector<moho::SBlackListInfo>*>(objectPtr);

    unsigned int count = 0;
    archive->ReadUInt(&count);

    msvc8::vector<moho::SBlackListInfo> loaded;
    loaded.reserve(count);
    for (unsigned int i = 0; i < count; ++i) {
      moho::SBlackListInfo element;
      archive->Read(ResolveSBlackListInfoType(), &element, gpg::RRef{});
      loaded.push_back(element);
    }

    storage.swap(loaded);
  }

  /**
   * Address: 0x006DC1C0 (FUN_006DC1C0, sub_6DC1C0)
   *
   * What it does:
   * `vector<SBlackListInfo>`'s save callback: the count, then each element
   * through the reflected `SBlackListInfo` type with the caller's owner.
   * Nothing is null-tested.
   */
  void SaveSBlackListInfoVector(gpg::WriteArchive* const archive, const int objectPtr, int, gpg::RRef* const ownerRef)
  {
    const auto& storage = *reinterpret_cast<const msvc8::vector<moho::SBlackListInfo>*>(objectPtr);
    const unsigned int count = static_cast<unsigned int>(storage.size());
    archive->WriteUInt(count);
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(ResolveSBlackListInfoType(), &storage[i], *ownerRef);
    }
  }

  struct SBlackListInfoVectorReflectionBootstrap
  {
    SBlackListInfoVectorReflectionBootstrap()
    {
      moho::register_SBlackListInfoVectorType();
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

gpg::RVectorType<moho::SBlackListInfo>::~RVectorType() = default;

/**
 * Address: 0x006DB5D0 (FUN_006DB5D0, gpg::RVectorType_SBlackListInfo::GetName)
 * Address: 0x00BFE800 (FUN_00BFE800, atexit destructor of GetName's cached name)
 *
 * What it does:
 * Builds `vector<SBlackListInfo>` once and returns it.
 */
const char* gpg::RVectorType<moho::SBlackListInfo>::GetName() const
{
  static const msvc8::string sName = gpg::STR_Printf("vector<%s>", ResolveSBlackListInfoType()->GetName());
  return sName.c_str();
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
  static_assert(sizeof(msvc8::vector<moho::SBlackListInfo>) == 0x10, "msvc8::vector<moho::SBlackListInfo> is 0x10 bytes on x86");
  size_ = sizeof(msvc8::vector<moho::SBlackListInfo>);
  version_ = 1;
  serLoadFunc_ = &LoadSBlackListInfoVector;
  serSaveFunc_ = &SaveSBlackListInfoVector;
}

/**
 * Address: 0x006DB790 (FUN_006DB790, gpg::RVectorType_SBlackListInfo::SubscriptIndex)
 */
gpg::RRef gpg::RVectorType<moho::SBlackListInfo>::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<msvc8::vector<moho::SBlackListInfo>*>(obj);
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

  return static_cast<const msvc8::vector<moho::SBlackListInfo>*>(obj)->size();
}

/**
 * Address: 0x006DB760 (FUN_006DB760, gpg::RVectorType_SBlackListInfo::SetCount)
 *
 * What it does:
 * `resize(count, SBlackListInfo())` (0x006DCB10), the default entry built on
 * the stack as the by-value fill argument. The binary zeroes only its weak
 * pointer (MSVC8's `T()` left `mValue` as it found it); value-initialisation
 * here zeroes `mValue` too. Nothing is null-tested.
 */
void gpg::RVectorType<moho::SBlackListInfo>::SetCount(void* const obj, const int count) const
{
  static_cast<msvc8::vector<moho::SBlackListInfo>*>(obj)->resize(static_cast<std::size_t>(count), moho::SBlackListInfo());
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
 * Registers `vector<SBlackListInfo>` reflection.
 */
void moho::register_SBlackListInfoVectorType()
{
  (void)register_SBlackListInfoVectorType_00();
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SBlackListInfoVectorType_00_ca9d53, moho::register_SBlackListInfoVectorType_00)
