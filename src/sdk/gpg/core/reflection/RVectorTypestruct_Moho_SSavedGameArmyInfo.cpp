#include "gpg/core/reflection/RVectorTypestruct_Moho_SSavedGameArmyInfo.h"

#include <typeinfo>

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
   * Address: 0x008826C0 (FUN_008826C0)
   *
   * What it does:
   * Reads vector count, deserializes each SSavedGameArmyInfo element, and
   * replaces the destination vector.
   */
  void LoadSavedGameArmyInfoVector(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const storage = reinterpret_cast<msvc8::vector<moho::SSavedGameArmyInfo>*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    msvc8::vector<moho::SSavedGameArmyInfo> loaded{};
    loaded.resize(static_cast<std::size_t>(count));

    gpg::RType* const elementType = moho::SSavedGameArmyInfo::StaticGetClass();
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(elementType, &loaded[static_cast<std::size_t>(i)], NullOwnerRef());
    }

    *storage = std::move(loaded);
  }

  /**
   * Address: 0x008827F0 (FUN_008827F0)
   *
   * What it does:
   * Writes vector count and serializes each SSavedGameArmyInfo element.
   */
  void SaveSavedGameArmyInfoVector(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<msvc8::vector<moho::SSavedGameArmyInfo>*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    const unsigned int count = static_cast<unsigned int>(storage->size());
    archive->WriteUInt(count);

    gpg::RType* const elementType = moho::SSavedGameArmyInfo::StaticGetClass();
    const gpg::RRef owner = ownerRef ? *ownerRef : NullOwnerRef();
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, &(*storage)[static_cast<std::size_t>(i)], owner);
    }
  }

  gpg::RVectorType_SSavedGameArmyInfo gSavedGameArmyInfoVectorType;

  void EnsureSavedGameArmyInfoVectorRegistered()
  {
    static const bool kRegistered = []() {
      gpg::PreRegisterRType(typeid(msvc8::vector<moho::SSavedGameArmyInfo>), &gSavedGameArmyInfoVectorType);
      return true;
    }();

    (void)kRegistered;
  }
} // namespace

gpg::RType* gpg::ResolveSavedGameArmyInfoVectorType()
{
  EnsureSavedGameArmyInfoVectorRegistered();
  return gpg::LookupRType(typeid(msvc8::vector<moho::SSavedGameArmyInfo>));
}

/**
 * Address: 0x00882100 (FUN_00882100)
 */
const char* gpg::RVectorType_SSavedGameArmyInfo::GetName() const
{
  static msvc8::string sName;
  if (sName.empty()) {
    const char* const elementName = moho::SSavedGameArmyInfo::StaticGetClass()->GetName();
    sName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "SSavedGameArmyInfo");
  }
  return sName.c_str();
}

/**
 * Address: 0x008821C0 (FUN_008821C0)
 */
msvc8::string gpg::RVectorType_SSavedGameArmyInfo::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x00882250 (FUN_00882250)
 */
const gpg::RIndexed* gpg::RVectorType_SSavedGameArmyInfo::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x008821A0 (FUN_008821A0)
 */
void gpg::RVectorType_SSavedGameArmyInfo::Init()
{
  size_ = sizeof(msvc8::vector<moho::SSavedGameArmyInfo>);
  version_ = 1;
  serLoadFunc_ = &LoadSavedGameArmyInfoVector;
  serSaveFunc_ = &SaveSavedGameArmyInfoVector;
}

/**
 * Address: 0x008822C0 (FUN_008822C0)
 */
gpg::RRef gpg::RVectorType_SSavedGameArmyInfo::SubscriptIndex(void* obj, const int ind) const
{
  auto* const storage = static_cast<msvc8::vector<moho::SSavedGameArmyInfo>*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(static_cast<std::size_t>(ind) < storage->size());

  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = moho::SSavedGameArmyInfo::StaticGetClass();
    return out;
  }

  gpg::RRef out{};
  gpg::RRef_SSavedGameArmyInfo(&out, &(*storage)[static_cast<std::size_t>(ind)]);
  return out;
}

/**
 * Address: 0x00882260 (FUN_00882260)
 */
size_t gpg::RVectorType_SSavedGameArmyInfo::GetCount(void* obj) const
{
  auto* const storage = static_cast<msvc8::vector<moho::SSavedGameArmyInfo>*>(obj);
  return storage ? storage->size() : 0u;
}

/**
 * Address: 0x00882290 (FUN_00882290)
 */
void gpg::RVectorType_SSavedGameArmyInfo::SetCount(void* obj, const int count) const
{
  auto* const storage = static_cast<msvc8::vector<moho::SSavedGameArmyInfo>*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  storage->resize(static_cast<std::size_t>(count));
}

/**
 * Address: 0x00884040 (FUN_00884040)
 */
gpg::RRef* gpg::RRef_SSavedGameArmyInfo(gpg::RRef* outRef, moho::SSavedGameArmyInfo* value)
{
  if (!outRef) {
    return nullptr;
  }

  outRef->mObj = value;
  outRef->mType = moho::SSavedGameArmyInfo::StaticGetClass();
  return outRef;
}
