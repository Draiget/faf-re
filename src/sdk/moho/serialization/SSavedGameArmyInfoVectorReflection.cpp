#include "moho/serialization/SSavedGameArmyInfoVectorReflection.h"

#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "legacy/containers/Vector.h"

namespace
{
  [[nodiscard]] const gpg::RRef& NullOwnerRef()
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  /**
   * Address: 0x00882A90 (FUN_00882A90, sub_882A90)
   *
   * What it does:
   * Appends one deserialized `SSavedGameArmyInfo` row to the destination
   * vector, growing backing storage when needed.
   */
  void AppendSavedGameArmyInfo(
    msvc8::vector<moho::SSavedGameArmyInfo>& destination,
    const moho::SSavedGameArmyInfo& value
  )
  {
    destination.push_back(value);
  }

  /**
   * Address: 0x00882650 (FUN_00882650, sub_882650)
   *
   * What it does:
   * Releases backing storage for one saved-game-army-info vector lane and
   * resets begin/end/capacity pointers to null.
   */
  void ReleaseSavedGameArmyInfoVectorStorage(msvc8::vector<moho::SSavedGameArmyInfo>& storage)
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    if (view.begin != nullptr) {
      for (moho::SSavedGameArmyInfo* item = view.begin; item != view.end; ++item) {
        item->~SSavedGameArmyInfo();
      }
      ::operator delete(view.begin);
    }

    view.begin = nullptr;
    view.end = nullptr;
    view.capacityEnd = nullptr;
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
    loaded.reserve(static_cast<std::size_t>(count));

    gpg::RType* const elementType = moho::SSavedGameArmyInfo::StaticGetClass();
    for (unsigned int i = 0; i < count; ++i) {
      moho::SSavedGameArmyInfo loadedItem{};
      archive->Read(elementType, &loadedItem, NullOwnerRef());
      AppendSavedGameArmyInfo(loaded, loadedItem);
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

  /**
   * Address: 0x00883660 (FUN_00883660)
   *
   * What it does:
   * Builds one `gpg::RRef` payload for one `SSavedGameArmyInfo` lane and
   * writes the object/type pair to caller-provided output storage.
   */
  [[nodiscard]] gpg::RRef* BuildSavedGameArmyInfoRefLane(
    moho::SSavedGameArmyInfo* const value,
    gpg::RRef* const outRef
  )
  {
    gpg::RRef temp{};
    gpg::RRef_SSavedGameArmyInfo(&temp, value);
    outRef->mObj = temp.mObj;
    outRef->mType = temp.mType;
    return outRef;
  }

  gpg::RVectorType_SSavedGameArmyInfo gSavedGameArmyInfoVectorType;

  void EnsureSavedGameArmyInfoVectorRegistered()
  {
    static const bool kRegistered = []() {
      (void)gpg::preregister_SSavedGameArmyInfoVectorTypeStartup();
      return true;
    }();

    (void)kRegistered;
  }
} // namespace

/**
 * Address: 0x00883960 (FUN_00883960, preregister_SSavedGameArmyInfoVectorTypeStartup)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for
 * `msvc8::vector<moho::SSavedGameArmyInfo>`.
 */
gpg::RType* gpg::preregister_SSavedGameArmyInfoVectorTypeStartup()
{
  gpg::PreRegisterRType(typeid(msvc8::vector<moho::SSavedGameArmyInfo>), &gSavedGameArmyInfoVectorType);
  return &gSavedGameArmyInfoVectorType;
}

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
  BuildSavedGameArmyInfoRefLane(&(*storage)[static_cast<std::size_t>(ind)], &out);
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

