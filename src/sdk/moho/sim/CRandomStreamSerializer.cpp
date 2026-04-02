#include "moho/sim/CRandomStreamSerializer.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/CRandomStreamTypeInfo.h"

// Make CRandomStream registration run before default-segment bootstrap objects
// that query RTTI during static initialization.
#pragma init_seg(lib)

namespace
{
  [[nodiscard]] gpg::RType* CachedCRandomStreamType()
  {
    gpg::RType* type = moho::CRandomStream::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CRandomStream));
      moho::CRandomStream::sType = type;
    }
    return type;
  }

  template <typename TObject>
  void LoadMemberThunk(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<TObject*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    object->MemberDeserialize(archive);
  }

  template <typename TObject>
  void SaveMemberThunk(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    const auto* const object = reinterpret_cast<const TObject*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x0040F1D0 (FUN_0040F1D0)
   *
   * What it does:
   * Loads CRandomStream payload through the member deserializer wrapper.
   */
  void LoadCRandomStream(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    LoadMemberThunk<moho::CRandomStream>(archive, objectPtr, 0, nullptr);
  }

  /**
   * Address: 0x0040F1E0 (FUN_0040F1E0)
   *
   * What it does:
   * Saves CRandomStream payload through the member serializer wrapper.
   */
  void SaveCRandomStream(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    SaveMemberThunk<moho::CRandomStream>(archive, objectPtr, 0, nullptr);
  }

  moho::CRandomStreamTypeInfo gCRandomStreamTypeInfo;
  moho::CRandomStreamSerializer gCRandomStreamSerializer;

  struct CRandomStreamReflectionRegistration
  {
    CRandomStreamReflectionRegistration()
    {
      gCRandomStreamSerializer.mHelperNext = nullptr;
      gCRandomStreamSerializer.mHelperPrev = nullptr;
      gCRandomStreamSerializer.mLoadCallback = &LoadCRandomStream;
      gCRandomStreamSerializer.mSaveCallback = &SaveCRandomStream;
      gCRandomStreamSerializer.RegisterSerializeFunctions();
    }
  };

  CRandomStreamReflectionRegistration gCRandomStreamReflectionRegistration;
} // namespace

namespace moho
{
  /**
   * Address: 0x0040F380 (FUN_0040F380, gpg::SerSaveLoadHelper<class Moho::CRandomStream>::Init)
   *
   * What it does:
   * Resolves CRandomStream RTTI and installs load/save callbacks from this helper.
   */
  void CRandomStreamSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCRandomStreamType();
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
