#include "moho/sim/CRandomStreamSerializer.h"

#include <cstddef>
#include <cstdlib>
#include <new>
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

  alignas(moho::CRandomStreamTypeInfo) std::byte gCRandomStreamTypeInfoStorage[sizeof(moho::CRandomStreamTypeInfo)]{};
  alignas(moho::CRandomStreamSerializer) std::byte gCRandomStreamSerializerStorage[sizeof(moho::CRandomStreamSerializer)]{};
  bool gCRandomStreamTypeInfoInitialized = false;
  bool gCRandomStreamSerializerInitialized = false;

  [[nodiscard]] moho::CRandomStreamTypeInfo& CRandomStreamTypeInfoSlot()
  {
    return *reinterpret_cast<moho::CRandomStreamTypeInfo*>(gCRandomStreamTypeInfoStorage);
  }

  [[nodiscard]] moho::CRandomStreamSerializer& CRandomStreamSerializerSlot()
  {
    return *reinterpret_cast<moho::CRandomStreamSerializer*>(gCRandomStreamSerializerStorage);
  }

  /**
   * Address: 0x00BEE720 (FUN_00BEE720, ??1CRandomStreamTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Executes process-exit teardown for CRandomStream type-info startup storage.
   */
  void cleanup_CRandomStreamTypeInfo()
  {
    if (gCRandomStreamTypeInfoInitialized) {
      CRandomStreamTypeInfoSlot().~CRandomStreamTypeInfo();
      gCRandomStreamTypeInfoInitialized = false;
    }
  }

  /**
   * Address: 0x00BEE780 (FUN_00BEE780, ??1CRandomStreamSerializer@Moho@@QAE@@Z)
   *
   * What it does:
   * Executes process-exit teardown for CRandomStream serializer helper storage.
   */
  void cleanup_CRandomStreamSerializer()
  {
    if (gCRandomStreamSerializerInitialized) {
      CRandomStreamSerializerSlot().~CRandomStreamSerializer();
      gCRandomStreamSerializerInitialized = false;
    }
  }

  struct CRandomStreamReflectionRegistration
  {
    CRandomStreamReflectionRegistration()
    {
      moho::register_CRandomStreamTypeInfo();
      moho::register_CRandomStreamSerializer();
      CRandomStreamSerializerSlot().RegisterSerializeFunctions();
    }
  };

  CRandomStreamReflectionRegistration gCRandomStreamReflectionRegistration;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BC3360 (FUN_00BC3360, register_CRandomStreamTypeInfo)
   *
   * What it does:
   * Startup thunk that materializes CRandomStream type-info storage and
   * registers its process-exit destructor.
   */
  void register_CRandomStreamTypeInfo()
  {
    if (!gCRandomStreamTypeInfoInitialized) {
      new (&CRandomStreamTypeInfoSlot()) CRandomStreamTypeInfo();
      gCRandomStreamTypeInfoInitialized = true;
    }
    (void)std::atexit(&cleanup_CRandomStreamTypeInfo);
  }

  /**
   * Address: 0x00BC3380 (FUN_00BC3380, register_CRandomStreamSerializer)
   *
   * What it does:
   * Startup thunk that initializes CRandomStream serializer helper lanes and
   * registers process-exit teardown.
   */
  void register_CRandomStreamSerializer()
  {
    CRandomStreamSerializer& serializer = CRandomStreamSerializerSlot();
    if (!gCRandomStreamSerializerInitialized) {
      new (&serializer) CRandomStreamSerializer();
      gCRandomStreamSerializerInitialized = true;
    }

    serializer.mHelperNext = nullptr;
    serializer.mHelperPrev = nullptr;
    serializer.mLoadCallback = &LoadCRandomStream;
    serializer.mSaveCallback = &SaveCRandomStream;
    (void)std::atexit(&cleanup_CRandomStreamSerializer);
  }

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
