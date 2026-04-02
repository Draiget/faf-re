#include "moho/sim/CMersenneTwisterSerializer.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/sim/CMersenneTwister.h"
#include "moho/sim/CMersenneTwisterTypeInfo.h"

// Make CMersenneTwister registration run before default-segment bootstrap
// objects that query RTTI during static initialization.
#pragma init_seg(lib)

namespace
{
  [[nodiscard]] gpg::RType* CachedCMersenneTwisterType()
  {
    gpg::RType* type = moho::CMersenneTwister::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CMersenneTwister));
      moho::CMersenneTwister::sType = type;
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
   * Address: 0x0040EDB0 (FUN_0040EDB0)
   *
   * What it does:
   * Loads CMersenneTwister payload through the member deserializer wrapper.
   */
  void LoadCMersenneTwister(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    LoadMemberThunk<moho::CMersenneTwister>(archive, objectPtr, 0, nullptr);
  }

  /**
   * Address: 0x0040EDD0 (FUN_0040EDD0)
   *
   * What it does:
   * Saves CMersenneTwister payload through the member serializer wrapper.
   */
  void SaveCMersenneTwister(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    SaveMemberThunk<moho::CMersenneTwister>(archive, objectPtr, 0, nullptr);
  }

  template <typename TObject>
  void MaterializeReflectionSingleton(TObject& singleton)
  {
    (void)singleton;
  }

  moho::CMersenneTwisterTypeInfo gCMersenneTwisterTypeInfo;
  moho::CMersenneTwisterSerializer gCMersenneTwisterSerializer;

  /**
   * Address: 0x00BC3300 (FUN_00BC3300, register_CMersenneTwisterTypeInfo)
   *
   * What it does:
   * Materializes the global reflection descriptor for `CMersenneTwister`.
   */
  void RegisterCMersenneTwisterTypeInfoBootstrap()
  {
    MaterializeReflectionSingleton(gCMersenneTwisterTypeInfo);
  }

  /**
   * Address: 0x00BC3320 (FUN_00BC3320, register_CMersenneTwisterSerializer)
   *
   * What it does:
   * Initializes the global CMersenneTwister serializer helper and binds
   * load/save callbacks into reflected type metadata.
   */
  void RegisterCMersenneTwisterSerializerBootstrap()
  {
    gCMersenneTwisterSerializer.mHelperNext = nullptr;
    gCMersenneTwisterSerializer.mHelperPrev = nullptr;
    gCMersenneTwisterSerializer.mLoadCallback = &LoadCMersenneTwister;
    gCMersenneTwisterSerializer.mSaveCallback = &SaveCMersenneTwister;
    gCMersenneTwisterSerializer.RegisterSerializeFunctions();
  }

  struct CMersenneTwisterReflectionRegistration
  {
    CMersenneTwisterReflectionRegistration()
    {
      RegisterCMersenneTwisterTypeInfoBootstrap();
      RegisterCMersenneTwisterSerializerBootstrap();
    }
  };

  CMersenneTwisterReflectionRegistration gCMersenneTwisterReflectionRegistration;
} // namespace

namespace moho
{
  /**
   * Address: 0x0040F2C0 (FUN_0040F2C0, gpg::SerSaveLoadHelper<class Moho::CMersenneTwister>::Init)
   *
   * What it does:
   * Resolves CMersenneTwister RTTI and installs load/save callbacks from this helper.
   */
  void CMersenneTwisterSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCMersenneTwisterType();
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
