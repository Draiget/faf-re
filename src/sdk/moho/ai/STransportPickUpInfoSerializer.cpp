#include "moho/ai/STransportPickUpInfoSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "moho/ai/CAiTransportImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedSTransportPickUpInfoType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(STransportPickUpInfo));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSCoordsVec2Type()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(SCoordsVec2));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedQuaternionfType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Quaternion<float>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3<float>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedEntitySetTemplateUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(SEntitySetTemplateUnit));
    }
    return cached;
  }

  // Address: 0x010B07EC -- process-global `STransportPickUpInfoSerializer`
  // singleton. Constructing it runs STransportPickUpInfoSerializer::
  // STransportPickUpInfoSerializer() (0x00BCEE50), which splices this
  // helper into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::
  // InitNewHelpers() later dispatches Init() on it from within the first
  // ReadArchive/WriteArchive construction. Its destructor
  // (~STransportPickUpInfoSerializer, 0x00BF8B20) runs at normal
  // static-duration teardown, matching the real binary's atexit
  // registration.
  STransportPickUpInfoSerializer gSTransportPickUpInfoSerializer;
} // namespace

/**
 * Address: 0x005E4660 (FUN_005E4660, STransportPickUpInfoSerializer::Deserialize)
 */
void STransportPickUpInfoSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const info = reinterpret_cast<STransportPickUpInfo*>(static_cast<std::uintptr_t>(objectPtr));
  const gpg::RRef ownerRef{};

  gpg::RType* const coordsType = CachedSCoordsVec2Type();
  GPG_ASSERT(coordsType != nullptr);
  archive->Read(coordsType, &info->mFallbackPos, ownerRef);

  gpg::RType* const orientationType = CachedQuaternionfType();
  GPG_ASSERT(orientationType != nullptr);
  archive->Read(orientationType, &info->mOri, ownerRef);

  gpg::RType* const vectorType = CachedVector3fType();
  GPG_ASSERT(vectorType != nullptr);
  archive->Read(vectorType, &info->mPos, ownerRef);

  gpg::RType* const unitSetType = CachedEntitySetTemplateUnitType();
  GPG_ASSERT(unitSetType != nullptr);
  archive->Read(unitSetType, &info->mUnits, ownerRef);

  bool hasSpace = false;
  archive->ReadBool(&hasSpace);
  info->mHasSpace = static_cast<std::uint8_t>(hasSpace ? 1 : 0);
}

/**
 * Address: 0x005E4670 (FUN_005E4670, STransportPickUpInfoSerializer::Serialize)
 */
void STransportPickUpInfoSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  auto* const info = reinterpret_cast<const STransportPickUpInfo*>(static_cast<std::uintptr_t>(objectPtr));
  const gpg::RRef ownerRef{};

  gpg::RType* const coordsType = CachedSCoordsVec2Type();
  GPG_ASSERT(coordsType != nullptr);
  archive->Write(coordsType, &info->mFallbackPos, ownerRef);

  gpg::RType* const orientationType = CachedQuaternionfType();
  GPG_ASSERT(orientationType != nullptr);
  archive->Write(orientationType, &info->mOri, ownerRef);

  gpg::RType* const vectorType = CachedVector3fType();
  GPG_ASSERT(vectorType != nullptr);
  archive->Write(vectorType, &info->mPos, ownerRef);

  gpg::RType* const unitSetType = CachedEntitySetTemplateUnitType();
  GPG_ASSERT(unitSetType != nullptr);
  archive->Write(unitSetType, &info->mUnits, ownerRef);

  archive->WriteBool(info->mHasSpace != 0);
}

/**
 * Address: 0x00BCEE50 (FUN_00BCEE50, dynamic initializer for the global
 * `STransportPickUpInfoSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
STransportPickUpInfoSerializer::STransportPickUpInfoSerializer()
  : mLoadCallback(&STransportPickUpInfoSerializer::Deserialize)
  , mSaveCallback(&STransportPickUpInfoSerializer::Serialize)
{}

/**
 * Address: 0x00BF8B20 (FUN_00BF8B20, ??1STransportPickUpInfoSerializer@Moho@@QAE@@Z)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits in
 * and restores a self-linked sentinel state.
 */
STransportPickUpInfoSerializer::~STransportPickUpInfoSerializer()
{
  ResetLinks();
}

void STransportPickUpInfoSerializer::Init()
{
  gpg::RType* const type = CachedSTransportPickUpInfoType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCEE50 caller lane (`IAiTransport.cpp`'s reflection bootstrap
 * sequence)
 *
 * What it does:
 * Historically forced construction of the (then lazily-constructed)
 * `STransportPickUpInfoSerializer` singleton from an explicit registration
 * sequence. `gSTransportPickUpInfoSerializer` is now a genuine
 * namespace-scope global, so its constructor already runs unconditionally
 * at static-init time; this call is kept only so `IAiTransport.cpp`'s
 * existing bootstrap sequence does not need editing.
 */
int moho::register_STransportPickUpInfoSerializer()
{
  return 0;
}
