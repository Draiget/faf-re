#include "moho/entity/intel/CIntelSerializer.h"

#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "moho/entity/intel/CIntel.h"

namespace
{
  /**
   * Address: 0x0076E6B0 (FUN_0076E6B0, gpg::SerSaveLoadHelper_CIntel load thunk)
   *
   * What it does:
   * Forwards the installed mLoadCallback role into `CIntel::ReadArchive`.
   */
  int DeserializeCIntelFromArchiveBridge(const int archivePtr, const int objectPtr)
  {
    gpg::ReadArchive* const archive = reinterpret_cast<gpg::ReadArchive*>(archivePtr);
    auto* const intel = reinterpret_cast<moho::CIntel*>(objectPtr);
    if (archive == nullptr || intel == nullptr) {
      return 0;
    }

    const gpg::RRef nullOwner{};
    intel->ReadArchive(*archive, nullOwner);
    return 0;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BDCBE0 (FUN_00BDCBE0, dynamic initializer for the global
   * `CIntelSerializer` singleton)
   */
  CIntelSerializer::CIntelSerializer()
    : mLoadCallback(reinterpret_cast<gpg::RType::load_func_t>(&DeserializeCIntelFromArchiveBridge))
    , mSaveCallback(reinterpret_cast<gpg::RType::save_func_t>(&CIntel::SerializeSave))
  {}

  /**
   * Address: 0x00C01DF0 (FUN_00C01DF0, atexit target registered by the real
   * ctor above)
   */
  CIntelSerializer::~CIntelSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x0076E810 (FUN_0076E810, gpg::SerSaveLoadHelper_CIntel::Init)
   */
  void CIntelSerializer::Init()
  {
    gpg::RType* type = CIntel::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CIntel));
      CIntel::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010BB3D0 -- process-global `CIntelSerializer` singleton.
  moho::CIntelSerializer gCIntelSerializer;
} // namespace
