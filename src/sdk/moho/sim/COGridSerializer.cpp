#include "moho/sim/COGridSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/sim/COGrid.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCOGridType()
  {
    gpg::RType* type = moho::COGrid::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::COGrid));
      moho::COGrid::sType = type;
    }
    GPG_ASSERT(type != nullptr);
    return type;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BDAAB0 (FUN_00BDAAB0, dynamic initializer for the global
   * `COGridSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  COGridSerializer::COGridSerializer()
    : mLoadCallback(&COGridSerializer::Deserialize)
    , mSaveCallback(&COGridSerializer::Serialize)
  {}

  COGridSerializer::~COGridSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00722CC0 (FUN_00722CC0, Moho::COGridSerializer::Deserialize)
   */
  void COGridSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const grid = reinterpret_cast<COGrid*>(static_cast<std::uintptr_t>(objectPtr));
    gpg::RRef selfRef{};
    gpg::RRef_COGrid(&selfRef, grid);
    archive->TrackPointer(selfRef);
  }

  /**
   * Address: 0x00722D00 (FUN_00722D00, Moho::COGridSerializer::Serialize)
   */
  void COGridSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const grid = reinterpret_cast<COGrid*>(static_cast<std::uintptr_t>(objectPtr));
    gpg::RRef selfRef{};
    gpg::RRef_COGrid(&selfRef, grid);
    archive->PreCreatedPtr(selfRef);
  }

  /**
   * Address: 0x00722F90 (FUN_00722F90, gpg::SerSaveLoadHelper_COGrid::Init)
   */
  void COGridSerializer::Init()
  {
    gpg::RType* const type = CachedCOGridType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010B95D0 -- process-global `COGridSerializer` singleton.
  moho::COGridSerializer gCOGridSerializer;
} // namespace
