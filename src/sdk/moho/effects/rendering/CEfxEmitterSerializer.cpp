#include "moho/effects/rendering/CEfxEmitterSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/effects/rendering/CEfxEmitter.h"

namespace
{
  // Address: 0x010B3C64 -- process-global `CEfxEmitterSerializer` singleton.
  // Constructing it runs CEfxEmitterSerializer::CEfxEmitterSerializer()
  // (0x00BD4310), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::CEfxEmitterSerializer gCEfxEmitterSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD4310 (FUN_00BD4310, register_CEfxEmitterSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CEfxEmitterSerializer::CEfxEmitterSerializer()
    : mLoadCallback(&CEfxEmitterSerializer::Deserialize)
    , mSaveCallback(&CEfxEmitterSerializer::Serialize)
  {}

  /**
   * Address: 0x00BFBDB0 (FUN_00BFBDB0, Moho::CEfxEmitterSerializer::~CEfxEmitterSerializer)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently sits
   * in and restores a self-linked sentinel state.
   */
  CEfxEmitterSerializer::~CEfxEmitterSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x0065E140 (FUN_0065E140, Moho::CEfxEmitterSerializer::Deserialize)
   *
   * What it does:
   * Forwards the reflected object pointer to `CEfxEmitter::MemberDeserialize`.
   */
  void CEfxEmitterSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    auto* const object = reinterpret_cast<CEfxEmitter*>(static_cast<std::uintptr_t>(objectPtr));
    if (object != nullptr) {
      object->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x0065E150 (FUN_0065E150, Moho::CEfxEmitterSerializer::Serialize)
   *
   * What it does:
   * Forwards the reflected object pointer to `CEfxEmitter::MemberSerialize`.
   */
  void CEfxEmitterSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    auto* const object = reinterpret_cast<CEfxEmitter*>(static_cast<std::uintptr_t>(objectPtr));
    if (object != nullptr) {
      object->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x0065F150 (FUN_0065F150, gpg::SerSaveLoadHelper_CEfxEmitter::Init)
   *
   * What it does:
   * Lazily resolves `CEfxEmitter` RTTI and installs load/save callbacks from
   * this helper object into the type descriptor.
   */
  void CEfxEmitterSerializer::Init()
  {
    gpg::RType* type = CEfxEmitter::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(CEfxEmitter));
      CEfxEmitter::sType = type;
    }

    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
