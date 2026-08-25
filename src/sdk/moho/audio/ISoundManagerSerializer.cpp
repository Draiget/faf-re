#include "moho/audio/ISoundManagerSerializer.h"

#include "moho/audio/AudioReflectionHelpers.h"

namespace
{
  // Address: 0x010BAE8C -- process-global `ISoundManagerSerializer` singleton.
  // Constructing it runs ISoundManagerSerializer::ISoundManagerSerializer()
  // (0x00BDC4C0), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::ISoundManagerSerializer gISoundManagerSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BDC4C0 (FUN_00BDC4C0, register_ISoundManagerSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  ISoundManagerSerializer::ISoundManagerSerializer()
    : mLoadCallback(&ISoundManagerSerializer::Deserialize)
    , mSaveCallback(&ISoundManagerSerializer::Serialize)
  {}

  /**
   * Address: 0x00C014D0 (FUN_00C014D0, Moho::ISoundManagerSerializer::~ISoundManagerSerializer)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently sits
   * in and restores a self-linked sentinel state.
   */
  ISoundManagerSerializer::~ISoundManagerSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00760BD0 (FUN_00760BD0, Moho::ISoundManagerSerializer::Deserialize)
   */
  void ISoundManagerSerializer::Deserialize(gpg::ReadArchive*, int, int, gpg::RRef*)
  {
  }

  /**
   * Address: 0x00760BE0 (FUN_00760BE0, Moho::ISoundManagerSerializer::Serialize)
   */
  void ISoundManagerSerializer::Serialize(gpg::WriteArchive*, int, int, gpg::RRef*)
  {
  }

  /**
   * Address: 0x00761BE0 (FUN_00761BE0, gpg::SerSaveLoadHelper_ISoundManager::Init)
   *
   * What it does:
   * Resolves `ISoundManager` RTTI and installs load/save callbacks.
   */
  void ISoundManagerSerializer::Init()
  {
    gpg::RType* const typeInfo = audio_reflection::ResolveISoundManagerType();
    audio_reflection::RegisterSerializeCallbacks(typeInfo, mLoadCallback, mSaveCallback);
  }
} // namespace moho
