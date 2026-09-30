
#include <cstddef>
#include "moho/audio/SParamKey.h"
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  constexpr const char* kSerializationSourcePath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

} // namespace

namespace moho
{
  /**
   * Inlined into `gpg::SerSaveLoadHelper<SParamKey>::Deserialize` 0x004DEFD0.
   */
  void SParamKey::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    archive->ReadString(&mCueName);
    archive->ReadString(&mBankName);
    archive->ReadString(&mLodCutoffVariableName);
    archive->ReadString(&mRpcLoopVariableName);
  }

  /**
   * Inlined into `gpg::SerSaveLoadHelper<SParamKey>::Serialize` 0x004DF010.
   */
  void SParamKey::MemberSerialize(gpg::WriteArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    archive->WriteString(&mCueName);
    archive->WriteString(&mBankName);
    archive->WriteString(&mLodCutoffVariableName);
    archive->WriteString(&mRpcLoopVariableName);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SParamKey>`, vtable 0x00E0B9E0.
   *
   * Address: 0x00BC6860 (FUN_00BC6860 -- constructs the global and registers its destructor.)
   * Address: 0x00BF0E50 (FUN_00BF0E50 -- the global's destructor.)
   * Address: 0x004E1600 (FUN_004E1600 -- `Init`.)
   * Address: 0x004DEFD0 (FUN_004DEFD0 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x004DF010 (FUN_004DF010 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct SParamKeySerializer : gpg::SerSaveLoadHelper<SParamKey>
  {};
} // namespace moho

namespace
{
  // Address: 0x010A9364 -- process-global `SParamKeySerializer` singleton.
  moho::SParamKeySerializer gSParamKeySerializer;
} // namespace
