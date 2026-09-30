
#include <cstddef>
#include <cstdlib>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/RResId.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
} // namespace

namespace moho
{
  /**
   * Inlined into `gpg::SerSaveLoadHelper<RResId>::Deserialize` 0x004A9690.
   */
  void RResId::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    archive->ReadString(&name);
  }

  /**
   * Inlined into `gpg::SerSaveLoadHelper<RResId>::Serialize` 0x004A96B0.
   */
  void RResId::MemberSerialize(gpg::WriteArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    archive->WriteString(&name);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<RResId>`, vtable 0x00E073BC.
   *
   * Address: 0x00BC5A80 (FUN_00BC5A80 -- constructs the global and registers its destructor.)
   * Address: 0x00BF04C0 (FUN_00BF04C0 -- the global's destructor.)
   * Address: 0x004A9790 (FUN_004A9790 -- `Init`.)
   * Address: 0x004A9690 (FUN_004A9690 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x004A96B0 (FUN_004A96B0 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct RResIdSerializer : gpg::SerSaveLoadHelper<RResId>
  {};
} // namespace moho

namespace
{
  // Address: 0x010A8924 -- process-global `RResIdSerializer` singleton.
  moho::RResIdSerializer gRResIdSerializer;
} // namespace
