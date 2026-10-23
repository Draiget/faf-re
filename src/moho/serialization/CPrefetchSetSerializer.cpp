
#include <cstddef>
#include "gpg/core/utils/Global.h"
#include "moho/serialization/CPrefetchSet.h"
#include "moho/serialization/PrefetchHandleBaseVectorReflection.h"
#include "gpg/core/reflection/Reflection.h"

namespace moho
{
} // namespace moho

namespace
{
} // namespace

namespace moho
{
  /**
   * Inlined into `gpg::SerSaveLoadHelper<CPrefetchSet>::Deserialize` 0x004A55F0.
   */
  void CPrefetchSet::MemberDeserialize(gpg::ReadArchive* const archive, const int, const gpg::RRef& ownerRef)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    archive->Read(gpg::ResolvePrefetchHandleBaseVectorType(), this, ownerRef);
  }

  /**
   * Inlined into `gpg::SerSaveLoadHelper<CPrefetchSet>::Serialize` 0x004A5630.
   */
  void CPrefetchSet::MemberSerialize(gpg::WriteArchive* const archive, const int, const gpg::RRef& ownerRef)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    archive->Write(gpg::ResolvePrefetchHandleBaseVectorType(), this, ownerRef);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CPrefetchSet>`, vtable 0x00E07324.
   *
   * Address: 0x00BC5990 (FUN_00BC5990 -- constructs the global and registers its destructor.)
   * Address: 0x00BF03A0 (FUN_00BF03A0 -- the global's destructor.)
   * Address: 0x004A5F50 (FUN_004A5F50 -- `Init`.)
   * Address: 0x004A55F0 (FUN_004A55F0 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x004A5630 (FUN_004A5630 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct CPrefetchSetSerializer : gpg::SerSaveLoadHelper<CPrefetchSet>
  {};
} // namespace moho

namespace
{
  // Address: 0x010A87D4 -- process-global `CPrefetchSetSerializer` singleton.
  moho::CPrefetchSetSerializer gCPrefetchSetSerializer;
} // namespace
