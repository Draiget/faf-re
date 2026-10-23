
#include <cstddef>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"
#include "moho/serialization/SBlackListInfo.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  [[nodiscard]] gpg::RType* ResolveWeakPtrEntityType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::WeakPtr<moho::Entity>));
    }

    GPG_ASSERT(cached != nullptr);
    return cached;
  }

} // namespace

namespace moho
{
} // namespace moho

namespace
{
} // namespace

namespace moho
{
  /**
   * Address: 0x006DD2B0 (FUN_006DD2B0, weakptr+int load body)
   *
   * What it does:
   * Loads the reflected `WeakPtr<Entity>` lane and the trailing integer payload.
   */
  void SBlackListInfo::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(ResolveWeakPtrEntityType(), &mEntity, nullOwner);
    archive->ReadInt(&mValue);
  }

  /**
   * Address: 0x006DD300 (FUN_006DD300, weakptr+int save body)
   *
   * What it does:
   * Saves the reflected `WeakPtr<Entity>` lane and the trailing integer payload.
   */
  void SBlackListInfo::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(ResolveWeakPtrEntityType(), &mEntity, nullOwner);
    archive->WriteInt(mValue);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SBlackListInfo>`, vtable 0x00E2E268.
   *
   * Address: 0x00BD8830 (FUN_00BD8830 -- constructs the global and registers its destructor.)
   * Address: 0x00BFE680 (FUN_00BFE680 -- the global's destructor.)
   * Address: 0x006DB560 (FUN_006DB560 -- `Init`.)
   * Address: 0x006D3980 (FUN_006D3980 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x006D3990 (FUN_006D3990 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SBlackListInfoSerializer : gpg::SerSaveLoadHelper<SBlackListInfo>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B7DB8 -- process-global `SBlackListInfoSerializer` singleton.
  moho::SBlackListInfoSerializer gSBlackListInfoSerializer;
} // namespace
