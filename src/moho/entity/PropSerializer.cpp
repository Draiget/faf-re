#include "moho/entity/PropSerializer.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/entity/Prop.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  template <typename T>
  [[nodiscard]] gpg::RType* ResolveSerializerType(gpg::RType*& cache)
  {
    if (cache == nullptr) {
      cache = gpg::LookupRType(typeid(T));
    }
    GPG_ASSERT(cache != nullptr);
    return cache;
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
   * Inlined into `gpg::SerSaveLoadHelper<SPropPriorityInfo>::Deserialize` 0x006F9BE0.
   */
  void SPropPriorityInfo::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    archive->ReadInt(&mPriority);
    archive->ReadInt(&mBoundedTick);
  }

  /**
   * Inlined into `gpg::SerSaveLoadHelper<SPropPriorityInfo>::Serialize` 0x006F9C10.
   */
  void SPropPriorityInfo::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    archive->WriteInt(mPriority);
    archive->WriteInt(mBoundedTick);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SPropPriorityInfo>`, vtable 0x00E2F4C4.
   *
   * Address: 0x00BD9840 (FUN_00BD9840 -- constructs the global and registers its destructor.)
   * Address: 0x00BFF140 (FUN_00BFF140 -- the global's destructor.)
   * Address: 0x006FA8C0 (FUN_006FA8C0 -- `Init`.)
   * Address: 0x006F9BE0 (FUN_006F9BE0 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x006F9C10 (FUN_006F9C10 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct SPropPriorityInfoSerializer : gpg::SerSaveLoadHelper<SPropPriorityInfo>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B8710 -- process-global `SPropPriorityInfoSerializer` singleton.
  moho::SPropPriorityInfoSerializer gSPropPriorityInfoSerializer;
} // namespace
