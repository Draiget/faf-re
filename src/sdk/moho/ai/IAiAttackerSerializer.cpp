
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiAttacker.h"
#include "gpg/core/reflection/Reflection.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedAttackerBroadcasterType()
  {
    gpg::RType* type = Broadcaster<EAiAttackerEvent>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(Broadcaster<EAiAttackerEvent>));
      Broadcaster<EAiAttackerEvent>::sType = type;
    }
    return type;
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x005DE8D0 (FUN_005DE8D0, sub_5DE8D0)
   */
  void IAiAttacker::MemberDeserialize(gpg::ReadArchive* const archive, const int, const gpg::RRef& const)
  {
    if (!archive) {
      return;
    }

    void* const broadcasterLane = (this != nullptr) ? static_cast<void*>(static_cast<Broadcaster<EAiAttackerEvent>*>(this)) : nullptr;
    gpg::RType* const broadcasterType = CachedAttackerBroadcasterType();
    GPG_ASSERT(broadcasterType != nullptr);
    const gpg::RRef ownerRef{};
    archive->Read(broadcasterType, broadcasterLane, ownerRef);
  }

  /**
   * Address: 0x005DE920 (FUN_005DE920, sub_5DE920)
   */
  void IAiAttacker::MemberSerialize(gpg::WriteArchive* const archive, const int, const gpg::RRef& const) const
  {
    if (!archive) {
      return;
    }

    const void* const broadcasterLane = (this != nullptr) ? static_cast<const void*>(static_cast<const Broadcaster<EAiAttackerEvent>*>(this)) : nullptr;
    gpg::RType* const broadcasterType = CachedAttackerBroadcasterType();
    GPG_ASSERT(broadcasterType != nullptr);
    const gpg::RRef ownerRef{};
    archive->Write(broadcasterType, broadcasterLane, ownerRef);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<IAiAttacker>`, vtable 0x00E1E9B8.
   *
   * Address: 0x00BCE7D0 (FUN_00BCE7D0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF82E0 (FUN_00BF82E0 -- the global's destructor.)
   * Address: 0x005DBC90 (FUN_005DBC90 -- `Init`.)
   * Address: 0x005D5C50 (FUN_005D5C50 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x005D5C60 (FUN_005D5C60 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct IAiAttackerSerializer : gpg::SerSaveLoadHelper<IAiAttacker>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B0344 -- process-global `IAiAttackerSerializer` singleton.
  moho::IAiAttackerSerializer gIAiAttackerSerializer;
} // namespace
