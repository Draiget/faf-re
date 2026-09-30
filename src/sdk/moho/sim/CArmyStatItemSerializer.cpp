
#include <cstddef>
#include <typeinfo>

#include "moho/sim/CArmyStats.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  gpg::RType* gStatItemType = nullptr;
  gpg::RType* gBlueprintStatsType = nullptr;

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
   * Address: 0x00714750 (FUN_00714750)
   *
   * What it does:
   * Deserializes one `CArmyStatItem` lane by loading `StatItem` base state and
   * the blueprint-weight map payload.
   */
  void CArmyStatItem::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef owner{};
    archive->Read(CachedType<moho::StatItem>(gStatItemType), static_cast<moho::StatItem*>(this), owner);
    archive->Read(CachedType<moho::ArmyBlueprintStatTree>(gBlueprintStatsType), &mBlueprintStats, owner);
  }

  /**
   * Address: 0x007147D0 (FUN_007147D0)
   *
   * What it does:
   * Serializes one `CArmyStatItem` lane by saving `StatItem` base state and
   * the blueprint-weight map payload.
   */
  void CArmyStatItem::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef owner{};
    archive->Write(
      CachedType<moho::StatItem>(gStatItemType),
      const_cast<moho::StatItem*>(static_cast<const moho::StatItem*>(this)),
      owner
    );
    archive->Write(CachedType<moho::ArmyBlueprintStatTree>(gBlueprintStatsType), &mBlueprintStats, owner);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CArmyStatItem>`, vtable 0x00E311D8.
   *
   * Address: 0x00BDA120 (FUN_00BDA120 -- constructs the global and registers its destructor.)
   * Address: 0x00BFF730 (FUN_00BFF730 -- the global's destructor.)
   * Address: 0x0070EEE0 (FUN_0070EEE0 -- `Init`.)
   * Address: 0x0070B770 (FUN_0070B770 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x0070B780 (FUN_0070B780 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CArmyStatItemSerializer : gpg::SerSaveLoadHelper<CArmyStatItem>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B8F8C -- process-global `CArmyStatItemSerializer` singleton.
  moho::CArmyStatItemSerializer gCArmyStatItemSerializer;
} // namespace
