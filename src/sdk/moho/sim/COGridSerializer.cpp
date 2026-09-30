
#include <cstddef>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/sim/COGrid.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
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
   * Inlined into `gpg::SerSaveLoadHelper<COGrid>::Deserialize` 0x00722CC0.
   */
  void COGrid::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    gpg::RRef selfRef{};
    selfRef = gpg::MakeRRef<moho::COGrid>(this);
    archive->TrackPointer(selfRef);
  }

  /**
   * Inlined into `gpg::SerSaveLoadHelper<COGrid>::Serialize` 0x00722D00.
   */
  void COGrid::MemberSerialize(gpg::WriteArchive* const archive)
  {
    gpg::RRef selfRef{};
    selfRef = gpg::MakeRRef<moho::COGrid>(this);
    archive->PreCreatedPtr(selfRef);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<COGrid>`, vtable 0x00E3195C.
   *
   * Address: 0x00BDAAB0 (FUN_00BDAAB0 -- constructs the global and registers its destructor.)
   * Address: 0x00C003E0 (FUN_00C003E0 -- the global's destructor.)
   * Address: 0x00722D40 (FUN_00722D40 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x00722F90 (FUN_00722F90 -- `Init`.)
   * Address: 0x00722CC0 (FUN_00722CC0 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x00722D00 (FUN_00722D00 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct COGridSerializer : gpg::SerSaveLoadHelper<COGrid>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B95D0 -- process-global `COGridSerializer` singleton.
  moho::COGridSerializer gCOGridSerializer;
} // namespace
