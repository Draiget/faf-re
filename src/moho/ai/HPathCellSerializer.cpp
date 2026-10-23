
#include <cstddef>
#include <bit>
#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiPathFinder.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
} // namespace

namespace moho
{

  /**
   * Inlined into `gpg::SerSaveLoadHelper<HPathCell>::Deserialize` 0x00762F80.
   */
  void HPathCell::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    static_assert(sizeof(moho::HPathCell) == sizeof(unsigned int), "HPathCell must pack to one unsigned int for archive I/O");

    unsigned int packed = 0;
    archive->ReadUInt(&packed);
    *this = std::bit_cast<moho::HPathCell>(packed);
  }

  /**
   * Inlined into `gpg::SerSaveLoadHelper<HPathCell>::Serialize` 0x00762FA0.
   */
  void HPathCell::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    archive->WriteUInt(std::bit_cast<unsigned int>(*this));
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<HPathCell>`, vtable 0x00E35B1C.
   *
   * Address: 0x00BDC630 (FUN_00BDC630 -- constructs the global and registers its destructor.)
   * Address: 0x00C016E0 (FUN_00C016E0 -- the global's destructor.)
   * Address: 0x007632D0 (FUN_007632D0 -- `Init`.)
   * Address: 0x00762F80 (FUN_00762F80 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x00762FA0 (FUN_00762FA0 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct HPathCellSerializer : gpg::SerSaveLoadHelper<HPathCell>
  {};
} // namespace moho

namespace
{
  // Address: 0x010BAF8C -- process-global `HPathCellSerializer` singleton.
  moho::HPathCellSerializer gHPathCellSerializer;
} // namespace
