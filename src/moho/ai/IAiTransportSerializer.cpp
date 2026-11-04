
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiTransport.h"
#include "gpg/core/reflection/Reflection.h"

using namespace moho;

namespace
{

} // namespace

namespace moho
{
  /**
   * Address: 0x005EBC80 (FUN_005EBC80)
   *
   * What it does:
   * Loads the `Broadcaster<EAiTransportEvent>` base.
   */
  void IAiTransport::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    archive->Read(gpg::RTypeOf<moho::Broadcaster<moho::EAiTransportEvent>>(), static_cast<Broadcaster<EAiTransportEvent>*>(this), gpg::RRef{});
  }

  /**
   * Address: 0x005EBCD0 (FUN_005EBCD0)
   *
   * What it does:
   * Saves the `Broadcaster<EAiTransportEvent>` base.
   */
  void IAiTransport::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    archive->Write(gpg::RTypeOf<moho::Broadcaster<moho::EAiTransportEvent>>(), static_cast<const Broadcaster<EAiTransportEvent>*>(this), gpg::RRef{});
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<IAiTransport>`, vtable 0x00E1F3B8.
   *
   * Address: 0x00BCEEB0 (FUN_00BCEEB0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF8BB0 (FUN_00BF8BB0 -- the global's destructor.)
   * Address: 0x005E9530 (FUN_005E9530 -- `Init`.)
   * Address: 0x005E4880 (FUN_005E4880 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x005E4890 (FUN_005E4890 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct IAiTransportSerializer : gpg::SerSaveLoadHelper<IAiTransport>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B06D4 -- process-global `IAiTransportSerializer` singleton.
  moho::IAiTransportSerializer gIAiTransportSerializer;
} // namespace
