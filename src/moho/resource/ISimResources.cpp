#include "ISimResources.h"
#include "CSimResources.h"

namespace moho
{
  gpg::RType* ISimResources::sType = nullptr;

  /**
   * Address: 0x00546E70 (FUN_00546E70)
   *
   * `CSimResources` objects are owned by `boost::shared_ptr<CSimResources>` (`Sim::mSimResources`); their
   * `sp_enable_shared_from_this` step is the shared no-op at 0x0042AC30 (FUN_0042AC30, nullsub_1). A hand-built
   * control block for them, with no users, was removed from this file.
   */
  ISimResources::ISimResources() = default;
} // namespace moho

namespace moho::detail
{

} // namespace moho::detail
