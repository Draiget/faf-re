#include "ID3DRenderTarget.h"

namespace moho
{
  /**
   * Address: 0x0043EC50 (FUN_0043EC50, sub_43EC50)
   *
   * What it does:
   * Initializes the base interface vftable lane for derived render targets.
   */
  ID3DRenderTarget::ID3DRenderTarget() = default;

  /**
   * Address: 0x0043CC90 (FUN_0043CC90, sub_43CC90)
   *
   * What it does:
   * Resets base vftable state and owns the deleting-destructor entrypoint.
   */
  ID3DRenderTarget::~ID3DRenderTarget() = default;
} // namespace moho
