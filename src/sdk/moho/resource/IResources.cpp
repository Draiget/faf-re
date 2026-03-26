#include "IResources.h"

namespace moho
{
  gpg::RType* IResources::sType = nullptr;

  /**
   * Address: 0x00546E80 (loc_00546E80, shared constructor/destructor helper chunk)
   *
   * What it does:
   * Initializes the IResources base-subobject vtable slot.
   */
  IResources::IResources() noexcept = default;

  /**
   * Address: 0x00546E80 (loc_00546E80, shared constructor/destructor helper chunk)
   *
   * What it does:
   * Tears down the IResources base-subobject vtable state.
   */
  IResources::~IResources() noexcept = default;
} // namespace moho
