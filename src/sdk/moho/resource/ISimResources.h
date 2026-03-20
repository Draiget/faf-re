#pragma once

#include "../../gpg/core/utils/BoostWrappers.h"
#include <type_traits>

namespace moho
{
  class ISimResources;
  class CSimResources;
  using SimResourcesHandle = boost::BorrowedSharedPtr<ISimResources>;

  class ISimResources
  {
  protected:
    ~ISimResources() = default;
  };

  namespace detail
  {
    /**
     * Address: 0x00754BD0 (FUN_00754BD0, func_CreateBoostPtrISimResources)
     *
     * What it does:
     * Allocates and initializes the Boost-style shared control block used for
     * `CSimResources` ownership through `ISimResources` handles.
     */
    [[nodiscard]] boost::detail::sp_counted_base* CreateSimResourcesSharedControl(CSimResources* resources);

    /**
     * Address: 0x00753800 (FUN_00753800, sub_753800)
     *
     * What it does:
     * Initializes a fresh raw shared handle from `resources` and a newly
     * constructed control block.
     */
    boost::SharedPtrRaw<ISimResources>&
    InitSharedISimResources(boost::SharedPtrRaw<ISimResources>& outHandle, CSimResources* resources);

    /**
     * Address: 0x00750EA0 (FUN_00750EA0, func_CreateWeakPtrISimResources)
     *
     * What it does:
     * Rebinds an existing raw shared handle to `resources`, releasing the prior
     * control block strong reference.
     */
    void AssignSharedISimResources(boost::SharedPtrRaw<ISimResources>& outHandle, CSimResources* resources);
  } // namespace detail

  static_assert(sizeof(ISimResources) == 0x1, "ISimResources size must be 0x1");
  static_assert(!std::is_polymorphic<ISimResources>::value, "ISimResources must be non-polymorphic");
} // namespace moho
