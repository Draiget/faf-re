#pragma once

#include "../../gpg/core/utils/BoostWrappers.h"
#include <type_traits>

#include "IResources.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class ISimResources;
  class CSimResources;
  using SimResourcesHandle = boost::BorrowedSharedPtr<ISimResources>;

  class ISimResources : public IResources
  {
  public:
    static gpg::RType* sType;

  protected:
    /**
     * Address: 0x00546E70 (FUN_00546E70)
     *
     * What it does:
     * Initializes one `ISimResources` interface subobject vtable lane.
     */
    ISimResources();
    ~ISimResources() override = default;
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

  } // namespace detail

  static_assert(sizeof(ISimResources) == 0x4, "ISimResources size must be 0x4");
  static_assert(std::is_polymorphic<ISimResources>::value, "ISimResources must remain polymorphic");
  static_assert(std::is_abstract<ISimResources>::value, "ISimResources must remain abstract");
} // namespace moho
