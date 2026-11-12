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

  } // namespace detail

  static_assert(sizeof(ISimResources) == 0x4, "ISimResources size must be 0x4");
  static_assert(std::is_polymorphic<ISimResources>::value, "ISimResources must remain polymorphic");
  static_assert(std::is_abstract<ISimResources>::value, "ISimResources must remain abstract");
} // namespace moho
