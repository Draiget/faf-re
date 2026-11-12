#include "ISimResources.h"
#include "CSimResources.h"

namespace
{
  void DeleteSimResourcesOwned(
    moho::CSimResources* resources
  ) noexcept
  {
    // Binary invokes the scalar deleting destructor through vtable slot 0,
    // which is exactly what `delete` compiles to for this virtual hierarchy.
    delete resources;
  }

  class SimResourcesSharedControl final : public boost::detail::sp_counted_base
  {
  public:
    explicit SimResourcesSharedControl(
      moho::CSimResources* resources
    ) noexcept
      : resources_(resources)
    {}

    void dispose() noexcept override
    {
      DeleteSimResourcesOwned(resources_);
      resources_ = nullptr;
    }

    void* get_deleter(
      boost::detail::sp_typeinfo const&
    ) noexcept override
    {
      return nullptr;
    }

  private:
    moho::CSimResources* resources_;
  };

  static_assert(sizeof(SimResourcesSharedControl) == 0x10, "SimResourcesSharedControl size must be 0x10");

  void NoopSimResourcesSharedHook(
    moho::CSimResources*,
    boost::detail::sp_counted_base*
  ) noexcept
  {
    // Address: 0x0042AC30 (FUN_0042AC30, nullsub_1)
  }
} // namespace

namespace moho
{
  gpg::RType* ISimResources::sType = nullptr;

  /**
   * Address: 0x00546E70 (FUN_00546E70)
   */
  ISimResources::ISimResources() = default;
} // namespace moho

namespace moho::detail
{
  /**
   * Address: 0x00754BD0 (FUN_00754BD0, func_CreateBoostPtrISimResources)
   *
   * What it does:
   * Allocates a shared control block for `CSimResources`, and ensures
   * exception-safety by deleting `resources` on control-block construction
   * failure.
   */
  boost::detail::sp_counted_base* CreateSimResourcesSharedControl(
    CSimResources* resources
  )
  {
    try {
      return new SimResourcesSharedControl(resources);
    } catch (...) {
      DeleteSimResourcesOwned(resources);
      throw;
    }
  }

} // namespace moho::detail
