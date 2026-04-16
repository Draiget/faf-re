#include "ISimResources.h"
#include "CSimResources.h"

namespace
{
  using DeletingDestructorFn = int(__thiscall*)(void*, int);

  void DeleteSimResourcesViaVTable(moho::CSimResources* resources) noexcept
  {
    if (resources == nullptr) {
      return;
    }

    auto* const vftable = *reinterpret_cast<DeletingDestructorFn**>(resources);
    if (vftable == nullptr || vftable[0] == nullptr) {
      return;
    }

    vftable[0](resources, 1);
  }

  class SimResourcesSharedControl final : public boost::detail::sp_counted_base
  {
  public:
    explicit SimResourcesSharedControl(moho::CSimResources* resources) noexcept
      : resources_(resources)
    {}

    void dispose() noexcept override
    {
      DeleteSimResourcesViaVTable(resources_);
      resources_ = nullptr;
    }

    void* get_deleter(boost::detail::sp_typeinfo const&) noexcept override
    {
      return nullptr;
    }

  private:
    moho::CSimResources* resources_;
  };

  static_assert(sizeof(SimResourcesSharedControl) == 0x10, "SimResourcesSharedControl size must be 0x10");

  void NoopSimResourcesSharedHook(moho::CSimResources*, boost::detail::sp_counted_base*) noexcept
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
  boost::detail::sp_counted_base* CreateSimResourcesSharedControl(CSimResources* resources)
  {
    try {
      return new SimResourcesSharedControl(resources);
    } catch (...) {
      DeleteSimResourcesViaVTable(resources);
      throw;
    }
  }

  /**
   * Address: 0x00753800 (FUN_00753800, sub_753800)
   *
   * What it does:
   * Initializes one raw shared handle from `resources` and a fresh control block.
   */
  boost::SharedPtrRaw<ISimResources>&
  InitSharedISimResources(boost::SharedPtrRaw<ISimResources>& outHandle, CSimResources* resources)
  {
    outHandle.px = resources;
    outHandle.pi = CreateSimResourcesSharedControl(resources);
    NoopSimResourcesSharedHook(resources, outHandle.pi);
    return outHandle;
  }

  /**
   * Address: 0x00750EA0 (FUN_00750EA0, func_CreateWeakPtrISimResources)
   *
   * What it does:
   * Rebinds an existing raw shared handle to `resources` and releases the
   * previous strong control-block reference.
   */
  void AssignSharedISimResources(boost::SharedPtrRaw<ISimResources>& outHandle, CSimResources* resources)
  {
    boost::detail::sp_counted_base* const newControl = CreateSimResourcesSharedControl(resources);
    NoopSimResourcesSharedHook(resources, newControl);

    outHandle.px = resources;
    boost::detail::sp_counted_base* const oldControl = outHandle.pi;
    outHandle.pi = newControl;

    if (oldControl != nullptr) {
      oldControl->release();
    }
  }
} // namespace moho::detail
