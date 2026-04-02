#include "moho/render/d3d/D3DSingletonCleanup.h"

#include <cstdint>
#include <cstdlib>

#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/CD3DVertexStream.h"

namespace
{
  template <std::uintptr_t SlotAddress, typename T>
  struct D3DSingletonSlot;

  template <>
  struct D3DSingletonSlot<0x10A792Cu, moho::CD3DVertexStream>
  {
    static moho::CD3DVertexStream* value;
  };
  moho::CD3DVertexStream* D3DSingletonSlot<0x10A792Cu, moho::CD3DVertexStream>::value = nullptr;

  template <>
  struct D3DSingletonSlot<0x10A7928u, moho::CD3DIndexSheet>
  {
    static moho::CD3DIndexSheet* value;
  };
  moho::CD3DIndexSheet* D3DSingletonSlot<0x10A7928u, moho::CD3DIndexSheet>::value = nullptr;

  template <std::uintptr_t SlotAddress, typename T>
  void CleanupD3DSingletonSlot() noexcept
  {
    T* const value = D3DSingletonSlot<SlotAddress, T>::value;
    if (value == nullptr) {
      return;
    }

    delete value;
    D3DSingletonSlot<SlotAddress, T>::value = nullptr;
  }

  template <void (*Cleanup)()>
  void RegisterExitCleanup() noexcept
  {
    (void)std::atexit(Cleanup);
  }

  struct D3DSingletonCleanupBootstrap
  {
    D3DSingletonCleanupBootstrap()
    {
      moho::register_D3DVertexStreamCleanup();
      moho::register_D3DIndexSheetCleanup();
    }
  };

  [[maybe_unused]] D3DSingletonCleanupBootstrap gD3DSingletonCleanupBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BEF190 (FUN_00BEF190, ??1sVertexStream@Moho@@QAE@@Z)
   *
   * What it does:
   * Deletes the recovered global `CD3DVertexStream` singleton when present.
   */
  void cleanup_D3DVertexStream()
  {
    CleanupD3DSingletonSlot<0x10A792Cu, CD3DVertexStream>();
  }

  /**
   * Address: 0x00BC40C0 (FUN_00BC40C0, register_sVertexStream)
   *
   * What it does:
   * Registers the recovered process-exit cleanup thunk for the global
   * `CD3DVertexStream` singleton slot.
   */
  void register_D3DVertexStreamCleanup()
  {
    RegisterExitCleanup<&cleanup_D3DVertexStream>();
  }

  /**
   * Address: 0x00BEF1B0 (FUN_00BEF1B0, ??1sIndexSheet@Moho@@QAE@@Z)
   *
   * What it does:
   * Deletes the recovered global `CD3DIndexSheet` singleton when present.
   */
  void cleanup_D3DIndexSheet()
  {
    CleanupD3DSingletonSlot<0x10A7928u, CD3DIndexSheet>();
  }

  /**
   * Address: 0x00BC40D0 (FUN_00BC40D0, register_sIndexSheet)
   *
   * What it does:
   * Registers the recovered process-exit cleanup thunk for the global
   * `CD3DIndexSheet` singleton slot.
   */
  void register_D3DIndexSheetCleanup()
  {
    RegisterExitCleanup<&cleanup_D3DIndexSheet>();
  }
} // namespace moho
