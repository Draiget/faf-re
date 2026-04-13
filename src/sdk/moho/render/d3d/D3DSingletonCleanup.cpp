#include "moho/render/d3d/D3DSingletonCleanup.h"

#include <cstdint>
#include <cstdlib>

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DVertexStream.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/CD3DVertexFormat.h"
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
  CD3DVertexStream*& SharedVertexStreamSlot() noexcept
  {
    return D3DSingletonSlot<0x10A792Cu, CD3DVertexStream>::value;
  }

  CD3DIndexSheet*& SharedIndexSheetSlot() noexcept
  {
    return D3DSingletonSlot<0x10A7928u, CD3DIndexSheet>::value;
  }

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

  /**
   * Address: 0x0043C690 (FUN_0043C690, sub_43C690)
   *
   * IDA signature:
   * int sub_43C690(Moho::CD3DVertexFormat *a2, int a3);
   *
   * What it does:
   * Creates one shared `CD3DVertexStream` holding 0x10000 vertices of
   * `vertexFormat`, installs it into the `sVertexStream` singleton slot
   * (releasing any previous holder), locks its buffer starting 20
   * bytes into the mapped region, writes 0x4000 unit-quad corner
   * templates (each 8 floats: two (x,y) pairs + two (u,v) pairs
   * matching the original binary layout), and unlocks the stream.
   */
  void func_CreateSharedVertexStream(CD3DVertexFormat* const vertexFormat)
  {
    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();
    CD3DVertexStream* const newStream = resources->Func5(0u, 1, 0x10000, vertexFormat);

    CD3DVertexStream*& slot = SharedVertexStreamSlot();
    if (newStream != slot && slot != nullptr) {
      delete slot;
    }
    slot = newStream;

    constexpr int kQuadCount = 0x4000;
    auto* const mappedBase = static_cast<std::uint32_t*>(slot->Lock(0, kQuadCount, false, false));
    std::uint32_t* cursor = mappedBase + 5;
    for (int i = 0; i < kQuadCount; ++i) {
      cursor[-5] = 0u;
      cursor[-4] = 0u;
      cursor[-3] = 0x3F800000u; // 1.0f
      cursor[-2] = 0u;
      cursor[-1] = 0x3F800000u; // 1.0f
      cursor[ 0] = 0x3F800000u; // 1.0f
      cursor[ 1] = 0u;
      cursor[ 2] = 0x3F800000u; // 1.0f
      cursor += 8;
    }
    slot->Unlock();
  }

  /**
   * Address: 0x0043C800 (FUN_0043C800, func_InitIndexSheet)
   *
   * IDA signature:
   * void func_InitIndexSheet();
   *
   * What it does:
   * Lazily creates the shared index sheet (0x18000 indices, static
   * usage) via the device resources, swaps it into the `sIndexSheet`
   * singleton slot, then locks the entire sheet and fills it with the
   * repeating quad index pattern (per quad q in 0..0x3FFF the sequence
   * `4q, 4q+1, 4q+2, 4q, 4q+2, 4q+3`), unlocking when finished.
   */
  void func_InitSharedIndexSheet()
  {
    CD3DIndexSheet*& slot = SharedIndexSheetSlot();
    if (slot != nullptr) {
      return;
    }

    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();
    CD3DIndexSheet* const newSheet = resources->CreateIndexSheet(false, 0x18000);

    if (newSheet != slot && slot != nullptr) {
      delete slot;
    }
    slot = newSheet;

    const std::uint32_t indexByteSize = slot->GetSize();
    std::int16_t* const base = slot->Lock(0u, indexByteSize, false, false);

    constexpr unsigned int kQuadCount = 0x4000u;
    std::int16_t* cursor = base;
    for (unsigned int q = 0; q < kQuadCount; ++q) {
      const std::int16_t v0 = static_cast<std::int16_t>(4u * q);
      const std::int16_t v1 = static_cast<std::int16_t>(4u * q + 1u);
      const std::int16_t v2 = static_cast<std::int16_t>(4u * q + 2u);
      const std::int16_t v3 = static_cast<std::int16_t>(4u * q + 3u);
      cursor[0] = v0;
      cursor[1] = v1;
      cursor[2] = v2;
      cursor[3] = v0;
      cursor[4] = v2;
      cursor[5] = v3;
      cursor += 6;
    }
    slot->Unlock();
  }

  /**
   * Address: 0x0043C8E0 (FUN_0043C8E0, sub_43C8E0)
   *
   * IDA signature:
   * Moho::CD3DIndexSheet *sub_43C8E0();
   *
   * What it does:
   * Returns the shared index sheet, initializing it first when the
   * singleton slot is still empty.
   */
  CD3DIndexSheet* func_GetSharedIndexSheet()
  {
    CD3DIndexSheet* const current = SharedIndexSheetSlot();
    if (current != nullptr) {
      return current;
    }
    func_InitSharedIndexSheet();
    return SharedIndexSheetSlot();
  }

  /**
   * Address: 0x0043C900 (FUN_0043C900, sub_43C900)
   *
   * IDA signature:
   * int sub_43C900();
   *
   * What it does:
   * Deletes the shared index-sheet singleton (if present) through
   * its deleting dtor thunk and clears the slot.
   */
  void func_ClearSharedIndexSheet()
  {
    CD3DIndexSheet*& slot = SharedIndexSheetSlot();
    if (slot != nullptr) {
      delete slot;
    }
    slot = nullptr;
  }

  /**
   * Address: 0x0043CA50 (FUN_0043CA50, sub_43CA50)
   *
   * IDA signature:
   * Moho::CD3DVertexStream **__stdcall sub_43CA50(Moho::CD3DVertexStream **a1);
   *
   * What it does:
   * Moves the vertex-stream pointer out of caller storage into the
   * `sVertexStream` singleton slot. The caller slot is nulled first;
   * the prior singleton holder is deleted through its deleting dtor
   * thunk when it differs from the incoming stream. Returns the
   * address of the updated singleton slot.
   */
  CD3DVertexStream** func_MoveIntoSharedVertexStream(CD3DVertexStream** const inOutStream)
  {
    CD3DVertexStream* const incoming = *inOutStream;
    *inOutStream = nullptr;

    CD3DVertexStream*& slot = SharedVertexStreamSlot();
    if (incoming != slot && slot != nullptr) {
      delete slot;
    }
    slot = incoming;
    return &slot;
  }

  /**
   * Address: 0x0043CAF0 (FUN_0043CAF0, sub_43CAF0)
   *
   * IDA signature:
   * int __usercall sub_43CAF0@<eax>(Moho::CD3DVertexStream *a1@<esi>);
   *
   * What it does:
   * Replaces the `sVertexStream` singleton with `stream`, releasing
   * the prior holder through its deleting dtor thunk when present
   * and distinct from the new stream.
   */
  void func_SetSharedVertexStream(CD3DVertexStream* const stream)
  {
    CD3DVertexStream*& slot = SharedVertexStreamSlot();
    if (stream != slot && slot != nullptr) {
      delete slot;
    }
    slot = stream;
  }
} // namespace moho
