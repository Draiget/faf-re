#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{

  /**
   * Address: 0x008F7F30 (FUN_008F7F30)
   *
   * IDA signature:
   * char *__thiscall CubeRenderTargetD3D10::CubeRenderTargetD3D10(CubeRenderTargetD3D10 *this@<ecx>);
   *
   * What it does:
   * Default-initializes one `CubeRenderTargetD3D10` wrapper: applies its
   * vftable at `this+0x00` and default-constructs the embedded
   * `CubeRenderTargetContext` at `this+0x04`.
   */
  CubeRenderTargetD3D10::CubeRenderTargetD3D10()
    : context_()
  {
  }

  /**
   * Address: 0x008F7F80 (FUN_008F7F80)
   *
   * CubeRenderTargetContext const *
   *
   * What it does:
   * Initializes one cube-render-target wrapper and default-constructs context lane.
   */
  CubeRenderTargetD3D10::CubeRenderTargetD3D10(const CubeRenderTargetContext* const context)
    : context_()
  {
    static_cast<void>(context);
  }

  /**
   * Address: 0x008F8030 (FUN_008F8030)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates non-deleting body lanes.
   */
  CubeRenderTargetD3D10::~CubeRenderTargetD3D10() = default;

  /**
   * Address: 0x008F8020 (FUN_008F8020)
   *
   * What it does:
   * Returns the embedded cube-render-target context lane at `this+0x04`.
   */
  CubeRenderTargetContext* CubeRenderTargetD3D10::GetContext()
  {
    return &context_;
  }
}

