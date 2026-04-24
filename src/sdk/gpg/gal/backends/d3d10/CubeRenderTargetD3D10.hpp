// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include <cstddef>

#include "gpg/gal/CubeRenderTargetContext.hpp"

namespace gpg {
namespace gal {
    /**
     * VFTABLE: 0x00D4300C
     * COL:  0x00E50BE8
     */
    class CubeRenderTargetD3D10 {
    public:
      /**
       * Address: 0x008F7F30 (FUN_008F7F30)
       *
       * What it does:
       * Default-initializes one D3D10 cube-render-target wrapper and
       * default-constructs the embedded cube-render-target context lane
       * (dimension and format both zeroed).
       */
      CubeRenderTargetD3D10();

      /**
       * Address: 0x008F7F80 (FUN_008F7F80)
       *
       * CubeRenderTargetContext const *
       *
       * What it does:
       * Initializes one cube-render-target wrapper and default-constructs the
       * embedded context lane.
       */
      explicit CubeRenderTargetD3D10(const CubeRenderTargetContext* context);
      /**
       * Address: 0x008F8030 (FUN_008F8030)
       *
       * What it does:
       * Owns the deleting-destructor path for the wrapper and delegates body cleanup.
       */
      virtual ~CubeRenderTargetD3D10();

      /**
       * Address: 0x008F8020 (FUN_008F8020)
       *
       * What it does:
       * Returns the embedded cube-render-target context lane at `this+0x04`.
       */
      virtual CubeRenderTargetContext* GetContext();

    public:
      CubeRenderTargetContext context_{}; // +0x04
    };

    static_assert(offsetof(CubeRenderTargetD3D10, context_) == 0x04, "CubeRenderTargetD3D10::context_ offset must be 0x04");
    static_assert(sizeof(CubeRenderTargetD3D10) == 0x10, "CubeRenderTargetD3D10 size must be 0x10");
} // namespace gal
} // namespace gpg
