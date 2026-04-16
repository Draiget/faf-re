// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace gpg {
namespace gal {
    /**
     * VFTABLE: 0x00D421B8
     * COL:  0x00E50470
     */
    class DepthStencilTarget {
    public:
      /**
       * Address: 0x008E7E90 (FUN_008E7E90)
       * Address: 0x008E7EA0 (FUN_008E7EA0)
       *
       * What it does:
       * Initializes one abstract depth-stencil target base lane.
       */
      DepthStencilTarget();

      /**
       * Address: 0x00A82547
       * Slot: 0
       * Demangled: _purecall
       */
      virtual void purecall0() = 0;
      /**
       * Address: 0x00A82547
       * Slot: 1
       * Demangled: _purecall
       */
      virtual void purecall1() = 0;
    };
} // namespace gal
} // namespace gpg
