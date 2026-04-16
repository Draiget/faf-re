// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace gpg {
namespace gal {
    /**
     * VFTABLE: 0x00D436F0
     * COL:  0x00E510B0
     */
    class PipelineState {
    public:
      /**
       * Address: 0x00902230 (FUN_00902230)
       *
       * What it does:
       * Initializes one base `PipelineState` lane by installing the class
       * vtable.
       */
      PipelineState();

      /**
       * Address: 0x00A82547
       * Slot: 0
       * Demangled: _purecall
       */
      virtual void purecall0() = 0;
    };
} // namespace gal
} // namespace gpg
