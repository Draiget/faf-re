// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace gpg
{
  namespace gal
  {
    /**
     * VFTABLE: 0x00D42F08
     * COL:  0x00E50AB8
     */
    class VertexBuffer
    {
    public:
      /**
       * Address: 0x008F56A0 (FUN_008F56A0, gpg::gal::VertexBuffer::VertexBuffer)
       *
       * What it does:
       * Initializes one abstract vertex-buffer base object and applies the
       * base vftable lane used by derived constructors/unwind paths.
       */
      VertexBuffer();

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
      /**
       * Address: 0x00A82547
       * Slot: 2
       * Demangled: _purecall
       */
      virtual void purecall2() = 0;
      /**
       * Address: 0x00A82547
       * Slot: 3
       * Demangled: _purecall
       */
      virtual void purecall3() = 0;
    };
  } // namespace gal
} // namespace gpg
