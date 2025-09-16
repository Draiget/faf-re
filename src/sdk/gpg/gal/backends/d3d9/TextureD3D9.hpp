// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace gpg {
namespace gal {
    /**
     * VFTABLE: 0x00D481D4
     * COL:  0x00E53720
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\TextureD3D9.cpp
     */
    class TextureD3D9 {
    public:
      /**
       * Address: 0x0094AB60
       * Slot: 0
       * Demangled: sub_94AB60
       */
      virtual void sub_94AB60() = 0;
      /**
       * Address: 0x0094A080
       * Slot: 1
       * Demangled: gpg::gal::TextureD3D9::GetContext
       */
      virtual void GetContext() = 0;
      /**
       * Address: 0x0094A150
       * Slot: 2
       * Demangled: gpg::gal::TextureD3D9::Lock
       */
      virtual void Lock() = 0;
      /**
       * Address: 0x0094A410
       * Slot: 3
       * Demangled: gpg::gal::TextureD3D9::Unlock
       */
      virtual void Unlock() = 0;
      /**
       * Address: 0x0094A090
       * Slot: 4
       * Demangled: gpg::gal::TextureD3D9::Func1
       */
      virtual void Func1() = 0;
      /**
       * Address: 0x0094A630
       * Slot: 5
       * Demangled: gpg::gal::TextureD3D9::SaveToBuffer
       */
      virtual void SaveToBuffer() = 0;
    };
} // namespace gal
} // namespace gpg
