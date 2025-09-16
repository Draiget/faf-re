// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace gpg {
namespace gal {
    /**
     * VFTABLE: 0x00D47D6C
     * COL:  0x00E5331C
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\EffectD3D9.cpp
     * Log/code strings:
     *  - invalid effect variable requested: 
     *  - invalid effect technique requested: 
     */
    class EffectD3D9 {
    public:
      /**
       * Address: 0x00942EC0
       * Slot: 0
       * Demangled: sub_942EC0
       */
      virtual void sub_942EC0() = 0;
      /**
       * Address: 0x009415B0
       * Slot: 1
       * Demangled: gpg::gal::EffectD3D9::GetContext
       */
      virtual void GetContext() = 0;
      /**
       * Address: 0x00942920
       * Slot: 2
       * Demangled: gpg::gal::EffectD3D9::GetTechniques
       */
      virtual void GetTechniques() = 0;
      /**
       * Address: 0x00941D70
       * Slot: 3
       * Demangled: gpg::gal::EffectD3D9::SetMatrix
       */
      virtual void SetMatrix() = 0;
      /**
       * Address: 0x00941F60
       * Slot: 4
       * Demangled: gpg::gal::EffectD3D9::SetTechnique
       */
      virtual void SetTechnique() = 0;
      /**
       * Address: 0x00942150
       * Slot: 5
       * Demangled: gpg::gal::EffectD3D9::OnReset
       */
      virtual void OnReset() = 0;
      /**
       * Address: 0x00942290
       * Slot: 6
       * Demangled: gpg::gal::EffectD3D9::OnLost
       */
      virtual void OnLost() = 0;
    };
} // namespace gal
} // namespace gpg
