// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "boost/shared_ptr.h"

namespace gpg {
namespace gal {
    class EffectContext;

    /**
     * VFTABLE: 0x00D47D24
     * COL:  0x00E53238
     */
    class Effect {
    public:
      /**
       * EffectContext const &
       *
       * What it does:
       * Creates one backend effect instance from one prepared effect context.
       */
      static boost::shared_ptr<Effect> Create(const EffectContext& context);

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
      /**
       * Address: 0x00A82547
       * Slot: 4
       * Demangled: _purecall
       */
      virtual void purecall4() = 0;
      /**
       * Address: 0x00A82547
       * Slot: 5
       * Demangled: _purecall
       */
      virtual void purecall5() = 0;
      /**
       * Address: 0x00A82547
       * Slot: 6
       * Demangled: _purecall
       */
      virtual void purecall6() = 0;
    };
} // namespace gal
} // namespace gpg
