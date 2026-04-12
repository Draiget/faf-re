#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/effects/rendering/CEffectImpl.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E240B4
   * COL: 0x00E7E5E4
   *
   * Particle emitter effect implementation.
   * Derives from CEffectImpl; binary size is 0x6F8.
   * Full field layout not yet recovered -- placeholder padding preserves size.
   */
  class CEfxEmitter : public CEffectImpl
  {
  public:
    ~CEfxEmitter() override;

  private:
    // Unrecovered fields: 0x6F8 - sizeof(CEffectImpl) = 0x568 bytes.
    std::uint8_t mUnrecoveredFields[0x6F8 - sizeof(CEffectImpl)]{};
  };

  static_assert(sizeof(CEfxEmitter) == 0x6F8, "CEfxEmitter size must be 0x6F8");
} // namespace moho
