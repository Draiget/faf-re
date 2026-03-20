#pragma once

#include <cstdint>
#include <type_traits>

#include "gpg/core/containers/FastVector.h"
#include "moho/audio/HSound.h"
#include "moho/audio/SAudioRequest.h"
#include "moho/containers/TDatList.h"

namespace moho
{
  class Entity;
  class CSndParams;

  /**
   * VFTABLE: 0x00E359B0
   * COL:     0x00E8F368
   */
  class ISoundManager
  {
  public:
    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 0
     */
    virtual void AddEntitySound(Entity* entity, CSndParams* params) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 1
     */
    virtual void DrainRequests(gpg::fastvector_n<SAudioRequest, 64>& outRequests) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 2
     */
    virtual TDatListItem<HSound, void>* AddLoop(HSound* sound) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 3
     */
    virtual TDatListItem<HSound, void>* StopLoop(HSound* sound) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 4
     */
    virtual void Shutdown() = 0;

    /**
     * Address: 0x00760A70 (FUN_00760A70)
     * Slot: 5
     *
     * std::uint8_t deleteFlags
     *
     * IDA signature:
     * _DWORD *__thiscall sub_760A70(_DWORD *this, char deleteFlags);
     *
     * What it does:
     * Implements deleting-style virtual teardown for interface pointers.
     */
    virtual ISoundManager* Destroy(std::uint8_t flags);
  };

  static_assert(sizeof(ISoundManager) == 0x4, "ISoundManager size must be 0x4");
  static_assert(std::is_polymorphic<ISoundManager>::value, "ISoundManager must remain polymorphic");
} // namespace moho
