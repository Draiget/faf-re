#include "moho/sim/SimWaterEvents.h"

namespace moho
{
  namespace
  {
    SSimWaterEventSink gSink;
  } // namespace

  void SetSimWaterEventSink(
    const SSimWaterEventSink& sink
  ) noexcept
  {
    gSink = sink;
  }

  void SimWaterImpact(
    const float x,
    const float z,
    const float energy,
    const float scale,
    const CArmyImpl* const army
  )
  {
    if (gSink.impact != nullptr) {
      gSink.impact(x, z, energy, scale, army);
    }
  }

  void SimWaterUnitDeath(
    const float x,
    const float y,
    const float z,
    const float mass,
    const CArmyImpl* const army
  )
  {
    if (gSink.unitDeath != nullptr) {
      gSink.unitDeath(x, y, z, mass, army);
    }
  }
} // namespace moho
