#pragma once

#include <cstddef>
#include <vector>

namespace moho
{
  /**
   * Engine addition, not in the binary: what the simulation tells the client's water of what lands in it (a shell, a
   * bomb, a torpedo, a hull going down, a wreck that falls into the sea). Render only: nothing the water does reaches
   * the simulation back, so the sim runs the same with the events on, off, and in headless (which never switches them
   * on and does nothing here).
   *
   * The sim thread only appends a plain record to a list behind a mutex; the render thread takes the list once a frame
   * (DrainSimWaterEvents) and works it into its own state. No render state is touched from the sim thread.
   */
  struct SSimWaterEvent
  {
    enum class Kind : unsigned char
    {
      Impact,    // a landing on or under the sea
      UnitDeath, // a hull going down
    };

    Kind kind = Kind::Impact;
    float x = 0.0f;
    float y = 0.0f; // the height of a hull (UnitDeath)
    float z = 0.0f;
    /// Impact: the damage of the shot (a shell: 100, a nuke: 8000; the renderer takes its cube root, which the sim must
    /// not: no libm call in the sim). UnitDeath: the build cost of the hull in mass.
    float value = 0.0f;
    float scale = 1.0f; // Impact: 1 on the surface, less below it
    int army = -1;      // the army the shot or hull belongs to (-1: none)
  };

  /// The renderer switches the events on when it starts and off when it stops; off, the calls below do nothing.
  void EnableSimWaterEvents(bool on) noexcept;
  [[nodiscard]] bool SimWaterEventsEnabled() noexcept;

  void SimWaterImpact(float x, float z, float damage, float scale, int army);
  void SimWaterUnitDeath(float x, float y, float z, float mass, int army);

  /// Moves the queued events to `out` (appending) and returns how many. Render thread.
  std::size_t DrainSimWaterEvents(std::vector<SSimWaterEvent>& out);
} // namespace moho
