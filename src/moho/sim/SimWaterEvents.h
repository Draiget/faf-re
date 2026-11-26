#pragma once

namespace moho
{
  class CArmyImpl;

  /**
   * Engine addition, not in the binary: what the simulation tells the client's water of what lands in it (a shell, a
   * bomb, a torpedo, a hull going down, a wreck that falls into the sea). Render only: the sink draws waves from it and
   * nothing it does reaches the simulation back, so the sim runs the same with a sink, without one, and in headless
   * (which has none and does nothing here). The water simulation of the client installs its sink at start
   * (moho/terrain/water/WaterSimulation.cpp).
   */
  struct SSimWaterEventSink
  {
    /// A landing on or under the sea: `energy` is the damage of the shot (a shell: 100, a nuke: 8000; the sink takes
    /// its cube root, which the sim does not: no libm call in the sim) and `scale` is 1 on the surface, less below it.
    /// `army` is the army the shot belongs to (null: none).
    void (*impact)(float x, float z, float energy, float scale, const CArmyImpl* army) = nullptr;
    /// A hull going down: `mass` is its build cost in mass. `army` is the army it belonged to.
    void (*unitDeath)(float x, float y, float z, float mass, const CArmyImpl* army) = nullptr;
  };

  /// Installs the sink (a copy is kept); an empty sink removes it.
  void SetSimWaterEventSink(const SSimWaterEventSink& sink) noexcept;

  void SimWaterImpact(float x, float z, float energy, float scale, const CArmyImpl* army);
  void SimWaterUnitDeath(float x, float y, float z, float mass, const CArmyImpl* army);
} // namespace moho
