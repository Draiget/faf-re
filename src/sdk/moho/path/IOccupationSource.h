#pragma once

namespace moho
{
  struct SNamedFootprint;
  class COGrid;
} // namespace moho

namespace moho
{
  class IOccupationSource
  {
  public:
    void* v0;
    COGrid* grid;
    SNamedFootprint* footprint;
  };
} // namespace moho
