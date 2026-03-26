#pragma once
#include <cstdint>
#include <vector>

#include "gpg/core/containers/BitArray2D.h"

namespace moho
{
  class Sim;

  struct EntityOccupation
  {};

  struct EntityOccupationGrid
  {
    int xPos;
    int zPos;
    int32_t lastIndex;
    int32_t gridWidth;
    std::vector<EntityOccupation>* units;
    std::vector<EntityOccupation>* props;
    std::vector<EntityOccupation>* entities;
    int32_t v8;
    int32_t v9;
    int32_t v10;
    void** start;
    void** end;
    int32_t v13;
  };
  static_assert(sizeof(EntityOccupationGrid) == 0x34, "EntityOccupationGrid size must be 0x34");

  class COGrid
  {
  public:
    Sim* sim;
    EntityOccupationGrid entityGrid;
    gpg::BitArray2D terrainOccupation;
    gpg::BitArray2D waterOccupation;
    gpg::BitArray2D mOccupation;
  };
} // namespace moho
