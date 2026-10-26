#pragma once

namespace gpg::gal
{
  /**
   * Engine addition, not in the shipped binary: Direct3D 12 places file textures and static
   * buffers in large heaps created ahead of time instead of giving each its own committed
   * resource. Every committed resource costs the driver a memory allocation and a wait on its
   * paging fence, 1-2 ms each; a zoom that brings many unit types into view creates hundreds
   * in one frame (40% of a 917 ms frame). Console variable `d3d_PlacedResources` (moho), read
   * at each creation; `/con d3d_PlacedResources=0` turns it off from the start.
   */
  extern bool gPlacedResources;
} // namespace gpg::gal
