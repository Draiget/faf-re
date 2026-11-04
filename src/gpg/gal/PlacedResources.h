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

  /**
   * Engine addition: megabytes of idle Direct3D 12 upload pages kept for reuse; idle pages past it
   * are given back. Each page is 8 MB of committed process memory, and a burst (a loading screen, a
   * terrain normal-map rebuild) would otherwise leave them mapped. Console variable
   * `d3d_UploadIdleMB` (moho), read at each retire.
   */
  extern int gUploadIdleMB;

  /**
   * Engine addition: Direct3D 12 keeps small static buffers at offsets inside large buffers. A
   * buffer of its own takes at least 64 KB of a heap, and most mesh buffers are far smaller: 61 MB
   * of them took 296 MB. Console variable `d3d_SharedBuffers` (moho), read at each creation; it
   * needs `d3d_PlacedResources`.
   */
  extern bool gSharedBuffers;

  /**
   * Engine addition: Direct3D 12 and Vulkan free the CPU copy of a static buffer its owner says it
   * won't lock again (Device::ReleaseBufferCopy). Console variable `ren_ReleaseBufferCopies` (moho).
   */
  extern bool gReleaseBufferCopies;
} // namespace gpg::gal
