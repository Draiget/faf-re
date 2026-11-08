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
   * Engine addition: megabytes of idle Direct3D 12 and Vulkan upload pages kept for reuse; idle pages past it
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

  /**
   * Engine addition: Direct3D 12 and Vulkan rename a dynamic buffer into upload memory by copying
   * all of it, as draws may read past what a lock wrote. An owner that says it doesn't
   * (Device::CopyLockedRangeOnly) has only the locked bytes copied: the prim batcher's 0x8000 vertices
   * for each flush were 11 % of an uncapped frame. Console variable `ren_LockedRangeOnly` (moho).
   */
  extern bool gLockedRangeOnly;

  /**
   * Engine addition: each Vulkan head draws into an image of its own and Present copies it into the
   * swap chain's image, scaled to the window, so the swap chain can be made again when the window
   * changes size. Without it a resized window left every acquire out of date and the picture froze
   * (the engine never resets the device on a resize; Direct3D 12's flip model presents into the
   * resized window). Costs one copy of the head per frame. Console variable
   * `ren_VulkanScaledPresent` (moho), read when the device makes its head targets.
   */
  extern bool gVulkanScaledPresent;

  /**
   * Engine addition: a Vulkan image layout change between drawing into a target, sampling it and
   * copying it waits only for the stages that used the image before and holds only the stages that
   * use it next. Without it every change waited for all earlier work and held all later work, which
   * drains the GPU at every switch: the glow passes switch between small targets several times a
   * frame. Changes into or out of the window's images keep the full wait (they chain with the
   * acquire semaphore). Console variable `ren_VulkanPreciseBarriers` (moho), read at each change.
   */
  extern bool gVulkanPreciseBarriers;
} // namespace gpg::gal
