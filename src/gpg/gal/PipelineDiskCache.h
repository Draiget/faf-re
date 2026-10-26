#pragma once

namespace gpg::gal
{
  /**
   * Engine addition, not in the shipped binary: keep the pipeline states a backend creates
   * on first use on disk (Direct3D 12: an ID3D12PipelineLibrary in the shader cache
   * directory), so the next session loads them instead of having the driver compile each
   * one again in the frame that first draws it - 10-30 ms per mesh pipeline, several at
   * once when new units come into view. Console variable `d3d_PipelineCache` (moho); the
   * `/nopipelinecache` startup flag turns it off before the device is created.
   */
  extern bool gPipelineDiskCache;
} // namespace gpg::gal
