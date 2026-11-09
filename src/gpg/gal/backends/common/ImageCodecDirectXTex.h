#pragma once

// FAF addition, not in the shipped binary: ImageCodec's decoder and encoder without d3dx11_43.dll
// (issue #318), on DirectXTex (dependencies/DirectXTex, MIT). See ImageCodec.h.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ImageCodec.h"

namespace gpg::gal::imaging
{
  /** What DecodeWithD3dx returns, from DirectXTex: same formats, sizes and mip counts; built levels differ slightly. */
  HRESULT DecodeWithDirectXTex(const void* data, std::size_t bytes, const DecodeOptions& options, Image& outImage);

  /** The file's width and height, as ImageCodec::GetImageSize. */
  HRESULT GetImageSizeWithDirectXTex(const void* data, std::size_t bytes, std::uint32_t& outWidth, std::uint32_t& outHeight);

  /** The image's first array slice as a file: DDS through ImageCodec::WriteDds, BMP, JPG and PNG through WIC. */
  HRESULT EncodeWithDirectXTex(const Image& image, FileFormat format, std::vector<std::uint8_t>& outBytes);
} // namespace gpg::gal::imaging
