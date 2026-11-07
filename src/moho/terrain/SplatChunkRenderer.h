#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include "gpg/core/utils/Global.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DrawIndexedContext.hpp"
#include "gpg/gal/EffectTechnique.hpp"
#include "gpg/gal/Error.hpp"
#include "moho/render/ID3DVertexStream.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/font/MsdfTextGpuRenderer.h"
#include "moho/terrain/splat/CWldSplat.h"

namespace moho
{
  // Caller selects technique and binds atlas; caller ensures count is multiple
  // of four and cap is the existing sheet's real quad capacity (250 or 2500).
  // Must remain on the same render thread as the original DrawTriangleList.
  inline void DrawSplatChunksPassMajor(
    CD3DDevice* device, CD3DVertexSheet* sheet, CD3DIndexSheet* indices,
    const CWldSplat::SplatVertex* source, std::size_t count, std::size_t quadCap)
  {
    if (count == 0) {
      return;
    }
    if ((count % 4) != 0 || (quadCap != 250 && quadCap != 2500)) {
      gpg::Die("Invalid splat batch geometry");
    }
    // As in CD3DDevice::DrawTriangleList, queued UI text must be submitted
    // before binding another draw's sheets and effect passes.
    MSDF_FlushPendingText();
    auto* galDevice = gpg::gal::Device::GetInstance();
    try {
      // Match original DrawTriangleList state order: bind sheets BEFORE technique.
      sheet->Func9();
      indices->SetBufferIndices();
      auto* technique = device->GetCurEffect()->mCurrentTechnique.get();
      const unsigned passes = static_cast<unsigned>(technique->BeginTechnique());
      for (unsigned pass = 0; pass < passes; ++pass) {
        technique->BeginPass(static_cast<int>(pass));
        for (std::size_t offset = 0; offset < count;) {
          const auto n = std::min(count - offset, quadCap * 4);
          // A single chunk remains current for every pass, as in the original
          // DrawTriangleList path. Multi-chunk passes must rewrite each chunk:
          // the previous pass left the last chunk in this shared sheet.
          // Keep the buffer bound, not a raw upload address; modern backends
          // refresh its storage if recording serials change between draws.
          if (pass == 0 || count > quadCap * 4) {
            auto* stream = sheet->GetVertStream(0U);
            void* output = stream->Lock(0, static_cast<int>(n), false, true);
            if (output == nullptr) {
              gpg::Die("Splat vertex buffer lock failed");
            }
            std::copy_n(source + offset, n, static_cast<CWldSplat::SplatVertex*>(output));
            stream->Unlock();
          }
          gpg::gal::DrawIndexedContext context(gpg::gal::DrawContext::TOPOLOGY_TRIANGLELIST,
            0U, static_cast<std::uint32_t>(n), static_cast<std::uint32_t>((n / 4) * 6), 0U, 0);
          galDevice->DrawIndexedPrimitive(&context);
          offset += n;
        }
        technique->EndPass();
      }
      technique->EndTechnique();
    } catch (const gpg::gal::Error& error) {
      // Match existing DrawTriangleList's fail-fast behavior. No partial replay.
      gpg::Die("%s(%d) %s", error.GetFile(), error.GetLine(), error.what());
    }
  }
} // namespace moho
