// Host test of the ambient occlusion pass (src/gpg/gal/backends/common/AmbientOcclusion.h): the arithmetic around the
// shaders, and the shaders themselves, run on a software Direct3D 11 device (WARP) over synthetic depth buffers whose
// answer is known: open ground stays unoccluded, the foot of a box and a groove are darkened, the box's roof is not,
// the sky is untouched, and half resolution agrees with full resolution.

#define NOMINMAX
#include <d3d11.h>
#include <d3dcompiler.h>
#include <wrl/client.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "gpg/gal/backends/common/AmbientOcclusion.h"

using Microsoft::WRL::ComPtr;
using namespace gpg::gal;

namespace
{
  int gFailures = 0;

  void Check(
    const bool condition,
    const char* const what
  )
  {
    if (!condition) {
      ++gFailures;
      std::printf("FAIL: %s\n", what);
    }
  }

  void CheckNear(
    const double actual,
    const double expected,
    const double tolerance,
    const char* const what
  )
  {
    if (std::fabs(actual - expected) > tolerance) {
      ++gFailures;
      std::printf("FAIL: %s (got %.4f, want %.4f +- %.4f)\n", what, actual, expected, tolerance);
    }
  }

  int gWidth = 192;
  int gHeight = 128;

  // A perspective projection as the game builds it (Direct3D row-vector form).
  AmbientOcclusionParams MakeParams(
    const int level
  )
  {
    const float nearZ = 0.1f;
    const float farZ = 2000.0f;
    const float fovY = 0.7f;
    AmbientOcclusionParams params;
    params.level = level;
    params.projectionYScale = 1.0f / std::tan(fovY * 0.5f);
    params.projectionXScale = params.projectionYScale * static_cast<float>(gHeight) / static_cast<float>(gWidth);
    params.projectionDepthScale = farZ / (farZ - nearZ);
    params.projectionDepthBias = -nearZ * farZ / (farZ - nearZ);
    params.rectWidth = static_cast<float>(gWidth);
    params.rectHeight = static_cast<float>(gHeight);
    params.radius = 1.5f;
    params.power = 1.6f;
    return params;
  }

  // The game's projection: an infinite far plane (depth 1 at infinity) and a near plane of 6.271.
  AmbientOcclusionParams MakeGameParams(
    const int level
  )
  {
    AmbientOcclusionParams params = MakeParams(level);
    params.projectionDepthScale = 1.0f;
    params.projectionDepthBias = -6.271f;
    return params;
  }

  // ---- the scene: ground plane y = 0, a box standing on it, a groove cut in it; camera 8 up, looking down 35 degrees
  // ----------------------

  struct Hit
  {
    float viewZ = 0.0f; // 0 = sky
    bool box = false;
    bool boxTop = false;
  };

  Hit Trace(
    const AmbientOcclusionParams& params,
    const int px,
    const int py,
    const bool withBox,
    const bool withGroove
  )
  {
    const float vx = ((px + 0.5f) / gWidth * 2.0f - 1.0f) / params.projectionXScale;
    const float vy = (1.0f - (py + 0.5f) / gHeight * 2.0f) / params.projectionYScale;
    const float pitch = 0.61f;
    const float sinP = std::sin(pitch);
    const float cosP = std::cos(pitch);
    // world = right * vx + up * vy + forward * 1, camera at (0, 8, 0)
    const float dx = vx;
    const float dy = vy * cosP - sinP;
    const float dz = vy * sinP + cosP;
    const float eyeY = 8.0f;
    Hit best;
    float bestT = 1.0e9f;
    if (dy < -1.0e-5f) {
      const float t = -eyeY / dy;
      float groundT = t;
      if (withGroove) {
        // A groove 0.8 wide and 1.2 deep along z at x in [-6, -5.2]: the ground there is 1.2 lower.
        const float gx = t * dx;
        if (gx > -6.0f && gx < -5.2f) {
          groundT = (-eyeY - 1.2f) / dy;
          // keep the part of the ray inside the groove walls
          const float inner = groundT * dx;
          if (inner <= -6.0f || inner >= -5.2f) {
            groundT = t;
          }
        }
      }
      bestT = groundT;
      best.viewZ = groundT;
    }
    if (withBox) {
      // box x in [-1.5, 1.5], y in [0, 2], z in [14, 17]
      const float lo[3] = {-1.5f, 0.0f, 14.0f};
      const float hi[3] = {1.5f, 2.0f, 17.0f};
      const float origin[3] = {0.0f, eyeY, 0.0f};
      const float dir[3] = {dx, dy, dz};
      float tMin = 0.0f;
      float tMax = 1.0e9f;
      int axisHit = -1;
      for (int axis = 0; axis < 3; ++axis) {
        if (std::fabs(dir[axis]) < 1.0e-8f) {
          if (origin[axis] < lo[axis] || origin[axis] > hi[axis]) {
            tMax = -1.0f;
          }
          continue;
        }
        float t0 = (lo[axis] - origin[axis]) / dir[axis];
        float t1 = (hi[axis] - origin[axis]) / dir[axis];
        if (t0 > t1) {
          std::swap(t0, t1);
        }
        if (t0 > tMin) {
          tMin = t0;
          axisHit = axis;
        }
        tMax = std::min(tMax, t1);
      }
      if (tMax >= tMin && tMin > 0.0f && tMin < bestT) {
        best.viewZ = tMin;
        best.box = true;
        best.boxTop = axisHit == 1;
        bestT = tMin;
      }
    }
    // view z of a hit at ray parameter t is t (the view-space ray has z = 1)
    return best;
  }

  struct Frame
  {
    std::vector<float> depth;
    std::vector<Hit> hits;
  };

  Frame BuildFrame(
    const AmbientOcclusionParams& params,
    const bool withBox,
    const bool withGroove
  )
  {
    Frame frame;
    frame.depth.resize(gWidth * gHeight);
    frame.hits.resize(gWidth * gHeight);
    for (int y = 0; y < gHeight; ++y) {
      for (int x = 0; x < gWidth; ++x) {
        const Hit hit = Trace(params, x, y, withBox, withGroove);
        frame.hits[y * gWidth + x] = hit;
        frame.depth[y * gWidth + x] =
          hit.viewZ > 0.0f ? params.projectionDepthScale + params.projectionDepthBias / hit.viewZ : 1.0f;
      }
    }
    return frame;
  }

  // ---- a terrain: smooth hills sampled once per world unit and drawn as two triangles per cell (what the game's
  // height
  // ---- field mesh looks like), against the same hills with no mesh at all (the surface the mesh stands for)
  // ----------

  bool gFlatTerrain = false;
  float gTerrainPitch = 0.9f;

  float HillHeight(
    const float x,
    const float z
  )
  {
    if (gFlatTerrain) {
      return 0.0f;
    }
    return 5.0f * std::sin(x / 13.0f) * std::cos(z / 17.0f) + 2.5f * std::sin(x / 6.0f + z / 9.0f);
  }

  float MeshHeight(
    const float x,
    const float z,
    const bool faceted
  )
  {
    if (!faceted) {
      return HillHeight(x, z);
    }
    const float x0 = std::floor(x);
    const float z0 = std::floor(z);
    const float u = x - x0;
    const float v = z - z0;
    const float h00 = HillHeight(x0, z0);
    const float h10 = HillHeight(x0 + 1.0f, z0);
    const float h01 = HillHeight(x0, z0 + 1.0f);
    const float h11 = HillHeight(x0 + 1.0f, z0 + 1.0f);
    return u >= v ? h00 + u * (h10 - h00) + v * (h11 - h10) : h00 + v * (h01 - h00) + u * (h11 - h01);
  }

  // Camera 40 up at the origin looking along +z, pitched down 0.9 radians; the ray's view-space z is its parameter.
  Frame BuildTerrainFrame(
    const AmbientOcclusionParams& params,
    const bool faceted
  )
  {
    Frame frame;
    frame.depth.resize(gWidth * gHeight);
    frame.hits.resize(gWidth * gHeight);
    const float eyeY = 40.0f;
    const float sinP = std::sin(gTerrainPitch);
    const float cosP = std::cos(gTerrainPitch);
    for (int py = 0; py < gHeight; ++py) {
      for (int px = 0; px < gWidth; ++px) {
        const float vx = ((px + 0.5f) / gWidth * 2.0f - 1.0f) / params.projectionXScale;
        const float vy = (1.0f - (py + 0.5f) / gHeight * 2.0f) / params.projectionYScale;
        const float dx = vx;
        const float dy = vy * cosP - sinP;
        const float dz = vy * sinP + cosP;
        const auto above = [&](const float t) {
          return eyeY + t * dy - MeshHeight(t * dx, t * dz, faceted);
        };
        Hit hit;
        float low = 5.0f;
        for (float t = 5.0f; t < 200.0f; t += 0.25f) {
          if (above(t) < 0.0f) {
            float high = t;
            for (int i = 0; i < 24; ++i) {
              const float mid = 0.5f * (low + high);
              (above(mid) < 0.0f ? high : low) = mid;
            }
            hit.viewZ = 0.5f * (low + high);
            break;
          }
          low = t;
        }
        frame.hits[py * gWidth + px] = hit;
        frame.depth[py * gWidth + px] =
          hit.viewZ > 0.0f ? params.projectionDepthScale + params.projectionDepthBias / hit.viewZ : 1.0f;
      }
    }
    return frame;
  }

  struct TerrainStats
  {
    double darkening = 0.0;     ///< mean of 1 - occlusion over the terrain pixels
    double highFrequency = 0.0; ///< mean absolute five-point Laplacian of the occlusion
    int count = 0;
  };

  TerrainStats MeasureTerrain(
    const std::vector<float>& ao,
    const Frame& frame
  )
  {
    TerrainStats stats;
    const int margin = 12;
    for (int y = margin; y < gHeight - margin; ++y) {
      for (int x = margin; x < gWidth - margin; ++x) {
        const auto at = [&](const int dx, const int dy) {
          return ao[(y + dy) * gWidth + x + dx];
        };
        if (frame.hits[y * gWidth + x].viewZ <= 0.0f) {
          continue;
        }
        stats.darkening += 1.0 - at(0, 0);
        stats.highFrequency += std::fabs(at(-1, 0) + at(1, 0) + at(0, -1) + at(0, 1) - 4.0f * at(0, 0));
        ++stats.count;
      }
    }
    if (stats.count > 0) {
      stats.darkening /= stats.count;
      stats.highFrequency /= stats.count;
    }
    return stats;
  }

  // ---- a minimal Direct3D 11 runner of the three passes
  // ---------------------------------------------------------------------------------

  struct Runner
  {
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<ID3D11VertexShader> vertexShader;
    ComPtr<ID3D11PixelShader> compute;
    ComPtr<ID3D11PixelShader> blur;
    ComPtr<ID3D11PixelShader> wide;
    ComPtr<ID3D11PixelShader> composite;
    ComPtr<ID3D11BlendState> opaque;
    ComPtr<ID3D11BlendState> alpha;
    ComPtr<ID3D11RasterizerState> raster;
    ComPtr<ID3D11Buffer> constants;

    bool Init()
    {
      D3D_FEATURE_LEVEL level{};
      if (
        FAILED(D3D11CreateDevice(
          nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0U, nullptr, 0U, D3D11_SDK_VERSION, &device, &level, &context
        ))
      ) {
        std::printf("no WARP device\n");
        return false;
      }
      const std::string source = backend::AmbientOcclusionSource();
      const auto compile = [&](const char* const entry, const char* const profile, ComPtr<ID3DBlob>& code) {
        ComPtr<ID3DBlob> errors;
        const HRESULT result =
          D3DCompile(source.c_str(), source.size(), "ao", nullptr, nullptr, entry, profile, 0U, 0U, &code, &errors);
        if (FAILED(result)) {
          std::printf(
            "compile %s failed: %s\n", entry, errors ? static_cast<const char*>(errors->GetBufferPointer()) : "?"
          );
        }
        return SUCCEEDED(result);
      };
      ComPtr<ID3DBlob> vs, ps0, ps1, ps2, ps3;
      if (
        !compile("AoVS", "vs_5_0", vs) || !compile("AoComputePS", "ps_5_0", ps0) ||
        !compile("AoBlurPS", "ps_5_0", ps1) || !compile("AoCompositePS", "ps_5_0", ps2) ||
        !compile("AoWidePS", "ps_5_0", ps3)
      ) {
        return false;
      }
      device->CreateVertexShader(vs->GetBufferPointer(), vs->GetBufferSize(), nullptr, &vertexShader);
      device->CreatePixelShader(ps0->GetBufferPointer(), ps0->GetBufferSize(), nullptr, &compute);
      device->CreatePixelShader(ps1->GetBufferPointer(), ps1->GetBufferSize(), nullptr, &blur);
      device->CreatePixelShader(ps2->GetBufferPointer(), ps2->GetBufferSize(), nullptr, &composite);
      device->CreatePixelShader(ps3->GetBufferPointer(), ps3->GetBufferSize(), nullptr, &wide);
      D3D11_BLEND_DESC blend{};
      blend.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
      device->CreateBlendState(&blend, &opaque);
      blend.RenderTarget[0].BlendEnable = TRUE;
      blend.RenderTarget[0].SrcBlend = D3D11_BLEND_SRC_ALPHA;
      blend.RenderTarget[0].DestBlend = D3D11_BLEND_INV_SRC_ALPHA;
      blend.RenderTarget[0].BlendOp = D3D11_BLEND_OP_ADD;
      blend.RenderTarget[0].SrcBlendAlpha = D3D11_BLEND_ZERO;
      blend.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_ONE;
      blend.RenderTarget[0].BlendOpAlpha = D3D11_BLEND_OP_ADD;
      blend.RenderTarget[0].RenderTargetWriteMask = 0x07;
      device->CreateBlendState(&blend, &alpha);
      D3D11_RASTERIZER_DESC rasterDesc{};
      rasterDesc.FillMode = D3D11_FILL_SOLID;
      rasterDesc.CullMode = D3D11_CULL_NONE;
      device->CreateRasterizerState(&rasterDesc, &raster);
      D3D11_BUFFER_DESC bufferDesc{};
      bufferDesc.ByteWidth = sizeof(AmbientOcclusionConstants);
      bufferDesc.Usage = D3D11_USAGE_DEFAULT;
      bufferDesc.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
      device->CreateBuffer(&bufferDesc, nullptr, &constants);
      return true;
    }

    struct Target
    {
      ComPtr<ID3D11Texture2D> texture;
      ComPtr<ID3D11RenderTargetView> rtv;
      ComPtr<ID3D11ShaderResourceView> srv;
    };

    Target MakeTarget(
      const UINT width,
      const UINT height,
      const DXGI_FORMAT format
    )
    {
      Target target;
      D3D11_TEXTURE2D_DESC desc{};
      desc.Width = width;
      desc.Height = height;
      desc.MipLevels = 1;
      desc.ArraySize = 1;
      desc.Format = format;
      desc.SampleDesc.Count = 1;
      desc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
      device->CreateTexture2D(&desc, nullptr, &target.texture);
      device->CreateRenderTargetView(target.texture.Get(), nullptr, &target.rtv);
      device->CreateShaderResourceView(target.texture.Get(), nullptr, &target.srv);
      return target;
    }

    void Draw(
      ID3D11PixelShader* const shader,
      ID3D11BlendState* const blend,
      Target& output,
      const UINT width,
      const UINT height,
      ID3D11ShaderResourceView* const depth,
      ID3D11ShaderResourceView* const ao,
      const AmbientOcclusionConstants& block,
      const float x0,
      const float y0,
      const float w,
      const float h
    )
    {
      context->UpdateSubresource(constants.Get(), 0, nullptr, &block, 0, 0);
      ID3D11ShaderResourceView* views[7] = {nullptr, nullptr, nullptr, nullptr, ao, nullptr, depth};
      context->PSSetShaderResources(0, 7, views);
      ID3D11RenderTargetView* rtv = output.rtv.Get();
      context->OMSetRenderTargets(1, &rtv, nullptr);
      context->OMSetBlendState(blend, nullptr, 0xFFFFFFFFU);
      context->RSSetState(raster.Get());
      const D3D11_VIEWPORT viewport{x0, y0, w, h, 0.0f, 1.0f};
      context->RSSetViewports(1, &viewport);
      context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
      context->VSSetShader(vertexShader.Get(), nullptr, 0);
      context->PSSetShader(shader, nullptr, 0);
      ID3D11Buffer* cb = constants.Get();
      context->PSSetConstantBuffers(0, 1, &cb);
      context->Draw(3, 0);
      ID3D11ShaderResourceView* none[7] = {};
      context->PSSetShaderResources(0, 7, none);
      ID3D11RenderTargetView* noTarget = nullptr;
      context->OMSetRenderTargets(1, &noTarget, nullptr);
      (void)width;
      (void)height;
    }

    // Runs the three passes over `frame` and returns the occlusion factor (1 = open) per back buffer pixel.
    std::vector<float> Run(
      const AmbientOcclusionParams& params,
      const Frame& frame
    )
    {
      D3D11_TEXTURE2D_DESC depthDesc{};
      depthDesc.Width = gWidth;
      depthDesc.Height = gHeight;
      depthDesc.MipLevels = 1;
      depthDesc.ArraySize = 1;
      depthDesc.Format = DXGI_FORMAT_R32_FLOAT;
      depthDesc.SampleDesc.Count = 1;
      depthDesc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
      D3D11_SUBRESOURCE_DATA data{frame.depth.data(), static_cast<UINT>(gWidth * 4), 0};
      ComPtr<ID3D11Texture2D> depthTexture;
      ComPtr<ID3D11ShaderResourceView> depthView;
      device->CreateTexture2D(&depthDesc, &data, &depthTexture);
      device->CreateShaderResourceView(depthTexture.Get(), nullptr, &depthView);

      const bool half = AmbientOcclusionHalfRes(params);
      const UINT aoWidth = AmbientOcclusionTargetExtent(gWidth, half);
      const UINT aoHeight = AmbientOcclusionTargetExtent(gHeight, half);
      Target a = MakeTarget(aoWidth, aoHeight, DXGI_FORMAT_R16G16_UNORM);
      Target b = MakeTarget(aoWidth, aoHeight, DXGI_FORMAT_R16G16_UNORM);
      Target out = MakeTarget(gWidth, gHeight, DXGI_FORMAT_R32G32B32A32_FLOAT);
      const float white[4] = {1, 1, 1, 1};
      context->ClearRenderTargetView(out.rtv.Get(), white);

      AmbientOcclusionConstants block = BuildAmbientOcclusionConstants(params);
      const float scale = half ? 2.0f : 1.0f;
      Draw(
        compute.Get(),
        opaque.Get(),
        a,
        aoWidth,
        aoHeight,
        depthView.Get(),
        nullptr,
        block,
        0,
        0,
        static_cast<float>(aoWidth),
        static_cast<float>(aoHeight)
      );
      block.blur[0] = 1.0f;
      block.blur[1] = 0.0f;
      Draw(
        blur.Get(),
        opaque.Get(),
        b,
        aoWidth,
        aoHeight,
        depthView.Get(),
        a.srv.Get(),
        block,
        0,
        0,
        static_cast<float>(aoWidth),
        static_cast<float>(aoHeight)
      );
      const bool smooth = block.shape[2] > 0.0f;
      if (smooth) {
        const auto drawAo = [&](ID3D11PixelShader* const shader, Target& output, Target& input) {
          Draw(
            shader,
            opaque.Get(),
            output,
            aoWidth,
            aoHeight,
            depthView.Get(),
            input.srv.Get(),
            block,
            0,
            0,
            static_cast<float>(aoWidth),
            static_cast<float>(aoHeight)
          );
        };
        block.blur[0] = 0.0f;
        block.blur[1] = 1.0f;
        drawAo(blur.Get(), a, b);
        block.blur[0] = 1.0f;
        block.blur[1] = 0.0f;
        drawAo(wide.Get(), b, a);
      }
      block.blur[0] = 0.0f;
      block.blur[1] = 1.0f;
      block.blur[3] = smooth ? 1.0f : 0.0f;
      Draw(
        composite.Get(),
        alpha.Get(),
        out,
        gWidth,
        gHeight,
        depthView.Get(),
        b.srv.Get(),
        block,
        0,
        0,
        static_cast<float>(gWidth),
        static_cast<float>(gHeight)
      );
      (void)scale;

      D3D11_TEXTURE2D_DESC stagingDesc{};
      stagingDesc.Width = gWidth;
      stagingDesc.Height = gHeight;
      stagingDesc.MipLevels = 1;
      stagingDesc.ArraySize = 1;
      stagingDesc.Format = DXGI_FORMAT_R32G32B32A32_FLOAT;
      stagingDesc.SampleDesc.Count = 1;
      stagingDesc.Usage = D3D11_USAGE_STAGING;
      stagingDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
      ComPtr<ID3D11Texture2D> staging;
      device->CreateTexture2D(&stagingDesc, nullptr, &staging);
      context->CopyResource(staging.Get(), out.texture.Get());
      D3D11_MAPPED_SUBRESOURCE mapped{};
      std::vector<float> result(gWidth * gHeight, 1.0f);
      if (SUCCEEDED(context->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &mapped))) {
        for (int y = 0; y < gHeight; ++y) {
          const auto* row =
            reinterpret_cast<const float*>(static_cast<const unsigned char*>(mapped.pData) + y * mapped.RowPitch);
          for (int x = 0; x < gWidth; ++x) {
            result[y * gWidth + x] = row[x * 4];
          }
        }
        context->Unmap(staging.Get(), 0);
      }
      return result;
    }
  };

  struct Stats
  {
    double mean = 0.0;
    double minimum = 1.0;
    int count = 0;
  };

  template <typename Predicate>
  Stats Measure(
    const std::vector<float>& ao,
    const Frame& frame,
    Predicate predicate
  )
  {
    Stats stats;
    double sum = 0.0;
    for (int y = 0; y < gHeight; ++y) {
      for (int x = 0; x < gWidth; ++x) {
        if (predicate(x, y, frame.hits[y * gWidth + x])) {
          const float value = ao[y * gWidth + x];
          sum += value;
          stats.minimum = std::min<double>(stats.minimum, value);
          ++stats.count;
        }
      }
    }
    stats.mean = stats.count > 0 ? sum / stats.count : 1.0;
    return stats;
  }

  void TestArithmetic()
  {
    const AmbientOcclusionParams params = MakeParams(kAmbientOcclusionHigh);
    for (const float z : {0.2f, 1.0f, 30.0f, 900.0f}) {
      const float depth = params.projectionDepthScale + params.projectionDepthBias / z;
      CheckNear(AmbientOcclusionViewDepth(params, depth), z, z * 1.0e-3, "view depth round trip");
    }
    Check(AmbientOcclusionQualityFor(kAmbientOcclusionLow).halfRes, "Low runs at half resolution");
    Check(!AmbientOcclusionQualityFor(kAmbientOcclusionHigh).halfRes, "High runs at full resolution");
    Check(AmbientOcclusionQualityFor(kAmbientOcclusionOff).slices == 0, "Off has no work");
    Check(
      AmbientOcclusionQualityFor(kAmbientOcclusionLow).steps < AmbientOcclusionQualityFor(kAmbientOcclusionHigh).steps,
      "more steps with level"
    );
    Check(AmbientOcclusionTargetExtent(1601U, true) == 801U, "half resolution rounds up");
    Check(AmbientOcclusionTargetExtent(900U, false) == 900U, "full resolution keeps the size");
    AmbientOcclusionParams half = MakeParams(kAmbientOcclusionHigh);
    half.halfResolution = 1;
    Check(AmbientOcclusionHalfRes(half), "halfResolution=1 forces half");
    half.halfResolution = -1;
    Check(!AmbientOcclusionHalfRes(half), "halfResolution=-1 follows the level");
    const AmbientOcclusionConstants block = BuildAmbientOcclusionConstants(MakeParams(kAmbientOcclusionLow));
    CheckNear(block.size[0], 2.0, 1.0e-6, "scale 2 at Low");
    CheckNear(block.aoRect[2], gWidth / 2 - 1, 1.0e-6, "last AO column at half resolution");
    CheckNear(1.0 / block.size[1], 2000.0, 20.0, "far depth");
    Check(sizeof(AmbientOcclusionConstants) % 16 == 0, "constants are a multiple of 16 bytes");
    // The game's camera has an infinite far plane (depth scale 1): the depth channel gets a fixed range instead of
    // dividing by zero.
    AmbientOcclusionParams infinite = MakeParams(kAmbientOcclusionLow);
    infinite.projectionDepthScale = 1.0f;
    infinite.projectionDepthBias = -6.271f;
    const AmbientOcclusionConstants infiniteBlock = BuildAmbientOcclusionConstants(infinite);
    Check(
      std::isfinite(infiniteBlock.size[1]) && infiniteBlock.size[1] > 0.0f,
      "infinite far plane keeps a finite depth range"
    );
    CheckNear(
      AmbientOcclusionViewDepth(infinite, 1.0f - 6.271f / 100.0f), 100.0, 0.5, "view depth with the game's projection"
    );
  }

  void TestShaders(
    Runner& runner
  )
  {
    for (const int level : {kAmbientOcclusionLow, kAmbientOcclusionMedium, kAmbientOcclusionHigh}) {
      const AmbientOcclusionParams params = MakeParams(level);
      char label[96];

      // Open ground only: nothing occludes.
      {
        const Frame frame = BuildFrame(params, false, false);
        const std::vector<float> ao = runner.Run(params, frame);
        const Stats ground = Measure(ao, frame, [](int x, int y, const Hit& hit) {
          return hit.viewZ > 0.0f && x > 12 && x < gWidth - 12 && y > 12 && y < gHeight - 12;
        });
        std::snprintf(
          label,
          sizeof(label),
          "level %d: open ground stays unoccluded (mean %.3f min %.3f)",
          level,
          ground.mean,
          ground.minimum
        );
        Check(ground.count > 1000 && ground.mean > 0.97 && ground.minimum > 0.85, label);
        const Stats sky = Measure(ao, frame, [](int, int, const Hit& hit) {
          return hit.viewZ <= 0.0f;
        });
        if (sky.count > 0) {
          Check(sky.minimum > 0.999, "the sky is untouched");
        }
      }

      // A box on the ground: its foot is darkened, its roof and the distant ground are not.
      {
        const Frame frame = BuildFrame(params, true, false);
        const std::vector<float> ao = runner.Run(params, frame);
        // ground pixels right next to the box's front face: just below the box in the picture
        int boxBottom = 0;
        int boxLeft = gWidth;
        int boxRight = 0;
        for (int y = 0; y < gHeight; ++y) {
          for (int x = 0; x < gWidth; ++x) {
            if (frame.hits[y * gWidth + x].box) {
              boxBottom = std::max(boxBottom, y);
              boxLeft = std::min(boxLeft, x);
              boxRight = std::max(boxRight, x);
            }
          }
        }
        const int footY = boxBottom;
        const Stats foot = Measure(ao, frame, [&](int x, int y, const Hit& hit) {
          return !hit.box && hit.viewZ > 0.0f && y > footY && y <= footY + 4 && x > boxLeft + 8 && x < boxRight - 8;
        });
        const Stats farGround = Measure(ao, frame, [&](int x, int y, const Hit& hit) {
          return !hit.box && hit.viewZ > 0.0f && (x < boxLeft - 40 || x > boxRight + 40) && y > 12 &&
            y < gHeight - 12 && x > 12 && x < gWidth - 12;
        });
        const Stats roof = Measure(ao, frame, [&](int x, int y, const Hit& hit) {
          return hit.box && hit.boxTop && x > boxLeft + 8 && x < boxRight - 8 && y > 12;
        });
        std::snprintf(
          label,
          sizeof(label),
          "level %d: ground at the box's foot is darkened (mean %.3f, open ground %.3f)",
          level,
          foot.mean,
          farGround.mean
        );
        Check(foot.count > 10 && foot.mean < farGround.mean - 0.08 && foot.mean < 0.9, label);
        std::snprintf(
          label, sizeof(label), "level %d: ground far from the box stays open (%.3f)", level, farGround.mean
        );
        Check(farGround.count > 500 && farGround.mean > 0.95, label);
        if (roof.count > 10) {
          std::snprintf(label, sizeof(label), "level %d: the roof of the box is open (%.3f)", level, roof.mean);
          Check(roof.mean > 0.9, label);
        }
        std::printf(
          "level %d box: foot %.3f (%d px) roof %.3f far ground %.3f\n",
          level,
          foot.mean,
          foot.count,
          roof.count > 0 ? roof.mean : -1.0,
          farGround.mean
        );
      }

      // The same crease seen from the wall's side: the bottom rows of the box's front face are darker than its middle.
      {
        const Frame frame = BuildFrame(params, true, false);
        const std::vector<float> ao = runner.Run(params, frame);
        int top = gHeight;
        int bottom = 0;
        for (int y = 0; y < gHeight; ++y) {
          for (int x = 0; x < gWidth; ++x) {
            const Hit& hit = frame.hits[y * gWidth + x];
            if (hit.box && !hit.boxTop) {
              top = std::min(top, y);
              bottom = std::max(bottom, y);
            }
          }
        }
        const Stats low = Measure(ao, frame, [&](int, int y, const Hit& hit) {
          return hit.box && !hit.boxTop && y > bottom - 3;
        });
        const Stats middle = Measure(ao, frame, [&](int, int y, const Hit& hit) {
          return hit.box && !hit.boxTop && y > top + 4 && y < top + 8;
        });
        std::printf(
          "level %d wall: bottom rows %.3f (%d px) upper rows %.3f (%d px)\n",
          level,
          low.mean,
          low.count,
          middle.mean,
          middle.count
        );
        if (low.count > 10 && middle.count > 10) {
          std::snprintf(
            label,
            sizeof(label),
            "level %d: the wall is darker at its foot (%.3f vs %.3f)",
            level,
            low.mean,
            middle.mean
          );
          Check(low.mean < middle.mean - 0.03, label);
        }
      }
    }

    // Half and full resolution agree on the same scene (the half-resolution result is an upsampled approximation).
    {
      AmbientOcclusionParams full = MakeParams(kAmbientOcclusionMedium);
      full.halfResolution = 0;
      AmbientOcclusionParams half = full;
      half.halfResolution = 1;
      const Frame frame = BuildFrame(full, true, true);
      const std::vector<float> aoFull = runner.Run(full, frame);
      const std::vector<float> aoHalf = runner.Run(half, frame);
      double difference = 0.0;
      int count = 0;
      for (int y = 8; y < gHeight - 8; ++y) {
        for (int x = 8; x < gWidth - 8; ++x) {
          if (frame.hits[y * gWidth + x].viewZ > 0.0f) {
            difference += std::fabs(aoFull[y * gWidth + x] - aoHalf[y * gWidth + x]);
            ++count;
          }
        }
      }
      std::printf("half vs full: mean abs difference %.4f over %d px\n", difference / std::max(count, 1), count);
      CheckNear(difference / std::max(count, 1), 0.0, 0.03, "half and full resolution agree");
    }
  }

  // Open ground at three view angles: a plane stays unoccluded. Taps rounded to a texel leave their slice plane and
  // read as geometry that rises above the surface, which darkened a plane by 0.7 % (looking down) to 3.9 % (grazing,
  // Low).
  void TestOpenGround(
    Runner& runner
  )
  {
    gWidth = 480;
    gHeight = 300;
    gFlatTerrain = true;
    for (const int level : {kAmbientOcclusionLow, kAmbientOcclusionMedium, kAmbientOcclusionHigh}) {
      for (const float pitch : {0.5f, 0.9f, 1.3f}) {
        gTerrainPitch = pitch;
        const AmbientOcclusionParams params = MakeGameParams(level);
        const Frame frame = BuildTerrainFrame(params, false);
        const TerrainStats stats = MeasureTerrain(runner.Run(params, frame), frame);
        char label[96];
        std::snprintf(
          label,
          sizeof(label),
          "level %d: open ground at pitch %.1f is unoccluded (%.4f)",
          level,
          pitch,
          stats.darkening
        );
        Check(stats.count > 50000 && stats.darkening < 0.006, label);
      }
    }
    gFlatTerrain = false;
    gTerrainPitch = 0.9f;
    gWidth = 192;
    gHeight = 128;
  }

  // Coarse terrain: hills drawn as a mesh of two triangles per world unit against the same hills with no mesh. The
  // occlusion on the mesh must not show its triangles (excess high-frequency energy over the smooth surface's, which
  // the smoothing pass takes down) and must not darken more than the surface it stands for.
  // `AO_LAB=<tolerance>,<reach>;...` prints the numbers for other settings.
  void TestTerrainFacets(
    Runner& runner
  )
  {
    gWidth = 480;
    gHeight = 300;
    struct Result
    {
      double excess = 0.0;
      double darkening = 0.0;
    };
    const auto measure = [&](const int level, const float tolerance, const float reach) {
      AmbientOcclusionParams params = MakeGameParams(level);
      params.planeTolerance = tolerance;
      params.smoothReach = reach;
      const Frame mesh = BuildTerrainFrame(params, true);
      const Frame smooth = BuildTerrainFrame(params, false);
      const TerrainStats onMesh = MeasureTerrain(runner.Run(params, mesh), mesh);
      const TerrainStats onSmooth = MeasureTerrain(runner.Run(params, smooth), smooth);
      return Result{onMesh.highFrequency - onSmooth.highFrequency, onMesh.darkening - onSmooth.darkening};
    };
    if (const char* lab = std::getenv("AO_LAB")) {
      float tolerance = 0.0f;
      float reach = 0.0f;
      int used = 0;
      while (std::sscanf(lab, "%f,%f%n", &tolerance, &reach, &used) == 2) {
        for (const int level : {kAmbientOcclusionLow, kAmbientOcclusionMedium, kAmbientOcclusionHigh}) {
          const Result result = measure(level, tolerance, reach);
          std::printf(
            "lab level %d tolerance %.2f reach %.1f: excess high-frequency %.5f, extra darkening %+.4f\n",
            level,
            tolerance,
            reach,
            result.excess,
            result.darkening
          );
        }
        lab += used;
        if (*lab == ';') {
          ++lab;
        }
      }
    }
    for (const int level : {kAmbientOcclusionLow, kAmbientOcclusionMedium, kAmbientOcclusionHigh}) {
      const AmbientOcclusionParams defaults = MakeGameParams(level);
      const Result plain = measure(level, defaults.planeTolerance, 0.0f);
      const Result smoothed = measure(level, defaults.planeTolerance, defaults.smoothReach);
      std::printf(
        "level %d terrain facets: excess high-frequency %.5f without the smoothing, %.5f with; extra darkening %+.4f\n",
        level,
        plain.excess,
        smoothed.excess,
        smoothed.darkening
      );
      char label[128];
      std::snprintf(
        label,
        sizeof(label),
        "level %d: the smoothing takes the mesh's pattern down (%.5f -> %.5f)",
        level,
        plain.excess,
        smoothed.excess
      );
      Check(smoothed.excess < 0.00006 && smoothed.excess < plain.excess, label);
      std::snprintf(
        label, sizeof(label), "level %d: the mesh darkens no more than its surface (%+.4f)", level, smoothed.darkening
      );
      Check(std::fabs(smoothed.darkening) < 0.002, label);
    }
    gWidth = 192;
    gHeight = 128;
  }
} // namespace

int main()
{
  TestArithmetic();
  Runner runner;
  if (runner.Init()) {
    TestShaders(runner);
    TestOpenGround(runner);
    TestTerrainFacets(runner);
  } else {
    ++gFailures;
  }
  if (gFailures == 0) {
    std::printf("all ambient occlusion tests passed\n");
    return 0;
  }
  std::printf("%d ambient occlusion check(s) failed\n", gFailures);
  return 1;
}
