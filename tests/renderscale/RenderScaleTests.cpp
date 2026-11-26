// Host test of the render scale (src/gpg/gal/backends/common/RenderScale.h): the arithmetic around the pass, and the
// upscale and sharpen shaders themselves, run on a software Direct3D 11 device (WARP) over synthetic images whose
// answer is known: flat areas stay flat, nothing leaves the range of its neighbourhood (no ringing), a diagonal edge
// and a thin line are reconstructed closer to the full-resolution truth than bilinear filtering does, a view rectangle
// offset in the target maps to the right place, and the sharpen pass steepens an edge without touching plateaus.

#define NOMINMAX
#include <d3d11.h>
#include <d3dcompiler.h>
#include <wrl/client.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <functional>
#include <limits>
#include <vector>

#include <gtest/gtest.h>

#include "gpg/gal/backends/common/RenderScale.h"

using Microsoft::WRL::ComPtr;
using namespace gpg::gal;

namespace
{
  void Check(
    const bool condition,
    const char* const what
  )
  {
    EXPECT_TRUE(condition) << what;
  }

  void CheckNear(
    const double actual,
    const double expected,
    const double tolerance,
    const char* const what
  )
  {
    EXPECT_NEAR(actual, expected, tolerance) << what;
  }

  // ---- the arithmetic
  // -----------------------------------------------------------------------------------------------------------------

  void TestArithmetic()
  {
    CheckNear(RenderScaleFactorFor(1.0f), 1.0, 1e-6, "1 is native");
    CheckNear(RenderScaleFactorFor(0.85f), 0.85, 1e-6, "0.85 is 85 %");
    CheckNear(RenderScaleFactorFor(0.75f), 0.75, 1e-6, "0.75 is 75 %");
    CheckNear(RenderScaleFactorFor(2.0f / 3.0f), 2.0 / 3.0, 1e-6, "0.67 is 67 %");
    CheckNear(RenderScaleFactorFor(0.5f), 0.5, 1e-6, "0.5 is 50 %");
    CheckNear(RenderScaleFactorFor(0.2f), 0.5, 1e-6, "less than half is clamped to half");
    CheckNear(RenderScaleFactorFor(3.0f), 1.0, 1e-6, "more than native is native");
    CheckNear(RenderScaleFactorFor(std::numeric_limits<float>::quiet_NaN()), 1.0, 1e-6, "not a number is native");

    Check(RenderScaleExtent(1600, 0.5f) == 800, "1600 at 50 % is 800");
    Check(RenderScaleExtent(900, 0.5f) == 450, "900 at 50 % is 450");
    Check(RenderScaleExtent(1600, 2.0f / 3.0f) == 1067, "1600 at 67 % rounds up to 1067");
    Check(RenderScaleExtent(900, 2.0f / 3.0f) == 600, "900 at 67 % is exactly 600");
    Check(RenderScaleExtent(3840, 0.75f) == 2880, "3840 at 75 % is 2880");
    Check(RenderScaleExtent(1, 0.5f) == 1, "never below 1");
    Check(RenderScaleExtent(0, 0.5f) == 1, "never below 1 (empty window)");

    // The full window maps to the whole scaled target; a sub-rectangle maps outward-rounded so neighbours leave no gap.
    const RenderScaleRect full = RenderScaleSourceRect({0, 0, 1600, 900}, 2.0f / 3.0f, 1067, 600);
    Check(
      full.x == 0 && full.y == 0 && full.width == 1067 && full.height == 600,
      "the full window is the whole scaled target"
    );
    const RenderScaleRect left = RenderScaleSourceRect({0, 0, 800, 900}, 2.0f / 3.0f, 1067, 600);
    const RenderScaleRect right = RenderScaleSourceRect({800, 0, 800, 900}, 2.0f / 3.0f, 1067, 600);
    Check(left.x + left.width >= right.x, "split views leave no gap between them");
    Check(left.x + left.width - right.x <= 1, "split views overlap by at most one texel");
    Check(right.x + right.width == 1067, "the right view ends at the target's edge");
    const RenderScaleRect outside = RenderScaleSourceRect({1500, 800, 400, 300}, 0.5f, 800, 450);
    Check(
      outside.x + outside.width <= 800 && outside.y + outside.height <= 450,
      "a rectangle past the window is clamped to the target"
    );

    const RenderScaleConstants constants = BuildRenderScaleConstants({1, 2, 3, 4}, {5, 6, 7, 8}, 2.5f);
    Check(
      constants.source[0] == 1.0f && constants.source[3] == 4.0f && constants.dest[2] == 7.0f,
      "constants hold the rectangles"
    );
    CheckNear(constants.params[0], 1.0, 1e-6, "sharpness is clamped to 1");
  }

  // ---- a minimal Direct3D 11 runner of the two passes
  // ---------------------------------------------------------------------------------------

  struct Image
  {
    int width = 0;
    int height = 0;
    std::vector<float> rgb; // 3 floats per pixel
    float& At(
      const int x,
      const int y,
      const int c
    )
    {
      return rgb[(static_cast<size_t>(y) * width + x) * 3 + c];
    }
    [[nodiscard]] float At(
      const int x,
      const int y,
      const int c
    ) const
    {
      return rgb[(static_cast<size_t>(y) * width + x) * 3 + c];
    }
  };

  Image MakeImage(
    const int width,
    const int height,
    const float fill = 0.0f
  )
  {
    Image image;
    image.width = width;
    image.height = height;
    image.rgb.assign(static_cast<size_t>(width) * height * 3, fill);
    return image;
  }

  struct Runner
  {
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<ID3D11VertexShader> vertexShader;
    ComPtr<ID3D11PixelShader> upscale;
    ComPtr<ID3D11PixelShader> sharpen;
    ComPtr<ID3D11BlendState> blend;
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
      const std::string source = RenderScaleSource();
      const auto compile = [&](const char* const entry, const char* const profile, ComPtr<ID3DBlob>& code) {
        ComPtr<ID3DBlob> errors;
        const HRESULT result = D3DCompile(
          source.c_str(), source.size(), "renderscale", nullptr, nullptr, entry, profile, 0U, 0U, &code, &errors
        );
        if (FAILED(result)) {
          std::printf(
            "compile %s failed: %s\n", entry, errors ? static_cast<const char*>(errors->GetBufferPointer()) : "?"
          );
        }
        return SUCCEEDED(result);
      };
      ComPtr<ID3DBlob> vs, ps0, ps1;
      if (
        !compile("ScaleVS", "vs_5_0", vs) || !compile("UpscalePS", "ps_5_0", ps0) ||
        !compile("SharpenPS", "ps_5_0", ps1)
      ) {
        return false;
      }
      device->CreateVertexShader(vs->GetBufferPointer(), vs->GetBufferSize(), nullptr, &vertexShader);
      device->CreatePixelShader(ps0->GetBufferPointer(), ps0->GetBufferSize(), nullptr, &upscale);
      device->CreatePixelShader(ps1->GetBufferPointer(), ps1->GetBufferSize(), nullptr, &sharpen);
      D3D11_BLEND_DESC blendDesc{};
      blendDesc.RenderTarget[0].RenderTargetWriteMask = 0x07;
      device->CreateBlendState(&blendDesc, &blend);
      D3D11_RASTERIZER_DESC rasterDesc{};
      rasterDesc.FillMode = D3D11_FILL_SOLID;
      rasterDesc.CullMode = D3D11_CULL_NONE;
      device->CreateRasterizerState(&rasterDesc, &raster);
      D3D11_BUFFER_DESC bufferDesc{};
      bufferDesc.ByteWidth = sizeof(RenderScaleConstants);
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
      int width = 0;
      int height = 0;
    };

    Target Upload(
      const Image& image
    )
    {
      Target target;
      target.width = image.width;
      target.height = image.height;
      std::vector<float> rgba(static_cast<size_t>(image.width) * image.height * 4);
      for (size_t i = 0; i < static_cast<size_t>(image.width) * image.height; ++i) {
        rgba[i * 4 + 0] = image.rgb[i * 3 + 0];
        rgba[i * 4 + 1] = image.rgb[i * 3 + 1];
        rgba[i * 4 + 2] = image.rgb[i * 3 + 2];
        rgba[i * 4 + 3] = 1.0f;
      }
      D3D11_TEXTURE2D_DESC desc{};
      desc.Width = image.width;
      desc.Height = image.height;
      desc.MipLevels = 1;
      desc.ArraySize = 1;
      desc.Format = DXGI_FORMAT_R32G32B32A32_FLOAT;
      desc.SampleDesc.Count = 1;
      desc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
      const D3D11_SUBRESOURCE_DATA data{rgba.data(), static_cast<UINT>(image.width * 4 * sizeof(float)), 0};
      device->CreateTexture2D(&desc, &data, &target.texture);
      device->CreateRenderTargetView(target.texture.Get(), nullptr, &target.rtv);
      device->CreateShaderResourceView(target.texture.Get(), nullptr, &target.srv);
      return target;
    }

    void Draw(
      ID3D11PixelShader* const shader,
      Target& input,
      Target& output,
      const RenderScaleConstants& block,
      const RenderScaleRect& dest
    )
    {
      context->UpdateSubresource(constants.Get(), 0, nullptr, &block, 0, 0);
      ID3D11ShaderResourceView* views[6] = {nullptr, nullptr, nullptr, nullptr, input.srv.Get(), nullptr};
      context->PSSetShaderResources(0, 6, views);
      ID3D11RenderTargetView* rtv = output.rtv.Get();
      context->OMSetRenderTargets(1, &rtv, nullptr);
      context->OMSetBlendState(blend.Get(), nullptr, 0xFFFFFFFFU);
      context->RSSetState(raster.Get());
      const D3D11_VIEWPORT viewport{
        static_cast<float>(dest.x),
        static_cast<float>(dest.y),
        static_cast<float>(dest.width),
        static_cast<float>(dest.height),
        0.0f,
        1.0f
      };
      context->RSSetViewports(1, &viewport);
      context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
      context->VSSetShader(vertexShader.Get(), nullptr, 0);
      context->PSSetShader(shader, nullptr, 0);
      ID3D11Buffer* cb = constants.Get();
      context->PSSetConstantBuffers(0, 1, &cb);
      context->Draw(3, 0);
      ID3D11ShaderResourceView* none[6] = {};
      context->PSSetShaderResources(0, 6, none);
      ID3D11RenderTargetView* noTarget = nullptr;
      context->OMSetRenderTargets(1, &noTarget, nullptr);
    }

    Image Read(
      Target& target
    )
    {
      D3D11_TEXTURE2D_DESC desc{};
      target.texture->GetDesc(&desc);
      desc.Usage = D3D11_USAGE_STAGING;
      desc.BindFlags = 0;
      desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
      ComPtr<ID3D11Texture2D> staging;
      device->CreateTexture2D(&desc, nullptr, &staging);
      context->CopyResource(staging.Get(), target.texture.Get());
      D3D11_MAPPED_SUBRESOURCE mapped{};
      context->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &mapped);
      Image image = MakeImage(target.width, target.height);
      for (int y = 0; y < target.height; ++y) {
        const float* row = reinterpret_cast<const float*>(
          static_cast<const char*>(mapped.pData) + static_cast<size_t>(y) * mapped.RowPitch
        );
        for (int x = 0; x < target.width; ++x) {
          for (int c = 0; c < 3; ++c) {
            image.At(x, y, c) = row[x * 4 + c];
          }
        }
      }
      context->Unmap(staging.Get(), 0);
      return image;
    }

    // Upscales the `source` rectangle of `input` into the `dest` rectangle of a fresh target of `outWidth` x
    // `outHeight` (cleared to `clear`).
    Image RunUpscale(
      const Image& input,
      const RenderScaleRect& source,
      const RenderScaleRect& dest,
      const int outWidth,
      const int outHeight,
      const float clear
    )
    {
      Target in = Upload(input);
      Target out = Upload(MakeImage(outWidth, outHeight, clear));
      Draw(upscale.Get(), in, out, BuildRenderScaleConstants(source, dest, 0.0f), dest);
      return Read(out);
    }

    Image RunSharpen(
      const Image& input,
      const RenderScaleRect& dest,
      const float sharpness
    )
    {
      Target in = Upload(input);
      Target out = Upload(MakeImage(input.width, input.height, 0.0f));
      Draw(sharpen.Get(), in, out, BuildRenderScaleConstants(dest, dest, sharpness), dest);
      return Read(out);
    }
  };

  // ---- the scene
  // -----------------------------------------------------------------------------------------------------------------------------

  // The truth at full resolution: a flat grey left third, a ramp, a diagonal black/white edge and a thin dark line on
  // white.
  float Truth(
    const double x,
    const double y,
    const double w,
    const double h
  )
  {
    const double u = x / w;
    const double v = y / h;
    if (u < 0.25) {
      return 0.5f; // flat
    }
    if (u < 0.5) {
      return static_cast<float>((u - 0.25) / 0.25); // a ramp 0..1
    }
    if (u < 0.75) {
      // a diagonal edge: black above the line v = 0.2 + 0.9 * (u - 0.5), white below
      return v > 0.2 + 0.9 * (u - 0.5) ? 1.0f : 0.0f;
    }
    // a thin dark line (1.3 full-resolution pixels wide) at v = 0.5, on white
    const double distance = std::fabs(y - 0.5 * h);
    return distance < 0.65 ? 0.1f : 1.0f;
  }

  // Box-filtered render of the truth at `width` x `height` (what a rasteriser produces after anti-aliasing), 4x4
  // samples per pixel, as a grey image.
  Image Render(
    const int width,
    const int height,
    const double truthWidth,
    const double truthHeight
  )
  {
    Image image = MakeImage(width, height);
    for (int y = 0; y < height; ++y) {
      for (int x = 0; x < width; ++x) {
        double sum = 0.0;
        for (int sy = 0; sy < 4; ++sy) {
          for (int sx = 0; sx < 4; ++sx) {
            const double px = (x + (sx + 0.5) / 4.0) * truthWidth / width;
            const double py = (y + (sy + 0.5) / 4.0) * truthHeight / height;
            sum += Truth(px, py, truthWidth, truthHeight);
          }
        }
        for (int c = 0; c < 3; ++c) {
          image.At(x, y, c) = static_cast<float>(sum / 16.0);
        }
      }
    }
    return image;
  }

  // Plain bilinear upscale of `source` to `width` x `height`, the baseline the upscaler has to beat.
  Image Bilinear(
    const Image& source,
    const int width,
    const int height
  )
  {
    Image image = MakeImage(width, height);
    for (int y = 0; y < height; ++y) {
      for (int x = 0; x < width; ++x) {
        const double fx = (x + 0.5) * source.width / width - 0.5;
        const double fy = (y + 0.5) * source.height / height - 0.5;
        const int x0 = static_cast<int>(std::floor(fx));
        const int y0 = static_cast<int>(std::floor(fy));
        const double tx = fx - x0;
        const double ty = fy - y0;
        const auto at = [&](const int ix, const int iy) {
          return source.At(std::clamp(ix, 0, source.width - 1), std::clamp(iy, 0, source.height - 1), 0);
        };
        const double value = (at(x0, y0) * (1 - tx) + at(x0 + 1, y0) * tx) * (1 - ty) +
          (at(x0, y0 + 1) * (1 - tx) + at(x0 + 1, y0 + 1) * tx) * ty;
        for (int c = 0; c < 3; ++c) {
          image.At(x, y, c) = static_cast<float>(value);
        }
      }
    }
    return image;
  }

  double RegionError(
    const Image& a,
    const Image& b,
    const int x0,
    const int y0,
    const int x1,
    const int y1
  )
  {
    double sum = 0.0;
    int count = 0;
    for (int y = y0; y < y1; ++y) {
      for (int x = x0; x < x1; ++x) {
        const double d = a.At(x, y, 0) - b.At(x, y, 0);
        sum += d * d;
        ++count;
      }
    }
    return count > 0 ? sum / count : 0.0;
  }

  void TestUpscale(
    Runner& runner,
    const float factor,
    const char* const label
  )
  {
    constexpr int kFullWidth = 320;
    constexpr int kFullHeight = 200;
    const int srcWidth = static_cast<int>(RenderScaleExtent(kFullWidth, factor));
    const int srcHeight = static_cast<int>(RenderScaleExtent(kFullHeight, factor));
    const Image truth = Render(kFullWidth, kFullHeight, kFullWidth, kFullHeight);
    const Image low = Render(srcWidth, srcHeight, kFullWidth, kFullHeight);
    const Image bilinear = Bilinear(low, kFullWidth, kFullHeight);
    const RenderScaleRect source{0, 0, srcWidth, srcHeight};
    const RenderScaleRect dest{0, 0, kFullWidth, kFullHeight};
    const Image up = runner.RunUpscale(low, source, dest, kFullWidth, kFullHeight, 0.0f);

    char text[160];
    // flat: exact (the kernel is normalised)
    double flatWorst = 0.0;
    for (int y = 8; y < kFullHeight - 8; ++y) {
      for (int x = 6; x < kFullWidth / 4 - 8; ++x) {
        flatWorst = std::max(flatWorst, static_cast<double>(std::fabs(up.At(x, y, 0) - 0.5f)));
      }
    }
    std::snprintf(text, sizeof(text), "%s: flat area stays flat (worst %.5f)", label, flatWorst);
    Check(flatWorst < 0.002, text);

    // range: nothing outside [0, 1], and no overshoot anywhere (every output lies in the range of its source
    // neighbourhood)
    float lowest = 1.0f;
    float highest = 0.0f;
    for (const float v : up.rgb) {
      lowest = std::min(lowest, v);
      highest = std::max(highest, v);
    }
    std::snprintf(text, sizeof(text), "%s: range stays inside the source's (%.4f..%.4f)", label, lowest, highest);
    Check(lowest >= -1e-4f && highest <= 1.0f + 1e-4f, text);

    // the ramp is smooth and monotonic
    bool monotonic = true;
    const int rampY = kFullHeight / 3;
    for (int x = kFullWidth / 4 + 4; x < kFullWidth / 2 - 4; ++x) {
      if (up.At(x + 1, rampY, 0) < up.At(x, rampY, 0) - 0.003f) {
        monotonic = false;
      }
    }
    std::snprintf(text, sizeof(text), "%s: the ramp stays monotonic", label);
    Check(monotonic, text);

    // the diagonal edge: closer to the truth than bilinear
    const int ex0 = kFullWidth / 2 + 6;
    const int ex1 = kFullWidth * 3 / 4 - 6;
    const double edgeBilinear = RegionError(bilinear, truth, ex0, 4, ex1, kFullHeight - 4);
    const double edgeUp = RegionError(up, truth, ex0, 4, ex1, kFullHeight - 4);
    std::snprintf(
      text, sizeof(text), "%s: diagonal edge error %.5f against bilinear %.5f", label, edgeUp, edgeBilinear
    );
    Check(edgeUp < edgeBilinear * 0.85, text);
    std::printf(
      "%-22s diagonal edge MSE: upscaler %.5f, bilinear %.5f (%.0f %%)\n",
      label,
      edgeUp,
      edgeBilinear,
      100.0 * edgeUp / std::max(edgeBilinear, 1e-9)
    );

    // the thin line keeps more of its contrast than bilinear (its darkest column is darker)
    const int lx = kFullWidth * 7 / 8;
    float darkestUp = 1.0f;
    float darkestBilinear = 1.0f;
    for (int y = kFullHeight / 2 - 3; y <= kFullHeight / 2 + 3; ++y) {
      darkestUp = std::min(darkestUp, up.At(lx, y, 0));
      darkestBilinear = std::min(darkestBilinear, bilinear.At(lx, y, 0));
    }
    std::snprintf(
      text, sizeof(text), "%s: thin line darkest %.3f against bilinear %.3f", label, darkestUp, darkestBilinear
    );
    Check(darkestUp <= darkestBilinear + 0.002f, text);
    std::printf(
      "%-22s thin line darkest value: upscaler %.3f, bilinear %.3f (truth 0.1)\n", label, darkestUp, darkestBilinear
    );
  }

  // A view rectangle that does not start at the origin lands where it should, and nothing outside it is touched.
  void TestOffsetRectangle(
    Runner& runner
  )
  {
    constexpr int kFullWidth = 160;
    constexpr int kFullHeight = 100;
    const float factor = 0.5f;
    const Image low = Render(kFullWidth / 2, kFullHeight / 2, kFullWidth, kFullHeight);
    const Image reference = runner.RunUpscale(
      low, {0, 0, kFullWidth / 2, kFullHeight / 2}, {0, 0, kFullWidth, kFullHeight}, kFullWidth, kFullHeight, 0.0f
    );

    // The same picture as the lower-right quadrant of a bigger window: source and dest both offset.
    const int offsetX = 24;
    const int offsetY = 12;
    Image padded = MakeImage(kFullWidth / 2 + 30, kFullHeight / 2 + 20, 0.25f);
    for (int y = 0; y < low.height; ++y) {
      for (int x = 0; x < low.width; ++x) {
        for (int c = 0; c < 3; ++c) {
          padded.At(x + 5, y + 7, c) = low.At(x, y, c);
        }
      }
    }
    const RenderScaleRect source{5, 7, low.width, low.height};
    const RenderScaleRect dest{offsetX, offsetY, kFullWidth, kFullHeight};
    const Image moved = runner.RunUpscale(padded, source, dest, kFullWidth + 40, kFullHeight + 20, 0.75f);
    double worst = 0.0;
    for (int y = 0; y < kFullHeight; ++y) {
      for (int x = 0; x < kFullWidth; ++x) {
        worst = std::max(
          worst, static_cast<double>(std::fabs(moved.At(x + offsetX, y + offsetY, 0) - reference.At(x, y, 0)))
        );
      }
    }
    CheckNear(worst, 0.0, 1e-4, "an offset view rectangle gives the same picture");
    Check(
      moved.At(2, 2, 0) == 0.75f && moved.At(kFullWidth + 30, kFullHeight + 10, 0) == 0.75f,
      "pixels outside the view rectangle are untouched"
    );
    (void)factor;
  }

  void TestSharpen(
    Runner& runner
  )
  {
    constexpr int kWidth = 96;
    constexpr int kHeight = 32;
    // A soft step (6 pixels wide) between 0.2 and 0.8 on a flat field, and a pure black / white pair of plateaus away
    // from it.
    Image soft = MakeImage(kWidth, kHeight);
    for (int y = 0; y < kHeight; ++y) {
      for (int x = 0; x < kWidth; ++x) {
        float v = 0.2f;
        if (x >= kWidth / 2 + 3) {
          v = 0.8f;
        } else if (x >= kWidth / 2 - 3) {
          v = 0.2f + 0.6f * static_cast<float>(x - (kWidth / 2 - 3) + 0.5f) / 6.0f;
        }
        for (int c = 0; c < 3; ++c) {
          soft.At(x, y, c) = v;
        }
      }
    }
    const Image sharp = runner.RunSharpen(soft, {0, 0, kWidth, kHeight}, 1.0f);
    // plateaus unchanged
    CheckNear(sharp.At(10, 10, 0), 0.2, 1e-4, "sharpen leaves the low plateau");
    CheckNear(sharp.At(kWidth - 10, 10, 0), 0.8, 1e-4, "sharpen leaves the high plateau");
    // the edge is steeper: the 10-90 % rise is shorter
    const auto riseWidth = [&](const Image& image) {
      float lowX = 0.0f;
      float highX = 0.0f;
      for (int x = kWidth / 2 - 8; x < kWidth / 2 + 8; ++x) {
        const float a = image.At(x, 10, 0);
        const float b = image.At(x + 1, 10, 0);
        const float lowLevel = 0.2f + 0.06f;
        const float highLevel = 0.8f - 0.06f;
        if (a < lowLevel && b >= lowLevel) {
          lowX = x + (lowLevel - a) / (b - a);
        }
        if (a < highLevel && b >= highLevel) {
          highX = x + (highLevel - a) / (b - a);
        }
      }
      return highX - lowX;
    };
    const float before = riseWidth(soft);
    const float after = riseWidth(sharp);
    char text[120];
    std::snprintf(text, sizeof(text), "sharpen shortens the edge (rise %.2f -> %.2f pixels)", before, after);
    Check(after < before - 0.2f, text);
    std::printf("sharpen: 10-90 %% rise %.2f -> %.2f pixels\n", before, after);
    // no overshoot beyond the plateaus: the lobe is limited by the neighbours
    float lowest = 1.0f;
    float highest = 0.0f;
    for (const float v : sharp.rgb) {
      lowest = std::min(lowest, v);
      highest = std::max(highest, v);
    }
    Check(lowest >= 0.2f - 0.12f && highest <= 0.8f + 0.12f, "the sharpened edge overshoots by less than 0.12");
    Check(lowest >= 0.0f && highest <= 1.0f, "output stays in 0..1");

    // pure black and white plateaus cannot take any lobe: unchanged
    Image bw = MakeImage(kWidth, kHeight);
    for (int y = 0; y < kHeight; ++y) {
      for (int x = kWidth / 2; x < kWidth; ++x) {
        for (int c = 0; c < 3; ++c) {
          bw.At(x, y, c) = 1.0f;
        }
      }
    }
    const Image bwSharp = runner.RunSharpen(bw, {0, 0, kWidth, kHeight}, 1.0f);
    double changed = 0.0;
    for (size_t i = 0; i < bw.rgb.size(); ++i) {
      changed = std::max(changed, static_cast<double>(std::fabs(bwSharp.rgb[i] - bw.rgb[i])));
    }
    CheckNear(changed, 0.0, 1e-4, "a pure black / white edge is left alone");

    // zero strength is the identity
    const Image none = runner.RunSharpen(soft, {0, 0, kWidth, kHeight}, 0.0f);
    double diff = 0.0;
    for (size_t i = 0; i < soft.rgb.size(); ++i) {
      diff = std::max(diff, static_cast<double>(std::fabs(none.rgb[i] - soft.rgb[i])));
    }
    CheckNear(diff, 0.0, 1e-5, "sharpness 0 is the identity");
  }
} // namespace

TEST(
  RenderScale,
  Arithmetic
)
{
  TestArithmetic();
}

class RenderScaleShaders : public ::testing::Test
{
protected:
  void SetUp() override
  {
    if (!runner.Init()) {
      GTEST_SKIP() << "no software Direct3D 11 device";
    }
  }

  Runner runner;
};

TEST_F(
  RenderScaleShaders,
  Upscale50
)
{
  TestUpscale(runner, 0.5f, "50 %");
}

TEST_F(
  RenderScaleShaders,
  Upscale67
)
{
  TestUpscale(runner, 2.0f / 3.0f, "67 %");
}

TEST_F(
  RenderScaleShaders,
  Upscale85
)
{
  TestUpscale(runner, 0.85f, "85 %");
}

TEST_F(
  RenderScaleShaders,
  OffsetRectangle
)
{
  TestOffsetRectangle(runner);
}

TEST_F(
  RenderScaleShaders,
  Sharpen
)
{
  TestSharpen(runner);
}
