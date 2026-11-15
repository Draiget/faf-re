// A mesh terrain map in the view (FAF Studio's meshview.lua and EdMeshTerrain): the scenario's TerrainSystem = 'mesh'
// names the manifest (TerrainMesh), its patches are read (EdMeshData), drawn shaded by their normals with the batcher
// (with their edges in the Both mode), checked (EdMeshScan), and things placed stand on the mesh while it is shown.

#include "editor/view/EdMapScene.h"

#include "editor/doc/EdDocument.h"
#include "editor/doc/EdMapFile.h"
#include "editor/graph/EdTextureBake.h"
#include "editor/graph/EdTextureGraph.h"
#include "gpg/gal/backends/common/ImageCodec.h"
#include "editor/doc/EdScenarioInfo.h"
#include "editor/tools/EdMeshScan.h"
#include "gpg/core/utils/Logging.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"
#include "moho/mesh/Mesh.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/resource/RResId.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>

namespace moho
{
  extern bool ren_Terrain; // the height field drawn (RuntimeTuningGlobals.cpp)
} // namespace moho

namespace faf::editor
{
  namespace
  {
    constexpr float kReach = 40.0f; // a bridge deck isn't the ground of a cell, scenery isn't either
    constexpr std::size_t kMaxDrawnTriangles = 1500000;
  } // namespace

  namespace
  {
    /** A game texture as RGBA floats (at most 1024 across), sampled bilinearly with wrap. */
    struct MeshTexture
    {
      int w = 0;
      int h = 0;
      std::vector<float> px;

      void Sample(
        float u,
        float v,
        float (&out)[4]
      ) const
      {
        u = u - std::floor(u);
        v = v - std::floor(v);
        const float fx = u * static_cast<float>(w) - 0.5f;
        const float fy = v * static_cast<float>(h) - 0.5f;
        const int x0 = static_cast<int>(std::floor(fx));
        const int y0 = static_cast<int>(std::floor(fy));
        const float tx = fx - static_cast<float>(x0);
        const float ty = fy - static_cast<float>(y0);
        const auto at = [&](int x, int y) {
          x = ((x % w) + w) % w;
          y = ((y % h) + h) % h;
          return &px[(static_cast<std::size_t>(y) * static_cast<std::size_t>(w) + static_cast<std::size_t>(x)) * 4];
        };
        const float* a = at(x0, y0);
        const float* b = at(x0 + 1, y0);
        const float* c = at(x0, y0 + 1);
        const float* d = at(x0 + 1, y0 + 1);
        for (int k = 0; k < 4; ++k) {
          out[k] = (a[k] * (1.0f - tx) + b[k] * tx) * (1.0f - ty) + (c[k] * (1.0f - tx) + d[k] * tx) * ty;
        }
      }
    };

    bool LoadMeshTexture(
      const std::string& path,
      MeshTexture& out
    )
    {
      gpg::gal::imaging::ImageCodec* const codec = gpg::gal::imaging::ImageCodec::Instance();
      std::string bytes;
      if (path.empty() || codec == nullptr || !ReadGameFile(path, bytes)) {
        return false;
      }
      gpg::gal::imaging::DecodeOptions options;
      options.format = DXGI_FORMAT_B8G8R8A8_UNORM;
      options.mipLevels = 1;
      gpg::gal::imaging::Image image;
      if (
        FAILED(codec->Decode(bytes.data(), bytes.size(), options, image)) || image.subresources.empty() ||
        image.format != DXGI_FORMAT_B8G8R8A8_UNORM
      ) {
        return false;
      }
      const auto& level = image.subresources.front();
      const int w = static_cast<int>(level.width);
      const int h = static_cast<int>(level.height);
      if (w <= 0 || h <= 0) {
        return false;
      }
      const int step = std::max(1, std::max(w, h) / 1024);
      out.w = std::max(1, w / step);
      out.h = std::max(1, h / step);
      out.px.resize(static_cast<std::size_t>(out.w) * static_cast<std::size_t>(out.h) * 4);
      for (int y = 0; y < out.h; ++y) {
        const std::uint8_t* const row =
          image.bytes.data() + level.offset + static_cast<std::size_t>(y * step) * level.rowPitch;
        for (int x = 0; x < out.w; ++x) {
          const std::uint8_t* const p = row + static_cast<std::size_t>(x * step) * 4U;
          float* const d = &out.px[(static_cast<std::size_t>(y) * static_cast<std::size_t>(out.w) + static_cast<std::size_t>(x)) * 4];
          d[0] = static_cast<float>(p[2]) / 255.0f;
          d[1] = static_cast<float>(p[1]) / 255.0f;
          d[2] = static_cast<float>(p[0]) / 255.0f;
          d[3] = static_cast<float>(p[3]) / 255.0f;
        }
      }
      return true;
    }

    float LinearOf(
      const float c
    )
    {
      return std::pow(std::max(c, 0.0001f), 2.2f);
    }
  } // namespace

  bool EdMapScene::BakeMeshPatch(
    const std::size_t index,
    const int generation,
    std::string& meshPath,
    std::string& albedoPath,
    std::string& why
  )
  {
    if (mMeshViewCache.empty()) {
      why = "no cache folder";
      return false;
    }
    const edmesh::Patch& patch = mMeshMap.patches[index];
    const edmesh::Settings& s = mMeshMap.settings;
    const std::size_t vertices = std::min<std::size_t>(patch.vertexCount, patch.vertices.size() / 68);
    if (vertices == 0 || patch.indices.size() < 3) {
      why = "an empty patch";
      return false;
    }
    const auto inFolder = [this](const std::string& file) {
      if (file.empty() || file.front() == '/') {
        return file;
      }
      return mMeshMap.dir + (mMeshMap.dir.empty() || mMeshMap.dir.back() == '/' ? "" : "/") + file;
    };
    // The material's textures (Studio's slot order: diffuse a, b, light masks 0..2, normal a, b, specular a, b).
    const edmesh::Material* material =
      patch.material >= 0 && static_cast<std::size_t>(patch.material) < mMeshMap.materials.size()
      ? &mMeshMap.materials[static_cast<std::size_t>(patch.material)]
      : nullptr;
    MeshTexture slot[9];
    bool have[9] = {};
    for (int k = 0; k < 9 && material != nullptr; ++k) {
      have[k] = LoadMeshTexture(inFolder(material->files[k]), slot[k]);
    }
    if (!have[0]) {
      // No ground texture: the map's lowest layer (and its normal map).
      for (const EdTools::LayerSlot& layer : LayerSlots()) {
        if (!layer.albedo.empty() && LoadMeshTexture(layer.albedo, slot[0])) {
          have[0] = true;
          have[5] = LoadMeshTexture(layer.normals, slot[5]);
          break;
        }
      }
    }
    if (!have[0]) {
      why = "no texture to bake";
      return false;
    }
    const bool masks = have[2] || have[3] || have[4];
    MeshTexture ramp;
    const bool haveRamp = LoadMeshTexture(mDocument.WaterNow().textures[1], ramp);
    // The sun for a material without baked light (an OBJ just imported): the manifest's, else the map's.
    float sunDir[3] = {s.sunDirection[0], s.sunDirection[1], s.sunDirection[2]};
    float sunColour[3] = {s.sunColor[0], s.sunColor[1], s.sunColor[2]};
    if (sunColour[0] + sunColour[1] + sunColour[2] <= 0.0f) {
      const LightingState light = mDocument.LightingNow();
      for (int k = 0; k < 3; ++k) {
        sunDir[k] = light.sunDirection[k];
        sunColour[k] = light.sunColor[k];
      }
    }
    {
      const float l = std::sqrt(sunDir[0] * sunDir[0] + sunDir[1] * sunDir[1] + sunDir[2] * sunDir[2]);
      for (float& c : sunDir) {
        c = l > 0.0f ? c / l : 0.0f;
      }
    }
    // The patch seen from above: about 4 texels a unit, 256 to 2048 across.
    const float minX = patch.boundsMin[0];
    const float minZ = patch.boundsMin[2];
    const float spanX = std::max(1.0f, patch.boundsMax[0] - minX);
    const float spanZ = std::max(1.0f, patch.boundsMax[2] - minZ);
    int n = 256;
    while (n < 2048 && static_cast<float>(n) < std::max(spanX, spanZ) * 4.0f) {
      n *= 2;
    }
    struct Texel
    {
      float y = -1.0e30f;
      float uv[2] = {0, 0};
      float uv2[2] = {0, 0};
      float normal[3] = {0, 1, 0};
      float tangent[3] = {1, 0, 0};
      float binormal[3] = {0, 0, 1};
    };
    std::vector<Texel> grid(static_cast<std::size_t>(n) * static_cast<std::size_t>(n));
    const auto field = [&](const std::size_t v, const std::size_t offset, const int count, float* out) {
      std::memcpy(out, patch.vertices.data() + v * 68 + offset, static_cast<std::size_t>(count) * 4);
    };
    for (std::size_t t = 0; t + 2 < patch.indices.size(); t += 3) {
      std::size_t idx[3];
      float pos[3][3];
      float sx[3];
      float sz[3];
      bool ok = true;
      for (int k = 0; k < 3; ++k) {
        idx[k] = patch.indices[t + static_cast<std::size_t>(k)];
        if (idx[k] >= vertices) {
          ok = false;
          break;
        }
        field(idx[k], 0, 3, pos[k]);
        sx[k] = (pos[k][0] - minX) / spanX * static_cast<float>(n);
        sz[k] = (pos[k][2] - minZ) / spanZ * static_cast<float>(n);
      }
      if (!ok) {
        continue;
      }
      const float area = (sx[1] - sx[0]) * (sz[2] - sz[0]) - (sx[2] - sx[0]) * (sz[1] - sz[0]);
      if (std::fabs(area) < 1e-8f) {
        continue; // seen edge-on from above (a vertical wall)
      }
      const int x0 = std::max(0, static_cast<int>(std::floor(std::min({sx[0], sx[1], sx[2]}))));
      const int x1 = std::min(n - 1, static_cast<int>(std::ceil(std::max({sx[0], sx[1], sx[2]}))));
      const int z0 = std::max(0, static_cast<int>(std::floor(std::min({sz[0], sz[1], sz[2]}))));
      const int z1 = std::min(n - 1, static_cast<int>(std::ceil(std::max({sz[0], sz[1], sz[2]}))));
      for (int z = z0; z <= z1; ++z) {
        for (int x = x0; x <= x1; ++x) {
          const float px = static_cast<float>(x) + 0.5f;
          const float pz = static_cast<float>(z) + 0.5f;
          const float w0 = ((sx[1] - px) * (sz[2] - pz) - (sx[2] - px) * (sz[1] - pz)) / area;
          const float w1 = ((sx[2] - px) * (sz[0] - pz) - (sx[0] - px) * (sz[2] - pz)) / area;
          const float w2 = 1.0f - w0 - w1;
          if (w0 < -1e-4f || w1 < -1e-4f || w2 < -1e-4f) {
            continue;
          }
          const float y = w0 * pos[0][1] + w1 * pos[1][1] + w2 * pos[2][1];
          Texel& texel = grid[static_cast<std::size_t>(z) * static_cast<std::size_t>(n) + static_cast<std::size_t>(x)];
          if (y <= texel.y) {
            continue; // the top surface wins
          }
          texel.y = y;
          const float w[3] = {w0, w1, w2};
          float sum[2] = {0, 0}, sum2[2] = {0, 0}, nrm[3] = {0, 0, 0}, tan[3] = {0, 0, 0}, bin[3] = {0, 0, 0};
          for (int k = 0; k < 3; ++k) {
            float a[3], b[3], c[3], uv[2], uv2[2];
            field(idx[k], 12, 3, a);
            field(idx[k], 24, 3, b);
            field(idx[k], 36, 3, c);
            field(idx[k], 48, 2, uv);
            field(idx[k], 56, 2, uv2);
            for (int q = 0; q < 3; ++q) {
              nrm[q] += a[q] * w[k];
              tan[q] += b[q] * w[k];
              bin[q] += c[q] * w[k];
            }
            for (int q = 0; q < 2; ++q) {
              sum[q] += uv[q] * w[k];
              sum2[q] += uv2[q] * w[k];
            }
          }
          const auto unit = [](float (&v)[3], const float (&fallback)[3]) {
            const float l = std::sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
            for (int q = 0; q < 3; ++q) {
              v[q] = l > 1e-6f ? v[q] / l : fallback[q];
            }
          };
          unit(nrm, {0.0f, 1.0f, 0.0f});
          unit(tan, {1.0f, 0.0f, 0.0f});
          unit(bin, {0.0f, 0.0f, 1.0f});
          std::memcpy(texel.normal, nrm, sizeof nrm);
          std::memcpy(texel.tangent, tan, sizeof tan);
          std::memcpy(texel.binormal, bin, sizeof bin);
          std::memcpy(texel.uv, sum, sizeof sum);
          std::memcpy(texel.uv2, sum2, sizeof sum2);
        }
      }
    }
    // Studio's pixel shader at each texel (EdMeshDraw.cpp's PS, the sun shadow as lit and no highlight).
    TexImage out;
    out.Reset(n, 4);
    const bool hasWater = s.water > -9000.0f;
    const bool hazeOn = !hasWater && s.haveVoid && s.haze > -9000.0f;
    const float depthScale = 1.0f / std::max(1.0f, s.water - s.waterAbyss);
    static constexpr float kBasis[3][3] = {
      {0.81649658f, 0.0f, 0.57735027f}, {-0.40824829f, 0.70710678f, 0.57735027f}, {-0.40824829f, -0.70710678f, 0.57735027f}
    };
    const auto sample = [&](const int k, const float u, const float v, float (&c)[4], const float fallback) {
      if (have[k]) {
        slot[k].Sample(u, v, c);
      } else {
        c[0] = c[1] = c[2] = c[3] = fallback;
      }
    };
    for (int z = 0; z < n; ++z) {
      for (int x = 0; x < n; ++x) {
        const Texel& t = grid[static_cast<std::size_t>(z) * static_cast<std::size_t>(n) + static_cast<std::size_t>(x)];
        float* const d = out.Pixel(x, z);
        if (t.y < -1.0e29f) {
          d[0] = d[1] = d[2] = 0.0f;
          d[3] = 0.0f; // no surface: the alpha test drops it
          continue;
        }
        float l0[4], l1[4], l2[4];
        sample(2, t.uv2[0], t.uv2[1], l0, 1.0f);
        sample(3, t.uv2[0], t.uv2[1], l1, 1.0f);
        sample(4, t.uv2[0], t.uv2[1], l2, 1.0f);
        const float blend = material != nullptr && material->blending ? l1[3] : 0.0f;
        float a[4], b[4];
        sample(0, t.uv[0], t.uv[1], a, 1.0f);
        if (have[1]) {
          slot[1].Sample(t.uv[0], t.uv[1], b);
        } else {
          std::memcpy(b, a, sizeof a);
        }
        float diffuse[4];
        for (int q = 0; q < 4; ++q) {
          diffuse[q] = a[q] + (b[q] - a[q]) * blend;
        }
        const bool kept = material == nullptr || material->alphaTest < 0.0f || diffuse[3] * 255.0f > material->alphaTest;
        float na[4], nb[4];
        sample(5, t.uv[0], t.uv[1], na, 0.5f);
        if (!have[5]) {
          na[2] = 1.0f;
        }
        if (have[6]) {
          slot[6].Sample(t.uv[0], t.uv[1], nb);
        } else {
          std::memcpy(nb, na, sizeof na);
        }
        float nn[3];
        for (int q = 0; q < 3; ++q) {
          nn[q] = (na[q] + (nb[q] - na[q]) * blend) * 2.0f - 1.0f;
        }
        {
          const float l = std::sqrt(nn[0] * nn[0] + nn[1] * nn[1] + nn[2] * nn[2]);
          for (float& c : nn) {
            c = l > 1e-6f ? c / l : 0.0f;
          }
        }
        float light[3] = {0, 0, 0};
        if (masks) {
          const float* const maskRgb[3] = {l0, l1, l2};
          for (int k = 0; k < 3; ++k) {
            const float dp = std::clamp(nn[0] * kBasis[k][0] + nn[1] * kBasis[k][1] + nn[2] * kBasis[k][2], 0.0f, 1.0f);
            for (int q = 0; q < 3; ++q) {
              light[q] += dp * LinearOf(maskRgb[k][q]);
            }
          }
        } else {
          // No baked light: the sun on the surface's normal (its normal map turned into the world), and a fill.
          float world[3];
          for (int q = 0; q < 3; ++q) {
            world[q] = nn[0] * t.tangent[q] + nn[1] * t.binormal[q] + nn[2] * t.normal[q];
          }
          const float lambert = std::max(0.0f, world[0] * sunDir[0] + world[1] * sunDir[1] + world[2] * sunDir[2]);
          for (int q = 0; q < 3; ++q) {
            light[q] = LinearOf(std::clamp(sunColour[q], 0.0f, 2.0f)) * lambert + LinearOf(s.shadowColor[q]) * 0.6f;
          }
        }
        float ma[4], mb[4];
        sample(7, t.uv[0], t.uv[1], ma, 0.0f);
        if (have[8]) {
          slot[8].Sample(t.uv[0], t.uv[1], mb);
        } else {
          std::memcpy(mb, ma, sizeof ma);
        }
        const float glow = material != nullptr && material->glow ? ma[1] + (mb[1] - ma[1]) * blend : 0.0f;
        float colour[3];
        for (int q = 0; q < 3; ++q) {
          const float lit = light[q] + (1.0f - light[q]) * glow;
          float c = std::pow(std::max(0.0f, LinearOf(diffuse[q]) * lit), 1.0f / 2.2f);
          c = std::min(c, 0.7f) + 0.3f * (1.0f - std::exp(std::max(c - 0.7f, 0.0f) / -0.3f));
          colour[q] = c;
        }
        if (hasWater && t.y <= s.water && haveRamp) {
          float water[4];
          ramp.Sample(std::clamp((s.water - t.y) * depthScale, 0.0f, 1.0f), 0.5f, water);
          for (int q = 0; q < 3; ++q) {
            colour[q] += (water[q] - colour[q]) * water[3] * s.waterTint;
          }
        }
        if (hazeOn) {
          const float haze = std::clamp((s.haze - t.y) / s.hazeSpan, 0.0f, 1.0f);
          for (int q = 0; q < 3; ++q) {
            colour[q] += (s.voidColor[q] - colour[q]) * haze;
          }
        }
        d[0] = colour[0];
        d[1] = colour[1];
        d[2] = colour[2];
        d[3] = kept ? 1.0f : 0.0f;
      }
    }
    // The files: the baked texture and the patch whose first texture coordinates span it.
    std::string bytes;
    if (!ReadGameFile(inFolder(patch.file), bytes) || bytes.size() < 48) {
      why = "the patch file can't be read";
      return false;
    }
    std::uint32_t vertexOffset = 0;
    std::uint32_t vertexCount = 0;
    std::memcpy(&vertexOffset, bytes.data() + 16, 4);
    std::memcpy(&vertexCount, bytes.data() + 24, 4);
    if (static_cast<std::uint64_t>(vertexOffset) + vertexCount * 68ull > bytes.size()) {
      why = "the patch file's vertices are outside it";
      return false;
    }
    for (std::uint32_t v = 0; v < vertexCount; ++v) {
      char* const at = bytes.data() + vertexOffset + static_cast<std::size_t>(v) * 68;
      float position[3];
      std::memcpy(position, at, 12);
      const float uv[2] = {(position[0] - minX) / spanX, (position[2] - minZ) / spanZ};
      std::memcpy(at + 48, uv, 8);
    }
    std::vector<std::uint8_t> dds;
    if (!EncodeDds(out, DdsKind::Bc3, dds, why)) {
      return false;
    }
    const std::string name = mDocument.FolderName() + "_" + std::to_string(generation);
    const std::filesystem::path folder = mMeshViewCache / name;
    std::error_code ec;
    std::filesystem::create_directories(folder, ec);
    const std::string base = "patch" + std::to_string(index);
    std::ofstream(folder / (base + ".scm"), std::ios::binary | std::ios::trunc).write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    std::ofstream(folder / (base + "_albedo.dds"), std::ios::binary | std::ios::trunc)
      .write(reinterpret_cast<const char*>(dds.data()), static_cast<std::streamsize>(dds.size()));
    meshPath = "/editor_meshview/" + name + "/" + base + ".scm";
    albedoPath = "/editor_meshview/" + name + "/" + base + "_albedo.dds";
    return true;
  }

  void EdMapScene::DeleteMeshInstances()
  {
    if (moho::MeshRenderer::GetInstance() != nullptr) {
      for (moho::MeshInstance* const instance : mMeshPatchInstances) {
        delete instance;
      }
    }
    mMeshPatchInstances.clear();
    for (moho::RMeshBlueprint* const blueprint : mMeshPatchBlueprints) {
      delete blueprint;
    }
    mMeshPatchBlueprints.clear();
    mMeshInstancesTried = false;
  }

  void EdMapScene::BuildMeshInstances()
  {
    mMeshInstancesTried = true;
    moho::RRuleGameRules* const rules = Rules();
    moho::MeshRenderer* const renderer = moho::MeshRenderer::GetInstance();
    if (rules == nullptr || renderer == nullptr || !mMeshMap.Loaded()) {
      mMeshInstancesTried = false; // again once they are up
      return;
    }
    static constexpr int kDiffuse = 0;
    static constexpr int kNormal = 5;
    static constexpr int kSpecular = 7;
    const auto inFolder = [this](const std::string& file) {
      if (file.empty() || file.front() == '/') {
        return file;
      }
      return mMeshMap.dir + (mMeshMap.dir.empty() || mMeshMap.dir.back() == '/' ? "" : "/") + file;
    };
    // The material baked per patch (FAF Studio's mesh shader on the patch), into a new cache folder each load, mounted
    // once its files are written.
    const auto bakeStarted = std::chrono::steady_clock::now();
    const int generation = ++mMeshBakeGeneration;
    // The map's older bakes go (a folder still mounted may refuse: it goes next time).
    if (!mMeshViewCache.empty()) {
      std::error_code ec;
      const std::string prefix = mDocument.FolderName() + "_";
      for (const auto& entry : std::filesystem::directory_iterator(mMeshViewCache, ec)) {
        const std::string name = entry.path().filename().string();
        if (name.rfind(prefix, 0) == 0 && name != prefix + std::to_string(generation)) {
          std::error_code removeError;
          std::filesystem::remove_all(entry.path(), removeError);
        }
      }
    }
    std::vector<std::pair<std::string, std::string>> baked(mMeshMap.patches.size());
    int bakedCount = 0;
    std::string bakeWhy;
    for (std::size_t i = 0; i < mMeshMap.patches.size(); ++i) {
      if (!mMeshMap.patches[i].sky && BakeMeshPatch(i, generation, baked[i].first, baked[i].second, bakeWhy)) {
        ++bakedCount;
      } else {
        baked[i] = {};
      }
    }
    if (bakedCount > 0) {
      const std::string name = mDocument.FolderName() + "_" + std::to_string(generation);
      if (!moho::DISK_MountDirectoryNow(mMeshViewCache / name, ("/editor_meshview/" + name).c_str())) {
        gpg::Warnf("editor: mesh terrain: the baked patches' folder couldn't be mounted");
        baked.assign(baked.size(), {});
        bakedCount = 0;
      }
    }
    gpg::Logf(
      "editor: mesh terrain: %d of %zu patches baked with their materials in %.2f s%s%s",
      bakedCount,
      mMeshMap.patches.size(),
      std::chrono::duration<double>(std::chrono::steady_clock::now() - bakeStarted).count(),
      bakeWhy.empty() ? "" : "; not baked: ",
      bakeWhy.c_str()
    );
    int made = 0;
    for (std::size_t i = 0; i < mMeshMap.patches.size(); ++i) {
      const edmesh::Patch& patch = mMeshMap.patches[i];
      if (patch.sky) {
        continue;
      }
      moho::RResId id{};
      id.name.assign(("/editor/meshterrain/patch" + std::to_string(i) + "_mesh").c_str());
      auto* const blueprint = new moho::RMeshBlueprint(rules, id);
      moho::RMeshBlueprintLOD lod;
      lod.mMeshName.assign(inFolder(patch.file).c_str());
      if (patch.material >= 0 && static_cast<std::size_t>(patch.material) < mMeshMap.materials.size()) {
        const edmesh::Material& material = mMeshMap.materials[static_cast<std::size_t>(patch.material)];
        lod.mAlbedoName.assign(inFolder(material.files[kDiffuse]).c_str());
        lod.mNormalsName.assign(inFolder(material.files[kNormal]).c_str());
        lod.mSpecularName.assign(inFolder(material.files[kSpecular]).c_str());
      }
      // A material without textures takes the map's lowest layer's (its ground), not black.
      if (lod.mAlbedoName.empty() || lod.mAlbedoName[0] == '\0') {
        const std::vector<EdTools::LayerSlot> slots = LayerSlots();
        for (const EdTools::LayerSlot& slot : slots) {
          if (!slot.albedo.empty()) {
            lod.mAlbedoName.assign(slot.albedo.c_str());
            lod.mNormalsName.assign(slot.normals.c_str());
            break;
          }
        }
      }
      lod.mShaderName.assign("NormalMappedTerrain");
      if (!baked[i].first.empty()) {
        // The baked material: unlit (Flat: the colour times the texture), its light baked in.
        lod.mMeshName.assign(baked[i].first.c_str());
        lod.mAlbedoName.assign(baked[i].second.c_str());
        lod.mNormalsName.assign("");
        lod.mSpecularName.assign("");
        lod.mShaderName.assign("Flat");
      }
      lod.mLodCutoff = 1.0e6f; // drawn at any distance, as ground
      blueprint->mLods.push_back(lod);
      mMeshPatchBlueprints.push_back(blueprint);
      if (i == 0) {
        gpg::Logf(
          "editor: mesh terrain: patch 0 model %s (%s), albedo %s, normals %s",
          blueprint->GetMesh() != nullptr ? "loads" : "doesn't load",
          lod.mMeshName.c_str(),
          lod.mAlbedoName.c_str(),
          lod.mNormalsName.c_str()
        );
      }
      moho::MeshInstance* const instance = renderer->CreateMeshInstance(
        0, -1, blueprint, Wm3::Vec3f{1.0f, 1.0f, 1.0f}, false, std::shared_ptr<moho::MeshMaterial>()
      );
      if (instance == nullptr) {
        continue;
      }
      // The patches are in map units already: at the origin, unturned.
      moho::VTransform at{};
      at.orient_ = Wm3::Quatf(1.0f, 0.0f, 0.0f, 0.0f);
      at.pos_ = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
      instance->SetStance(at, at);
      instance->isHidden = mMeshMode == 0 ? 1 : 0;
      mMeshPatchInstances.push_back(instance);
      ++made;
    }
    gpg::Logf("editor: mesh terrain: %d of %zu patches drawn as models", made, mMeshMap.patches.size());
  }

  void EdMapScene::SyncMeshView()
  {
    // Each frame: the patches' models made once the rules are up, shown or hidden by the mode; the height field off
    // in Mesh only (back on whenever the mesh isn't shown alone).
    if (mMeshMap.Loaded() && !mMeshInstancesTried) {
      BuildMeshInstances();
    }
    // Their bounds published again each frame: SetStance publishes them only when the place changes (a patch at the
    // origin, unturned, is where a new instance already "is", so it never would), and a model still loading has none
    // to publish yet; without bounds the renderer's spatial database never hands the instance over, and it isn't drawn.
    // A nudge and back is a change each time.
    for (moho::MeshInstance* const instance : mMeshPatchInstances) {
      instance->isHidden = mMeshMode == 0 ? 1 : 0;
      const moho::VTransform at = instance->endTransform;
      moho::VTransform nudged = at;
      nudged.pos_.y += 0.001f;
      instance->SetStance(nudged, nudged);
      instance->SetStance(at, at);
    }
    const bool hide = mMeshMode == 1 && mMeshMap.Loaded() && !mMeshPatchInstances.empty();
    if (hide != mMeshHidesTerrain) {
      mMeshHidesTerrain = hide;
      moho::ren_Terrain = !hide;
    }
  }

  std::string EdMapScene::LoadMeshTerrain()
  {
    DeleteMeshInstances();
    mMeshMap.Clear();
    mMeshTris.clear();
    mMeshEdges.clear();
    std::string system;
    std::string manifest;
    const std::string& scenario = mDocument.Scenario();
    if (!ReadScenarioField(scenario, "TerrainSystem", system) || system != "mesh") {
      return "This map isn't a mesh terrain map (its scenario has no TerrainSystem = 'mesh').";
    }
    if (!ReadScenarioField(scenario, "TerrainMesh", manifest) || manifest.empty()) {
      manifest = "/maps/" + mDocument.FolderName() + "/terrain/terrain.lua";
    }
    if (!mMeshMap.Load(manifest)) {
      gpg::Warnf("editor: mesh terrain: %s", mMeshMap.error.c_str());
      return "The mesh terrain didn't load: " + mMeshMap.error;
    }
    // The triangles shaded by their normals against a light from above, once; the edges for the Both mode.
    std::size_t drawn = 0;
    for (const edmesh::Patch& p : mMeshMap.patches) {
      if (p.sky) {
        continue;
      }
      const std::size_t n = std::min<std::size_t>(p.vertexCount, p.vertices.size() / 68);
      const auto at = [&p](const std::size_t i, const std::size_t offset, float (&out)[3]) {
        std::memcpy(out, p.vertices.data() + i * 68 + offset, 12);
      };
      for (std::size_t t = 0; t + 2 < p.indices.size() && drawn < kMaxDrawnTriangles; t += 3) {
        moho::CD3DPrimBatcher::Vertex v[3]{};
        bool ok = true;
        for (int k = 0; k < 3; ++k) {
          const std::size_t i = p.indices[t + static_cast<std::size_t>(k)];
          if (i >= n) {
            ok = false;
            break;
          }
          float pos[3];
          float nrm[3];
          at(i, 0, pos);
          at(i, 12, nrm);
          const float light = std::clamp(0.35f + 0.65f * (nrm[1] * 0.8f + nrm[0] * 0.35f + nrm[2] * 0.2f), 0.15f, 1.0f);
          const auto c = static_cast<std::uint32_t>(std::clamp(light * 200.0f, 0.0f, 255.0f));
          v[k].mX = pos[0];
          v[k].mY = pos[1];
          v[k].mZ = pos[2];
          v[k].mColor = 0xFF000000u | (c << 16) | (c << 8) | static_cast<std::uint32_t>(c * 0.9f);
        }
        if (!ok) {
          continue;
        }
        mMeshTris.insert(mMeshTris.end(), v, v + 3);
        for (int k = 0; k < 3; ++k) {
          moho::CD3DPrimBatcher::Vertex a = v[k];
          moho::CD3DPrimBatcher::Vertex b = v[(k + 1) % 3];
          a.mColor = b.mColor = 0x6040E0FFu;
          mMeshEdges.push_back(a);
          mMeshEdges.push_back(b);
        }
        ++drawn;
      }
    }
    char text[200];
    (void)std::snprintf(
      text,
      sizeof(text),
      "Mesh terrain %s: %zu patches, %u triangles%s",
      manifest.c_str(),
      mMeshMap.patches.size(),
      mMeshMap.TotalTriangles(),
      drawn < mMeshMap.TotalTriangles() ? " (the view draws the first 1.5 million)" : ""
    );
    gpg::Logf("editor: %s", text);
    return text;
  }

  std::vector<std::string> EdMapScene::CheckMeshTerrain()
  {
    std::vector<std::string> lines;
    for (const MeshScanFinding& f : ScanMeshMap(mMeshMap).findings) {
      lines.push_back(std::string(1, f.severity) + " " + f.code + ": " + f.text);
    }
    return lines;
  }

  float EdMapScene::PlacementHeight(
    const float x,
    const float z
  ) const
  {
    const float field = mMap != nullptr
      ? mMap->mTerrainRes->GetHeightAt(
          static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z))
        )
      : 0.0f;
    if (mMeshMode != 0 && mMeshMap.Loaded()) {
      float y = 0.0f;
      if (mMeshMap.HeightAt(x, z, field + kReach, y)) {
        return y;
      }
    }
    return field;
  }

  void EdMapScene::DrawMeshTerrain(
    moho::CD3DPrimBatcher& batcher
  )
  {
    // The models draw the patches; the shaded triangles only until they are made (or when they can't be).
    if (mMeshMode == 0 || (mMeshTris.empty() && mMeshEdges.empty())) {
      return;
    }
    if (!mMeshPatchInstances.empty()) {
      if (mMeshMode == 2) {
        for (std::size_t i = 0; i + 1 < mMeshEdges.size(); i += 2) {
          batcher.DrawLine(mMeshEdges[i], mMeshEdges[i + 1]);
        }
      }
      return;
    }
    // In pieces (the batcher takes a bounded count at a time).
    constexpr std::size_t kChunk = 6000;
    for (std::size_t at = 0; at < mMeshTris.size(); at += kChunk * 3) {
      const std::size_t count = std::min(kChunk, (mMeshTris.size() - at) / 3);
      batcher.DrawTriangles(mMeshTris.data() + at, static_cast<std::uint32_t>(count));
    }
    if (mMeshMode == 2) {
      for (std::size_t i = 0; i + 1 < mMeshEdges.size(); i += 2) {
        batcher.DrawLine(mMeshEdges[i], mMeshEdges[i + 1]);
      }
    }
  }
} // namespace faf::editor
