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
#include "editor/tools/EdScm.h"
#include "gpg/core/utils/Logging.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"
#include "moho/mesh/Mesh.h"
#include "moho/render/camera/CameraImpl.h"
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
  extern bool ren_TerrainSurface;   // the height field's surface drawn (WRenViewport.cpp)
  extern float ren_ShadowExtraMinY; // heights the shadow map must also hold (Shadow.cpp)
  extern float ren_ShadowExtraMaxY;
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
  } // namespace

  std::expected<EdMapScene::MeshMaterialView, std::string> EdMapScene::BakeMeshMaterial(
    const int materialIndex,
    const std::filesystem::path& folder,
    const std::string& vfs
  )
  {
    std::string why;
    const auto inFolder = [this](const std::string& file) {
      if (file.empty() || file.front() == '/') {
        return file;
      }
      return mMeshMap.dir + (mMeshMap.dir.empty() || mMeshMap.dir.back() == '/' ? "" : "/") + file;
    };
    const edmesh::Material* material =
      materialIndex >= 0 && static_cast<std::size_t>(materialIndex) < mMeshMap.materials.size()
      ? &mMeshMap.materials[static_cast<std::size_t>(materialIndex)]
      : nullptr;
    const std::string tag = "mat" + std::to_string(materialIndex);
    const auto write = [&](const std::string& name, const TexImage& image, const DdsKind kind) -> std::string {
      const auto dds = EncodeDds(image, kind);
      if (!dds) {
        why = dds.error();
        return {};
      }
      std::ofstream(folder / name, std::ios::binary | std::ios::trunc)
        .write(reinterpret_cast<const char*>(dds->data()), static_cast<std::streamsize>(dds->size()));
      return vfs + "/" + name;
    };
    const auto exists = [&](const std::string& path) {
      std::string bytes;
      return !path.empty() && ReadGameFile(path, bytes);
    };
    // FAF Studio's slots: diffuse a, b, light masks 0..2, normal a, b, mask a, b. The game's mesh technique has five
    // samplers, so the editor's techniques read them packed (CD3DEffectTechnique.cpp, EditorMeshTerrainPS):
    //   albedo / secondary: the layers as they are;
    //   normals: layer A's normal x, y and layer B's (z made again in the shader);
    //   lookup: layer A's mask green (glow) and blue (sun highlight, times Studio's 0.5), then layer B's;
    //   specular: 2 x 2 tiles over the second coordinates, light masks 0, 1 (its alpha the layers' blend), 2, and a
    //   tile of constants in four bands: the void colour and whether the ground fades into it; SC2's shadow fill colour
    //   and how far a moving shadow pulls towards it; the fade's level and span; the alpha test's reference.
    // The map's lowest layer for a material with no ground texture.
    MeshMaterialView out;
    std::string normalsA;
    std::string normalsB;
    if (material != nullptr && exists(inFolder(material->files[0]))) {
      out.albedo = inFolder(material->files[0]);
      normalsA = inFolder(material->files[5]);
      normalsB = inFolder(material->files[6]);
    } else {
      for (const EdTools::LayerSlot& layer : LayerSlots()) {
        if (!layer.albedo.empty()) {
          out.albedo = layer.albedo;
          normalsA = layer.normals;
          break;
        }
      }
    }
    if (out.albedo.empty()) {
      return std::unexpected("no ground texture");
    }
    out.secondary =
      material != nullptr && exists(inFolder(material->files[1])) ? inFolder(material->files[1]) : out.albedo;
    out.alphaTest = material != nullptr && material->alphaTest >= 0.0f;
    const auto square =
      [](const MeshTexture& a, const MeshTexture& b, const bool haveA, const bool haveB, const int lo, const int hi) {
      int side = 0;
      side = std::max(side, haveA ? std::max(a.w, a.h) : 0);
      side = std::max(side, haveB ? std::max(b.w, b.h) : 0);
      return std::clamp(side, lo, hi);
    };
    // The normal maps, A's and B's (one layer only: B is A).
    {
      MeshTexture a;
      MeshTexture b;
      const bool haveA = LoadMeshTexture(normalsA, a);
      const bool haveB = LoadMeshTexture(normalsB, b);
      const int side = haveA || haveB ? square(a, b, haveA, haveB, 4, 1024) : 4;
      TexImage image;
      image.Reset(side, 4);
      for (int y = 0; y < side; ++y) {
        for (int x = 0; x < side; ++x) {
          const float u = (static_cast<float>(x) + 0.5f) / static_cast<float>(side);
          const float v = (static_cast<float>(y) + 0.5f) / static_cast<float>(side);
          float ca[4] = {0.5f, 0.5f, 1.0f, 1.0f};
          float cb[4] = {0.5f, 0.5f, 1.0f, 1.0f};
          if (haveA) {
            a.Sample(u, v, ca);
          }
          if (haveB) {
            b.Sample(u, v, cb);
          } else if (haveA) {
            std::copy(std::begin(ca), std::end(ca), std::begin(cb));
          }
          float* const d = image.Pixel(x, y);
          d[0] = ca[0];
          d[1] = ca[1];
          d[2] = cb[0];
          d[3] = cb[1];
        }
      }
      out.normals = write(tag + "_normals.dds", image, DdsKind::Bgra);
    }
    // The masks, with only what the material uses (Studio: no mask A, no glow, and a full highlight).
    {
      MeshTexture a;
      MeshTexture b;
      const bool haveA = material != nullptr && LoadMeshTexture(inFolder(material->files[7]), a);
      const bool haveB = material != nullptr && LoadMeshTexture(inFolder(material->files[8]), b);
      const bool glow = material != nullptr && material->glow && haveA;
      const float highlight = material != nullptr && material->highlight ? 0.5f : 0.0f;
      const int side = haveA || haveB ? square(a, b, haveA, haveB, 4, 1024) : 4;
      TexImage image;
      image.Reset(side, 4);
      for (int y = 0; y < side; ++y) {
        for (int x = 0; x < side; ++x) {
          const float u = (static_cast<float>(x) + 0.5f) / static_cast<float>(side);
          const float v = (static_cast<float>(y) + 0.5f) / static_cast<float>(side);
          float ca[4] = {1.0f, 1.0f, 1.0f, 1.0f};
          float cb[4] = {1.0f, 1.0f, 1.0f, 1.0f};
          if (haveA) {
            a.Sample(u, v, ca);
          }
          if (haveB) {
            b.Sample(u, v, cb);
          } else {
            std::copy(std::begin(ca), std::end(ca), std::begin(cb));
          }
          float* const d = image.Pixel(x, y);
          d[0] = glow ? ca[1] : 0.0f;
          d[1] = ca[2] * highlight;
          d[2] = glow ? cb[1] : 0.0f;
          d[3] = cb[2] * highlight;
        }
      }
      out.lookup = write(tag + "_mask.dds", image, DdsKind::Bgra);
    }
    // The light masks and the constants.
    {
      MeshTexture masks[3];
      bool haveMask[3] = {};
      int tile = 4;
      for (int k = 0; k < 3 && material != nullptr; ++k) {
        haveMask[k] = LoadMeshTexture(inFolder(material->files[2 + k]), masks[k]);
        tile = std::max(tile, haveMask[k] ? std::max(masks[k].w, masks[k].h) : 0);
      }
      out.lightMasks = haveMask[0] || haveMask[1] || haveMask[2];
      tile = std::clamp(tile, 4, 512);
      const edmesh::Settings& settings = mMeshMap.settings;
      const bool water = settings.water > -9000.0f;
      const bool haze = !water && settings.haveVoid && settings.haze > -9000.0f;
      // 16 bits over two channels: the level over -1024 .. 3072, the span over 0 .. 4096.
      const auto split = [](const float value, const float lo, const float span, float& high, float& low) {
        const int word = std::clamp(static_cast<int>(std::lround((value - lo) / span * 65535.0f)), 0, 65535);
        high = static_cast<float>(word >> 8) / 255.0f;
        low = static_cast<float>(word & 0xFF) / 255.0f;
      };
      float band[4][4] = {
        {settings.voidColor[0], settings.voidColor[1], settings.voidColor[2], haze ? 1.0f : 0.0f},
        {settings.shadowColor[0],
         settings.shadowColor[1],
         settings.shadowColor[2],
         std::clamp(settings.shadowColor[3], 0.0f, 1.0f)},
        {0, 0, 0, 0},
        {material != nullptr && material->alphaTest >= 0.0f ? std::clamp(material->alphaTest, 0.0f, 255.0f) / 255.0f
                                                            : 0.5f,
         0,
         0,
         0},
      };
      split(settings.haze, -1024.0f, 4096.0f, band[2][0], band[2][1]);
      split(std::max(settings.hazeSpan, 0.001f), 0.0f, 4096.0f, band[2][2], band[2][3]);
      TexImage atlas;
      atlas.Reset(tile * 2, 4);
      for (int y = 0; y < tile * 2; ++y) {
        for (int x = 0; x < tile * 2; ++x) {
          float* const d = atlas.Pixel(x, y);
          const int k = (y >= tile ? 2 : 0) + (x >= tile ? 1 : 0);
          if (k == 3) {
            const int b = std::clamp((y - tile) * 4 / tile, 0, 3);
            std::copy(std::begin(band[b]), std::end(band[b]), d);
            continue;
          }
          float c[4] = {0.5f, 0.5f, 0.5f, 0.5f}; // Studio's grey for a mask the material lacks
          if (haveMask[k]) {
            masks[k].Sample(
              (static_cast<float>(x % tile) + 0.5f) / static_cast<float>(tile),
              (static_cast<float>(y % tile) + 0.5f) / static_cast<float>(tile),
              c
            );
          }
          if (k == 1 && (material == nullptr || !material->blending || !haveMask[1])) {
            c[3] = 0.0f; // the layers don't blend
          }
          std::copy(std::begin(c), std::end(c), d);
        }
      }
      out.specular = write(tag + "_light.dds", atlas, DdsKind::Bgra);
    }
    if (out.specular.empty() || out.lookup.empty() || out.normals.empty()) {
      return std::unexpected(why);
    }
    return out;
  }

  void EdMapScene::DeleteMeshInstances()
  {
    if (moho::MeshRenderer::GetInstance() != nullptr) {
      for (moho::MeshInstance* const instance : mMeshPatchInstances) {
        delete instance;
      }
    }
    mMeshPatchInstances.clear();
    mMeshPatchKinds.clear();
    if (mMeshSetsShadowRange) {
      moho::ren_ShadowExtraMinY = 1.0f; // (empty: the shadow map fitted to the height field alone again)
      moho::ren_ShadowExtraMaxY = 0.0f;
      mMeshSetsShadowRange = false;
    }
    for (moho::RMeshBlueprint* const blueprint : mMeshPatchBlueprints) {
      delete blueprint;
    }
    mMeshPatchBlueprints.clear();
    mMeshInstancesTried = false;
  }

  void EdMapScene::BuildMeshInstances()
  {
    mMeshInstancesTried = true;
    mMeshBuiltForBoth = mMeshMode == 2;
    moho::RRuleGameRules* const rules = Rules();
    moho::MeshRenderer* const renderer = moho::MeshRenderer::GetInstance();
    if (rules == nullptr || renderer == nullptr || !MeshInView()) {
      mMeshInstancesTried = false; // again once they are up
      return;
    }
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
        if (name.starts_with(prefix) && name != prefix + std::to_string(generation)) {
          std::error_code removeError;
          std::filesystem::remove_all(entry.path(), removeError);
        }
      }
    }
    // Each material once, into this load's cache folder (mounted when its files are written).
    const std::string name = mDocument.FolderName() + "_" + std::to_string(generation);
    const std::filesystem::path folder = mMeshViewCache / name;
    const std::string vfs = "/editor_meshview/" + name;
    std::error_code ec;
    std::filesystem::create_directories(folder, ec);
    std::map<int, MeshMaterialView> views;
    std::string bakeWhy;
    int masked = 0;
    for (const edmesh::Patch& patch : mMeshMap.patches) {
      if (!views.contains(patch.material)) {
        const auto view = mMeshViewCache.empty()
          ? std::expected<MeshMaterialView, std::string>(std::unexpected(bakeWhy))
          : BakeMeshMaterial(patch.material, folder, vfs);
        if (view) {
          masked += view->lightMasks ? 1 : 0;
          views[patch.material] = *view;
        } else {
          bakeWhy = view.error();
          views[patch.material] = MeshMaterialView{};
        }
      }
    }
    // Each ground patch again about its own middle, the instance placed there: the renderer culls a model by a sphere
    // round the instance's place (half the model's size: MeshInstance::UpdateInterpolatedFields), so a patch kept in
    // world coordinates at the origin was culled by any view that doesn't hold the origin, the shadow map's above all.
    std::map<std::size_t, std::pair<std::string, Wm3::Vec3f>> centred;
    if (!mMeshViewCache.empty()) {
      for (std::size_t i = 0; i < mMeshMap.patches.size(); ++i) {
        const edmesh::Patch& patch = mMeshMap.patches[i];
        std::string bytes;
        if (patch.sky || !ReadGameFile(inFolder(patch.file), bytes) || bytes.size() < 0x1C) {
          continue;
        }
        const auto word = [&](const std::size_t at) {
          std::uint32_t v = 0;
          std::memcpy(&v, bytes.data() + at, 4);
          return v;
        };
        const std::size_t vertices = word(0x10);
        const std::size_t count = word(0x18);
        if (!bytes.starts_with("MODL") || vertices + count * 68 > bytes.size()) {
          continue;
        }
        const float middle[3] = {
          (patch.boundsMin[0] + patch.boundsMax[0]) * 0.5f,
          (patch.boundsMin[1] + patch.boundsMax[1]) * 0.5f,
          (patch.boundsMin[2] + patch.boundsMax[2]) * 0.5f,
        };
        for (std::size_t v = 0; v < count; ++v) {
          for (int k = 0; k < 3; ++k) {
            float f = 0.0f;
            char* const at = bytes.data() + vertices + v * 68 + static_cast<std::size_t>(k) * 4;
            std::memcpy(&f, at, 4);
            f -= middle[k];
            std::memcpy(at, &f, 4);
          }
        }
        const std::string file = "patch" + std::to_string(i) + ".scm";
        std::ofstream(folder / file, std::ios::binary | std::ios::trunc)
          .write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        centred[i] = {vfs + "/" + file, Wm3::Vec3f{middle[0], middle[1], middle[2]}};
      }
    }
    // The fill to the horizon past the mesh: at the water (its deep colour) or below the mesh (the void's colour).
    const edmesh::Settings& settings = mMeshMap.settings;
    std::string fillMesh;
    std::string fillTexture;
    if (!mMeshViewCache.empty()) {
      const bool water = settings.water > -9000.0f;
      float y = water ? settings.water : settings.groundLow;
      if (!water && settings.groundLow <= -9000.0f) {
        y = 1.0e9f;
        for (const edmesh::Patch& patch : mMeshMap.patches) {
          y = std::min(y, patch.boundsMin[1]);
        }
        y -= 1.0f;
      }
      float colour[3] = {settings.voidColor[0], settings.voidColor[1], settings.voidColor[2]};
      MeshTexture ramp;
      if (water && LoadMeshTexture(mDocument.WaterNow().textures[1], ramp)) {
        float c[4];
        ramp.Sample(0.97f, 0.5f, c);
        colour[0] = c[0];
        colour[1] = c[1];
        colour[2] = c[2];
      }
      TexImage image;
      image.Reset(4, 4);
      for (int k = 0; k < 16; ++k) {
        float* const d = image.Pixel(k % 4, k / 4);
        d[0] = colour[0];
        d[1] = colour[1];
        d[2] = colour[2];
        d[3] = 1.0f;
      }
      std::vector<std::uint8_t> dds;
      ObjMesh quad;
      const float c = settings.size * 0.5f;
      const float r = std::max(settings.size, 1024.0f) * 20.0f;
      quad.positions = {{c - r, y, c - r}, {c + r, y, c - r}, {c + r, y, c + r}, {c - r, y, c + r}};
      quad.uvs = {{0, 0}, {1, 0}, {1, 1}, {0, 1}};
      quad.normals = {{0, 1, 0}};
      quad.triangles = {
        {ObjMesh::Corner{0, 0, 0}, ObjMesh::Corner{2, 2, 0}, ObjMesh::Corner{1, 1, 0}},
        {ObjMesh::Corner{0, 0, 0}, ObjMesh::Corner{3, 3, 0}, ObjMesh::Corner{2, 2, 0}},
      };
      std::string scmWhy;
      const auto scm = ScmFromObj(quad, "fill", 1.0f, "the mesh view's fill");
      if (!scm) {
        scmWhy = scm.error();
      }
      if (scm) {
        if (auto encoded = EncodeDds(image, DdsKind::Bgra); !encoded) {
          scmWhy = encoded.error();
        } else {
          dds = std::move(*encoded);
          std::ofstream(folder / "fill.scm", std::ios::binary | std::ios::trunc)
            .write(reinterpret_cast<const char*>(scm->data()), static_cast<std::streamsize>(scm->size()));
          std::ofstream(folder / "fill.dds", std::ios::binary | std::ios::trunc)
            .write(reinterpret_cast<const char*>(dds.data()), static_cast<std::streamsize>(dds.size()));
          fillMesh = vfs + "/fill.scm";
          fillTexture = vfs + "/fill.dds";
        }
      }
    }
    if (!mMeshViewCache.empty() && !moho::DISK_MountDirectoryNow(folder, vfs.c_str())) {
      gpg::Warnf("editor: mesh terrain: the cache folder couldn't be mounted");
      views.clear();
      fillMesh.clear();
    }
    gpg::Logf(
      "editor: mesh terrain: %zu materials made ready (%d with light masks) in %.2f s%s%s",
      views.size(),
      masked,
      std::chrono::duration<double>(std::chrono::steady_clock::now() - bakeStarted).count(),
      bakeWhy.empty() ? "" : "; ",
      bakeWhy.c_str()
    );
    int made = 0;
    int skies = 0;
    const auto add = [&](
                       const std::string& id,
                       const std::string& mesh,
                       const MeshMaterialView& view,
                       const std::string& shader,
                       const int kind,
                       const Wm3::Vec3f& place
                     ) {
      moho::RResId rid{};
      rid.name.assign(id.c_str());
      auto* const blueprint = new moho::RMeshBlueprint(rules, rid);
      moho::RMeshBlueprintLOD lod;
      lod.mMeshName.assign(mesh.c_str());
      lod.mAlbedoName.assign(view.albedo.c_str());
      lod.mSecondaryName.assign(view.secondary.c_str());
      lod.mNormalsName.assign(view.normals.c_str());
      lod.mSpecularName.assign(view.specular.c_str());
      lod.mLookupName.assign(view.lookup.c_str());
      lod.mShaderName.assign(shader.c_str());
      lod.mLodCutoff = 1.0e6f; // drawn at any distance, as ground
      blueprint->mLods.push_back(lod);
      mMeshPatchBlueprints.push_back(blueprint);
      moho::MeshInstance* const instance = renderer->CreateMeshInstance(
        0, -1, blueprint, Wm3::Vec3f{1.0f, 1.0f, 1.0f}, false, std::shared_ptr<moho::MeshMaterial>()
      );
      if (instance == nullptr) {
        return false;
      }
      moho::VTransform at{};
      at.orient_ = Wm3::Quatf(1.0f, 0.0f, 0.0f, 0.0f);
      at.pos_ = place;
      instance->SetStance(at, at);
      instance->isHidden = mMeshMode == 0 ? 1 : 0;
      mMeshPatchInstances.push_back(instance);
      mMeshPatchKinds.push_back(kind);
      return true;
    };
    for (std::size_t i = 0; i < mMeshMap.patches.size(); ++i) {
      const edmesh::Patch& patch = mMeshMap.patches[i];
      const MeshMaterialView& view = views[patch.material];
      if (view.albedo.empty() || patch.vertexCount == 0) {
        continue; // (no cache, no texture, or its file couldn't be read: not drawn)
      }
      const edmesh::Material* material =
        patch.material >= 0 && static_cast<std::size_t>(patch.material) < mMeshMap.materials.size()
        ? &mMeshMap.materials[static_cast<std::size_t>(patch.material)]
        : nullptr;
      std::string shader;
      if (patch.sky) {
        shader = material != nullptr && material->additive ? "EditorMeshSkyAdd" : "EditorMeshSky";
      } else {
        // Both: the variants pulled towards the camera, so the height field shows only where it lies above the mesh.
        shader = std::string(view.lightMasks ? "EditorMeshTerrain" : "EditorMeshTerrainSun") +
          (view.alphaTest ? "Alpha" : "") + (mMeshMode == 2 ? "Both" : "");
      }
      const auto own = centred.find(i);
      if (
        add(
          "/editor/meshterrain/patch" + std::to_string(i) + "_mesh",
          own != centred.end() ? own->second.first : inFolder(patch.file),
          view,
          shader,
          patch.sky ? 1 : 0,
          own != centred.end() ? own->second.second : Wm3::Vec3f{0.0f, 0.0f, 0.0f}
        )
      ) {
        ++made;
        skies += patch.sky ? 1 : 0;
      }
    }
    if (!fillMesh.empty()) {
      MeshMaterialView fill;
      fill.albedo = fill.secondary = fillTexture;
      fill.normals = fill.specular = fill.lookup = fillTexture;
      (void)add("/editor/meshterrain/fill_mesh", fillMesh, fill, "EditorMeshFill", 2, Wm3::Vec3f{0.0f, 0.0f, 0.0f});
    }
    gpg::Logf(
      "editor: mesh terrain: %d of %zu patches drawn by the mesh technique (%d sky)%s",
      made,
      mMeshMap.patches.size(),
      skies,
      fillMesh.empty() ? "" : ", the fill to the horizon"
    );
  }

  void EdMapScene::SyncMeshView()
  {
    // Each frame: the patches' models made once the rules are up, shown or hidden by the mode; the height field off
    // in Mesh only (back on whenever the mesh isn't shown alone).
    if (MeshInView() && mMeshInstancesTried && !mMeshPatchInstances.empty() && (mMeshMode == 2) != mMeshBuiltForBoth) {
      DeleteMeshInstances(); // into or out of Both: the patches again with or without the pull towards the camera
    }
    if (MeshInView() && !mMeshInstancesTried) {
      BuildMeshInstances();
    }
    // Their bounds published again each frame: SetStance publishes them only when the place changes (a patch at the
    // origin, unturned, is where a new instance already "is", so it never would), and a model still loading has none
    // to publish yet; without bounds the renderer's spatial database never hands the instance over, and it isn't drawn.
    // A nudge and back is a change each time.
    const float middle = mMeshMap.settings.size * 0.5f;
    const Wm3::Vec3f eye =
      mCamera != nullptr ? mCamera->CameraGetView().tranform.pos_ : Wm3::Vec3f{middle, 0.0f, middle};
    for (std::size_t i = 0; i < mMeshPatchInstances.size(); ++i) {
      moho::MeshInstance* const instance = mMeshPatchInstances[i];
      const int kind = i < mMeshPatchKinds.size() ? mMeshPatchKinds[i] : 0;
      instance->isHidden = mMeshMode == 0 || (kind == 2 && mMeshMode != 1) ? 1 : 0;
      moho::VTransform at = instance->endTransform;
      if (kind == 1) {
        // Studio's sky: its pieces about the map's middle, carried along with the camera.
        at.pos_ = Wm3::Vec3f{eye.x - middle, eye.y, eye.z - middle};
      }
      moho::VTransform nudged = at;
      nudged.pos_.y += 0.001f;
      instance->SetStance(nudged, nudged);
      instance->SetStance(at, at);
    }
    // The shadow map fitted to the mesh's heights too (fitted to the height field alone, a mesh below or above it is
    // past the light camera's depth range and all in shadow). Sky pieces left out: they follow the camera.
    // Only the scene showing a mesh sets it, and clears only what it set (other scenes run this too).
    if (mMeshMode != 0 && !mMeshPatchInstances.empty()) {
      float shadowLow = 1.0e9f;
      float shadowHigh = -1.0e9f;
      for (const edmesh::Patch& patch : mMeshMap.patches) {
        if (!patch.sky) {
          shadowLow = std::min(shadowLow, patch.boundsMin[1]);
          shadowHigh = std::max(shadowHigh, patch.boundsMax[1]);
        }
      }
      moho::ren_ShadowExtraMinY = shadowLow;
      moho::ren_ShadowExtraMaxY = shadowHigh;
      mMeshSetsShadowRange = true;
    } else if (mMeshSetsShadowRange) {
      moho::ren_ShadowExtraMinY = 1.0f;
      moho::ren_ShadowExtraMaxY = 0.0f;
      mMeshSetsShadowRange = false;
    }
    const bool hide = mMeshMode == 1 && MeshInView() && !mMeshPatchInstances.empty();
    if (hide != mMeshHidesTerrain) {
      mMeshHidesTerrain = hide;
      moho::ren_TerrainSurface = !hide;
    }
  }

  std::string EdMapScene::LoadMeshTerrain()
  {
    DeleteMeshInstances();
    mMeshMap.Clear();
    mMeshTris.clear();
    mMeshEdges.clear();
    mMeshViewOff = false;
    std::string system;
    std::string manifest;
    const std::string& scenario = mDocument.Scenario();
    if (!ReadScenarioField(scenario, "TerrainSystem", system) || system != "mesh") {
      // FAF Studio keeps the manifest whatever the scenario says (meshmap.lua Load reads the folder's): the panel and
      // the next import get it, the view keeps the height field.
      const std::string own = "/maps/" + mDocument.FolderName() + "/terrain/terrain.lua";
      if (!edmesh::ReadVfs(own).empty()) {
        (void)mMeshMap.Load(own);
        mMeshMap.manifestPath = own;
        mMeshViewOff = true;
        gpg::Logf(
          "editor: mesh terrain: %s read into the panel (%zu patches, %zu materials); the scenario doesn't name it",
          own.c_str(),
          mMeshMap.patches.size(),
          mMeshMap.materials.size()
        );
        return "This map isn't a mesh terrain map (its scenario has no TerrainSystem = 'mesh'); its "
               "terrain/terrain.lua "
               "is in the panel (Mesh map in scenario makes it the ground).";
      }
      return "This map isn't a mesh terrain map (its scenario has no TerrainSystem = 'mesh').";
    }
    if (!ReadScenarioField(scenario, "TerrainMesh", manifest) || manifest.empty()) {
      manifest = "/maps/" + mDocument.FolderName() + "/terrain/terrain.lua";
    }
    if (!mMeshMap.Load(manifest)) {
      gpg::Warnf("editor: mesh terrain: %s", mMeshMap.error.c_str());
      return "The mesh terrain didn't load: " + mMeshMap.error;
    }
    const std::size_t drawn = BuildMeshLines();
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
    if (!mMeshMap.error.empty()) {
      // Patches whose files are missing or broken: their entries stay (Save writes them back), they aren't drawn.
      gpg::Warnf("editor: mesh terrain: patches not read: %s", mMeshMap.error.c_str());
      return std::string(text) + "; not read (kept in the manifest, Check names them): " + mMeshMap.error;
    }
    return text;
  }

  std::size_t EdMapScene::BuildMeshLines()
  {
    mMeshTris.clear();
    mMeshEdges.clear();
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
    return drawn;
  }

  std::string EdMapScene::SetMeshInScenario(
    const bool on
  )
  {
    // FAF Studio's "Mesh map in scenario": the view takes up (or leaves) the manifest the panel holds, as it is (its
    // edits not saved yet stay), without reading it again.
    DeleteMeshInstances();
    if (!on || mMeshMap.manifestPath.empty()) {
      mMeshViewOff = true;
      mMeshTris.clear();
      mMeshEdges.clear();
      return on ? "No manifest in the panel: Load, New manifest from the map or an import first."
                : "The map's ground is its height field again (the manifest stays in the panel and its folder).";
    }
    mMeshViewOff = false;
    const std::size_t drawn = BuildMeshLines();
    char text[200];
    (void)std::snprintf(
      text,
      sizeof(text),
      "The scenario names %s: %zu patches, %zu triangles drawn (the panel's manifest as it is; Save writes it)",
      mMeshMap.manifestPath.c_str(),
      mMeshMap.patches.size(),
      drawn
    );
    gpg::Logf("editor: mesh terrain: %s", text);
    return text;
  }

  std::vector<std::string> EdMapScene::CheckMeshTerrain()
  {
    std::vector<std::string> lines;
    if (mMeshMap.manifestPath.empty()) {
      lines.push_back(
        "I: no mesh terrain manifest is loaded (Mesh map in scenario, Load or New manifest from the map first)"
      );
      return lines;
    }
    // Studio's manifest checks against the open map and the files, then the patches' own.
    MeshManifestFacts facts;
    if (const std::shared_ptr<TerrainSource> terrain = TerrainHeights(); terrain != nullptr && terrain->width > 1) {
      facts.mapSize = terrain->width - 1;
      facts.groundHighest = *std::max_element(terrain->heights.begin(), terrain->heights.end());
    }
    if (const std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea()) {
      facts.havePlayable = true;
      facts.playable[0] = static_cast<float>(area->x0);
      facts.playable[1] = static_cast<float>(area->z0);
      facts.playable[2] = static_cast<float>(area->x1);
      facts.playable[3] = static_cast<float>(area->z1);
    }
    const WaterState water = mDocument.WaterNow();
    facts.water = water.enabled;
    facts.waterLevel = water.elevation;
    const std::string& scenario = mDocument.Scenario();
    facts.haveScenario = !scenario.empty();
    (void)ReadScenarioField(scenario, "TerrainSystem", facts.terrainSystem);
    (void)ReadScenarioField(scenario, "TerrainMesh", facts.terrainMesh);
    facts.expectedMesh = "/maps/" + mDocument.FolderName() + "/terrain/terrain.lua";
    facts.read = [](const std::string& path) {
      return edmesh::ReadVfs(path);
    };
    for (const MeshScanFinding& f : CheckMeshManifest(mMeshMap, facts)) {
      lines.push_back(std::string(1, f.severity) + " " + f.code + ": " + f.text);
    }
    if (mMeshMap.Loaded()) {
      for (const MeshScanFinding& f : ScanMeshMap(mMeshMap).findings) {
        lines.push_back(std::string(1, f.severity) + " " + f.code + ": " + f.text);
      }
    }
    return lines;
  }

  std::string EdMapScene::SyncMeshFromMap(
    const bool fresh
  )
  {
    const std::shared_ptr<TerrainSource> terrain = TerrainHeights();
    if (terrain == nullptr || terrain->width < 2) {
      return "No map open.";
    }
    if (fresh) {
      DeleteMeshInstances();
      mMeshMap.Clear();
      mMeshTris.clear();
      mMeshEdges.clear();
      mMeshMap.manifestPath = "/maps/" + mDocument.FolderName() + "/terrain/terrain.lua";
      mMeshMap.dir = "/maps/" + mDocument.FolderName() + "/terrain";
    } else if (mMeshMap.manifestPath.empty()) {
      return "Load a mesh terrain manifest, or make a new one from the map, first.";
    }
    edmesh::Settings& s = mMeshMap.settings;
    const auto give = [&s](const char* key, const float value) {
      if (float* slot = edmesh::SettingNumber(s, key)) {
        *slot = value;
        s.given.insert(key);
      }
    };
    const float size = static_cast<float>(terrain->width - 1);
    give("size", size);
    if (const std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea()) {
      give("playable_x0", static_cast<float>(area->x0));
      give("playable_z0", static_cast<float>(area->z0));
      give("playable_x1", static_cast<float>(area->x1));
      give("playable_z1", static_cast<float>(area->z1));
    } else {
      give("playable_x0", 0.0f);
      give("playable_z0", 0.0f);
      give("playable_x1", size);
      give("playable_z1", size);
    }
    const WaterState water = mDocument.WaterNow();
    if (water.enabled) {
      give("water", water.elevation);
      give("water_abyss", std::min(water.abyss, water.elevation - 1.0f));
    } else {
      for (const char* key : {"water", "water_abyss", "water_tint"}) {
        edmesh::SetSettingGiven(s, key, false);
      }
    }
    const auto [low, high] = std::minmax_element(terrain->heights.begin(), terrain->heights.end());
    give("ground_low", *low);
    give("ground_high", *high);
    const LightingState lighting = mDocument.LightingNow();
    const float length = std::sqrt(
      lighting.sunDirection[0] * lighting.sunDirection[0] + lighting.sunDirection[1] * lighting.sunDirection[1] +
      lighting.sunDirection[2] * lighting.sunDirection[2]
    );
    if (length > 0.0001f) {
      give("sun_x", lighting.sunDirection[0] / length);
      give("sun_y", lighting.sunDirection[1] / length);
      give("sun_z", lighting.sunDirection[2] / length);
    }
    gpg::Logf(
      "editor: mesh terrain: %s: size %.0f, playable %.0f,%.0f - %.0f,%.0f, water %s, ground %.2f .. %.2f",
      fresh ? "new manifest from the map" : "synced from the map",
      static_cast<double>(s.size),
      static_cast<double>(s.playable[0]),
      static_cast<double>(s.playable[1]),
      static_cast<double>(s.playable[2]),
      static_cast<double>(s.playable[3]),
      water.enabled ? std::to_string(water.elevation).c_str() : "none",
      static_cast<double>(*low),
      static_cast<double>(*high)
    );
    return fresh ? "A new manifest from the map (no patches yet: import an OBJ, then Save)."
                 : "Size, playable area, water, heights and sun taken from the map (Save writes them).";
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
    if (mMeshMode != 0 && MeshInView()) {
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
