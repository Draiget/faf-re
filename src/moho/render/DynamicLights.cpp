#include "moho/render/DynamicLights.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <map>
#include <string_view>
#include <tuple>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/backends/common/ImageCodec.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/console/CConCommand.h"
#include "moho/math/VMatrix4.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/resource/CParticleTexture.h"
#include "moho/render/DynamicLightsShader.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"

namespace moho
{
  // Engine addition (ren_DynamicLights): see DynamicLights.h.
  int ren_DynamicLights = 0;
  float ren_DynamicLightIntensity = 1.0f;
  float ren_DynamicLightRadius = 1.0f;
  float ren_DynamicLightTest = 0.0f;

  namespace
  {
    TConVar<int> gTConVar_ren_DynamicLights(
      "ren_DynamicLights",
      "Direct3D 12 and Vulkan: explosions, muzzle flashes, engines, projectiles and beams light the ground and the "
      "units "
      "around them (from the effects' additive particles and beams). 1 on, 0 off (default).",
      &ren_DynamicLights
    );
    TConVar<float> gTConVar_ren_DynamicLightIntensity(
      "ren_DynamicLightIntensity",
      "ren_DynamicLights: how bright the lights are (1 the default).",
      &ren_DynamicLightIntensity
    );
    TConVar<float> gTConVar_ren_DynamicLightTest(
      "ren_DynamicLightTest",
      "ren_DynamicLights diagnostics: a white light this many units wide on the view's centre; 0 none.",
      &ren_DynamicLightTest
    );
    TConVar<float> gTConVar_ren_DynamicLightRadius(
      "ren_DynamicLightRadius",
      "ren_DynamicLights: how far the lights reach, times their size (1 the default).",
      &ren_DynamicLightRadius
    );

    /** Must match the cbuffer in DynamicLightsShader.h. */
    struct LightConstants
    {
      VMatrix4 inverseViewProjection;
      float viewRect[4];
      float bufferSize[4];
      float eye[4];
      float params[4];
      float lights[kDynamicLightSlots * 2][4];
    };
    static_assert(
      sizeof(LightConstants) == 64 + 4 * 16 + kDynamicLightSlots * 2 * 16,
      "LightConstants matches the shader's cbuffer"
    );
    static_assert(
      sizeof(LightConstants) <= gpg::gal::kGpuMaxConstantBytes,
      "LightConstants fits the GPU program's constants"
    );

    // Merged per cell of this size (world units) and beat: an explosion's dozens of particles become one light.
    constexpr float kCellSize = 3.0f;
    // A light lasts no longer than this many ticks, whatever its source's life (smoke that glows for seconds).
    constexpr float kMaxLifetime = 12.0f;

    [[nodiscard]] bool BackendReadsBoundDepth(
      gpg::gal::Device& device
    )
    {
      const gpg::gal::DeviceContext* const context = device.GetDeviceContext();
      return context != nullptr &&
        (context->mDeviceType == gpg::gal::DeviceApi::Direct3D12 ||
         context->mDeviceType == gpg::gal::DeviceApi::Vulkan);
    }
  } // namespace

  const DynamicLights::RampColor* DynamicLights::ColorOfRamp(
    const char* const path
  )
  {
    const std::string key = (path != nullptr) ? path : "";
    const auto found = mRampColors.find(key);
    if (found != mRampColors.end()) {
      return &found->second;
    }
    // Reading a ramp is a file read and a decode on the render thread: a battle that brings many new effects at once
    // would stall one frame for all of them, so each beat reads a few and the rest light in the default colour until
    // a later beat reads theirs.
    if (!key.empty() && mRampReadsLeft == 0) {
      return nullptr; // read on a later beat; until then the source gives no light
    }
    if (mRampReadsLeft > 0) {
      --mRampReadsLeft;
    }
    RampColor ramp; // the warm default when the ramp can't be read
    if (!key.empty()) {
      // The game path (/textures/particles/...) resolved to its file in the mounted folders and archives.
      fa::string diskPath{};
      if (FWaitHandleSet* const files = FILE_GetWaitHandleSet(); files != nullptr && files->mHandle != nullptr) {
        files->mHandle->FindFile(&diskPath, key.c_str(), nullptr);
      }
      const gpg::MemBuffer<char> file = diskPath.empty() ? gpg::MemBuffer<char>{} : DISK_ReadFile(diskPath.c_str());
      gpg::gal::imaging::ImageCodec* const codec = gpg::gal::imaging::ImageCodec::Instance();
      gpg::gal::imaging::DecodeOptions options{};
      options.format = DXGI_FORMAT_R8G8B8A8_UNORM;
      gpg::gal::imaging::Image image;
      if (
        file.mBegin != nullptr && file.Size() != 0U && codec != nullptr &&
        SUCCEEDED(codec->Decode(file.mBegin, file.Size(), options, image)) && !image.subresources.empty() &&
        image.width != 0U
      ) {
        // A ramp runs over the particle's life left to right (one row per ramp selection): the light is its
        // alpha-weighted colour over the first 60 %, where effects are brightest.
        const gpg::gal::imaging::Image::Subresource& top = image.subresources.front();
        const std::uint32_t columns = std::max<std::uint32_t>(1U, (top.width * 3U) / 5U);
        double sum[3]{};
        double samples = 0.0;
        for (std::uint32_t row = 0U; row < top.height; ++row) {
          const std::uint8_t* const pixels =
            image.bytes.data() + top.offset + static_cast<std::size_t>(row) * top.rowPitch;
          for (std::uint32_t column = 0U; column < columns; ++column) {
            const std::uint8_t* const pixel = pixels + static_cast<std::size_t>(column) * 4U;
            const double a = pixel[3] / 255.0;
            for (int channel = 0; channel < 3; ++channel) {
              sum[channel] += a * pixel[channel] / 255.0;
            }
            samples += 1.0;
          }
        }
        const double peak = std::max({sum[0], sum[1], sum[2]});
        if (peak > 1.0e-6 && samples > 0.0) {
          for (int channel = 0; channel < 3; ++channel) {
            ramp.color[channel] = static_cast<float>(sum[channel] / peak);
          }
          // Mean brightness of the brightest channel, weighted by alpha: dim smoke ramps give weak lights.
          ramp.strength = static_cast<float>(std::clamp(peak / samples * 1.5, 0.1, 1.0));
        }
      }
    }
    return &mRampColors.emplace(key, ramp).first->second;
  }

  DynamicLights& DynamicLights::Get()
  {
    static DynamicLights sLights;
    return sLights;
  }

  void DynamicLights::AddSource(
    const float position[3],
    const float velocity[3],
    const float color[3],
    const float size,
    const float birth,
    const float lifetime
  )
  {
    Light light;
    std::memcpy(light.position, position, sizeof(light.position));
    std::memcpy(light.velocity, velocity, sizeof(light.velocity));
    std::memcpy(light.color, color, sizeof(light.color));
    light.radius = std::clamp(3.0f + size * 2.5f, 3.0f, 30.0f);
    light.intensity = 0.6f;
    light.birth = birth;
    light.lifetime = std::clamp(lifetime, 1.0f, kMaxLifetime);
    mLights.push_back(light);
  }

  void DynamicLights::AddParticles(
    const SParticleBuffer& batch,
    const int tick
  )
  {
    if (ren_DynamicLights <= 0) {
      mLights.clear();
      return;
    }
    // The timeline went back (a replay rewound, a new game): the lights belong to the old one.
    if (tick < mLastTick) {
      mLights.clear();
    }
    mLastTick = tick;
    mRampReadsLeft = kRampReadsPerBeat;
    const std::size_t first = mLights.size();
    const float now = static_cast<float>(tick);
    for (const SWorldParticle& particle : batch.mParticles) {
      const bool light = std::string_view(particle.mTypeTag.c_str()) == "TLight";
      if (!light && particle.mBlendMode != SWorldParticle::BlendMode::Mode3) {
        continue;
      }
      const float position[3] = {particle.mPos.x, particle.mPos.y, particle.mPos.z};
      const float velocity[3] = {particle.mDir.x, particle.mDir.y, particle.mDir.z};
      const float size = 0.5f * (particle.mBeginSize + particle.mEndSize);
      // The particle's own colour: its ramp texture's (UEF build effects blue, Cybran red, fire orange).
      const RampColor* const ramp =
        ColorOfRamp(particle.mRampTexture.tex != nullptr ? particle.mRampTexture.tex->mTexturePath.c_str() : nullptr);
      if (ramp == nullptr) {
        continue;
      }
      AddSource(
        position, velocity, ramp->color, light ? size * 1.5f : size, now + particle.mInterop, particle.mLifetime
      );
      mLights.back().intensity *= ramp->strength;
    }
    for (const SWorldTrail& trail : batch.mTrails) {
      if (trail.mBlendMode != 3) {
        continue;
      }
      // The trail's newest end follows its projectile or engine.
      const float position[3] = {trail.mEndPos.x, trail.mEndPos.y, trail.mEndPos.z};
      const float still[3]{};
      const RampColor* const ramp =
        ColorOfRamp(trail.mRampTexture.tex != nullptr ? trail.mRampTexture.tex->mTexturePath.c_str() : nullptr);
      if (ramp == nullptr) {
        continue;
      }
      AddSource(position, still, ramp->color, trail.mSize, now, 2.0f);
      mLights.back().intensity *= ramp->strength;
    }
    for (const SWorldBeam& beam : batch.mBeams) {
      if (beam.mBlendMode != SWorldBeam::BlendMode::Mode3) {
        continue;
      }
      // A beam is sent again every beat while it lasts, so each light lives one beat. Its colour is the beam's own
      // (build lasers: UEF blue, Cybran red), at full brightness: the beam colours are dim (0.6 for a Cybran
      // build beam) and the texture brightens them on screen. Where it hits (the build point, the target) gets
      // the light; where it starts a smaller one.
      const auto bright = [](const Vector4f& c, float (&out)[3]) {
        const float peak = std::max({c.x, c.y, c.z, 1.0e-3f});
        out[0] = std::clamp(c.x / peak, 0.0f, 1.0f);
        out[1] = std::clamp(c.y / peak, 0.0f, 1.0f);
        out[2] = std::clamp(c.z / peak, 0.0f, 1.0f);
      };
      float startColor[3]{};
      float endColor[3]{};
      bright(beam.mStartColor, startColor);
      bright(beam.mEndColor, endColor);
      const float still[3]{};
      const float end[3] = {beam.mEnd.x, beam.mEnd.y, beam.mEnd.z};
      const float start[3] = {beam.mStart.x, beam.mStart.y, beam.mStart.z};
      AddSource(end, still, endColor, 1.2f + beam.mWidth * 10.0f, now, 1.5f);
      AddSource(start, still, startColor, 0.4f + beam.mWidth * 5.0f, now, 1.5f);
      mLights.back().intensity *= 0.6f;
    }

    // Merge this beat's sources per cell: brighter (each further source adds less) and as far-reaching as the largest.
    std::map<std::tuple<int, int, int>, std::size_t> cells;
    std::size_t kept = first;
    for (std::size_t index = first; index < mLights.size(); ++index) {
      const Light source = mLights[index];
      const auto key = std::make_tuple(
        static_cast<int>(std::floor(source.position[0] / kCellSize)),
        static_cast<int>(std::floor(source.position[1] / kCellSize)),
        static_cast<int>(std::floor(source.position[2] / kCellSize))
      );
      const auto found = cells.find(key);
      if (found == cells.end()) {
        cells.emplace(key, kept);
        mLights[kept++] = source;
        continue;
      }
      Light& merged = mLights[found->second];
      const float total = merged.intensity + source.intensity;
      for (int axis = 0; axis < 3; ++axis) {
        merged.position[axis] =
          (merged.position[axis] * merged.intensity + source.position[axis] * source.intensity) / total;
        merged.velocity[axis] =
          (merged.velocity[axis] * merged.intensity + source.velocity[axis] * source.intensity) / total;
        merged.color[axis] = (merged.color[axis] * merged.intensity + source.color[axis] * source.intensity) / total;
      }
      merged.intensity = std::min(merged.intensity + source.intensity * 0.35f, 2.5f);
      merged.radius = std::max(merged.radius, source.radius);
      merged.lifetime = std::max(merged.lifetime, source.lifetime);
      merged.birth = std::min(merged.birth, source.birth);
    }
    mLights.resize(kept);
    // Old lights go once their life is over (and the list stays bounded in a long battle).
    mLights.erase(
      std::remove_if(
        mLights.begin(),
        mLights.end(),
        [now](const Light& light) {
      return now - light.birth > light.lifetime + 1.0f || light.birth > now + 2.0f;
    }
      ),
      mLights.end()
    );
    if (mLights.size() > 4096U) {
      mLights.erase(mLights.begin(), mLights.begin() + static_cast<std::ptrdiff_t>(mLights.size() - 4096U));
    }
  }

  bool DynamicLights::IsActive()
  {
    if (ren_DynamicLights <= 0) {
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    if (device != mDevice) {
      mDevice = device;
      mSupported = false;
      mCompute.reset();
      mComposite.reset();
      mTerms.reset();
      mTermCapacity = 0U;
      constexpr std::uint32_t kNeeded = gpg::gal::kGpuFeatureVertexPulling | gpg::gal::kGpuFeatureCompute;
      if (BackendReadsBoundDepth(*device) && (device->GetGpuDrivenFeatures() & kNeeded) == kNeeded) {
        gpg::gal::GpuProgramDesc compute{};
        compute.name = "DynamicLights";
        compute.source = kDynamicLightsShaderSource;
        compute.sourceBytes = sizeof(kDynamicLightsShaderSource) - 1U;
        compute.computeEntry = "LightsCS";
        mCompute = device->CreateGpuProgram(compute);

        gpg::gal::GpuProgramDesc composite{};
        composite.name = "DynamicLightsComposite";
        composite.source = kDynamicLightsShaderSource;
        composite.sourceBytes = sizeof(kDynamicLightsShaderSource) - 1U;
        composite.vertexEntry = "LightsCompositeVS";
        composite.pixelEntry = "LightsCompositePS";
        composite.blend = gpg::gal::GpuBlend::Brighten; // colour * (1 + light): lit ground keeps its hue
        composite.colorWriteMask = 0x07U;               // alpha is the glow amount and the water mask
        composite.depthTest = false;
        composite.depthWrite = false;
        composite.cullBackFaces = false;
        mComposite = device->CreateGpuProgram(composite);
      }
      mSupported = mCompute != nullptr && mComposite != nullptr;
      if (mSupported) {
        gpg::Logf("Dynamic lights: on this renderer (ren_DynamicLights)");
      }
    }
    return mSupported;
  }

  void DynamicLights::Render(
    const GeomCamera3& camera,
    const int x,
    const int y,
    const int width,
    const int height
  )
  {
    if (!mSupported || width < 8 || height < 8 || (mLights.empty() && ren_DynamicLightTest <= 0.0f)) {
      return;
    }
    const float now = static_cast<float>(REN_GetGameTick()) + REN_GetSimDeltaSeconds();
    const float eye[3] = {camera.inverseView.r[3].x, camera.inverseView.r[3].y, camera.inverseView.r[3].z};

    // This frame's lights: aged, moved, faded; the strongest within reach of the camera.
    struct Lit
    {
      float position[3];
      float radius;
      float color[3];
      float weight;
    };
    std::vector<Lit> lit;
    lit.reserve(mLights.size());
    for (const Light& light : mLights) {
      const float age = now - light.birth;
      if (age < 0.0f || age > light.lifetime) {
        continue;
      }
      const float left = 1.0f - age / light.lifetime;
      const float strength = light.intensity * left * left * std::max(ren_DynamicLightIntensity, 0.0f);
      if (strength <= 0.01f) {
        continue;
      }
      Lit entry{};
      for (int axis = 0; axis < 3; ++axis) {
        entry.position[axis] = light.position[axis] + light.velocity[axis] * age;
        entry.color[axis] = light.color[axis] * strength;
      }
      entry.radius = light.radius * std::max(ren_DynamicLightRadius, 0.0f);
      const float dx = entry.position[0] - eye[0];
      const float dy = entry.position[1] - eye[1];
      const float dz = entry.position[2] - eye[2];
      const float distance = std::sqrt(dx * dx + dy * dy + dz * dz);
      if (entry.radius <= 0.0f || distance > 800.0f + entry.radius) {
        continue;
      }
      entry.weight = strength * entry.radius * entry.radius / (1.0f + distance * 0.01f);
      lit.push_back(entry);
    }
    if (lit.empty() && ren_DynamicLightTest <= 0.0f) {
      return;
    }
    if (lit.size() > static_cast<std::size_t>(kDynamicLightSlots)) {
      std::partial_sort(lit.begin(), lit.begin() + kDynamicLightSlots, lit.end(), [](const Lit& a, const Lit& b) {
        return a.weight > b.weight;
      });
      lit.resize(kDynamicLightSlots);
    }

    const auto samplesAcross = static_cast<std::uint32_t>(width + 1) / 2U;
    const auto samplesDown = static_cast<std::uint32_t>(height + 1) / 2U;
    const std::uint32_t needed = samplesAcross * samplesDown;
    if (mTerms == nullptr || needed > mTermCapacity) {
      gpg::gal::GpuBufferDesc desc{};
      desc.name = "DynamicLightTerms";
      desc.stride = 4U * sizeof(float);
      desc.capacity = needed;
      desc.shaderWrite = true;
      mTerms = mDevice->CreateGpuBuffer(desc);
      mTermCapacity = (mTerms != nullptr) ? needed : 0U;
      if (mTerms == nullptr) {
        return;
      }
    }

    LightConstants constants{};
    constants.inverseViewProjection = camera.inverseViewProjection;
    constants.viewRect[0] = static_cast<float>(x);
    constants.viewRect[1] = static_cast<float>(y);
    constants.viewRect[2] = static_cast<float>(width);
    constants.viewRect[3] = static_cast<float>(height);
    constants.bufferSize[0] = static_cast<float>(samplesAcross);
    constants.bufferSize[1] = static_cast<float>(samplesDown);
    constants.bufferSize[2] = 1.0f / static_cast<float>(samplesAcross);
    constants.bufferSize[3] = 1.0f / static_cast<float>(samplesDown);
    constants.eye[0] = eye[0];
    constants.eye[1] = eye[1];
    constants.eye[2] = eye[2];
    constants.eye[3] = static_cast<float>(lit.size());
    constants.params[0] = 1.0f; // the most light a pixel takes (the output's 0..1 clamp: twice its own colour)
    constants.params[1] = std::max(ren_DynamicLightTest, 0.0f);
    for (std::size_t index = 0U; index < lit.size(); ++index) {
      float* const position = constants.lights[index * 2U];
      float* const color = constants.lights[index * 2U + 1U];
      position[0] = lit[index].position[0];
      position[1] = lit[index].position[1];
      position[2] = lit[index].position[2];
      position[3] = lit[index].radius;
      color[0] = lit[index].color[0];
      color[1] = lit[index].color[1];
      color[2] = lit[index].color[2];
    }

    gpg::gal::GpuDispatch dispatch{};
    dispatch.program = mCompute.get();
    dispatch.bindings.constants = &constants;
    dispatch.bindings.constantBytes = sizeof(constants);
    dispatch.bindings.writeBuffers[0] = mTerms.get();
    dispatch.bindings.readBoundDepth = true;
    dispatch.groupsX = (samplesAcross + 7U) / 8U;
    dispatch.groupsY = (samplesDown + 7U) / 8U;
    mDevice->DispatchGpuProgram(dispatch);

    gpg::gal::GpuDrawCall draw{};
    draw.program = mComposite.get();
    draw.bindings.constants = &constants;
    draw.bindings.constantBytes = sizeof(constants);
    draw.bindings.readBuffers[0] = mTerms.get();
    draw.vertexCountPerInstance = 3U;
    draw.instanceCount = 1U;
    mDevice->DrawGpuProgram(draw);
  }
} // namespace moho
