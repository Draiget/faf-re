#include "moho/terrain/TerrainDynamicTextureHelpers.h"

#include <cstdint>

#include "gpg/core/utils/Global.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"

namespace
{
  constexpr std::uint32_t kLookupTextureWidth = 128;
  constexpr std::uint32_t kLookupTextureHeight = 1;
  constexpr int kLookupTextureFormat = 18;
  constexpr float kOne = 1.0f;
  constexpr float kThree = 3.0f;
  constexpr float kFour = 4.0f;
  constexpr float kSix = 6.0f;
  constexpr float kOneSixth = 1.0f / 6.0f;
  constexpr float kSampleStep = 0.0078740157f;

  constexpr const char* kUnreachableAssertText = "Reached the supposably unreachable.";
  constexpr int kTrackedLookupAssertLine = 2316;
  constexpr int kTransientLookupAssertLine = 1238;
  constexpr const char* kUnreachableAssertSourcePath = "c:\\work\\rts\\main\\code\\src\\user\\RenTerrain.cpp";

  using DynamicSheetHandle = boost::shared_ptr<moho::CD3DDynamicTextureSheet>;

  enum class LookupTextureCreationLane : std::uint8_t
  {
    Tracked,
    Transient
  };

  void FillCubicBlendLookupTexture(moho::CD3DDynamicTextureSheet* const sheet, const int assertLine)
  {
    std::uint32_t pitchBytes = 0;
    void* mappedBits = nullptr;
    if (!sheet->Lock(&pitchBytes, &mappedBits)) {
      gpg::HandleAssertFailure(kUnreachableAssertText, assertLine, kUnreachableAssertSourcePath);
      // Binary path traps immediately after assert; keep this lane non-returning.
      for (;;) {
      }
    }

    (void)pitchBytes;

    float* texelWrite = static_cast<float*>(mappedBits);
    float sample = kOne;

    for (std::uint32_t texel = 0; texel < kLookupTextureWidth; ++texel) {
      const float sampleSquared = sample * sample;
      const float sampleCubed = sampleSquared * sample;

      const float weight3 = ((kThree * sampleSquared) - sampleCubed - (kThree * sample) + kOne) * kOneSixth;
      const float weight2 = ((kThree * sampleCubed) - (kSix * sampleSquared) + kFour) * kOneSixth;

      texelWrite[0] = (sample + kOne) - (weight2 / (weight2 + weight3));

      const float weight0 = sampleCubed * kOneSixth;
      const float weight1 = ((kThree * sampleSquared) - (kThree * sampleCubed) + (kThree * sample) + kOne) * kOneSixth;
      texelWrite[1] = (weight0 / (weight0 + weight1)) + (kOne - sample);

      texelWrite[2] = weight2 + weight3;
      texelWrite[3] = 0.0f;

      texelWrite += 4;
      sample -= kSampleStep;
    }

    (void)sheet->Unlock();
  }

  DynamicSheetHandle CreateTerrainCubicBlendLookupTextureImpl(
    const LookupTextureCreationLane creationLane,
    const int assertLine
  )
  {
    DynamicSheetHandle lookupTexture{};

    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    if (device == nullptr) {
      return lookupTexture;
    }

    moho::ID3DDeviceResources* const resources = device->GetResources();
    if (resources == nullptr) {
      return lookupTexture;
    }

    if (creationLane == LookupTextureCreationLane::Tracked) {
      (void)resources->CreateDynamicTextureSheet2(
        lookupTexture,
        static_cast<int>(kLookupTextureWidth),
        static_cast<int>(kLookupTextureHeight),
        kLookupTextureFormat
      );
    } else {
      (void)resources->NewDynamicTextureSheet(
        lookupTexture,
        static_cast<int>(kLookupTextureWidth),
        static_cast<int>(kLookupTextureHeight),
        kLookupTextureFormat
      );
    }

    moho::CD3DDynamicTextureSheet* const sheet = lookupTexture.get();
    if (sheet == nullptr) {
      return lookupTexture;
    }

    FillCubicBlendLookupTexture(sheet, assertLine);
    return lookupTexture;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00807740 (FUN_00807740, sub_807740)
   *
   * What it does:
   * Creates one 128x1 dynamic texture sheet (`format = 18`), writes a
   * cubic-blend lookup table into 128 RGBA texels, unlocks the sheet, and
   * returns retained ownership.
   */
  boost::shared_ptr<CD3DDynamicTextureSheet> CreateTerrainCubicBlendLookupTexture()
  {
    return CreateTerrainCubicBlendLookupTextureImpl(
      LookupTextureCreationLane::Tracked,
      kTrackedLookupAssertLine
    );
  }

  /**
   * Address: 0x00803720 (FUN_00803720, func_NewDynamicTextureSheet)
   *
   * What it does:
   * Creates one 128x1 dynamic texture sheet (`format = 18`) through the
   * non-tracked resource lane, writes the cubic-blend lookup table into 128
   * RGBA texels, unlocks the sheet, and returns retained ownership.
   */
  boost::shared_ptr<CD3DDynamicTextureSheet> CreateTerrainCubicBlendLookupTextureTransient()
  {
    return CreateTerrainCubicBlendLookupTextureImpl(
      LookupTextureCreationLane::Transient,
      kTransientLookupAssertLine
    );
  }
} // namespace moho
