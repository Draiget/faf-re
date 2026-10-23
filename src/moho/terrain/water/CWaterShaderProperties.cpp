#include "moho/terrain/water/CWaterShaderProperties.h"

#include <cmath>
#include <new>
#include <boost/detail/sp_counted_base.hpp>

#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/BinaryWriter.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"

namespace
{
void NormalizeVector3(float (&vector)[3])
{
  const float lengthSquared = (vector[0] * vector[0]) + (vector[1] * vector[1]) + (vector[2] * vector[2]);
  if (lengthSquared <= 0.0f) {
    return;
  }

  const float invLength = 1.0f / std::sqrt(lengthSquared);
  vector[0] *= invLength;
  vector[1] *= invLength;
  vector[2] *= invLength;
}

void WriteFloat(gpg::BinaryWriter& writer, const float value)
{
  writer.Write(value);
}

void ReadFloat(gpg::BinaryReader& reader, float& value)
{
  reader.Read(reinterpret_cast<char*>(&value), sizeof(value));
}
} // namespace

namespace moho
{
/**
 * Address: 0x0089F600 (FUN_0089F600, ??0CWaterShaderProperties@Moho@@QAE@XZ)
 *
 * What it does:
 * Seeds default water-shader numeric lanes, initializes wave/cubemap/ramp
 * texture path strings, clears cached texture handles, and normalizes
 * the two direction vectors used by wave projection.
 */
CWaterShaderProperties::CWaterShaderProperties()
{
  WaterShaderNumericState& state = mNumericState;
  state.mWaterColor[0] = 0.0f;
  state.mWaterColor[1] = 0.7f;
  state.mWaterColor[2] = 1.5f;
  state.mWaterLerp[0] = 0.064f;
  state.mWaterLerp[1] = 0.119f;
  state.mRefractionScale = 0.375f;
  state.mFresnelBias = 0.15f;
  state.mFresnelPower = 1.5f;
  state.mUnitReflectionAmount = 0.5f;
  state.mSkyReflectionAmount = 1.5f;
  state.mNormalRepeatRate[0] = 0.0009f;
  state.mNormalRepeatRate[1] = 0.009f;
  state.mNormalRepeatRate[2] = 0.05f;
  state.mNormalRepeatRate[3] = 0.5f;
  state.mSunShininess = 50.0f;
  state.mSunStrength = 10.0f;
  state.mSunDirection[0] = 0.1f;
  state.mSunDirection[1] = -0.967f;
  state.mSunDirection[2] = 0.253f;
  state.mSunColor[0] = 1.2f;
  state.mSunColor[1] = 0.7f;
  state.mSunColor[2] = 0.5f;
  state.mSunReflectionAmount = 5.0f;
  state.mSunGlow = 0.1f;

  // Both are stored pre-normalised: the sun direction becomes the stock unit
  // vector (0.0999, -0.9626, 0.2519) and the sun colour the stock warm tint
  // (0.8127, 0.4741, 0.3387), which is how the seeds above are recognisable
  // as the shipped map defaults at all.
  NormalizeVector3(state.mSunDirection);
  NormalizeVector3(state.mSunColor);

  state.mNormal1Movement[0] = 0.5f;
  state.mNormal1Movement[1] = -0.95f;
  state.mNormal2Movement[0] = 0.05f;
  state.mNormal2Movement[1] = -0.095f;
  state.mNormal3Movement[0] = 0.01f;
  state.mNormal3Movement[1] = 0.03f;
  state.mNormal4Movement[0] = 0.0005f;
  state.mNormal4Movement[1] = 0.0009f;

  for (auto& wave : mShaderNames) {
    wave.assign("/textures/engine/waves.dds");
  }
  mWaterCubemap.assign("/textures/engine/waterCubemap.dds");
  mWaterRamp.assign("/textures/engine/waterramp.dds");
}

/**
 * Address: 0x0089F8D0 (FUN_0089F8D0, ??0CWaterShaderProperties@Moho@@QAE@ABV01@@Z)
 *
 * Moho::CWaterShaderProperties const &
 *
 * IDA signature:
 * Moho::CWaterShaderProperties * __stdcall
 *   Moho::CWaterShaderProperties::CWaterShaderProperties(
 *     Moho::CWaterShaderProperties *dst, Moho::CWaterShaderProperties *src);
 *
 * What it does:
 * Constructs one water-shader payload from another instance, initializing
 * local string/shared-pointer lanes and then copying scalar + string state.
 */
CWaterShaderProperties::CWaterShaderProperties(const CWaterShaderProperties& rhs)
{
  copy(rhs);
}

/**
 * Address: 0x008A08D0 (FUN_008A08D0, ?copy@CWaterShaderProperties@Moho@@AAEXABV12@@Z)
 *
 * Moho::CWaterShaderProperties const &
 *
 * IDA signature:
 * std::string * __usercall
 *   Moho::CWaterShaderProperties::copy@<eax>(
 *     Moho::CWaterShaderProperties *this@<ecx>,
 *     Moho::CWaterShaderProperties *rhs@<eax>);
 *
 * What it does:
 * Releases resident texture handles, copies scalar shader lanes, and assigns
 * all shader/cubemap/ramp strings from `rhs`.
 */
void CWaterShaderProperties::copy(const CWaterShaderProperties& rhs)
{
  releaseTextures();

  mNumericState = rhs.mNumericState;

  for (std::size_t index = 0; index < 4u; ++index) {
    mShaderNames[index] = rhs.mShaderNames[index];
  }
  mWaterCubemap = rhs.mWaterCubemap;
  mWaterRamp = rhs.mWaterRamp;
}

/**
 * Address: 0x0089FEA0 (FUN_0089FEA0, ?Save@CWaterShaderProperties@Moho@@QBEXAAVBinaryWriter@gpg@@@Z)
 * Mangled: ?Save@CWaterShaderProperties@Moho@@QBEXAAVBinaryWriter@gpg@@@Z
 *
 * What it does:
 * Persists one deterministic water-shader payload in the legacy terrain
 * archive order (float lanes + shader-name strings + ramp/cubemap paths).
 */
void CWaterShaderProperties::Save(gpg::BinaryWriter& writer) const
{
  const WaterShaderNumericState& state = mNumericState;

  // Mirrors `Load`'s archive order exactly - ground truth FUN_0089FEA0 writes
  // from class +0x04 +0x08 +0x0C +0x10 +0x14 +0x18 +0x1C +0x20 +0x24 +0x28
  // +0x5C +0x60 +0x64 +0x68 +0x6C +0x70 +0x74 +0x78 +0x7C +0x80, then the two
  // paths, then +0x2C +0x30 +0x34 +0x38, then the wave entries. Same 20/4
  // split as FUN_008A03C0, so the two round-trip.
  WriteFloat(writer, state.mWaterColor[0]);
  WriteFloat(writer, state.mWaterColor[1]);
  WriteFloat(writer, state.mWaterColor[2]);
  WriteFloat(writer, state.mWaterLerp[0]);
  WriteFloat(writer, state.mWaterLerp[1]);
  WriteFloat(writer, state.mRefractionScale);
  WriteFloat(writer, state.mFresnelBias);
  WriteFloat(writer, state.mFresnelPower);
  WriteFloat(writer, state.mUnitReflectionAmount);
  WriteFloat(writer, state.mSkyReflectionAmount);
  WriteFloat(writer, state.mSunShininess);
  WriteFloat(writer, state.mSunStrength);
  WriteFloat(writer, state.mSunDirection[0]);
  WriteFloat(writer, state.mSunDirection[1]);
  WriteFloat(writer, state.mSunDirection[2]);
  WriteFloat(writer, state.mSunColor[0]);
  WriteFloat(writer, state.mSunColor[1]);
  WriteFloat(writer, state.mSunColor[2]);
  WriteFloat(writer, state.mSunReflectionAmount);
  WriteFloat(writer, state.mSunGlow);

  writer.WriteString(mWaterCubemap);
  writer.WriteString(mWaterRamp);

  WriteFloat(writer, state.mNormalRepeatRate[0]);
  WriteFloat(writer, state.mNormalRepeatRate[1]);
  WriteFloat(writer, state.mNormalRepeatRate[2]);
  WriteFloat(writer, state.mNormalRepeatRate[3]);

  const float* const waveMovement[4] = {
    state.mNormal1Movement,
    state.mNormal2Movement,
    state.mNormal3Movement,
    state.mNormal4Movement,
  };
  for (std::size_t index = 0; index < 4u; ++index) {
    WriteFloat(writer, waveMovement[index][0]);
    WriteFloat(writer, waveMovement[index][1]);
    writer.WriteString(mShaderNames[index]);
  }
}

/**
 * Address: 0x008A03C0 (FUN_008A03C0, ?Load@CWaterShaderProperties@Moho@@QAEXIAAVBinaryReader@gpg@@@Z)
 * Mangled: ?Load@CWaterShaderProperties@Moho@@QAEXIAAVBinaryReader@gpg@@@Z
 *
 * What it does:
 * Restores one water-shader payload from the legacy terrain archive lane,
 * including the interleaved `(float,float,string)` wave entries.
 */
void CWaterShaderProperties::Load(const unsigned int version, gpg::BinaryReader& reader)
{
  (void)version;

  WaterShaderNumericState& state = mNumericState;

  // Archive order and destinations are ground truth, taken from the `movss
  // dword ptr [ebp+NN], xmm0` store after each `BinaryReader::Read(&buf, 4)`
  // in FUN_008A03C0 (`ebp` = `this`, so class offset = struct offset + 4):
  //
  //   header, 20 reads -> +0x04 +0x08 +0x0C +0x10 +0x14 +0x18 +0x1C +0x20
  //                       +0x24 +0x28 +0x5C +0x60 +0x64 +0x68 +0x6C +0x70
  //                       +0x74 +0x78 +0x7C +0x80
  //   cubemap string    -> +0xF4       (lea ecx, [ebp+0F4h])
  //   ramp string       -> +0x110      (lea ecx, [ebp+110h])
  //   4 reads           -> +0x2C +0x30 +0x34 +0x38
  //   then 4x { read, read, string } into the wave-texture lanes.
  //
  // The counts also match the on-disk map byte-for-byte: in SCMP_009.scmap the
  // water block is exactly 20 floats, then the two paths, then 4 floats, then
  // the interleaved wave entries - with the 13th..15th header floats forming a
  // unit vector (the sun direction), which pins the alignment independently.
  //
  // This previously read 19 then 3, starting one lane too late in each run.
  // Both shortfalls left the stream 4 bytes early at a string read, so the
  // following path picked up the tail of the preceding float: the water
  // cubemap loaded as "<2 junk bytes>(>/textures/environment/skycube_*.dds"
  // and the first wave texture as "\n<junk>#</textures/engine/waves.dds",
  // which is what the "Can't find texture" warnings were.
  ReadFloat(reader, state.mWaterColor[0]);
  ReadFloat(reader, state.mWaterColor[1]);
  ReadFloat(reader, state.mWaterColor[2]);
  ReadFloat(reader, state.mWaterLerp[0]);
  ReadFloat(reader, state.mWaterLerp[1]);
  ReadFloat(reader, state.mRefractionScale);
  ReadFloat(reader, state.mFresnelBias);
  ReadFloat(reader, state.mFresnelPower);
  ReadFloat(reader, state.mUnitReflectionAmount);
  ReadFloat(reader, state.mSkyReflectionAmount);
  ReadFloat(reader, state.mSunShininess);
  ReadFloat(reader, state.mSunStrength);
  ReadFloat(reader, state.mSunDirection[0]);
  ReadFloat(reader, state.mSunDirection[1]);
  ReadFloat(reader, state.mSunDirection[2]);
  ReadFloat(reader, state.mSunColor[0]);
  ReadFloat(reader, state.mSunColor[1]);
  ReadFloat(reader, state.mSunColor[2]);
  ReadFloat(reader, state.mSunReflectionAmount);
  ReadFloat(reader, state.mSunGlow);

  reader.ReadString(&mWaterCubemap);
  reader.ReadString(&mWaterRamp);

  ReadFloat(reader, state.mNormalRepeatRate[0]);
  ReadFloat(reader, state.mNormalRepeatRate[1]);
  ReadFloat(reader, state.mNormalRepeatRate[2]);
  ReadFloat(reader, state.mNormalRepeatRate[3]);

  float* const waveMovement[4] = {
    state.mNormal1Movement,
    state.mNormal2Movement,
    state.mNormal3Movement,
    state.mNormal4Movement,
  };
  for (std::size_t index = 0; index < 4u; ++index) {
    ReadFloat(reader, waveMovement[index][0]);
    ReadFloat(reader, waveMovement[index][1]);
    reader.ReadString(&mShaderNames[index]);
  }
}

/**
 * Address: 0x0089F9A0 (FUN_0089F9A0)
 * Mangled: ??1CWaterShaderProperties@Moho@@UAE@XZ
 *
 * IDA signature:
 * void __thiscall Moho::CWaterShaderProperties::~CWaterShaderProperties(int this);
 *
 * What it does:
 * Resets the vtable pointer, calls releaseTextures() to atomically drop all
 * six texture sheet reference counts, then runs the eh_vector_destructor
 * on mTextures[0..3] (no-op after releaseTextures zeroes all pi_ fields),
 * and finally destroys the six msvc8::string members via eh_vector_destructor
 * and explicit SSO/heap teardown.
 *
 * In the binary, mTextures[4] and mTextures[5] are released manually before
 * the eh_vector loop; in C++ recovery these are already null after
 * releaseTextures() and the loop becomes a no-op.
 *
 * The destructor is virtual (UAE mangling); callers arrive via vtable or
 * as a direct non-virtual call from a derived-class destructor.
 */
CWaterShaderProperties::~CWaterShaderProperties()
{
  releaseTextures();

  // After releaseTextures() all mTextures entries have pi=null and px=null.
  // The remaining string members (mWaterRamp, mWaterCubemap, mShaderNames[])
  // require explicit tidy to release any heap-allocated buffers.  The binary
  // uses eh_vector_destructor_iterator and direct SSO teardown; we call tidy()
  // directly here to match the same observable side-effects.
  mWaterRamp.tidy();
  mWaterCubemap.tidy();
  for (auto& s : mShaderNames) {
    s.tidy();
  }
}

/**
 * Address: 0x0089F8B0 (FUN_0089F8B0)
 *
 * What it does:
 * Runs one deleting-destructor thunk for `CWaterShaderProperties`, forwarding
 * through non-deleting teardown and optional storage release.
 */
[[nodiscard]] CWaterShaderProperties* DestroyWaterShaderPropertiesDeleting(
  CWaterShaderProperties* const properties,
  const unsigned char deleteFlag
)
{
  properties->~CWaterShaderProperties();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(properties));
  }
  return properties;
}

/**
 * Address: 0x008A0740 (FUN_008A0740)
 * Mangled: ?releaseTextures@CWaterShaderProperties@Moho@@QAEXXZ
 *
 * IDA signature:
 * void __usercall Moho::CWaterShaderProperties::releaseTextures(
 *   Moho::CWaterShaderProperties *a1@<esi>);
 *
 * What it does:
 * Iterates mTextures[0..5] in order, zeroes the sheet pointer and atomically
 * decrements the shared control block use-count, calling dispose/destroy when
 * the count reaches zero.  This mirrors the binary's open-coded
 * boost::shared_ptr release loop.
 */
void CWaterShaderProperties::releaseTextures()
{
  for (auto& entry : mTextures) {
    entry.px = nullptr;
    boost::detail::sp_counted_base* const pi = entry.pi;
    entry.pi = nullptr;
    if (pi != nullptr) {
      pi->release();
    }
  }
}

/**
 * Address: 0x0089FD70 (FUN_0089FD70)
 * Mangled: ?GetWaterRamp@CWaterShaderProperties@Moho@@QBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ
 *
 * What it does:
 * Lazily resolves one water-ramp texture resource and caches its shared-owner
 * lane at `mTextures[5]`, then returns one retained shared texture-sheet
 * handle to the caller.
 */
boost::shared_ptr<ID3DTextureSheet> CWaterShaderProperties::GetWaterRamp() const
{
  if (mTextures[5].px == nullptr) {
    if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
      if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
        ID3DDeviceResources::TextureResourceHandle loadedTexture{};
        resources->GetTexture(loadedTexture, mWaterRamp.c_str(), 0, true);

        const boost::SharedPtrRaw<RD3DTextureResource> loadedRaw =
          boost::SharedPtrRawFromSharedBorrow(loadedTexture);

        boost::SharedPtrRaw<ID3DTextureSheet> resolvedTexture{};
        resolvedTexture.px = static_cast<ID3DTextureSheet*>(loadedRaw.px);
        resolvedTexture.pi = loadedRaw.pi;
        mTextures[5].assign_retain(resolvedTexture);
      }
    }
  }

  return boost::SharedPtrFromRawRetained(mTextures[5]);
}

/**
 * Address: 0x0089FC40 (FUN_0089FC40, ?GetCubeMap@CWaterShaderProperties@Moho@@QBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
 * Mangled: ?GetCubeMap@CWaterShaderProperties@Moho@@QBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ
 *
 * What it does:
 * Lazily resolves one water-cubemap texture and caches its shared-owner lane
 * at `mTextures[4]`, then returns one retained shared texture-sheet handle to
 * the caller.
 */
boost::shared_ptr<ID3DTextureSheet> CWaterShaderProperties::GetCubeMap() const
{
  if (mTextures[4].px == nullptr) {
    if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
      if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
        ID3DDeviceResources::TextureResourceHandle loadedTexture{};
        resources->GetTexture(loadedTexture, mWaterCubemap.c_str(), 0, true);

        const boost::SharedPtrRaw<RD3DTextureResource> loadedRaw =
          boost::SharedPtrRawFromSharedBorrow(loadedTexture);

        boost::SharedPtrRaw<ID3DTextureSheet> resolvedTexture{};
        resolvedTexture.px = static_cast<ID3DTextureSheet*>(loadedRaw.px);
        resolvedTexture.pi = loadedRaw.pi;
        mTextures[4].assign_retain(resolvedTexture);
      }
    }
  }

  return boost::SharedPtrFromRawRetained(mTextures[4]);
}

/**
 * Address: 0x0089FB00 (FUN_0089FB00, ?GetNormalMap@CWaterShaderProperties@Moho@@QBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@H@Z)
 * Mangled: ?GetNormalMap@CWaterShaderProperties@Moho@@QBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@H@Z
 *
 * What it does:
 * Lazily resolves one indexed normal-map texture from `mShaderNames[index]`,
 * caches it in `mTextures[index]`, and returns one retained shared texture
 * sheet handle.
 */
boost::shared_ptr<ID3DTextureSheet> CWaterShaderProperties::GetNormalMap(const int index) const
{
  boost::SharedPtrRaw<ID3DTextureSheet>& cachedTexture = mTextures[index];
  if (cachedTexture.px == nullptr) {
    if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
      if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
        ID3DDeviceResources::TextureResourceHandle loadedTexture{};
        resources->GetTexture(loadedTexture, mShaderNames[index].c_str(), 0, true);

        const boost::SharedPtrRaw<RD3DTextureResource> loadedRaw =
          boost::SharedPtrRawFromSharedBorrow(loadedTexture);

        boost::SharedPtrRaw<ID3DTextureSheet> resolvedTexture{};
        resolvedTexture.px = static_cast<ID3DTextureSheet*>(loadedRaw.px);
        resolvedTexture.pi = loadedRaw.pi;
        cachedTexture.assign_retain(resolvedTexture);
      }
    }
  }

  return boost::SharedPtrFromRawRetained(cachedTexture);
}

} // namespace moho
