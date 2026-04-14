#include "moho/terrain/water/CWaterShaderProperties.h"

#include <cmath>
#include <boost/detail/sp_counted_base.hpp>

#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/BinaryWriter.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"

namespace
{
void NormalizeVector3(moho::WaterDirectionVector& direction)
{
  const float lengthSquared = (direction.x * direction.x) + (direction.y * direction.y) +
    (direction.z * direction.z);
  if (lengthSquared <= 0.0f) {
    return;
  }

  const float invLength = 1.0f / std::sqrt(lengthSquared);
  direction.x *= invLength;
  direction.y *= invLength;
  direction.z *= invLength;
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
  state.laneFlags = 0u;
  state.scalar00 = 0.7f;
  state.scalar01 = 1.5f;
  state.scalar02 = 0.064f;
  state.scalar03 = 0.119f;
  state.scalar04 = 0.375f;
  state.scalar05 = 0.15f;
  state.scalar06 = 1.5f;
  state.scalar07 = 0.5f;
  state.scalar08 = 1.5f;
  state.scalar09 = 0.0009f;
  state.scalar10 = 0.009f;
  state.scalar11 = 0.05f;
  state.scalar12 = 0.5f;
  state.scalar21 = 50.0f;
  state.scalar22 = 10.0f;
  state.directionPrimary.x = 0.1f;
  state.directionPrimary.y = -0.967f;
  state.directionPrimary.z = 0.253f;
  state.directionSecondary.x = 1.2f;
  state.directionSecondary.y = 0.7f;
  state.directionSecondary.z = 0.5f;
  state.scalar29 = 5.0f;
  state.scalar30 = 0.1f;

  NormalizeVector3(state.directionPrimary);
  NormalizeVector3(state.directionSecondary);

  state.scalar13 = 0.5f;
  state.scalar14 = -0.95f;
  state.scalar15 = 0.05f;
  state.scalar16 = -0.095f;
  state.scalar17 = 0.01f;
  state.scalar18 = 0.03f;
  state.scalar19 = 0.0005f;
  state.scalar20 = 0.0009f;

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

  WriteFloat(writer, state.scalar00);
  WriteFloat(writer, state.scalar01);
  WriteFloat(writer, state.scalar02);
  WriteFloat(writer, state.scalar03);
  WriteFloat(writer, state.scalar04);
  WriteFloat(writer, state.scalar05);
  WriteFloat(writer, state.scalar06);
  WriteFloat(writer, state.scalar07);
  WriteFloat(writer, state.scalar08);
  WriteFloat(writer, state.scalar09);
  WriteFloat(writer, state.scalar22);
  WriteFloat(writer, state.directionPrimary.x);
  WriteFloat(writer, state.directionPrimary.y);
  WriteFloat(writer, state.directionPrimary.z);
  WriteFloat(writer, state.directionSecondary.x);
  WriteFloat(writer, state.directionSecondary.y);
  WriteFloat(writer, state.directionSecondary.z);
  WriteFloat(writer, state.scalar29);
  WriteFloat(writer, state.scalar30);

  writer.WriteString(mWaterCubemap);
  writer.WriteString(mWaterRamp);

  WriteFloat(writer, state.scalar10);
  WriteFloat(writer, state.scalar11);
  WriteFloat(writer, state.scalar12);

  const float* const firstLane[4] = {
    &state.scalar13,
    &state.scalar15,
    &state.scalar17,
    &state.scalar19,
  };
  const float* const secondLane[4] = {
    &state.scalar14,
    &state.scalar16,
    &state.scalar18,
    &state.scalar20,
  };
  for (std::size_t index = 0; index < 4u; ++index) {
    WriteFloat(writer, *firstLane[index]);
    WriteFloat(writer, *secondLane[index]);
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

  ReadFloat(reader, state.scalar00);
  ReadFloat(reader, state.scalar01);
  ReadFloat(reader, state.scalar02);
  ReadFloat(reader, state.scalar03);
  ReadFloat(reader, state.scalar04);
  ReadFloat(reader, state.scalar05);
  ReadFloat(reader, state.scalar06);
  ReadFloat(reader, state.scalar07);
  ReadFloat(reader, state.scalar08);
  ReadFloat(reader, state.scalar09);
  ReadFloat(reader, state.scalar22);
  ReadFloat(reader, state.directionPrimary.x);
  ReadFloat(reader, state.directionPrimary.y);
  ReadFloat(reader, state.directionPrimary.z);
  ReadFloat(reader, state.directionSecondary.x);
  ReadFloat(reader, state.directionSecondary.y);
  ReadFloat(reader, state.directionSecondary.z);
  ReadFloat(reader, state.scalar29);
  ReadFloat(reader, state.scalar30);

  reader.ReadString(&mWaterCubemap);
  reader.ReadString(&mWaterRamp);

  ReadFloat(reader, state.scalar10);
  ReadFloat(reader, state.scalar11);
  ReadFloat(reader, state.scalar12);

  float* const firstLane[4] = {
    &state.scalar13,
    &state.scalar15,
    &state.scalar17,
    &state.scalar19,
  };
  float* const secondLane[4] = {
    &state.scalar14,
    &state.scalar16,
    &state.scalar18,
    &state.scalar20,
  };
  for (std::size_t index = 0; index < 4u; ++index) {
    ReadFloat(reader, *firstLane[index]);
    ReadFloat(reader, *secondLane[index]);
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
