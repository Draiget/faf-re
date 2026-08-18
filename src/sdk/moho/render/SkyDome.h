#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class BinaryReader;
  class BinaryWriter;
}

namespace gpg::gal
{
  class Effect;
  class EffectTechnique;
  class EffectTechniqueD3D9;
  class TextureD3D9;
  class IndexBufferD3D9;
  class VertexBufferD3D9;
}

namespace moho
{
  class CD3DEffect;
  class CD3DVertexFormat;
  class RD3DTextureResource;
  struct GeomCamera3;
  struct WRenViewport;

  struct SkyDomeDecalUploadNode
  {
    SkyDomeDecalUploadNode* mNext;     // +0x00
    SkyDomeDecalUploadNode* mPrev;     // +0x04
    std::uint8_t mVertexData[0x28];    // +0x08
  };

  static_assert(sizeof(SkyDomeDecalUploadNode) == 0x30, "SkyDomeDecalUploadNode size must be 0x30");
  static_assert(offsetof(SkyDomeDecalUploadNode, mNext) == 0x00, "SkyDomeDecalUploadNode::mNext offset must be 0x00");
  static_assert(offsetof(SkyDomeDecalUploadNode, mPrev) == 0x04, "SkyDomeDecalUploadNode::mPrev offset must be 0x04");
  static_assert(
    offsetof(SkyDomeDecalUploadNode, mVertexData) == 0x08,
    "SkyDomeDecalUploadNode::mVertexData offset must be 0x08"
  );

  /**
   * VFTABLE: 0x00E422A0
   *
   * Manages the sky dome rendering state — atmosphere gradient, cumulus/cirrus
   * cloud layers, horizon lookup textures, and associated D3D vertex/index
   * buffers for the dome and decal geometry.
   */
  class SkyDome
  {
  public:
    /**
     * One per-cumulus-cloud instance record uploaded to the instanced cumulus
     * vertex stream (`mDecalVertBuf3`) by `RenderCumulus`.
     *
     * The stride is proven by the binary: `RenderCumulus` derives the cloud
     * count as `(verts.end() - verts.begin()) / 0x3C` and uploads
     * `count * 0x3C` bytes verbatim into the per-instance stream. The internal
     * field decomposition is not separately observable from the render path
     * (the records are copied as an opaque 0x3C-byte block), so the payload is
     * modeled as a raw byte lane pending a producer-side recovery that reveals
     * the named sub-fields.
     */
    struct CumulusVertex
    {
      std::uint8_t mPayload[0x3C]; // +0x00
    };

    static_assert(sizeof(CumulusVertex) == 0x3C, "SkyDome::CumulusVertex size must be 0x3C");

    /**
     * Address: 0x008149E0 (FUN_008149E0, ??0SkyDome@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes all sky dome rendering state to defaults — colors, texture
     * paths, inline vector storage, and null shared_ptr resource handles.
     */
    SkyDome();

    /**
     * Address: 0x00814CD0 (FUN_00814CD0, ??1SkyDome@Moho@@UAE@XZ)
     */
    virtual ~SkyDome();

    /**
     * Address: 0x008175D0 (FUN_008175D0, Moho::SkyDome::Destroy)
     *
     * What it does:
     * Releases all D3D resource handles and resets rendering state.
     */
    void Destroy();

    /**
     * Address: 0x00815FA0 (FUN_00815FA0, ?Load@SkyDome@Moho@@QAEXIAAVBinaryReader@gpg@@@Z)
     *
     * What it does:
     * Loads sky dome configuration from binary archive.
     */
    void Load(unsigned int version, gpg::BinaryReader& reader);

    /**
     * Address: 0x008164D0 (FUN_008164D0, ?Save@SkyDome@Moho@@QAEXAAVBinaryWriter@gpg@@@Z)
     *
     * What it does:
     * Saves sky dome configuration to binary archive.
     */
    void Save(gpg::BinaryWriter& writer);

    /**
     * Address: 0x00817160 (FUN_00817160, ?Reset@SkyDome@Moho@@QAEXXZ)
     *
     * What it does:
     * Recreates all D3D resources from current configuration state.
     */
    void Reset();

    /**
     * Address: 0x008158D0 (FUN_008158D0, ?SetCirrusContext@SkyDome@Moho@@QAEXMABV?$Vector3@M@Wm3@@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
     *
     * What it does:
     * Restores cirrus scalar/vector context lanes, releases the previous
     * cirrus texture handle, and stores the new texture path.
     */
    void SetCirrusContext(float speed, const Wm3::Vector3f& direction, const msvc8::string& texturePath);

    /**
     * Address: 0x00815230 (FUN_00815230, ?SetupHorizonAndCirrus@SkyDome@Moho@@...)
     *
     * What it does:
     * Reconfigures the dome shape (origin/elevation/radius) and default
     * tessellation, restores the horizon colour/size and sky colour, restores
     * the fixed cirrus colour/texture context, and copies the static cirrus
     * runtime table into the dome's cirrus-data lane. Invoked by
     * CWldTerrainRes::Load/Reset after the terrain map bounds are known.
     */
    void SetupHorizonAndCirrus(const Wm3::Vector3f& domeOrigin, float waterElevation, float domeRadius);

    /**
     * Address: 0x008177B0 (FUN_008177B0, ?CreateRenderAbility@SkyDome@Moho@@AAEXXZ)
     *
     * What it does:
     * Initializes the dome vertex format and associated vertex/index buffers.
     */
    void CreateRenderAbility();

    /**
     * Address: 0x00817810 (FUN_00817810)
     *
     * What it does:
     * Looks up the sky dome shader effect from the active D3D device.
     */
    boost::shared_ptr<gpg::gal::Effect> GetEffect();

    /**
     * Address: 0x00817850 (FUN_00817850, ?CreateTextures@SkyDome@Moho@@AAEXXZ)
     *
     * What it does:
     * Loads all dome textures from D3D device resources.
     */
    void CreateTextures();

    /**
     * Address: 0x008180A0 (FUN_008180A0, ?CreateDomeFormat@SkyDome@Moho@@AAEXXZ)
     *
     * What it does:
     * Creates the vertex format descriptor for dome geometry.
     */
    void CreateDomeFormat();

    /**
     * Address: 0x00818630 (FUN_00818630, ?CreateDecalFormat@SkyDome@Moho@@AAEXXZ)
     *
     * What it does:
     * Creates the two vertex-format descriptors used by sky decal geometry.
     */
    void CreateDecalFormat();

    /**
     * Address: 0x00818170 (FUN_00818170, ?CreateDomeVertexBuffer@SkyDome@Moho@@AAEXMMMHH@Z)
     *
     * What it does:
     * Builds dome vertex buffer with the specified spherical parameters.
     */
    void CreateDomeVertexBuffer(
      float verticalOffset,
      float domeRadius,
      float startAngleRadians,
      int widthSegments,
      int heightSegments
    );

    /**
     * Address: 0x00818410 (FUN_00818410, ?CreateDomeIndexBuffer@SkyDome@Moho@@AAEXHH@Z)
     *
     * What it does:
     * Builds dome index buffer from segment counts.
     */
    void CreateDomeIndexBuffer(int widthSegments, int heightSegments);

    /**
     * Address: 0x00818780 (FUN_00818780, ?CreateDecalVertexBuffers@SkyDome@Moho@@AAEXXZ)
     *
     * What it does:
     * Creates and initializes all sky decal vertex-buffer lanes.
     */
    void CreateDecalVertexBuffers();

    /**
     * Address: 0x00818A10 (FUN_00818A10, ?CreateDecalIndexBuffer@SkyDome@Moho@@AAEXXZ)
     *
     * What it does:
     * Creates and initializes the sky decal index buffer.
     */
    void CreateDecalIndexBuffer();

    /**
     * Address: 0x0081A190 (FUN_0081A190, Moho::SkyDome::UpdateDecalBuffer)
     *
     * What it does:
     * Uploads queued sky-decal vertex records to the dynamic decal vertex
     * buffer and clears the pending rebuild latch.
     */
    void UpdateDecalBuffer();

  private:
    // The per-head sky render dispatcher (FUN_007F80C0, PDB symbol
    // ?Render@SkyDome@Moho@@QAEX...) compiles with a `this` that is actually a
    // WRenViewport, not a SkyDome (its body reads WRenViewport fields mHead,
    // mScreenPos, mScreenSize, mCam — all far beyond SkyDome's 0x224 layout).
    // It is modeled as moho::WRenViewport::RenderSkyDome, which drives the
    // private atmosphere/decal/cirrus/cumulus passes below. The original
    // private access of those passes (mangled `AAE` = private __thiscall) is
    // preserved by granting WRenViewport friendship rather than widening them
    // to public.
    friend struct WRenViewport;

    /**
     * Address: 0x00818B40 (FUN_00818B40)
     * Mangled: ?RenderAtmosphere@SkyDome@Moho@@AAEXABVGeomCamera3@2@@Z
     *
     * IDA signature:
     * void __thiscall Moho::SkyDome::RenderAtmosphere(const GeomCamera3 &cam);
     *
     * What it does:
     * Selects the "Atmosphere" technique and feeds the dome shader the camera
     * view position/projection, horizon begin/end/colors, sky color, and the
     * horizon lookup texture, then renders the dome geometry.
     */
    void RenderAtmosphere(const GeomCamera3& cam);

    /**
     * Address: 0x00819650 (FUN_00819650)
     * Mangled: ?RenderCirrus@SkyDome@Moho@@AAEXHMABVGeomCamera3@2@@Z
     *
     * IDA signature:
     * void __thiscall Moho::SkyDome::RenderCirrus(int tick, float interpolant,
     *     const GeomCamera3 &cam);
     *
     * What it does:
     * Selects the "Cirrus" technique, feeds the tick/interpolant lanes plus the
     * camera/cirrus parameters and cloud texture, then renders the dome
     * geometry.
     */
    void RenderCirrus(int tick, float interpolant, const GeomCamera3& cam);

    /**
     * Address: 0x00818FB0 (FUN_00818FB0)
     * Mangled: ?RenderCumulus@SkyDome@Moho@@AAEXHMABVGeomCamera3@2@ABV?$vector@UCumulusVertex@SkyDome@Moho@@V?$allocator@UCumulusVertex@SkyDome@Moho@@@std@@@std@@@Z
     *
     * IDA signature:
     * void __thiscall Moho::SkyDome::RenderCumulus(int head, float deltaFrame,
     *     const GeomCamera3 &cam, const std::vector<CumulusVertex> &cumulusVertices);
     *
     * What it does:
     * Uploads the per-cloud cumulus instance records, selects the "Cumulus"
     * technique, binds the instanced quad/index streams plus cumulus textures,
     * then issues one indexed draw per technique pass.
     */
    void RenderCumulus(
      int head,
      float deltaFrame,
      const GeomCamera3& cam,
      const msvc8::vector<CumulusVertex>& cumulusVertices
    );

    /**
     * Address: 0x00819C90 (FUN_00819C90)
     * Mangled: ?RenderDecals@SkyDome@Moho@@AAEXABVGeomCamera3@2@@Z
     *
     * IDA signature:
     * void __thiscall Moho::SkyDome::RenderDecals(const GeomCamera3 &cam);
     *
     * What it does:
     * When decal records and both decal textures exist, flushes the decal
     * upload buffer, selects the "Decal" technique, binds the decal streams and
     * albedo/glow textures, then issues one indexed draw per technique pass.
     */
    void RenderDecals(const GeomCamera3& cam);

    /**
     * Address: 0x00819AF0 (FUN_00819AF0)
     * Mangled: ?RenderDomeUsing@SkyDome@Moho@@AAEXV?$shared_ptr@VEffectTechnique@gal@gpg@@@boost@@@Z
     *
     * IDA signature:
     * void __stdcall Moho::SkyDome::RenderDomeUsing(boost::shared_ptr<gpg::gal::EffectTechnique> technique);
     *
     * What it does:
     * Binds the dome vertex format/vertex buffer/index buffer, then iterates the
     * technique passes issuing one indexed dome draw per pass.
     *
     * The runtime object is always the D3D9 backend technique; the parameter is
     * typed as the concrete `EffectTechniqueD3D9` (the base `gpg::gal::EffectTechnique`
     * is the pure-virtual skeleton and its inheritance is not yet recovered).
     */
    void RenderDomeUsing(boost::shared_ptr<gpg::gal::EffectTechniqueD3D9> technique);

  public:
    // --- Layout from constructor ASM evidence ---
    // `SkyDome` doesn't C++-inherit `CResourceWatcher` (its own vtable at
    // 0x00E422A0 shows no evidence of a stacked base-class slot region) but
    // lays out these bytes identically - `CreateTextures` reinterpret_casts
    // `this` to `CResourceWatcher*` to reuse `ResourceManager::
    // ManageWatchedResources`. Named/typed to match, rather than left as an
    // opaque byte blob the constructor can silently leave uninitialized.
    std::uint32_t mWatcherFlags = 0;                              // +0x04
    void* mWatchedBegin = nullptr;                                // +0x08
    void* mWatchedEnd = nullptr;                                  // +0x0C
    void* mWatchedStorageEnd = nullptr;                           // +0x10
    void* mWatchedStorageOrigin = nullptr;                        // +0x14
    std::uint8_t mWatchedInline[0x08]{};                          // +0x18
    Wm3::Vector3f mDomeOrigin{0.0f, 0.0f, 0.0f};                 // +0x20
    Wm3::Vector3f mDomeShapeParams{0.0f, 512.0f, 1.2566371f};    // +0x2C (height/radius/start-angle)
    std::int32_t mWidth = 16;                                     // +0x38
    std::int32_t mHeight = 6;                                     // +0x3C
    float mHorizonSize = 44.0f;                                   // +0x40
    Wm3::Vector3f mHorizonColor{0.5608f, 0.6706f, 0.8857f};     // +0x44
    Wm3::Vector3f mSkyColor{0.1804f, 0.4039f, 0.7245f};         // +0x50
    msvc8::string mHorizonLookupPath;                              // +0x5C
    float mHorizonBlend = 0.1f;                                   // +0x78
    msvc8::string mAtmosphereTexPath;                              // +0x7C
    msvc8::string mAtmosphereTexPath2;                             // +0x98
    std::uint8_t mPadB4[0x04];                                    // +0xB4
    SkyDomeDecalUploadNode* mDecalUploadHead = nullptr;            // +0xB8
    std::int32_t mDecalUploadCount = 0;                            // +0xBC
    msvc8::string mDecalTexPath1;                                  // +0xC0
    msvc8::string mDecalTexPath2;                                  // +0xDC
    msvc8::string mDecalTexPath3;                                  // +0xF8
    float mCirrusMultiplier = 1.8f;                                // +0x114
    float mCirrusColor_R = 1.0f;                                  // +0x118
    float mCirrusColor_G = 1.0f;                                  // +0x11C
    float mCirrusColor_B = 1.0f;                                  // +0x120
    msvc8::string mCirrusTexPath;                                  // +0x124
    std::uint8_t mCirrusData[0x50];                                // +0x140 (copied from static)
    std::int32_t mDomeVertexCount = 0;                             // +0x190
    std::int32_t mDomeIndexCount = 0;                              // +0x194
    boost::shared_ptr<CD3DVertexFormat> mDomeFormat;               // +0x198
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mDomeVertBuf;    // +0x1A0
    boost::shared_ptr<gpg::gal::IndexBufferD3D9> mDomeIndexBuf;    // +0x1A8
    // Texture lanes hold the GAL base texture extracted from each source
    // RD3DTextureResource (CreateTextures @0x00817850 stores
    // `resource->GetBaseTexture()` into these fields, and the render passes
    // bind them directly to EffectVariableD3D9::SetTexture, which takes a
    // shared_ptr<TextureD3D9>). They are GAL texture handles, not the owning
    // resource wrappers.
    boost::shared_ptr<gpg::gal::TextureD3D9> mHorizonLookupTex;    // +0x1B0
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mDecalVertBuf1;  // +0x1B8
    boost::shared_ptr<gpg::gal::IndexBufferD3D9> mDecalIndexBuf;   // +0x1C0
    bool mNeedsRebuild = true;                                     // +0x1C8
    std::uint8_t mPad1C9[0x03];                                    // +0x1C9
    boost::shared_ptr<gpg::gal::TextureD3D9> mAtmosphereTex;       // +0x1CC (decal albedo lane)
    boost::shared_ptr<gpg::gal::TextureD3D9> mAtmosphereTex2;      // +0x1D4 (decal glow lane)
    boost::shared_ptr<CD3DVertexFormat> mDecalFormat1;             // +0x1DC
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mDecalVertBuf2;  // +0x1E4
    boost::shared_ptr<gpg::gal::TextureD3D9> mDecalTex1;           // +0x1EC (cumulus light ramp)
    boost::shared_ptr<gpg::gal::TextureD3D9> mDecalTex2;           // +0x1F4 (cumulus dispersion ramp)
    boost::shared_ptr<gpg::gal::TextureD3D9> mDecalTex3;           // +0x1FC (cumulus texture)
    boost::shared_ptr<CD3DVertexFormat> mDecalFormat2;             // +0x204
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mDecalVertBuf3;  // +0x20C
    boost::shared_ptr<gpg::gal::TextureD3D9> mCirrusTex;           // +0x214
    boost::shared_ptr<gpg::gal::TextureD3D9> mCloudsTexture;       // +0x21C
  };

  static_assert(offsetof(SkyDome, mWatcherFlags) == 0x04, "SkyDome::mWatcherFlags offset must be 0x04");
  static_assert(offsetof(SkyDome, mWatchedBegin) == 0x08, "SkyDome::mWatchedBegin offset must be 0x08");
  static_assert(offsetof(SkyDome, mWatchedEnd) == 0x0C, "SkyDome::mWatchedEnd offset must be 0x0C");
  static_assert(offsetof(SkyDome, mWatchedStorageEnd) == 0x10, "SkyDome::mWatchedStorageEnd offset must be 0x10");
  static_assert(offsetof(SkyDome, mWatchedStorageOrigin) == 0x14, "SkyDome::mWatchedStorageOrigin offset must be 0x14");
  static_assert(offsetof(SkyDome, mWatchedInline) == 0x18, "SkyDome::mWatchedInline offset must be 0x18");
  static_assert(offsetof(SkyDome, mDomeOrigin) == 0x20, "SkyDome::mDomeOrigin offset must be 0x20");
  static_assert(offsetof(SkyDome, mDomeShapeParams) == 0x2C, "SkyDome::mDomeShapeParams offset must be 0x2C");
  static_assert(offsetof(SkyDome, mWidth) == 0x38, "SkyDome::mWidth offset must be 0x38");
  static_assert(offsetof(SkyDome, mHeight) == 0x3C, "SkyDome::mHeight offset must be 0x3C");
  static_assert(offsetof(SkyDome, mHorizonSize) == 0x40, "SkyDome::mHorizonSize offset must be 0x40");
  static_assert(offsetof(SkyDome, mHorizonColor) == 0x44, "SkyDome::mHorizonColor offset must be 0x44");
  static_assert(offsetof(SkyDome, mSkyColor) == 0x50, "SkyDome::mSkyColor offset must be 0x50");
  static_assert(offsetof(SkyDome, mHorizonLookupPath) == 0x5C, "SkyDome::mHorizonLookupPath offset must be 0x5C");
  static_assert(offsetof(SkyDome, mHorizonBlend) == 0x78, "SkyDome::mHorizonBlend offset must be 0x78");
  static_assert(offsetof(SkyDome, mCirrusTexPath) == 0x124, "SkyDome::mCirrusTexPath offset must be 0x124");
  static_assert(offsetof(SkyDome, mDomeVertexCount) == 0x190, "SkyDome::mDomeVertexCount offset must be 0x190");
  static_assert(offsetof(SkyDome, mDomeFormat) == 0x198, "SkyDome::mDomeFormat offset must be 0x198");
  static_assert(offsetof(SkyDome, mNeedsRebuild) == 0x1C8, "SkyDome::mNeedsRebuild offset must be 0x1C8");
  static_assert(offsetof(SkyDome, mCirrusTex) == 0x214, "SkyDome::mCirrusTex offset must be 0x214");
  static_assert(offsetof(SkyDome, mCloudsTexture) == 0x21C, "SkyDome::mCloudsTexture offset must be 0x21C");
  static_assert(sizeof(SkyDome) == 0x224, "SkyDome size must be 0x224");
} // namespace moho
