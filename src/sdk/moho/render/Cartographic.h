#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/gal/Effect.hpp"
#include "legacy/containers/String.h"

namespace gpg
{
  class BinaryReader;
  class BinaryWriter;
}

namespace gpg::gal
{
  class DepthStencilTargetD3D9;
  class IndexBufferD3D9;
  class RenderTargetD3D9;
  class TextureD3D9;
  class VertexBufferD3D9;
  class VertexFormatD3D9;
}

namespace moho
{
  class BoundaryRenderer;
  class CD3DPrimBatcher;
  class CHeightField;
  class IRenderWorldView;
  class IWldTerrainRes;
  class RangeRenderer;
  class VisionRenderer;
  struct GeomCamera3;

  /**
   * VFTABLE: 0x00E3F710
   * COL:     0x00E97F88
   */
  class CartographicDecal
  {
  public:
    /**
     * Address: 0x007D4A00 (FUN_007D4A00, sub_7D4A00)
     *
     * What it does:
     * Initializes one cartographic decal payload object and installs the
     * decal runtime vtable lane.
     */
    CartographicDecal();
    virtual ~CartographicDecal() = default;

  public:
    float mVertexData[9]{}; // +0x04
  };

  static_assert(sizeof(CartographicDecal) == 0x28, "CartographicDecal size must be 0x28");

  struct CartographicDecalNode
  {
    CartographicDecalNode* mNext; // +0x00
    CartographicDecalNode* mPrev; // +0x04
    CartographicDecal mDecal;     // +0x08
  };

  static_assert(offsetof(CartographicDecalNode, mDecal) == 0x08, "CartographicDecalNode::mDecal offset must be 0x08");
  static_assert(sizeof(CartographicDecalNode) == 0x30, "CartographicDecalNode size must be 0x30");

  struct CartographicDecalList
  {
    void* mAllocatorCookie;                  // +0x00
    CartographicDecalNode* mDecalSentinel;   // +0x04
    std::int32_t mDecalCount;                // +0x08
  };

  static_assert(offsetof(CartographicDecalList, mDecalSentinel) == 0x04, "CartographicDecalList::mDecalSentinel offset must be 0x04");
  static_assert(offsetof(CartographicDecalList, mDecalCount) == 0x08, "CartographicDecalList::mDecalCount offset must be 0x08");
  static_assert(sizeof(CartographicDecalList) == 0x0C, "CartographicDecalList size must be 0x0C");

  class CartographicDecalBatch
  {
  public:
    /**
     * Address: 0x007D40E0 (FUN_007D40E0, ??0CartographicDecalBatch@Moho@@QAE@@Z)
     *
     * IDA signature:
     * int __thiscall Moho::CartographicDecalBatch::CartographicDecalBatch(int source, int destination);
     *
     * What it does:
     * Copy-constructs one cartographic decal batch, retaining shared render
     * handles and deep-copying the intrusive decal payload list.
     */
    CartographicDecalBatch(const CartographicDecalBatch& other);

    /**
     * Address: 0x007D4BE0 (FUN_007D4BE0, ??0CartographicDecalBatch@Moho@@QAE@IAAVBinaryReader@gpg@@@Z)
     *
     * IDA signature:
     * Moho::CartographicDecalBatch* __stdcall CartographicDecalBatch(
     *   CartographicDecalBatch* this, unsigned int version, gpg::BinaryReader* reader);
     *
     * What it does:
     * Default-initializes one cartographic decal-batch lane (empty SSO
     * strings, null render-resource shared-pointers, dirty vertex-upload
     * flag, fresh decal-list sentinel) then immediately deserializes the
     * batch payload from the binary reader at the given map version
     * through `Read(version, reader)`.
     */
    CartographicDecalBatch(std::uint32_t version, gpg::BinaryReader& reader);

    /**
     * Address: 0x007D4C80 (FUN_007D4C80, ??1CartographicDecalBatch@Moho@@UAE@XZ)
     *
     * What it does:
     * Tears down one cartographic decal-batch lane by clearing active decal
     * nodes, releasing retained resource handles, and restoring inline string
     * lanes to empty state.
     */
    virtual ~CartographicDecalBatch();

    /**
     * Address: 0x007D4E60 (FUN_007D4E60, ?Shutdown@CartographicDecalBatch@Moho@@QAEXXZ)
     *
     * What it does:
     * Clears one cartographic decal-batch payload in place, releasing
     * retained handles and intrusive decal nodes, then marks the decal vertex
     * stream dirty for the next resource rebuild.
     */
    void Shutdown();

    /**
     * Address: 0x007D5650 (FUN_007D5650, ?Write@CartographicDecalBatch@Moho@@QAEXAAVBinaryWriter@gpg@@@Z)
     *
     * What it does:
     * Serializes one cartographic decal-batch payload into the binary writer.
     */
    void Write(gpg::BinaryWriter& writer);

    /**
     * Address: 0x007D5400 (FUN_007D5400, ?Read@CartographicDecalBatch@Moho@@QAEXIAAVBinaryReader@gpg@@@Z)
     *
     * IDA signature:
     * void __thiscall CartographicDecalBatch::Read(
     *   CartographicDecalBatch* this, unsigned int version, gpg::BinaryReader* reader);
     *
     * What it does:
     * Deserializes one cartographic decal-batch payload from the binary
     * reader, replacing any prior batch state. Reads the technique name
     * (defaulting to `"Decal"` for legacy map versions < 0x3C), the
     * texture resource path, the decal count, and each decal's
     * nine-float instance payload, appending the decals into the
     * intrusive `mDecals` list.
     */
    void Read(std::uint32_t version, gpg::BinaryReader& reader);

    /**
     * Address: 0x007D50D0 (FUN_007D50D0, sub_7D50D0)
     *
     * IDA signature:
     * void __thiscall sub_7D50D0(
     *   Moho::CartographicDecalBatch *this@<ecx>, const Moho::GeomCamera3 *camera);
     *
     * What it does:
     * Ensures cartographic decal GPU resources and texture state exist, uploads
     * dirty decal instance vertices, binds the cartographic effect, and draws
     * one instanced quad pass for each technique pass.
     *
     * The shipped body ends in `retn 4` (0x007D53EE) - one stack argument, the
     * batch in `ecx` - and the sole call site, the decal-list walk inside
     * `Cartographic::Render` at 0x007D1B30..0x007D1B34, pushes only the camera.
     * The earlier `(enabled, tick, camera)` arity declared here was a guess the
     * body never read; it is dropped so the declaration matches the shipped ABI.
     */
    void Render(const GeomCamera3& camera);

    /**
     * Address: 0x007D56C0 (FUN_007D56C0, sub_7D56C0)
     *
     * What it does:
     * Lazily creates the cartographic decal vertex declaration, quad vertex
     * buffer, dynamic decal-instance buffer, and quad index buffer.
     */
    void InitializeRenderResources();

    /**
     * Address: 0x007D59C0 (FUN_007D59C0, sub_7D59C0)
     *
     * What it does:
     * Lazily resolves the decal texture resource named by the texture-path
     * string lane and retains its base GAL texture handle.
     */
    void ResolveDecalTexture();

    /**
     * Address: 0x007D5AD0 (FUN_007D5AD0, sub_7D5AD0)
     *
     * What it does:
     * Uploads each decal node's nine-float instance payload into the dynamic
     * decal vertex buffer when the dirty flag is set.
     */
    void UploadDecalVerticesIfDirty();

  public:
    msvc8::string mTechniqueName;                                         // +0x04
    msvc8::string mTexturePath;                                           // +0x20
    boost::shared_ptr<gpg::gal::TextureD3D9> mDecalTexture;               // +0x3C
    boost::shared_ptr<gpg::gal::VertexFormatD3D9> mVertexFormat;          // +0x44
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mQuadVertexBuffer;      // +0x4C
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mInstanceVertexBuffer;  // +0x54
    boost::shared_ptr<gpg::gal::IndexBufferD3D9> mIndexBuffer;            // +0x5C
    bool mNeedsVertexUpload;                                              // +0x64
    std::uint8_t mPadding65_67[0x03];                                     // +0x65
    CartographicDecalList mDecals;                                        // +0x68
  };

  static_assert(offsetof(CartographicDecalBatch, mTechniqueName) == 0x04, "CartographicDecalBatch::mTechniqueName offset must be 0x04");
  static_assert(offsetof(CartographicDecalBatch, mTexturePath) == 0x20, "CartographicDecalBatch::mTexturePath offset must be 0x20");
  static_assert(offsetof(CartographicDecalBatch, mDecalTexture) == 0x3C, "CartographicDecalBatch::mDecalTexture offset must be 0x3C");
  static_assert(offsetof(CartographicDecalBatch, mVertexFormat) == 0x44, "CartographicDecalBatch::mVertexFormat offset must be 0x44");
  static_assert(offsetof(CartographicDecalBatch, mQuadVertexBuffer) == 0x4C, "CartographicDecalBatch::mQuadVertexBuffer offset must be 0x4C");
  static_assert(offsetof(CartographicDecalBatch, mInstanceVertexBuffer) == 0x54, "CartographicDecalBatch::mInstanceVertexBuffer offset must be 0x54");
  static_assert(offsetof(CartographicDecalBatch, mIndexBuffer) == 0x5C, "CartographicDecalBatch::mIndexBuffer offset must be 0x5C");
  static_assert(offsetof(CartographicDecalBatch, mNeedsVertexUpload) == 0x64, "CartographicDecalBatch::mNeedsVertexUpload offset must be 0x64");
  static_assert(offsetof(CartographicDecalBatch, mDecals) == 0x68, "CartographicDecalBatch::mDecals offset must be 0x68");
  static_assert(sizeof(CartographicDecalBatch) == 0x74, "CartographicDecalBatch size must be 0x74");

  struct CartographicListNode
  {
    CartographicListNode* mNext;      // +0x00
    CartographicListNode* mPrev;      // +0x04
    CartographicDecalBatch mBatch;    // +0x08
  };

  static_assert(offsetof(CartographicListNode, mBatch) == 0x08, "CartographicListNode::mBatch offset must be 0x08");
  static_assert(sizeof(CartographicListNode) == 0x7C, "CartographicListNode size must be 0x7C");

  class Cartographic
  {
  public:
    /**
     * Address: 0x007D10C0 (FUN_007D10C0, ??0Cartographic@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes cartographic render-state defaults, color lanes, and one
     * self-linked list sentinel used by cartographic runtime storage.
     */
    Cartographic();

    /**
     * Address: 0x007D11B0 (FUN_007D11B0, ??1Cartographic@Moho@@UAE@XZ)
     *
     * IDA signature:
     * void __thiscall Moho::Cartographic::~Cartographic(Moho::Cartographic* this);
     *
     * What it does:
     * Shuts down all cartographic render resources, releases retained handles,
     * clears decal-batch storage, and deletes the list sentinel.
     */
    virtual ~Cartographic();

    /**
     * Address: 0x007D14B0 (FUN_007D14B0, ?Shutdown@Cartographic@Moho@@QAEXXZ)
     *
     * IDA signature:
     * void __stdcall Moho::Cartographic::Shutdown(Moho::Cartographic* this);
     *
     * What it does:
     * Clears cartographic decal batches, releases render/runtime handles, resets
     * projection state, and marks the runtime uninitialized.
     */
    void Shutdown();

    /**
     * Address: 0x007D1700 (FUN_007D1700, ?IsInitialized@Cartographic@Moho@@QBE_NXZ)
     *
     * What it does:
     * Returns whether the cartographic runtime lane has been initialized.
     */
    [[nodiscard]] bool IsInitialized() const;

    /**
     * Address: 0x007D1DF0 (FUN_007D1DF0, ?WriteDecals@Cartographic@Moho@@QAEXAAVBinaryWriter@gpg@@@Z)
     * Mangled: ?WriteDecals@Cartographic@Moho@@QAEXAAVBinaryWriter@gpg@@@Z
     *
     * What it does:
     * Writes the cartographic decal-batch count lane and then serializes each
     * intrusive decal batch node in list order.
     */
    void WriteDecals(gpg::BinaryWriter& writer);

    /**
     * Address: 0x007D1D30 (FUN_007D1D30, ?ReadDecals@Cartographic@Moho@@QAEXIAAVBinaryReader@gpg@@@Z)
     * Mangled: ?ReadDecals@Cartographic@Moho@@QAEXIAAVBinaryReader@gpg@@@Z
     *
     * What it does:
     * Clears the cartographic decal-batch list, reads the batch count
     * lane from the stream, and then deserializes each batch through
     * the `CartographicDecalBatch(version, reader)` constructor,
     * inserting each batch into the intrusive batch list via
     * `InsertCartographicDecalBatchCopy`.
     */
    void ReadDecals(std::uint32_t version, gpg::BinaryReader& reader);

    /**
     * Address: 0x007D1E50 (FUN_007D1E50, ?GetEffect@Cartographic@Moho@@AAE?AV?$shared_ptr@VEffect@gal@gpg@@@boost@@XZ)
     *
     * What it does:
     * Resolves the cartographic shader from the active D3D device resources
     * and returns the backing GAL effect handle.
     */
    [[nodiscard]] boost::shared_ptr<gpg::gal::Effect> GetEffect();

    /**
     * Address: 0x007D13E0 (FUN_007D13E0)
     * Mangled: ?Initialize@Cartographic@Moho@@QAEXPAVIWldTerrainRes@2@IIIII@Z
     *
     * IDA signature:
     * int __thiscall Moho::Cartographic::Initialize(Moho::CWldTerrainRes *this, Moho::Cartographic *a2);
     *
     * What it does:
     * Creates the screen-frame quad GPU resources, then hands the terrain
     * resource plus its topographic sample count and its five hypsometric
     * palette entries to `InitializeTerrain`, and finally marks the
     * cartographic runtime initialized. Anything thrown out of that
     * sequence runs `Shutdown()` before the exception is rethrown.
     *
     * The five `hypsometricColor*` parameters are declared by the mangled
     * symbol but are never read by the shipped body: it re-reads the same
     * five lanes through `terrain->GetHypsometricColor(0..4)` after
     * `InitializeFrame()` has run. MSVC's whole-program optimizer therefore
     * dropped them at the single call site (0x007F8C45 pushes only the
     * `this` lane and leaves the terrain-resource pointer in `ecx`). The
     * definition keeps the declared arity for symbol fidelity and the
     * binary's own reads for behavioral fidelity.
     */
    void Initialize(
      IWldTerrainRes* terrain,
      std::uint32_t hypsometricColor0,
      std::uint32_t hypsometricColor1,
      std::uint32_t hypsometricColor2,
      std::uint32_t hypsometricColor3,
      std::uint32_t hypsometricColor4
    );

    /**
     * Address: 0x007D17C0 (FUN_007D17C0)
     * Mangled: ?Render@Cartographic@Moho@@QAEXV?$shared_ptr@VRenderTarget@gal@gpg@@@boost@@
     *          V?$shared_ptr@VDepthStencilTarget@gal@gpg@@@4@HHM
     *          V?$shared_ptr@VCD3DPrimBatcher@Moho@@@4@PAVIRenderWorldView@2@_N@Z
     *
     * IDA signature:
     * void __usercall Moho::Cartographic::Render(
     *   Moho::Cartographic *this, unsigned int headIndex, int gameTick, float deltaFrame,
     *   Moho::IRenderWorldView *worldView, Moho::RangeRenderer *rangeRenderer,
     *   Moho::VisionRenderer *visionRenderer, Moho::BoundaryRenderer *boundaryRenderer,
     *   boost::shared_ptr<gpg::gal::RenderTarget> colorTarget,
     *   boost::shared_ptr<gpg::gal::DepthStencilTarget> depthStencilTarget,
     *   boost::shared_ptr<Moho::CD3DPrimBatcher> primBatcher);
     *
     * What it does:
     * Draws one complete cartographic ("strategic") view for one device head:
     * forces strategic icons on for the duration, clears the caller's colour and
     * depth pair, sets the world view's viewport rect, paints the terrain
     * hypsometric/topographic pass into it, overlays the range rings, the
     * fog-of-war and the playable boundary while a world session exists, then
     * composites that offscreen frame back onto the head and finally draws the
     * meshes, particles, decal batches and UI on top before restoring the head's
     * full viewport and the strategic-icon toggle.
     *
     * ABI note. The mangled symbol above spells an eight-argument list, but the
     * shipped body is `retn 38h` (0x007D1CCD) - 0x38 = 56 bytes of stack
     * arguments - and the sole call site (`WRenViewport::RenderCartographic`,
     * 0x007F8DCD..0x007F8DF6) pushes exactly the eleven lanes this declaration
     * carries, in this order, with `this` as the first stack argument:
     *
     *   +0x04 `this`              (0x007D19E6 feeds it to RenderTerrainStage0)
     *   +0x08 headIndex           (0x007D1807 -> DeviceContext::GetHead)
     *   +0x0C gameTick            (0x007D1B92 -> world-view render callback)
     *   +0x10 deltaFrame          (0x007D1A12 `fld`, a float)
     *   +0x14 worldView           (0x007D183F/0x007D1857 -> GetCamera/GetCameraView)
     *   +0x18 rangeRenderer       (0x007D19FF; caller passes `&viewport+0x37C`)
     *   +0x1C visionRenderer      (0x007D1A3F; caller gates it on `ren_FogOfWar`)
     *   +0x20 boundaryRenderer    (0x007D1A68; gated on `ren_PlayableBoundary`)
     *   +0x24 colorTarget         (0x007D19A6 -> OutputContext surface lane)
     *   +0x2C depthStencilTarget  (0x007D19A6 -> OutputContext second lane)
     *   +0x34 primBatcher         (0x007D1B4D -> UI pass / REN_DebugStuff)
     *
     * Whole-program optimization moved `this` onto the stack, hoisted the three
     * renderer lanes out of the caller and pushed the three by-value
     * `boost::shared_ptr` arguments to the tail. This declaration follows the
     * shipped layout because the shipped body reads lanes the mangled list does
     * not contain. The two target handles are typed as the concrete D3D9
     * implementations the runtime actually carries - `D3D9Interfaces.cpp` models
     * the same two `OutputContext` lanes as `boost::shared_ptr<RenderTargetD3D9>`
     * and `boost::shared_ptr<DepthStencilTargetD3D9>` - because the in-repo GAL
     * headers do not declare `RenderTargetD3D9 : RenderTarget`.
     */
    void Render(
      unsigned int headIndex,
      std::int32_t gameTick,
      float deltaFrame,
      IRenderWorldView* worldView,
      RangeRenderer* rangeRenderer,
      VisionRenderer* visionRenderer,
      BoundaryRenderer* boundaryRenderer,
      boost::shared_ptr<gpg::gal::RenderTargetD3D9> colorTarget,
      boost::shared_ptr<gpg::gal::DepthStencilTargetD3D9> depthStencilTarget,
      boost::shared_ptr<CD3DPrimBatcher> primBatcher
    );

  private:
    /**
     * Address: 0x007D2E40 (FUN_007D2E40, ?RenderParticles@Cartographic@Moho@@AAEXHMABVGeomCamera3@2@@Z)
     * Mangled: ?RenderParticles@Cartographic@Moho@@AAEXHMABVGeomCamera3@2@@Z
     *
     * What it does:
     * Forwards one cartographic particle-render pass into the global world
     * particle renderer with fixed water/suppress flags.
     */
    void RenderParticles(std::int32_t tick, float frameAlpha, const GeomCamera3& camera);

    /**
     * Address: 0x007D1E90 (FUN_007D1E90)
     * Mangled: ?InitializeFrame@Cartographic@Moho@@AAEXXZ
     *
     * IDA signature:
     * void __usercall Moho::Cartographic::InitializeFrame(Moho::Cartographic *this@<esi>);
     *
     * What it does:
     * Creates the cartographic frame vertex declaration, the four-vertex
     * frame vertex buffer and the shared six-index quad index buffer, then
     * uploads the two-triangle index list into the latter.
     */
    void InitializeFrame();

    /**
     * Address: 0x007D20F0 (FUN_007D20F0)
     * Mangled: ?InitializeTerrain@Cartographic@Moho@@AAEXPAVIWldTerrainRes@2@HIIIII@Z
     *
     * IDA signature:
     * int __thiscall Moho::Cartographic::InitializeTerrain(
     *   int this, int a2, int a3, int a4, int a5, int a6, int a7, int a8);
     *
     * What it does:
     * Derives the cartographic shader coefficient lanes and the elevation
     * band from the active terrain heightfield's tier-0 bounds and the map's
     * water configuration, stores the hypsometric palette, builds the three
     * terrain lookup textures, and uploads the terrain ground quad.
     */
    void InitializeTerrain(
      IWldTerrainRes* terrain,
      std::int32_t topographicSamples,
      std::uint32_t hypsometricColor0,
      std::uint32_t hypsometricColor1,
      std::uint32_t hypsometricColor2,
      std::uint32_t hypsometricColor3,
      std::uint32_t hypsometricColor4
    );

    /**
     * Address: 0x007D24F0 (FUN_007D24F0)
     * Mangled: ?InitializeTerrainTextures@Cartographic@Moho@@AAEXABVCHeightField@2@HHH@Z
     *
     * IDA signature:
     * void __thiscall Moho::Cartographic::InitializeTerrainTextures(
     *   Moho::Cartographic *this, const struct Moho::CHeightField *a2, int a3, int a4, int a5);
     *
     * What it does:
     * Builds the three cartographic lookup textures: the half-float
     * elevation map sampled off the heightfield at grid resolution, the
     * 256x1 hypsometric colour ramp, and the 256x1 topographic contour
     * ramp quantized into `topographicSamples` elevation bands.
     */
    void InitializeTerrainTextures(
      const CHeightField& heightField,
      std::int32_t gridWidth,
      std::int32_t gridHeight,
      std::int32_t topographicSamples
    );

    /**
     * Address: 0x007D2EA0 (FUN_007D2EA0)
     * Mangled: ?RenderTerrainStage0@Cartographic@Moho@@AAEXABVGeomCamera3@2@_N@Z
     *
     * IDA signature:
     * void __usercall Moho::Cartographic::RenderTerrainStage0(
     *   Moho::Cartographic *this@<edx>, const Moho::GeomCamera3 *camera@<ecx>, bool mirrored);
     *
     * What it does:
     * Paints the cartographic terrain into the currently bound offscreen frame:
     * clears it to opaque black, binds the camera matrices plus the eight
     * cartographic coefficient / elevation lanes and the three lookup textures
     * into the `"Terrain_Stage0"` technique, then draws the terrain ground quad
     * once per technique pass.
     *
     * The shipped body ends in a bare `retn` (0x007D3578): link-time code
     * generation put `this` in `edx` and the camera in `ecx`, and dropped the
     * declared `bool` entirely - the sole call site (0x007D19E6..0x007D19EF)
     * pushes nothing at all. The declared arity is kept for symbol fidelity and
     * the parameter stays unread, exactly as in the shipped image.
     */
    void RenderTerrainStage0(const GeomCamera3& camera, bool mirrored);

    /**
     * Address: 0x007D3580 (FUN_007D3580)
     * Mangled: ?RenderTerrainStage1@Cartographic@Moho@@AAEXH
     *          V?$shared_ptr@VRenderTarget@gal@gpg@@@boost@@@Z
     *
     * IDA signature:
     * void __usercall Moho::Cartographic::RenderTerrainStage1(
     *   Moho::Cartographic *this, int headIndex,
     *   boost::shared_ptr<gpg::gal::RenderTarget> colorTarget);
     *
     * What it does:
     * Composites the offscreen cartographic frame back onto the head. Clears the
     * head to opaque black, uploads a screen-space quad covering the head's
     * render target (half-texel corrected, `z = rhw = 1`), then draws it once per
     * pass of the `"Terrain_Stage1"` technique with the frame size and the
     * offscreen colour target bound as `frameWidth` / `frameHeight` /
     * `frameTexture`.
     *
     * The shipped body is `retn 10h` (0x007D3AB7): link-time code generation
     * moved `this` onto the stack ahead of the two declared arguments.
     */
    void RenderTerrainStage1(std::int32_t headIndex, boost::shared_ptr<gpg::gal::RenderTargetD3D9> colorTarget);

    /**
     * Address: 0x007D2CB0 (FUN_007D2CB0)
     * Mangled: ?RenderMeshes@Cartographic@Moho@@AAEXHMABVGeomCamera3@2@@Z
     *
     * IDA signature:
     * void __usercall Moho::Cartographic::RenderMeshes(
     *   Moho::Cartographic *this@<edi>, int gameTick, float deltaFrame,
     *   const Moho::GeomCamera3 *camera);
     *
     * What it does:
     * Binds this view's hypsometric ramp into the shared `"mesh"` effect and
     * makes that effect current, then rebuilds the global mesh batch map for the
     * frame and draws it through the mesh renderer's cartographic pass, fed with
     * the water-surface elevation and the tier elevation band.
     *
     * `retn 0Ch` (0x007D2E31): the three declared arguments stay on the stack;
     * link-time code generation only moved `this` into `edi`.
     */
    void RenderMeshes(std::int32_t gameTick, float deltaFrame, const GeomCamera3& camera);

  public:
    // Runtime-initialized flag. Cleared by the ctor and Shutdown, set by
    // Initialize once terrain textures/buffers exist.
    bool mInitialized;                                                          // +0x04
    std::uint8_t mPadding05_07[0x03];                                           // +0x05

    // Reciprocal grid dimensions used by the cartographic shader, bound to the
    // "gridSizeCoeff" effect variable. InitializeTerrain writes
    // {1/(w>>1), 1/(h>>1), 0, 1}.
    float mGridSizeCoeff[4];                                                    // +0x08

    // Reciprocal terrain dimensions bound to the "terrainSizeCoeff" effect
    // variable. InitializeTerrain writes {(w>>1)/(width-1), (h>>1)/(height-1), 0, 1}.
    float mTerrainSizeCoeff[4];                                                 // +0x18

    // Height-word-to-world scale for elevation sampling ("terrainHeightScale").
    // InitializeTerrain writes flt_E4F6DC, byte-verified as 0x3C000000 = 1/128 =
    // 0.0078125f in the shipped image - the same constant the cartographic
    // elevation kernel multiplies raw uint16 height words by.
    float mTerrainHeightScale;                                                  // +0x28

    // Elevation bounds of the tier box ("elevMaximum"/"elevMinimum"). Passed to
    // MeshRenderer::RenderCartographic (max = 3rd arg, min = 2nd arg).
    float mElevMaximum;                                                         // +0x2C
    float mElevMinimum;                                                         // +0x30

    // Whether the heightfield supplies explicit surface/water elevation bounds
    // (heightfield+0x1534). Gates the elevation-ramp texture build.
    bool mHasElevationBounds;                                                   // +0x34
    std::uint8_t mPadding35_37[0x03];                                           // +0x35

    // Surface/water/default elevations. Surface is the RenderCartographic 1st
    // arg; Shutdown zeros all three.
    float mSurfaceElevation;                                                    // +0x38
    float mWaterElevation;                                                      // +0x3C
    float mDefaultElevation;                                                    // +0x40

    // Hypsometric tint palette (ARGB), initialized to opaque black (0xFF000000)
    // by the ctor and filled from GetHypsometricColor(0..4) in InitializeTerrain.
    std::int32_t mHypsometricColors[5];                                         // +0x44

    // Not written by the ctor (constructor skips this lane); kept as a named
    // placeholder to preserve layout.
    std::int32_t mUnknownLane58;                                               // +0x58

    // Intrusive decal-batch list sentinel + node count.
    CartographicListNode* mListSentinel;                                        // +0x5C
    std::int32_t mBatchCount;                                                   // +0x60

    // GPU resource handles, all lazily created by InitializeTerrain /
    // InitializeTerrainTextures and released by Shutdown / the dtor.
    boost::shared_ptr<gpg::gal::TextureD3D9> mTopographicTexture;               // +0x64
    boost::shared_ptr<gpg::gal::TextureD3D9> mHypsometricTexture;               // +0x6C
    boost::shared_ptr<gpg::gal::TextureD3D9> mElevTexture;                      // +0x74
    boost::shared_ptr<gpg::gal::VertexFormatD3D9> mTerrainVertexFormat;         // +0x7C
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mTerrainVertexBuffer;         // +0x84
    boost::shared_ptr<gpg::gal::VertexFormatD3D9> mFrameVertexFormat;           // +0x8C
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mFrameVertexBuffer;           // +0x94
    boost::shared_ptr<gpg::gal::IndexBufferD3D9> mQuadIndexBuffer;              // +0x9C
  };

  static_assert(offsetof(Cartographic, mInitialized) == 0x04, "Cartographic::mInitialized offset must be 0x04");
  static_assert(offsetof(Cartographic, mGridSizeCoeff) == 0x08, "Cartographic::mGridSizeCoeff offset must be 0x08");
  static_assert(offsetof(Cartographic, mTerrainSizeCoeff) == 0x18, "Cartographic::mTerrainSizeCoeff offset must be 0x18");
  static_assert(offsetof(Cartographic, mTerrainHeightScale) == 0x28, "Cartographic::mTerrainHeightScale offset must be 0x28");
  static_assert(offsetof(Cartographic, mElevMaximum) == 0x2C, "Cartographic::mElevMaximum offset must be 0x2C");
  static_assert(offsetof(Cartographic, mElevMinimum) == 0x30, "Cartographic::mElevMinimum offset must be 0x30");
  static_assert(offsetof(Cartographic, mHasElevationBounds) == 0x34, "Cartographic::mHasElevationBounds offset must be 0x34");
  static_assert(offsetof(Cartographic, mSurfaceElevation) == 0x38, "Cartographic::mSurfaceElevation offset must be 0x38");
  static_assert(offsetof(Cartographic, mWaterElevation) == 0x3C, "Cartographic::mWaterElevation offset must be 0x3C");
  static_assert(offsetof(Cartographic, mDefaultElevation) == 0x40, "Cartographic::mDefaultElevation offset must be 0x40");
  static_assert(offsetof(Cartographic, mHypsometricColors) == 0x44, "Cartographic::mHypsometricColors offset must be 0x44");
  static_assert(offsetof(Cartographic, mUnknownLane58) == 0x58, "Cartographic::mUnknownLane58 offset must be 0x58");
  static_assert(offsetof(Cartographic, mListSentinel) == 0x5C, "Cartographic::mListSentinel offset must be 0x5C");
  static_assert(offsetof(Cartographic, mBatchCount) == 0x60, "Cartographic::mBatchCount offset must be 0x60");
  static_assert(offsetof(Cartographic, mTopographicTexture) == 0x64, "Cartographic::mTopographicTexture offset must be 0x64");
  static_assert(offsetof(Cartographic, mHypsometricTexture) == 0x6C, "Cartographic::mHypsometricTexture offset must be 0x6C");
  static_assert(offsetof(Cartographic, mElevTexture) == 0x74, "Cartographic::mElevTexture offset must be 0x74");
  static_assert(offsetof(Cartographic, mTerrainVertexFormat) == 0x7C, "Cartographic::mTerrainVertexFormat offset must be 0x7C");
  static_assert(offsetof(Cartographic, mTerrainVertexBuffer) == 0x84, "Cartographic::mTerrainVertexBuffer offset must be 0x84");
  static_assert(offsetof(Cartographic, mFrameVertexFormat) == 0x8C, "Cartographic::mFrameVertexFormat offset must be 0x8C");
  static_assert(offsetof(Cartographic, mFrameVertexBuffer) == 0x94, "Cartographic::mFrameVertexBuffer offset must be 0x94");
  static_assert(offsetof(Cartographic, mQuadIndexBuffer) == 0x9C, "Cartographic::mQuadIndexBuffer offset must be 0x9C");
  static_assert(sizeof(Cartographic) == 0xA4, "Cartographic size must be 0xA4");

  /**
   * Address: 0x007D1710 (FUN_007D1710)
   *
   * What it does:
   * Copy-inserts one decal-batch node after the cartographic list sentinel and
   * increments the owning batch count with VC8 list-overflow protection.
   */
  std::int32_t InsertCartographicDecalBatchCopy(const CartographicDecalBatch& sourceBatch, Cartographic& owner);

  /**
   * Address: 0x007D1740 (FUN_007D1740)
   *
   * What it does:
   * Unlinks and destroys one decal-batch node (when not sentinel), decrements
   * count, and returns the successor node.
   */
  CartographicListNode* EraseCartographicDecalBatchNode(Cartographic& owner, CartographicListNode* node);
} // namespace moho
