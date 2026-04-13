#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/String.h"
#include "Wm3Vector2.h"

namespace moho
{
  class CWldTerrainRes;
  class RD3DTextureResource;

  /**
   * Per-layer terrain texture state.
   *
   * Binary evidence:
   * - constructor lane at 0x0089E8B0
   * - destructor lane at 0x0089F0A0
   * - size/update lane at 0x0089F4E0
   */
  struct CStratumMaterial
  {
    CStratumMaterial() = default;

    msvc8::string mPath{};                               // +0x00
    float mScaleX{1.0f};                                 // +0x1C
    float mScaleY{1.0f};                                 // +0x20
    float v3{0.0f};                                      // +0x24
    float v4{1.0f};                                      // +0x28
    boost::SharedPtrRaw<RD3DTextureResource> mTextureSheet{}; // +0x2C
    float mSize{1.0f};                                   // +0x34

    /**
     * Address: 0x0089F0A0 (FUN_0089F0A0, Moho::CStratumMaterial::~CStratumMaterial)
     *
     * What it does:
     * Releases one retained texture-sheet handle and destroys the owned path
     * string buffer if heap-backed.
     */
    ~CStratumMaterial();

    /**
     * Address: 0x008A7B30 (FUN_008A7B30, Moho::CStratumMaterial::CStratumMaterial)
     *
     * What it does:
     * Copies one texture-layer descriptor, retaining the source texture-sheet
     * control block and deep-copying the path string.
     */
    CStratumMaterial(const CStratumMaterial& source);

    /**
     * Address: 0x0089F4E0 (FUN_0089F4E0, Moho::CStratumMaterial::SetSize)
     *
     * What it does:
     * Loads the texture sheet for one layer when needed, then scales the layer
     * against the provided `(width,height)` bounds.
     */
    static void SetSize(const Wm3::Vector2f& maxSize, CStratumMaterial& material);
  };

  static_assert(sizeof(CStratumMaterial) == 0x38, "CStratumMaterial size must be 0x38");
  static_assert(offsetof(CStratumMaterial, mPath) == 0x00, "CStratumMaterial::mPath offset must be 0x00");
  static_assert(offsetof(CStratumMaterial, mScaleX) == 0x1C, "CStratumMaterial::mScaleX offset must be 0x1C");
  static_assert(offsetof(CStratumMaterial, mTextureSheet) == 0x2C, "CStratumMaterial::mTextureSheet offset must be 0x2C");
  static_assert(offsetof(CStratumMaterial, mSize) == 0x34, "CStratumMaterial::mSize offset must be 0x34");

  /**
   * Terrain stratum material set used by CWldTerrainRes.
   */
  class StratumMaterial
  {
  public:
    /**
     * Address: 0x0089E8B0 (FUN_0089E8B0, Moho::StratumMaterial::StratumMaterial)
     *
     * What it does:
     * Initializes the default terrain shader name, weak mask handles, and all
     * twenty layer descriptors to their default sizes/paths.
     */
    StratumMaterial();

    /**
     * Address: 0x008A7890 (FUN_008A7890, Moho::StratumMaterial::StratumMaterial)
     *
     * What it does:
     * Copies the terrain shader name, mask handles, and all twenty layer
     * descriptors while retaining the shared texture control blocks.
     */
    StratumMaterial(const StratumMaterial& source);

    /**
     * Address: 0x008A74F0 (FUN_008A74F0, Moho::StratumMaterial::~StratumMaterial)
     *
     * What it does:
     * Releases all twenty layer descriptors, drops the two shared mask handles,
     * and clears the shader name buffer.
     */
    ~StratumMaterial();

    /**
     * Address: 0x0089F130 (FUN_0089F130, Moho::StratumMaterial::SetSizeTo)
     *
     * What it does:
     * Applies world-map dimensions to every configured terrain stratum layer.
     */
    void SetSizeTo(CWldTerrainRes* terrainRes);

  public:
    std::uint8_t byte0{0};                       // +0x00
    std::uint8_t byte1{0};                       // +0x01
    std::uint8_t pad02_03[2]{};                  // +0x02
    msvc8::string mShaderName{};                 // +0x04
    std::uint32_t v1{0};                         // +0x20
    std::uint32_t v2{0};                         // +0x24
    boost::SharedPtrRaw<RD3DTextureResource> mStratumMask0{}; // +0x28
    boost::SharedPtrRaw<RD3DTextureResource> mStratumMask1{}; // +0x30
    CStratumMaterial mLowerAlbedoTexture{};      // +0x38
    CStratumMaterial mStratum0AlbedoTexture{};   // +0x70
    CStratumMaterial mStratum1AlbedoTexture{};   // +0xA8
    CStratumMaterial mStratum2AlbedoTexture{};   // +0xE0
    CStratumMaterial mStratum3AlbedoTexture{};   // +0x118
    CStratumMaterial mStratum4AlbedoTexture{};   // +0x150
    CStratumMaterial mStratum5AlbedoTexture{};   // +0x188
    CStratumMaterial mStratum6AlbedoTexture{};   // +0x1C0
    CStratumMaterial mStratum7AlbedoTexture{};   // +0x1F8
    CStratumMaterial mUpperAlbedoTexture{};      // +0x230
    CStratumMaterial mLowerNormalTexture{};      // +0x268
    CStratumMaterial mStratum0NormalTexture{};   // +0x2A0
    CStratumMaterial mStratum1NormalTexture{};   // +0x2D8
    CStratumMaterial mStratum2NormalTexture{};   // +0x310
    CStratumMaterial mStratum3NormalTexture{};   // +0x348
    CStratumMaterial mStratum4NormalTexture{};   // +0x380
    CStratumMaterial mStratum5NormalTexture{};   // +0x3B8
    CStratumMaterial mStratum6NormalTexture{};   // +0x3F0
    CStratumMaterial mStratum7NormalTexture{};   // +0x428
    CStratumMaterial mUpperNormalTexture{};      // +0x460
  };

  static_assert(sizeof(StratumMaterial) == 0x498, "StratumMaterial size must be 0x498");
  static_assert(offsetof(StratumMaterial, mShaderName) == 0x04, "StratumMaterial::mShaderName offset must be 0x04");
  static_assert(offsetof(StratumMaterial, mStratumMask0) == 0x28, "StratumMaterial::mStratumMask0 offset must be 0x28");
  static_assert(offsetof(StratumMaterial, mStratumMask1) == 0x30, "StratumMaterial::mStratumMask1 offset must be 0x30");
  static_assert(
    offsetof(StratumMaterial, mLowerAlbedoTexture) == 0x38, "StratumMaterial::mLowerAlbedoTexture offset must be 0x38"
  );
  static_assert(
    offsetof(StratumMaterial, mUpperNormalTexture) == 0x460, "StratumMaterial::mUpperNormalTexture offset must be 0x460"
  );
} // namespace moho
