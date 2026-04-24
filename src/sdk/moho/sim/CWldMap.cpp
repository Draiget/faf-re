#include "CWldMap.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "gpg/core/containers/BitArray2D.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/BinaryWriter.h"
#include "gpg/core/streams/Stream.h"
#include "gpg/gal/Error.hpp"
#include "lua/LuaObject.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Tree.h"
#include "legacy/containers/Vector.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/math/Vector4f.h"
#include "moho/console/CVarAccess.h"
#include "moho/render/Cartographic.h"
#include "moho/render/RCamManager.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/SkyDome.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/render/textures/DXTCodec.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/UserArmy.h"
#include "moho/sim/WldSessionInfo.h"
#include "moho/terrain/StratumMaterial.h"
#include "moho/terrain/water/CWaterShaderProperties.h"
#include "moho/terrain/water/WaveSystem.h"

namespace
{
  constexpr float kQuaternionNormalizeEpsilon = 0.000001f;

  struct Stride76RangeRuntimeView
  {
    std::uint32_t lane00 = 0;
    const std::uint8_t* begin = nullptr; // +0x04
    const std::uint8_t* end = nullptr;   // +0x08
  };
  static_assert(
    offsetof(Stride76RangeRuntimeView, begin) == 0x04,
    "Stride76RangeRuntimeView::begin offset must be 0x04"
  );
  static_assert(
    offsetof(Stride76RangeRuntimeView, end) == 0x08,
    "Stride76RangeRuntimeView::end offset must be 0x08"
  );

  /**
   * Address: 0x00889FE0 (FUN_00889FE0)
   *
   * What it does:
   * Returns the number of 76-byte records currently stored in one raw
   * begin/end range lane.
   */
  [[maybe_unused]] std::int32_t CountStride76RecordsRuntime(
    const Stride76RangeRuntimeView* const range
  ) noexcept
  {
    const std::uint8_t* const begin = range != nullptr ? range->begin : nullptr;
    if (begin == nullptr) {
      return 0;
    }

    const std::uint8_t* const end = range->end;
    return static_cast<std::int32_t>((end - begin) / 76);
  }

  struct QuaternionLanes
  {
    float w;
    float x;
    float y;
    float z;
  };

  struct ListIteratorProxyRuntimeView
  {
    void* mFirstIterator; // +0x00
  };
  static_assert(sizeof(ListIteratorProxyRuntimeView) == 0x04, "ListIteratorProxyRuntimeView size must be 0x04");

  struct TerrainDirtyRectNodeRuntimeView
  {
    TerrainDirtyRectNodeRuntimeView* mNext; // +0x00
    TerrainDirtyRectNodeRuntimeView* mPrev; // +0x04
    gpg::Rect2i mValue;                     // +0x08
  };
  static_assert(sizeof(TerrainDirtyRectNodeRuntimeView) == 0x18, "TerrainDirtyRectNodeRuntimeView size must be 0x18");

  struct TerrainDirtyRectListRuntimeView
  {
    ListIteratorProxyRuntimeView* mIteratorProxy; // +0x00
    TerrainDirtyRectNodeRuntimeView* mHead;       // +0x04
    std::uint32_t mSize;                          // +0x08
  };
  static_assert(sizeof(TerrainDirtyRectListRuntimeView) == 0x0C, "TerrainDirtyRectListRuntimeView size must be 0x0C");

  using TerrainEditWordBufferRuntimeView = msvc8::detail::dword_lane_vector_view;
  static_assert(sizeof(TerrainEditWordBufferRuntimeView) == 0x10, "TerrainEditWordBufferRuntimeView size must be 0x10");

  struct TerrainNormalEncodeBlock
  {
    std::uint8_t mNormalX[16]{};
    std::uint8_t mNormalZ[16]{};
  };
  static_assert(sizeof(TerrainNormalEncodeBlock) == 0x20, "TerrainNormalEncodeBlock size must be 0x20");

  class IDecalManagerRuntimeView
  {
  public:
    virtual ~IDecalManagerRuntimeView() = default;
    virtual void Func1() = 0;
    virtual void Load(gpg::BinaryReader& reader, std::uint32_t version) = 0;
    virtual void Save(gpg::BinaryWriter& writer) = 0;
  };

  struct TerrainEnvironmentLookupNodeRuntimeView : msvc8::Tree<TerrainEnvironmentLookupNodeRuntimeView>
  {
    TerrainEnvironmentLookupNodeRuntimeView()
      : mKey()
      , mValue(msvc8::string(), boost::shared_ptr<moho::RD3DTextureResource>{})
      , mColor(1)
      , mIsNil(1)
      , mPad4E_4F{0, 0}
    {
      left = this;
      parent = this;
      right = this;
    }

    msvc8::string mKey;                        // +0x0C
    moho::TerrainEnvironmentLookupEntry mValue; // +0x28
    std::uint8_t mColor;                       // +0x4C
    std::uint8_t mIsNil;                       // +0x4D
    std::uint8_t mPad4E_4F[0x02]{};            // +0x4E
  };
  static_assert(
    offsetof(TerrainEnvironmentLookupNodeRuntimeView, mKey) == 0x0C,
    "TerrainEnvironmentLookupNodeRuntimeView::mKey offset must be 0x0C"
  );
  static_assert(
    offsetof(TerrainEnvironmentLookupNodeRuntimeView, mValue) == 0x28,
    "TerrainEnvironmentLookupNodeRuntimeView::mValue offset must be 0x28"
  );
  static_assert(
    offsetof(TerrainEnvironmentLookupNodeRuntimeView, mColor) == 0x4C,
    "TerrainEnvironmentLookupNodeRuntimeView::mColor offset must be 0x4C"
  );
  static_assert(
    offsetof(TerrainEnvironmentLookupNodeRuntimeView, mIsNil) == 0x4D,
    "TerrainEnvironmentLookupNodeRuntimeView::mIsNil offset must be 0x4D"
  );
  static_assert(sizeof(TerrainEnvironmentLookupNodeRuntimeView) == 0x50, "TerrainEnvironmentLookupNodeRuntimeView size must be 0x50");

  struct TerrainEnvironmentLookupMapRuntimeView
  {
    std::uint32_t mUnknown00;                            // +0x00
    TerrainEnvironmentLookupNodeRuntimeView* mHead;      // +0x04
    std::uint32_t mSize;                                 // +0x08
  };
  static_assert(sizeof(TerrainEnvironmentLookupMapRuntimeView) == 0x0C, "TerrainEnvironmentLookupMapRuntimeView size must be 0x0C");
  static_assert(
    offsetof(TerrainEnvironmentLookupMapRuntimeView, mHead) == 0x04,
    "TerrainEnvironmentLookupMapRuntimeView::mHead offset must be 0x04"
  );
  static_assert(
    offsetof(TerrainEnvironmentLookupMapRuntimeView, mSize) == 0x08,
    "TerrainEnvironmentLookupMapRuntimeView::mSize offset must be 0x08"
  );

  struct TerrainVisualResourceRuntimeView
  {
    std::uint8_t mUnknown0000_095B[0x95C]{};
    msvc8::string mBackgroundFile;                              // +0x95C
    moho::ID3DDeviceResources::TextureResourceHandle mBackgroundTexture; // +0x978
    msvc8::string mSkycubeFile;                                 // +0x980
    moho::ID3DDeviceResources::TextureResourceHandle mSkycubeTexture;     // +0x99C
    TerrainEnvironmentLookupMapRuntimeView mEnvLookup;          // +0x9A4
    TerrainEditWordBufferRuntimeView mEditWordBuffer;           // +0x9B0
    boost::shared_ptr<moho::CD3DDynamicTextureSheet> mWaterMapTexture; // +0x9C0
    std::uint8_t* mWaterFoam;                                   // +0x9C8
    std::uint8_t* mWaterFlatness;                               // +0x9CC
    std::uint8_t* mWaterDepthBias;                              // +0x9D0
    gpg::BitArray2D* mDebugDirtyTerrain;                        // +0x9D4
    TerrainDirtyRectListRuntimeView mDebugDirtyRects;           // +0x9D8
    std::uint8_t mUnknown09E4_0C2F[0x24C]{};
    IDecalManagerRuntimeView* mDecalManager;                    // +0xC30
  };

  static_assert(
    offsetof(TerrainVisualResourceRuntimeView, mBackgroundFile) == 0x95C,
    "TerrainVisualResourceRuntimeView::mBackgroundFile offset must be 0x95C"
  );
  static_assert(
    offsetof(TerrainVisualResourceRuntimeView, mBackgroundTexture) == 0x978,
    "TerrainVisualResourceRuntimeView::mBackgroundTexture offset must be 0x978"
  );
  static_assert(
    offsetof(TerrainVisualResourceRuntimeView, mSkycubeFile) == 0x980,
    "TerrainVisualResourceRuntimeView::mSkycubeFile offset must be 0x980"
  );
  static_assert(
    offsetof(TerrainVisualResourceRuntimeView, mSkycubeTexture) == 0x99C,
    "TerrainVisualResourceRuntimeView::mSkycubeTexture offset must be 0x99C"
  );
  static_assert(
    offsetof(TerrainVisualResourceRuntimeView, mEnvLookup) == 0x9A4,
    "TerrainVisualResourceRuntimeView::mEnvLookup offset must be 0x9A4"
  );
  static_assert(
    offsetof(TerrainVisualResourceRuntimeView, mEditWordBuffer) == 0x9B0,
    "TerrainVisualResourceRuntimeView::mEditWordBuffer offset must be 0x9B0"
  );
  static_assert(
    offsetof(TerrainVisualResourceRuntimeView, mEditWordBuffer) + offsetof(TerrainEditWordBufferRuntimeView, begin) == 0x9B4,
    "TerrainVisualResourceRuntimeView::mEditWordBuffer.begin offset must be 0x9B4"
  );
  static_assert(
    offsetof(TerrainVisualResourceRuntimeView, mWaterMapTexture) == 0x9C0,
    "TerrainVisualResourceRuntimeView::mWaterMapTexture offset must be 0x9C0"
  );
  static_assert(
    offsetof(TerrainVisualResourceRuntimeView, mWaterFoam) == 0x9C8,
    "TerrainVisualResourceRuntimeView::mWaterFoam offset must be 0x9C8"
  );
  static_assert(
    offsetof(TerrainVisualResourceRuntimeView, mWaterFlatness) == 0x9CC,
    "TerrainVisualResourceRuntimeView::mWaterFlatness offset must be 0x9CC"
  );
  static_assert(
    offsetof(TerrainVisualResourceRuntimeView, mWaterDepthBias) == 0x9D0,
    "TerrainVisualResourceRuntimeView::mWaterDepthBias offset must be 0x9D0"
  );
  static_assert(
    offsetof(TerrainVisualResourceRuntimeView, mDebugDirtyTerrain) == 0x9D4,
    "TerrainVisualResourceRuntimeView::mDebugDirtyTerrain offset must be 0x9D4"
  );
  static_assert(
    offsetof(TerrainVisualResourceRuntimeView, mDebugDirtyRects) == 0x9D8,
    "TerrainVisualResourceRuntimeView::mDebugDirtyRects offset must be 0x9D8"
  );
  static_assert(
    offsetof(TerrainVisualResourceRuntimeView, mDecalManager) == 0xC30,
    "TerrainVisualResourceRuntimeView::mDecalManager offset must be 0xC30"
  );

  struct TerrainNormalMapHandleArray
  {
    boost::shared_ptr<moho::CD3DDynamicTextureSheet>* mBegin;       // +0x00
    boost::shared_ptr<moho::CD3DDynamicTextureSheet>* mEnd;         // +0x04
    boost::shared_ptr<moho::CD3DDynamicTextureSheet>* mCapacityEnd; // +0x08
  };
  static_assert(sizeof(TerrainNormalMapHandleArray) == 0x0C, "TerrainNormalMapHandleArray size must be 0x0C");

  struct TerrainNormalMapRuntimeView
  {
    TerrainNormalMapRuntimeView() = default;
    ~TerrainNormalMapRuntimeView() {}

    void* mVftable;               // +0x00
    moho::STIMap* mMap;           // +0x04

    union
    {
      struct
      {
        std::uint8_t mUnknown0008_04D3[0x4CC];      // +0x08
        boost::shared_ptr<moho::CD3DDynamicTextureSheet> mStratumMask0; // +0x4D4
        boost::shared_ptr<moho::CD3DDynamicTextureSheet> mStratumMask1; // +0x4DC
        std::uint8_t mUnknown04E4_0947[0x464];      // +0x4E4
      };
      struct
      {
        std::uint8_t mUnknown0008_04AB[0x4A4];      // +0x08
        moho::StratumMaterial mStrata;                // +0x4AC
      };
    };

    TerrainNormalMapHandleArray mNormalMap; // +0x948
    std::int32_t mNormalMapWidth;           // +0x954
    std::int32_t mNormalMapHeight;          // +0x958
  };
  static_assert(
    offsetof(TerrainNormalMapRuntimeView, mMap) == 0x04,
    "TerrainNormalMapRuntimeView::mMap offset must be 0x04"
  );
  static_assert(
    offsetof(TerrainNormalMapRuntimeView, mStratumMask0) == 0x4D4,
    "TerrainNormalMapRuntimeView::mStratumMask0 offset must be 0x4D4"
  );
  static_assert(
    offsetof(TerrainNormalMapRuntimeView, mStratumMask1) == 0x4DC,
    "TerrainNormalMapRuntimeView::mStratumMask1 offset must be 0x4DC"
  );
  static_assert(
    offsetof(TerrainNormalMapRuntimeView, mStrata) == 0x4AC,
    "TerrainNormalMapRuntimeView::mStrata offset must be 0x4AC"
  );
  static_assert(
    offsetof(TerrainNormalMapRuntimeView, mNormalMap) == 0x948,
    "TerrainNormalMapRuntimeView::mNormalMap offset must be 0x948"
  );
  static_assert(
    offsetof(TerrainNormalMapRuntimeView, mNormalMapWidth) == 0x954,
    "TerrainNormalMapRuntimeView::mNormalMapWidth offset must be 0x954"
  );
  static_assert(
    offsetof(TerrainNormalMapRuntimeView, mNormalMapHeight) == 0x958,
    "TerrainNormalMapRuntimeView::mNormalMapHeight offset must be 0x958"
  );

  [[nodiscard]] TerrainVisualResourceRuntimeView* AsTerrainVisualResourceRuntimeView(moho::IWldTerrainRes* terrainRes) noexcept
  {
    return reinterpret_cast<TerrainVisualResourceRuntimeView*>(terrainRes);
  }

  [[nodiscard]] const TerrainNormalMapRuntimeView* AsTerrainNormalMapRuntimeView(
    const moho::IWldTerrainRes* const terrainRes
  ) noexcept
  {
    return reinterpret_cast<const TerrainNormalMapRuntimeView*>(terrainRes);
  }

  [[nodiscard]] TerrainNormalMapRuntimeView* AsTerrainNormalMapRuntimeView(moho::IWldTerrainRes* terrainRes) noexcept
  {
    return reinterpret_cast<TerrainNormalMapRuntimeView*>(terrainRes);
  }

  struct TerrainRuntimeView
  {
    void* mVftable;                                                 // +0x000
    moho::STIMap* mMap;                                             // +0x004
    std::uint8_t mBool;                                             // +0x008
    std::uint8_t mEditMode;                                         // +0x009
    std::uint8_t mUnknown0A_0B[0x02]{};                             // +0x00A
    moho::Cartographic mCartographic;                               // +0x00C
    moho::SkyDome mSkyDome;                                         // +0x0B0
    std::uint8_t mUnknown2D4_2D7[0x04]{};                           // +0x2D4
    float mLightingMultiplier;                                      // +0x2D8
    Wm3::Vector3f mSunDirection;                                    // +0x2DC
    Wm3::Vector3f mSunAmbience;                                     // +0x2E8
    Wm3::Vector3f mSunColor;                                        // +0x2F4
    Wm3::Vector3f mShadowFillColor;                                 // +0x300
    moho::Vector4f mSpecularColor;                                  // +0x30C
    float mBloom;                                                   // +0x31C
    union
    {
      moho::SFogInfo mFogInfo; // +0x320
      struct
      {
        float mFogStartDistance;          // +0x320
        float mFogCutoffDistance;         // +0x324
        float mFogMinClamp;               // +0x328
        float mFogMaxClamp;               // +0x32C
        float mFogCurveExponent;          // +0x330
        std::int32_t mTopographicSamples; // +0x334
        std::uint32_t mHypsometricColor[5]; // +0x338
        float mImagerElevationOffset;     // +0x34C
      };
    };
    moho::CWaterShaderProperties mWaterShaderProperties;            // +0x350
    moho::StratumMaterial mStrata;                                  // +0x4AC
    std::uint8_t mUnknown944_947[0x04]{};                           // +0x944
    TerrainNormalMapHandleArray mNormalMap;                         // +0x948
    std::int32_t mNormalMapWidth;                                   // +0x954
    std::int32_t mNormalMapHeight;                                  // +0x958
    msvc8::string mBackgroundFile;                                  // +0x95C
    moho::ID3DDeviceResources::TextureResourceHandle mBackgroundTexture; // +0x978
    msvc8::string mSkycubeFile;                                     // +0x980
    moho::ID3DDeviceResources::TextureResourceHandle mSkycubeTexture;     // +0x99C
    TerrainEnvironmentLookupMapRuntimeView mEnvLookup;              // +0x9A4
    TerrainEditWordBufferRuntimeView mEditWordBuffer;               // +0x9B0
    moho::ID3DDeviceResources::TextureResourceHandle mWaterMapTexture;    // +0x9C0
    std::uint8_t* mWaterFoam;                                       // +0x9C8
    std::uint8_t* mWaterFlatness;                                   // +0x9CC
    std::uint8_t* mWaterDepthBias;                                  // +0x9D0
    gpg::BitArray2D* mDebugDirtyTerrain;                            // +0x9D4
    TerrainDirtyRectListRuntimeView mDebugDirtyRects;               // +0x9D8
    std::uint8_t mUnknown9E4_9E7[0x04]{};                           // +0x9E4
    moho::WaveSystem mWaveSystem;                                   // +0x9E8
    IDecalManagerRuntimeView* mDecalManager;                        // +0xC30
  };

  static_assert(offsetof(TerrainRuntimeView, mBool) == 0x008, "TerrainRuntimeView::mBool offset must be 0x008");
  static_assert(offsetof(TerrainRuntimeView, mEditMode) == 0x009, "TerrainRuntimeView::mEditMode offset must be 0x009");
  static_assert(
    offsetof(TerrainRuntimeView, mCartographic) == 0x00C, "TerrainRuntimeView::mCartographic offset must be 0x00C"
  );
  static_assert(offsetof(TerrainRuntimeView, mSkyDome) == 0x0B0, "TerrainRuntimeView::mSkyDome offset must be 0x0B0");
  static_assert(
    offsetof(TerrainRuntimeView, mLightingMultiplier) == 0x2D8,
    "TerrainRuntimeView::mLightingMultiplier offset must be 0x2D8"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mSpecularColor) == 0x30C, "TerrainRuntimeView::mSpecularColor offset must be 0x30C"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mBloom) == 0x31C, "TerrainRuntimeView::mBloom offset must be 0x31C"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mFogInfo) == 0x320, "TerrainRuntimeView::mFogInfo offset must be 0x320"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mTopographicSamples) == 0x334,
    "TerrainRuntimeView::mTopographicSamples offset must be 0x334"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mHypsometricColor) == 0x338,
    "TerrainRuntimeView::mHypsometricColor offset must be 0x338"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mImagerElevationOffset) == 0x34C,
    "TerrainRuntimeView::mImagerElevationOffset offset must be 0x34C"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mWaterShaderProperties) == 0x350,
    "TerrainRuntimeView::mWaterShaderProperties offset must be 0x350"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mStrata) == 0x4AC, "TerrainRuntimeView::mStrata offset must be 0x4AC"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mNormalMap) == 0x948, "TerrainRuntimeView::mNormalMap offset must be 0x948"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mBackgroundTexture) == 0x978,
    "TerrainRuntimeView::mBackgroundTexture offset must be 0x978"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mSkycubeTexture) == 0x99C,
    "TerrainRuntimeView::mSkycubeTexture offset must be 0x99C"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mEnvLookup) == 0x9A4,
    "TerrainRuntimeView::mEnvLookup offset must be 0x9A4"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mEditWordBuffer) == 0x9B0,
    "TerrainRuntimeView::mEditWordBuffer offset must be 0x9B0"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mEditWordBuffer) + offsetof(TerrainEditWordBufferRuntimeView, begin) == 0x9B4,
    "TerrainRuntimeView::mEditWordBuffer.begin offset must be 0x9B4"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mWaterMapTexture) == 0x9C0,
    "TerrainRuntimeView::mWaterMapTexture offset must be 0x9C0"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mWaterFoam) == 0x9C8, "TerrainRuntimeView::mWaterFoam offset must be 0x9C8"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mWaterFlatness) == 0x9CC, "TerrainRuntimeView::mWaterFlatness offset must be 0x9CC"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mDebugDirtyTerrain) == 0x9D4,
    "TerrainRuntimeView::mDebugDirtyTerrain offset must be 0x9D4"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mWaveSystem) == 0x9E8, "TerrainRuntimeView::mWaveSystem offset must be 0x9E8"
  );
  static_assert(
    offsetof(TerrainRuntimeView, mDecalManager) == 0xC30, "TerrainRuntimeView::mDecalManager offset must be 0xC30"
  );

  [[nodiscard]] const TerrainRuntimeView* AsTerrainRuntimeView(const moho::IWldTerrainRes* const terrainRes) noexcept
  {
    return reinterpret_cast<const TerrainRuntimeView*>(terrainRes);
  }

  [[nodiscard]] TerrainRuntimeView* AsTerrainRuntimeView(moho::IWldTerrainRes* const terrainRes) noexcept
  {
    return reinterpret_cast<TerrainRuntimeView*>(terrainRes);
  }

  /**
   * Address: 0x0089E790 (FUN_0089E790)
   *
   * What it does:
   * Builds one terrain tier AABB directly from heightfield min/max words and
   * per-tier world-space step sizes.
   */
  [[nodiscard]] Wm3::AxisAlignedBox3f BuildTerrainTierBoundsFromHeightfield(
    const moho::CHeightField& field,
    const std::int32_t tier,
    const std::int32_t tierX,
    const std::int32_t tierZ
  ) noexcept
  {
    const moho::SMinMax<std::uint16_t> minMax = field.GetTierBoundsUWord(tier, tierX, tierZ);
    const float minY = static_cast<float>(minMax.min) * 0.0078125f;
    const float maxY = static_cast<float>(minMax.max) * 0.0078125f;

    const std::uint32_t safeTier = tier > 0 ? static_cast<std::uint32_t>(tier) : 0u;
    const std::uint32_t tierStep = 1u << safeTier;

    const std::uint32_t widthClamp =
      field.width > 0 ? static_cast<std::uint32_t>(field.width - 1) : 0u;
    const std::uint32_t heightClamp =
      field.height > 0 ? static_cast<std::uint32_t>(field.height - 1) : 0u;

    const std::uint32_t stepXWord = tierStep < widthClamp ? tierStep : widthClamp;
    const std::uint32_t stepZWord = tierStep < heightClamp ? tierStep : heightClamp;

    const float stepX = static_cast<float>(stepXWord);
    const double stepZ = static_cast<double>(stepZWord);

    Wm3::AxisAlignedBox3f out{};
    out.Min.x = static_cast<float>(tierX) * stepX;
    out.Max.x = static_cast<float>(tierX + 1) * stepX;
    out.Min.z = static_cast<float>(static_cast<double>(tierZ) * stepZ);
    out.Max.z = static_cast<float>(stepZ * static_cast<double>(tierZ + 1));
    out.Min.y = minY;
    out.Max.y = maxY;
    return out;
  }

  [[nodiscard]] bool IsTerrainEnvironmentLookupNil(const TerrainEnvironmentLookupNodeRuntimeView* const node) noexcept
  {
    return node == nullptr || node->mIsNil != 0;
  }

  [[nodiscard]] int CompareTerrainEnvironmentLookupKeys(
    const msvc8::string& lhs, const msvc8::string& rhs
  ) noexcept
  {
    return lhs.compare(0u, lhs.size(), rhs.c_str(), rhs.size());
  }

  [[nodiscard]] int CompareTerrainEnvironmentNodeKeyWithQuery(
    const TerrainEnvironmentLookupNodeRuntimeView& node, const msvc8::string& query
  ) noexcept
  {
    return node.mKey.compare(0u, node.mKey.size(), query.c_str(), query.size());
  }

  /**
   * Address: 0x008A98F0 (FUN_008A98F0, sub_8A98F0)
   *
   * What it does:
   * Copy-constructs one environment lookup `(key,value)` pair from two
   * temporary string lanes and returns the destination pair pointer.
   */
  [[maybe_unused]] moho::TerrainEnvironmentLookupPair* ConstructTerrainEnvironmentLookupPair(
    moho::TerrainEnvironmentLookupPair* const destination,
    msvc8::string key,
    msvc8::string value
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }

    new (destination) moho::TerrainEnvironmentLookupPair(key, value);
    return destination;
  }

  /**
   * Address: 0x008A8FE0 (FUN_008A8FE0)
   *
   * What it does:
   * Returns lower-bound node for one environment key in the terrain lookup map.
   */
  [[nodiscard]] TerrainEnvironmentLookupNodeRuntimeView* FindTerrainEnvironmentLowerBound(
    TerrainEnvironmentLookupMapRuntimeView& map, const msvc8::string& key
  ) noexcept
  {
    TerrainEnvironmentLookupNodeRuntimeView* const head = map.mHead;
    if (head == nullptr) {
      return nullptr;
    }

    TerrainEnvironmentLookupNodeRuntimeView* cursor = head->parent;
    TerrainEnvironmentLookupNodeRuntimeView* candidate = head;
    while (!IsTerrainEnvironmentLookupNil(cursor)) {
      if (CompareTerrainEnvironmentNodeKeyWithQuery(*cursor, key) >= 0) {
        candidate = cursor;
        cursor = cursor->left;
      } else {
        cursor = cursor->right;
      }
    }
    return candidate;
  }

  /**
   * Address: 0x008A8150 (FUN_008A8150)
   *
   * What it does:
   * Returns exact-match node for one key, or map head when no match exists.
   */
  [[nodiscard]] TerrainEnvironmentLookupNodeRuntimeView* FindTerrainEnvironmentNodeOrHead(
    TerrainEnvironmentLookupMapRuntimeView& map, const msvc8::string& key
  ) noexcept
  {
    TerrainEnvironmentLookupNodeRuntimeView* const head = map.mHead;
    TerrainEnvironmentLookupNodeRuntimeView* const candidate = FindTerrainEnvironmentLowerBound(map, key);
    if (candidate == nullptr || candidate == head) {
      return head;
    }

    if (CompareTerrainEnvironmentLookupKeys(key, candidate->mKey) < 0) {
      return head;
    }
    return candidate;
  }

  /**
   * Address: 0x008A80F0 (FUN_008A80F0)
   *
   * What it does:
   * Removes lane-specific exact-match lookup used by erase path.
   */
  [[nodiscard]] TerrainEnvironmentLookupNodeRuntimeView* FindTerrainEnvironmentNodeOrHeadForErase(
    TerrainEnvironmentLookupMapRuntimeView& map, const msvc8::string& key
  ) noexcept
  {
    return FindTerrainEnvironmentNodeOrHead(map, key);
  }

  /**
   * Address: 0x008A87E0 (FUN_008A87E0, sub_8A87E0)
   *
   * What it does:
   * Walks left links from one candidate node until the sentinel/nil lane and
   * returns the leftmost concrete node (or head fallback).
   */
  [[nodiscard]] TerrainEnvironmentLookupNodeRuntimeView* TerrainEnvironmentTreeMin(
    TerrainEnvironmentLookupNodeRuntimeView* node, TerrainEnvironmentLookupNodeRuntimeView* head
  ) noexcept
  {
    while (!IsTerrainEnvironmentLookupNil(node) && !IsTerrainEnvironmentLookupNil(node->left)) {
      node = node->left;
    }
    return node != nullptr ? node : head;
  }

  /**
   * Address: 0x008A87C0 (FUN_008A87C0, sub_8A87C0)
   *
   * What it does:
   * Walks right links from one candidate node until the sentinel/nil lane and
   * returns the rightmost concrete node (or head fallback).
   */
  [[nodiscard]] TerrainEnvironmentLookupNodeRuntimeView* TerrainEnvironmentTreeMax(
    TerrainEnvironmentLookupNodeRuntimeView* node, TerrainEnvironmentLookupNodeRuntimeView* head
  ) noexcept
  {
    while (!IsTerrainEnvironmentLookupNil(node) && !IsTerrainEnvironmentLookupNil(node->right)) {
      node = node->right;
    }
    return node != nullptr ? node : head;
  }

  [[nodiscard]] TerrainEnvironmentLookupNodeRuntimeView* IncrementTerrainEnvironmentNode(
    TerrainEnvironmentLookupNodeRuntimeView* node, TerrainEnvironmentLookupNodeRuntimeView* head
  ) noexcept
  {
    if (node == nullptr || head == nullptr) {
      return head;
    }

    if (node == head) {
      return head->right;
    }

    if (!IsTerrainEnvironmentLookupNil(node->right)) {
      node = node->right;
      while (!IsTerrainEnvironmentLookupNil(node->left)) {
        node = node->left;
      }
      return node;
    }

    TerrainEnvironmentLookupNodeRuntimeView* parent = node->parent;
    while (node == parent->right) {
      node = parent;
      parent = parent->parent;
    }
    if (node->right != parent) {
      node = parent;
    }
    return node;
  }

  void RotateTerrainEnvironmentLeft(
    TerrainEnvironmentLookupMapRuntimeView& map, TerrainEnvironmentLookupNodeRuntimeView* const pivot
  ) noexcept
  {
    TerrainEnvironmentLookupNodeRuntimeView* const right = pivot->right;
    pivot->right = right->left;
    if (!IsTerrainEnvironmentLookupNil(right->left)) {
      right->left->parent = pivot;
    }

    right->parent = pivot->parent;
    if (pivot == map.mHead->parent) {
      map.mHead->parent = right;
    } else if (pivot == pivot->parent->left) {
      pivot->parent->left = right;
    } else {
      pivot->parent->right = right;
    }

    right->left = pivot;
    pivot->parent = right;
  }

  void RotateTerrainEnvironmentRight(
    TerrainEnvironmentLookupMapRuntimeView& map, TerrainEnvironmentLookupNodeRuntimeView* const pivot
  ) noexcept
  {
    TerrainEnvironmentLookupNodeRuntimeView* const left = pivot->left;
    pivot->left = left->right;
    if (!IsTerrainEnvironmentLookupNil(left->right)) {
      left->right->parent = pivot;
    }

    left->parent = pivot->parent;
    if (pivot == map.mHead->parent) {
      map.mHead->parent = left;
    } else if (pivot == pivot->parent->right) {
      pivot->parent->right = left;
    } else {
      pivot->parent->left = left;
    }

    left->right = pivot;
    pivot->parent = left;
  }

  void FixAfterTerrainEnvironmentInsert(
    TerrainEnvironmentLookupMapRuntimeView& map, TerrainEnvironmentLookupNodeRuntimeView* node
  ) noexcept
  {
    TerrainEnvironmentLookupNodeRuntimeView* const head = map.mHead;
    while (node->parent->mColor == 0) {
      TerrainEnvironmentLookupNodeRuntimeView* const grandparent = node->parent->parent;
      if (node->parent == grandparent->left) {
        TerrainEnvironmentLookupNodeRuntimeView* uncle = grandparent->right;
        if (!IsTerrainEnvironmentLookupNil(uncle) && uncle->mColor == 0) {
          node->parent->mColor = 1;
          uncle->mColor = 1;
          grandparent->mColor = 0;
          node = grandparent;
        } else {
          if (node == node->parent->right) {
            node = node->parent;
            RotateTerrainEnvironmentLeft(map, node);
          }
          node->parent->mColor = 1;
          grandparent->mColor = 0;
          RotateTerrainEnvironmentRight(map, grandparent);
        }
      } else {
        TerrainEnvironmentLookupNodeRuntimeView* uncle = grandparent->left;
        if (!IsTerrainEnvironmentLookupNil(uncle) && uncle->mColor == 0) {
          node->parent->mColor = 1;
          uncle->mColor = 1;
          grandparent->mColor = 0;
          node = grandparent;
        } else {
          if (node == node->parent->left) {
            node = node->parent;
            RotateTerrainEnvironmentRight(map, node);
          }
          node->parent->mColor = 1;
          grandparent->mColor = 0;
          RotateTerrainEnvironmentLeft(map, grandparent);
        }
      }

      if (node == head->parent) {
        break;
      }
    }
    head->parent->mColor = 1;
  }

  [[nodiscard]] TerrainEnvironmentLookupNodeRuntimeView* InsertTerrainEnvironmentNode(
    TerrainEnvironmentLookupMapRuntimeView& map, const msvc8::string& key
  )
  {
    TerrainEnvironmentLookupNodeRuntimeView* const head = map.mHead;
    if (head == nullptr) {
      return nullptr;
    }

    TerrainEnvironmentLookupNodeRuntimeView* parent = head;
    TerrainEnvironmentLookupNodeRuntimeView* cursor = head->parent;
    bool linkLeft = true;
    while (!IsTerrainEnvironmentLookupNil(cursor)) {
      parent = cursor;
      const int cmp = CompareTerrainEnvironmentLookupKeys(key, cursor->mKey);
      if (cmp < 0) {
        linkLeft = true;
        cursor = cursor->left;
      } else if (cmp > 0) {
        linkLeft = false;
        cursor = cursor->right;
      } else {
        return cursor;
      }
    }

    auto* const inserted = new TerrainEnvironmentLookupNodeRuntimeView{};
    inserted->left = head;
    inserted->right = head;
    inserted->parent = parent;
    inserted->mColor = 0;
    inserted->mIsNil = 0;
    inserted->mKey.assign_owned(key.view());
    inserted->mValue.mEnvironmentName.clear();
    inserted->mValue.mTexture.reset();

    if (parent == head) {
      head->parent = inserted;
      head->left = inserted;
      head->right = inserted;
    } else if (linkLeft) {
      parent->left = inserted;
      if (parent == head->left) {
        head->left = inserted;
      }
    } else {
      parent->right = inserted;
      if (parent == head->right) {
        head->right = inserted;
      }
    }

    ++map.mSize;
    FixAfterTerrainEnvironmentInsert(map, inserted);
    return inserted;
  }

  void RecomputeTerrainEnvironmentExtrema(TerrainEnvironmentLookupMapRuntimeView& map) noexcept
  {
    TerrainEnvironmentLookupNodeRuntimeView* const head = map.mHead;
    if (head == nullptr) {
      return;
    }

    if (IsTerrainEnvironmentLookupNil(head->parent)) {
      head->left = head;
      head->right = head;
      return;
    }

    head->left = TerrainEnvironmentTreeMin(head->parent, head);
    head->right = TerrainEnvironmentTreeMax(head->parent, head);
  }

  void TransplantTerrainEnvironmentNode(
    TerrainEnvironmentLookupMapRuntimeView& map,
    TerrainEnvironmentLookupNodeRuntimeView* const source,
    TerrainEnvironmentLookupNodeRuntimeView* const replacement
  ) noexcept
  {
    if (source->parent->mIsNil != 0) {
      map.mHead->parent = replacement;
    } else if (source == source->parent->left) {
      source->parent->left = replacement;
    } else {
      source->parent->right = replacement;
    }

    if (!IsTerrainEnvironmentLookupNil(replacement)) {
      replacement->parent = source->parent;
    }
  }

  void FixAfterTerrainEnvironmentErase(
    TerrainEnvironmentLookupMapRuntimeView& map,
    TerrainEnvironmentLookupNodeRuntimeView* current,
    TerrainEnvironmentLookupNodeRuntimeView* parent
  ) noexcept
  {
    TerrainEnvironmentLookupNodeRuntimeView* const head = map.mHead;
    if (head == nullptr) {
      return;
    }

    while (current != head->parent && (current == nullptr || current->mColor == 1)) {
      if (current == parent->left) {
        TerrainEnvironmentLookupNodeRuntimeView* sibling = parent->right;
        if (sibling->mColor == 0) {
          sibling->mColor = 1;
          parent->mColor = 0;
          RotateTerrainEnvironmentLeft(map, parent);
          sibling = parent->right;
        }

        if (sibling->left->mColor == 1 && sibling->right->mColor == 1) {
          sibling->mColor = 0;
          current = parent;
          parent = current->parent;
        } else {
          if (sibling->right->mColor == 1) {
            sibling->left->mColor = 1;
            sibling->mColor = 0;
            RotateTerrainEnvironmentRight(map, sibling);
            sibling = parent->right;
          }

          sibling->mColor = parent->mColor;
          parent->mColor = 1;
          sibling->right->mColor = 1;
          RotateTerrainEnvironmentLeft(map, parent);
          current = head->parent;
        }
      } else {
        TerrainEnvironmentLookupNodeRuntimeView* sibling = parent->left;
        if (sibling->mColor == 0) {
          sibling->mColor = 1;
          parent->mColor = 0;
          RotateTerrainEnvironmentRight(map, parent);
          sibling = parent->left;
        }

        if (sibling->right->mColor == 1 && sibling->left->mColor == 1) {
          sibling->mColor = 0;
          current = parent;
          parent = current->parent;
        } else {
          if (sibling->left->mColor == 1) {
            sibling->right->mColor = 1;
            sibling->mColor = 0;
            RotateTerrainEnvironmentLeft(map, sibling);
            sibling = parent->left;
          }

          sibling->mColor = parent->mColor;
          parent->mColor = 1;
          sibling->left->mColor = 1;
          RotateTerrainEnvironmentRight(map, parent);
          current = head->parent;
        }
      }
    }

    if (current != nullptr) {
      current->mColor = 1;
    }
  }

  /**
   * Address: 0x008A7DE0 (FUN_008A7DE0)
   *
   * What it does:
   * Erases one node from terrain environment-lookup RB-tree and returns the
   * next in-order node.
   */
  [[nodiscard]] TerrainEnvironmentLookupNodeRuntimeView* EraseTerrainEnvironmentNode(
    TerrainEnvironmentLookupMapRuntimeView& map, TerrainEnvironmentLookupNodeRuntimeView* const eraseNode
  )
  {
    if (eraseNode == nullptr || map.mHead == nullptr) {
      return map.mHead;
    }
    if (eraseNode->mIsNil != 0) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    TerrainEnvironmentLookupNodeRuntimeView* const next = IncrementTerrainEnvironmentNode(eraseNode, map.mHead);

    TerrainEnvironmentLookupNodeRuntimeView* moved = eraseNode;
    std::uint8_t movedOriginalColor = moved->mColor;
    TerrainEnvironmentLookupNodeRuntimeView* child = map.mHead;
    TerrainEnvironmentLookupNodeRuntimeView* childParent = map.mHead;

    if (IsTerrainEnvironmentLookupNil(eraseNode->left)) {
      child = eraseNode->right;
      childParent = eraseNode->parent;
      TransplantTerrainEnvironmentNode(map, eraseNode, eraseNode->right);
    } else if (IsTerrainEnvironmentLookupNil(eraseNode->right)) {
      child = eraseNode->left;
      childParent = eraseNode->parent;
      TransplantTerrainEnvironmentNode(map, eraseNode, eraseNode->left);
    } else {
      moved = TerrainEnvironmentTreeMin(eraseNode->right, map.mHead);
      movedOriginalColor = moved->mColor;
      child = moved->right;
      if (moved->parent == eraseNode) {
        childParent = moved;
        if (!IsTerrainEnvironmentLookupNil(child)) {
          child->parent = moved;
        }
      } else {
        childParent = moved->parent;
        TransplantTerrainEnvironmentNode(map, moved, moved->right);
        moved->right = eraseNode->right;
        moved->right->parent = moved;
      }

      TransplantTerrainEnvironmentNode(map, eraseNode, moved);
      moved->left = eraseNode->left;
      moved->left->parent = moved;
      moved->mColor = eraseNode->mColor;
    }

    if (movedOriginalColor == 1) {
      FixAfterTerrainEnvironmentErase(map, child, childParent);
    }

    delete eraseNode;
    if (map.mSize != 0u) {
      --map.mSize;
    }
    RecomputeTerrainEnvironmentExtrema(map);
    return next;
  }

  /**
   * Address: 0x008A8720 (FUN_008A8720, sub_8A8720)
   *
   * What it does:
   * Clears one terrain environment-lookup subtree by recursively deleting right
   * branches, then deleting the left chain in post-order.
   */
  void DeleteTerrainEnvironmentSubtreePostOrder(TerrainEnvironmentLookupNodeRuntimeView* node) noexcept
  {
    while (!IsTerrainEnvironmentLookupNil(node)) {
      DeleteTerrainEnvironmentSubtreePostOrder(node->right);
      TerrainEnvironmentLookupNodeRuntimeView* const left = node->left;
      delete node;
      node = left;
    }
  }

  void DestroyTerrainEnvironmentIteratorRange(
    TerrainEnvironmentLookupNodeRuntimeView* node,
    TerrainEnvironmentLookupNodeRuntimeView* const head
  ) noexcept
  {
    while (!IsTerrainEnvironmentLookupNil(node)) {
      TerrainEnvironmentLookupNodeRuntimeView* const eraseNode = node;
      node = IncrementTerrainEnvironmentNode(node, head);
      delete eraseNode;
    }
  }

  /**
   * Address: 0x008A8D40 (FUN_008A8D40, sub_8A8D40)
   *
   * IDA signature:
   * int *__userpurge sub_8A8D40@<eax>(int a1@<edi>, int *a2, int a4, int arg8);
   *
   * What it does:
   * Erases the half-open node range `[eraseFirst, eraseLast)` from one
   * `TerrainEnvironmentLookup` red-black tree. When the range covers the
   * entire tree (matches `[head->left, head]`), the fast path clears the
   * whole tree in one `DeleteTerrainEnvironmentSubtreePostOrder` sweep,
   * rebinds the sentinel to an empty state, and writes the zero-size
   * iterator pair back into `*outIter`. The slow path steps from
   * `eraseFirst` toward `eraseLast`, resolving each predecessor/successor
   * via in-order walk and destroying one node per iteration through
   * `EraseTerrainEnvironmentNode` (FUN_008A7DE0). The final cursor is
   * published into `outIter` for the caller's iterator chain.
   */
  TerrainEnvironmentLookupNodeRuntimeView** EraseTerrainEnvironmentNodeRange(
    TerrainEnvironmentLookupMapRuntimeView& map,
    TerrainEnvironmentLookupNodeRuntimeView** const outIter,
    TerrainEnvironmentLookupNodeRuntimeView* eraseFirst,
    TerrainEnvironmentLookupNodeRuntimeView* const eraseLast
  )
  {
    TerrainEnvironmentLookupNodeRuntimeView* const head = map.mHead;
    if (head == nullptr) {
      *outIter = nullptr;
      return outIter;
    }

    // Fast path: whole-tree clear when `eraseFirst == head->left` (leftmost
    // in-order node) and `eraseLast == head` (end sentinel).
    if (eraseFirst == head->left && eraseLast == head) {
      DeleteTerrainEnvironmentSubtreePostOrder(head->parent);
      head->left = head;
      map.mSize = 0u;
      head->parent = head;
      head->right = head;
      *outIter = head->left;
      return outIter;
    }

    // Slow path: step through the range, destroying one node per iteration.
    // Walk toward the successor using the same in-order traversal the binary
    // emits inline (successor if a right subtree exists, otherwise climb
    // parents until we leave a right-branch ancestor).
    while (eraseFirst != eraseLast) {
      TerrainEnvironmentLookupNodeRuntimeView* cursor = eraseFirst;
      if (!IsTerrainEnvironmentLookupNil(cursor)) {
        TerrainEnvironmentLookupNodeRuntimeView* const rightChild = cursor->right;
        if (!IsTerrainEnvironmentLookupNil(rightChild)) {
          TerrainEnvironmentLookupNodeRuntimeView* leftmost = cursor->left;
          if (IsTerrainEnvironmentLookupNil(leftmost)) {
            // Walk left children from the right subtree looking for next.
            for (leftmost = cursor->right;
                 !IsTerrainEnvironmentLookupNil(leftmost) && leftmost != cursor->right;
                 leftmost = leftmost->left) {
              cursor = leftmost;
            }
            cursor = leftmost;
          } else {
            // Traverse predecessors until we leave a right-branch ancestor.
            TerrainEnvironmentLookupNodeRuntimeView* predecessor = leftmost;
            while (!IsTerrainEnvironmentLookupNil(predecessor)) {
              TerrainEnvironmentLookupNodeRuntimeView* const parentLink = predecessor->right;
              if (IsTerrainEnvironmentLookupNil(parentLink)) {
                break;
              }
              if (cursor != parentLink->left) {
                break;
              }
              cursor = predecessor;
              predecessor = predecessor->right;
            }
            cursor = predecessor;
          }
        }
      }

      (void)EraseTerrainEnvironmentNode(map, eraseFirst);
      eraseFirst = cursor;
    }

    *outIter = eraseFirst;
    return outIter;
  }

  /**
   * Address: 0x008A7700 (FUN_008A7700, sub_8A7700)
   *
   * What it does:
   * Destroys all terrain environment-lookup nodes from one sentinel map head,
   * releases the sentinel storage, and clears map head/size lanes.
   */
  void DestroyTerrainEnvironmentLookupMapStorage(TerrainEnvironmentLookupMapRuntimeView& map) noexcept
  {
    TerrainEnvironmentLookupNodeRuntimeView* const head = map.mHead;
    if (head != nullptr) {
      DestroyTerrainEnvironmentIteratorRange(head->left, head);
      delete head;
    }

    map.mHead = nullptr;
    map.mSize = 0u;
  }

  /**
   * Address: 0x008A9DC0 (FUN_008A9DC0, sub_8A9DC0)
   *
   * What it does:
   * Copies one half-open range of environment-lookup string pairs forward via
   * member string `assign` lanes and returns one-past-last destination lane.
   */
  [[nodiscard]] moho::TerrainEnvironmentLookupPair* CopyTerrainEnvironmentLookupPairRangeForward(
    moho::TerrainEnvironmentLookupPair* destinationBegin,
    const moho::TerrainEnvironmentLookupPair* sourceBegin,
    const moho::TerrainEnvironmentLookupPair* sourceEnd
  )
  {
    moho::TerrainEnvironmentLookupPair* destination = destinationBegin;
    const moho::TerrainEnvironmentLookupPair* source = sourceBegin;
    while (source != sourceEnd) {
      destination->first.assign(source->first, 0u, static_cast<std::size_t>(-1));
      destination->second.assign(source->second, 0u, static_cast<std::size_t>(-1));
      ++source;
      ++destination;
    }
    return destination;
  }

  /**
   * Address: 0x008AA0B0 (FUN_008AA0B0, sub_8AA0B0)
   *
   * What it does:
   * Copies one range of environment-lookup string pairs backward via member
   * string `assign` lanes and returns the first written destination lane.
   */
  [[nodiscard]] moho::TerrainEnvironmentLookupPair* CopyTerrainEnvironmentLookupPairRangeBackward(
    moho::TerrainEnvironmentLookupPair* destinationEnd,
    const moho::TerrainEnvironmentLookupPair* sourceEnd,
    const moho::TerrainEnvironmentLookupPair* sourceBegin
  )
  {
    moho::TerrainEnvironmentLookupPair* destination = destinationEnd;
    const moho::TerrainEnvironmentLookupPair* source = sourceEnd;
    while (source != sourceBegin) {
      --destination;
      --source;
      destination->first.assign(source->first, 0u, static_cast<std::size_t>(-1));
      destination->second.assign(source->second, 0u, static_cast<std::size_t>(-1));
    }
    return destination;
  }

  /**
   * Address: 0x008A8B00 (FUN_008A8B00, sub_8A8B00)
   *
   * What it does:
   * Erases one half-open pair range from a terrain environment-lookup vector
   * by shifting tail values into the erase slot and destroying the old tail
   * range, then stores the resulting iterator lane in `outResult`.
   */
  moho::TerrainEnvironmentLookupPair** EraseTerrainEnvironmentLookupPairRange(
    moho::TerrainEnvironmentLookupPairs& pairs,
    moho::TerrainEnvironmentLookupPair** const outResult,
    moho::TerrainEnvironmentLookupPair* const eraseFirst,
    moho::TerrainEnvironmentLookupPair* const eraseLast
  )
  {
    auto& runtime = msvc8::AsVectorRuntimeView(pairs);
    moho::TerrainEnvironmentLookupPair* const oldEnd = runtime.end;

    if (eraseFirst != eraseLast) {
      moho::TerrainEnvironmentLookupPair* const newEnd =
        CopyTerrainEnvironmentLookupPairRangeForward(eraseFirst, eraseLast, oldEnd);

      while (runtime.end != newEnd) {
        --runtime.end;
        std::destroy_at(runtime.end);
      }
    }

    *outResult = eraseFirst;
    return outResult;
  }

  /**
   * Address: 0x008A83A0 (FUN_008A83A0, sub_8A83A0)
   *
   * What it does:
   * Erases the full pair range from one terrain environment-lookup vector and
   * returns the resulting iterator lane.
   */
  [[maybe_unused]] moho::TerrainEnvironmentLookupPair* EraseAllTerrainEnvironmentLookupPairs(
    moho::TerrainEnvironmentLookupPairs& pairs
  )
  {
    moho::TerrainEnvironmentLookupPair* result = nullptr;
    auto& runtime = msvc8::AsVectorRuntimeView(pairs);
    (void)EraseTerrainEnvironmentLookupPairRange(pairs, &result, runtime.begin, runtime.end);
    return result;
  }

  void SaveStratumLayer(gpg::BinaryWriter& writer, const moho::CStratumMaterial& layer)
  {
    writer.WriteString(layer.mPath);
    writer.Write(layer.mSize);
  }

  [[nodiscard]] QuaternionLanes QuaternionFromMatrixRows(const float matrix[3][3]) noexcept
  {
    QuaternionLanes out{1.0f, 0.0f, 0.0f, 0.0f};

    const float trace = matrix[0][0] + matrix[1][1] + matrix[2][2];
    if (trace > 0.0f) {
      const float s = std::sqrt(trace + 1.0f) * 2.0f;
      if (s > kQuaternionNormalizeEpsilon) {
        out.w = 0.25f * s;
        out.x = (matrix[2][1] - matrix[1][2]) / s;
        out.y = (matrix[0][2] - matrix[2][0]) / s;
        out.z = (matrix[1][0] - matrix[0][1]) / s;
      }
      return out;
    }

    if (matrix[0][0] > matrix[1][1] && matrix[0][0] > matrix[2][2]) {
      const float s = std::sqrt(1.0f + matrix[0][0] - matrix[1][1] - matrix[2][2]) * 2.0f;
      if (s > kQuaternionNormalizeEpsilon) {
        out.w = (matrix[2][1] - matrix[1][2]) / s;
        out.x = 0.25f * s;
        out.y = (matrix[0][1] + matrix[1][0]) / s;
        out.z = (matrix[0][2] + matrix[2][0]) / s;
      }
      return out;
    }

    if (matrix[1][1] > matrix[2][2]) {
      const float s = std::sqrt(1.0f + matrix[1][1] - matrix[0][0] - matrix[2][2]) * 2.0f;
      if (s > kQuaternionNormalizeEpsilon) {
        out.w = (matrix[0][2] - matrix[2][0]) / s;
        out.x = (matrix[0][1] + matrix[1][0]) / s;
        out.y = 0.25f * s;
        out.z = (matrix[1][2] + matrix[2][1]) / s;
      }
      return out;
    }

    const float s = std::sqrt(1.0f + matrix[2][2] - matrix[0][0] - matrix[1][1]) * 2.0f;
    if (s > kQuaternionNormalizeEpsilon) {
      out.w = (matrix[1][0] - matrix[0][1]) / s;
      out.x = (matrix[0][2] + matrix[2][0]) / s;
      out.y = (matrix[1][2] + matrix[2][1]) / s;
      out.z = 0.25f * s;
    }
    return out;
  }

  void NormalizeQuaternionLanes(QuaternionLanes& q) noexcept
  {
    const float magnitude =
      std::sqrt((q.w * q.w) + (q.x * q.x) + (q.y * q.y) + (q.z * q.z));
    if (magnitude <= kQuaternionNormalizeEpsilon) {
      q.w = 0.0f;
      q.x = 0.0f;
      q.y = 0.0f;
      q.z = 0.0f;
      return;
    }

    const float inverseMagnitude = 1.0f / magnitude;
    q.w *= inverseMagnitude;
    q.x *= inverseMagnitude;
    q.y *= inverseMagnitude;
    q.z *= inverseMagnitude;
  }

  void QuaternionToRotationRows(const QuaternionLanes& q, float matrix[3][3]) noexcept
  {
    const float w = q.w;
    const float x = q.x;
    const float y = q.y;
    const float z = q.z;

    const float xx2 = 2.0f * x * x;
    const float yy2 = 2.0f * y * y;
    const float zz2 = 2.0f * z * z;
    const float xy2 = 2.0f * x * y;
    const float xz2 = 2.0f * x * z;
    const float yz2 = 2.0f * y * z;
    const float wx2 = 2.0f * w * x;
    const float wy2 = 2.0f * w * y;
    const float wz2 = 2.0f * w * z;

    matrix[0][0] = 1.0f - yy2 - zz2;
    matrix[0][1] = wz2 + xy2;
    matrix[0][2] = xz2 - wy2;

    matrix[1][0] = xy2 - wz2;
    matrix[1][1] = 1.0f - xx2 - zz2;
    matrix[1][2] = yz2 + wx2;

    matrix[2][0] = wy2 + xz2;
    matrix[2][1] = yz2 - wx2;
    matrix[2][2] = 1.0f - xx2 - yy2;
  }

  /**
   * Address: 0x008915F0 (FUN_008915F0, sub_8915F0)
   *
   * What it does:
   * Writes two contiguous 32-bit lanes to a binary writer in one 8-byte
   * payload.
   */
  void WriteBinaryWriterPairU32(gpg::BinaryWriter& writer, const std::uint32_t first, const std::uint32_t second)
  {
    const std::uint32_t pair[2]{first, second};
    writer.Write(reinterpret_cast<const char*>(pair), sizeof(pair));
  }

  [[nodiscard]] std::int32_t ClampWaterMapSampleCoordinate(
    const std::int32_t coordinate, const std::int32_t upperInclusive
  ) noexcept
  {
    if (coordinate < 0) {
      return 0;
    }
    if (coordinate > upperInclusive) {
      return upperInclusive;
    }
    return coordinate;
  }

  [[nodiscard]] float SampleTerrainHeightWordScaled(
    const moho::CHeightField& field, const std::int32_t x, const std::int32_t z
  ) noexcept
  {
    constexpr float kHeightWordScale = 0.0078125f;
    const std::int32_t sampleX = ClampWaterMapSampleCoordinate(x, field.width - 1);
    const std::int32_t sampleZ = ClampWaterMapSampleCoordinate(z, field.height - 1);
    const std::size_t index =
      static_cast<std::size_t>(sampleX) + static_cast<std::size_t>(sampleZ) * static_cast<std::size_t>(field.width);
    return static_cast<float>(field.data[index]) * kHeightWordScale;
  }

  [[nodiscard]] std::int32_t FloorHalfCoordinate(const std::int32_t coordinate) noexcept
  {
    return static_cast<std::int32_t>(std::floor(static_cast<float>(coordinate) * 0.5f));
  }

  [[nodiscard]] std::int32_t CeilHalfCoordinate(const std::int32_t coordinate) noexcept
  {
    return static_cast<std::int32_t>(std::ceil(static_cast<float>(coordinate) * 0.5f));
  }

  void AppendTerrainDirtyRect(TerrainDirtyRectListRuntimeView& list, const gpg::Rect2i& rect)
  {
    auto* const node = static_cast<TerrainDirtyRectNodeRuntimeView*>(::operator new(sizeof(TerrainDirtyRectNodeRuntimeView)));
    node->mNext = list.mHead;
    node->mPrev = list.mHead->mPrev;
    node->mValue = rect;

    if (list.mSize == 0x0FFFFFFFu) {
      throw std::length_error("list<T> too long");
    }
    ++list.mSize;

    if (list.mIteratorProxy != nullptr) {
      list.mIteratorProxy->mFirstIterator = nullptr;
    }

    list.mHead->mPrev = node;
    node->mPrev->mNext = node;
  }

  [[nodiscard]] bool ShouldSyncDirtyRectInCameraBounds(const gpg::Rect2i& dirtyRect, const gpg::Rect2i& cameraRect) noexcept
  {
    const bool fullyContained = dirtyRect.x0 >= cameraRect.x0
      && dirtyRect.x1 <= cameraRect.x1
      && dirtyRect.z0 >= cameraRect.z0
      && dirtyRect.z1 <= cameraRect.z1;
    if (fullyContained) {
      return true;
    }

    return dirtyRect.Overlaps(cameraRect);
  }

  [[nodiscard]] bool IntelRectVisibleOrGridMissing(const moho::CIntelGrid* const grid, const gpg::Rect2i& rect)
  {
    return grid == nullptr || grid->IsVisible(rect, false);
  }

  [[nodiscard]] bool TerrainRectVisibleForFocusArmy(const gpg::Rect2i& rect, const moho::UserArmy* const focusArmy)
  {
    if (focusArmy == nullptr) {
      return true;
    }

    const moho::CIntelGrid* const exploredGrid = focusArmy->mExploredReconGrid.get();
    if (exploredGrid == nullptr || !moho::console::RenderFogOfWarEnabled()) {
      return true;
    }

    const moho::CIntelGrid* const fogGrid = focusArmy->mFogReconGrid.get();
    if (exploredGrid->IsVisible(rect, false) || fogGrid->IsVisible(rect, false)) {
      return true;
    }

    const moho::CWldSession* const session = focusArmy->mSession;
    if (session == nullptr) {
      return false;
    }

    for (std::size_t armyIndex = 0; armyIndex < session->userArmies.size(); ++armyIndex) {
      moho::UserArmy* const alliedArmy = session->userArmies[armyIndex];
      if (alliedArmy == nullptr || !alliedArmy->IsAlly(focusArmy->mArmyIndex)) {
        continue;
      }

      if (
        IntelRectVisibleOrGridMissing(alliedArmy->mExploredReconGrid.get(), rect)
        || IntelRectVisibleOrGridMissing(alliedArmy->mFogReconGrid.get(), rect)
      ) {
        return true;
      }
    }

    return false;
  }

  void EraseTerrainDirtyRectNode(TerrainDirtyRectListRuntimeView& list, TerrainDirtyRectNodeRuntimeView* const node) noexcept
  {
    if (node == list.mHead) {
      return;
    }

    node->mPrev->mNext = node->mNext;
    node->mNext->mPrev = node->mPrev;
    ::operator delete(node);
    --list.mSize;
  }

  void EnsureTerrainEditWordCount(
    TerrainEditWordBufferRuntimeView& editWordBuffer,
    const std::size_t desiredWordCount,
    const std::uint32_t fillWord
  )
  {
    auto throwTooLong = []() {
      throw std::length_error("vector<bool> too long");
    };

    auto allocateWords = [](const unsigned int wordCount) -> void* {
      return ::operator new(static_cast<std::size_t>(wordCount) * sizeof(std::uint32_t));
    };

    auto growWords = [&throwTooLong, &allocateWords](
                       msvc8::detail::dword_lane_vector_view* const view,
                       std::uint32_t* const insertAt,
                       const std::size_t count,
                       const std::uint32_t value
                     ) {
      (void)msvc8::detail::InsertFillWordsIntoLanes(
        view,
        insertAt,
        count,
        value,
        throwTooLong,
        allocateWords
      );
    };

    auto eraseWords = [](
                        msvc8::detail::dword_lane_vector_view* const view,
                        std::uint32_t* const first,
                        std::uint32_t* const last
                      ) {
      if (first == last) {
        return;
      }

      if (last != view->end) {
        const std::size_t tailWordCount = static_cast<std::size_t>(view->end - last);
        std::memmove(first, last, tailWordCount * sizeof(std::uint32_t));
      }

      view->end -= static_cast<std::ptrdiff_t>(last - first);
    };

    (void)msvc8::detail::EnsureWordCountInLanes(
      &editWordBuffer,
      desiredWordCount,
      fillWord,
      growWords,
      eraseWords
    );
  }

  void DestroyNormalMapHandleStorage(TerrainNormalMapHandleArray& handles) noexcept
  {
    if (handles.mBegin == nullptr) {
      handles.mEnd = nullptr;
      handles.mCapacityEnd = nullptr;
      return;
    }

    for (auto* it = handles.mBegin; it != handles.mEnd; ++it) {
      std::destroy_at(it);
    }

    ::operator delete(handles.mBegin);
    handles.mBegin = nullptr;
    handles.mEnd = nullptr;
    handles.mCapacityEnd = nullptr;
  }

  [[nodiscard]] std::size_t GetNormalMapHandleCount(const TerrainNormalMapHandleArray& handles) noexcept
  {
    if (handles.mBegin == nullptr || handles.mEnd == nullptr) {
      return 0u;
    }
    return static_cast<std::size_t>(handles.mEnd - handles.mBegin);
  }

  [[nodiscard]] std::size_t GetNormalMapHandleCapacity(const TerrainNormalMapHandleArray& handles) noexcept
  {
    if (handles.mBegin == nullptr || handles.mCapacityEnd == nullptr) {
      return 0u;
    }
    return static_cast<std::size_t>(handles.mCapacityEnd - handles.mBegin);
  }

  void ReserveNormalMapHandleStorage(TerrainNormalMapHandleArray& handles, const std::size_t requiredCount)
  {
    const std::size_t currentCapacity = GetNormalMapHandleCapacity(handles);
    if (requiredCount <= currentCapacity) {
      return;
    }

    const std::size_t currentCount = GetNormalMapHandleCount(handles);
    std::size_t newCapacity = currentCapacity + (currentCapacity >> 1u);
    if (newCapacity < requiredCount) {
      newCapacity = requiredCount;
    }

    auto* const storage = static_cast<boost::shared_ptr<moho::CD3DDynamicTextureSheet>*>(
      ::operator new(sizeof(boost::shared_ptr<moho::CD3DDynamicTextureSheet>) * newCapacity)
    );

    auto* it = storage;
    try {
      for (auto* src = handles.mBegin; src != handles.mEnd; ++src, ++it) {
        new (it) boost::shared_ptr<moho::CD3DDynamicTextureSheet>(*src);
      }
    } catch (...) {
      while (it != storage) {
        --it;
        std::destroy_at(it);
      }
      ::operator delete(storage);
      throw;
    }

    DestroyNormalMapHandleStorage(handles);
    handles.mBegin = storage;
    handles.mEnd = storage + currentCount;
    handles.mCapacityEnd = storage + newCapacity;
  }

  /**
   * Address: 0x008A9E90 (FUN_008A9E90)
   *
   * What it does:
   * Copy-assigns one half-open normal-map handle range into destination
   * storage, preserving shared-pointer reference-count semantics lane by lane.
   */
  [[maybe_unused]] boost::shared_ptr<moho::CD3DDynamicTextureSheet>* CopyAssignNormalMapHandleRange(
    boost::shared_ptr<moho::CD3DDynamicTextureSheet>* destinationBegin,
    const boost::shared_ptr<moho::CD3DDynamicTextureSheet>* sourceBegin,
    const boost::shared_ptr<moho::CD3DDynamicTextureSheet>* sourceEnd
  )
  {
    auto* destination = destinationBegin;
    const auto* source = sourceBegin;
    while (source != sourceEnd) {
      *destination = *source;
      ++destination;
      ++source;
    }
    return destination;
  }

  /**
   * Address: 0x008A8BC0 (FUN_008A8BC0)
   *
   * What it does:
   * Erases one half-open normal-map handle range, compacts trailing elements,
   * destroys vacated shared-pointer lanes, updates vector end, and returns the
   * legacy erase iterator result.
   */
  [[nodiscard]] boost::shared_ptr<moho::CD3DDynamicTextureSheet>** EraseNormalMapHandleRange(
    TerrainNormalMapHandleArray& handles,
    boost::shared_ptr<moho::CD3DDynamicTextureSheet>** const outIterator,
    boost::shared_ptr<moho::CD3DDynamicTextureSheet>* const first,
    boost::shared_ptr<moho::CD3DDynamicTextureSheet>* const last
  )
  {
    if (first != last) {
      auto* const newEnd = CopyAssignNormalMapHandleRange(first, last, handles.mEnd);
      for (auto* it = newEnd; it != handles.mEnd; ++it) {
        std::destroy_at(it);
      }
      handles.mEnd = newEnd;
    }

    *outIterator = first;
    return outIterator;
  }

  /**
   * Address: 0x008A8430 (FUN_008A8430, sub_8A8430)
   *
   * What it does:
   * Resizes normal-map texture-handle storage to one target element count
   * while preserving existing handles and filling newly appended lanes with
   * one caller-provided shared-pointer value.
   */
  void ResizeNormalMapHandleStorage(
    TerrainNormalMapHandleArray& handles,
    const std::size_t tileCount,
    const boost::shared_ptr<moho::CD3DDynamicTextureSheet>& fillValue
  )
  {
    constexpr std::size_t kMaxHandleCount = 0x1FFFFFFFu;
    if (tileCount > kMaxHandleCount) {
      throw std::length_error("CWldTerrainRes normal-map handle count exceeds legacy limit");
    }

    const std::size_t currentCount = GetNormalMapHandleCount(handles);
    if (currentCount < tileCount) {
      ReserveNormalMapHandleStorage(handles, tileCount);

      auto* appendedEnd = handles.mEnd;
      try {
        for (std::size_t index = currentCount; index < tileCount; ++index, ++appendedEnd) {
          new (appendedEnd) boost::shared_ptr<moho::CD3DDynamicTextureSheet>(fillValue);
        }
      } catch (...) {
        while (appendedEnd != handles.mEnd) {
          --appendedEnd;
          std::destroy_at(appendedEnd);
        }
        throw;
      }
      handles.mEnd = appendedEnd;
      return;
    }

    if (handles.mBegin != nullptr && tileCount < currentCount) {
      auto* const newEnd = handles.mBegin + tileCount;
      boost::shared_ptr<moho::CD3DDynamicTextureSheet>* eraseResult = nullptr;
      (void)EraseNormalMapHandleRange(handles, &eraseResult, newEnd, handles.mEnd);
    }
  }

  /**
   * Address: 0x008A7C20 (FUN_008A7C20)
   *
   * What it does:
   * Thin overload lane that zero-initializes one empty shared-pointer fill
   * value and forwards resize work into the canonical 3-argument helper.
   */
  void ResizeNormalMapHandleStorage(TerrainNormalMapHandleArray& handles, const std::size_t tileCount)
  {
    boost::shared_ptr<moho::CD3DDynamicTextureSheet> fillValue;
    ResizeNormalMapHandleStorage(handles, tileCount, fillValue);
  }

  [[nodiscard]] std::uint8_t EncodeNormalLaneByte(const float lane) noexcept
  {
    int encoded = static_cast<int>((lane + 1.0f) * 128.0f);
    if (encoded < 0) {
      encoded = 0;
    } else if (encoded > 255) {
      encoded = 255;
    }
    return static_cast<std::uint8_t>(encoded);
  }

  [[nodiscard]] std::int32_t AlignDownTo4(const std::int32_t value) noexcept
  {
    return value & ~3;
  }

  [[nodiscard]] std::int32_t AlignUpTo4(const std::int32_t value) noexcept
  {
    return (value + 3) & ~3;
  }

  void CloneTerrainDynamicTextureForEdit(boost::shared_ptr<moho::CD3DDynamicTextureSheet>& slot, const bool archiveMode)
  {
    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    if (device == nullptr) {
      return;
    }

    boost::shared_ptr<moho::CD3DDynamicTextureSheet> replacement;
    (void)device->CreateDynamicTextureSheetFromSource(
      replacement,
      slot.get(),
      nullptr,
      2,
      archiveMode
    );
    slot = replacement;
  }

  void RebuildWaterMapRect(moho::IWldTerrainRes& terrainRes, const gpg::Rect2i& updateRect)
  {
    constexpr float kNoWaterElevation = -10000.0f;
    auto* const terrainView = AsTerrainNormalMapRuntimeView(&terrainRes);
    auto* const visualView = AsTerrainVisualResourceRuntimeView(&terrainRes);
    moho::STIMap* const map = terrainView->mMap;
    moho::CHeightField* const field = map->mHeightField.get();

    const std::int32_t maxZ = field->height - 1;
    const std::int32_t maxX = field->width - 1;

    std::int32_t x0 = updateRect.x0;
    std::int32_t z0 = updateRect.z0;
    std::int32_t x1 = updateRect.x1;
    std::int32_t z1 = updateRect.z1;

    if (x0 < 0) {
      x0 = 0;
    }
    if (x1 >= maxX) {
      x1 = maxX;
    }
    if (z0 < 0) {
      z0 = 0;
    }
    if (z1 >= maxZ) {
      z1 = maxZ;
    }

    const float waterElevation = map->mWaterEnabled != 0u ? map->mWaterElevation : kNoWaterElevation;
    const float waterAbyssElevation = map->mWaterEnabled != 0u ? map->mWaterElevationAbyss : kNoWaterElevation;

    const std::int32_t halfX0 = x0 >> 1;
    const std::int32_t halfX1 = x1 >> 1;
    const std::int32_t halfZ0 = z0 >> 1;
    const std::int32_t halfZ1 = z1 >> 1;

    const std::uint32_t halfMapWidth =
      static_cast<std::uint32_t>(static_cast<std::uint32_t>(field->width - 1) >> 1u);

    if (halfZ0 < halfZ1) {
      for (std::int32_t halfZ = halfZ0; halfZ < halfZ1; ++halfZ) {
        if (halfX0 >= halfX1) {
          continue;
        }

        const std::int32_t worldZ = halfZ * 2;
        const float depthDenominator = waterElevation - waterAbyssElevation;
        std::uint32_t pixelIndex = static_cast<std::uint32_t>(halfX0) + static_cast<std::uint32_t>(halfZ) * halfMapWidth;
        std::int32_t worldX = halfX0 * 2;

        for (std::int32_t halfX = halfX0; halfX < halfX1; ++halfX) {
          const float h00 = SampleTerrainHeightWordScaled(*field, worldX, worldZ);
          const float h10 = SampleTerrainHeightWordScaled(*field, worldX + 2, worldZ);
          const float h01 = SampleTerrainHeightWordScaled(*field, worldX, worldZ + 2);
          const float h11 = SampleTerrainHeightWordScaled(*field, worldX + 2, worldZ + 2);

          std::uint32_t packedSample = 0;
          packedSample |= static_cast<std::uint32_t>(visualView->mWaterFoam[pixelIndex]) << 24u;
          packedSample |= static_cast<std::uint32_t>(visualView->mWaterFlatness[pixelIndex]) << 16u;

          float depthByte = ((waterElevation - h00) / depthDenominator) * 255.0f;
          if (depthByte >= 255.0f) {
            depthByte = 255.0f;
          }
          if (depthByte < 0.0f) {
            depthByte = 0.0f;
          }

          if (waterElevation > h00 || waterElevation > h10 || waterElevation > h01 || waterElevation > h11) {
            packedSample |= static_cast<std::uint32_t>(static_cast<std::uint8_t>(depthByte)) << 8u;
          }

          if (waterElevation < h00 || waterElevation < h10 || waterElevation < h01 || waterElevation < h11) {
            packedSample |= 0xFFu;
          }

          visualView->mEditWordBuffer.begin[pixelIndex] = packedSample;
          ++pixelIndex;
          worldX += 2;
        }
      }
    }

    terrainRes.UpdateTexture(visualView->mWaterMapTexture, visualView->mEditWordBuffer.begin);
  }

  void DestroyTerrainRes(moho::IWldTerrainRes* const terrainRes) noexcept
  {
    delete terrainRes;
  }

  /**
   * Address: 0x00891620 (FUN_00891620, sub_891620)
   *
   * What it does:
   * Destroys one owned preview chunk pointer and frees its allocation when
   * the pointer is non-null.
   */
  void DestroyPreviewChunk(moho::RWldMapPreviewChunk* const chunk) noexcept
  {
    if (chunk == nullptr) {
      return;
    }

    chunk->~RWldMapPreviewChunk();
    operator delete(chunk);
  }

  /**
   * Address: 0x00891680 (FUN_00891680)
   *
   * What it does:
   * Runs one `RWldMapPreviewChunk` teardown+free deleting path and returns the
   * original pointer lane.
   */
  [[maybe_unused]] moho::RWldMapPreviewChunk* DeletePreviewChunkAndReturn(
    moho::RWldMapPreviewChunk* const chunk
  ) noexcept
  {
    chunk->~RWldMapPreviewChunk();
    operator delete(chunk);
    return chunk;
  }

  /**
   * Address: 0x00891400 (FUN_00891400, sub_891400)
   *
   * What it does:
   * Replaces one preview-chunk owner slot and destroys/frees the previous
   * chunk when it exists.
   */
  void ReplaceOwnedPreviewChunk(
    moho::RWldMapPreviewChunk** const slot,
    moho::RWldMapPreviewChunk* const replacement
  ) noexcept
  {
    moho::RWldMapPreviewChunk* const previous = *slot;
    *slot = replacement;
    if (previous != nullptr) {
      previous->~RWldMapPreviewChunk();
      operator delete(previous);
    }
  }

  void DestroyPropsEntry(moho::CWldPropEntry& entry) noexcept
  {
    entry.mBlueprintPath.tidy(true, 0U);
  }

  /**
   * Address: 0x00891700 (FUN_00891700, sub_891700)
   *
   * What it does:
   * Destroys one contiguous CWldPropEntry string lane range in-place.
   */
  void DestroyPropsEntriesRange(moho::CWldPropEntry* const begin, moho::CWldPropEntry* const end) noexcept
  {
    for (auto* entry = begin; entry != end; ++entry) {
      DestroyPropsEntry(*entry);
    }
  }

  /**
   * Address: 0x008915A0 (FUN_008915A0)
   *
   * What it does:
   * Register-order adapter lane for prop-entry range destruction.
   */
  [[maybe_unused]] void DestroyPropsEntriesRangeRegisterAdapterLaneA(
    moho::CWldPropEntry* const end,
    moho::CWldPropEntry* const begin
  ) noexcept
  {
    DestroyPropsEntriesRange(begin, end);
  }

  /**
   * Address: 0x00891660 (FUN_00891660)
   *
   * What it does:
   * Secondary register-order adapter lane for prop-entry range destruction.
   */
  [[maybe_unused]] void DestroyPropsEntriesRangeRegisterAdapterLaneB(
    moho::CWldPropEntry* const end,
    moho::CWldPropEntry* const begin
  ) noexcept
  {
    DestroyPropsEntriesRange(begin, end);
  }

  void DestroyPropsEntries(moho::CWldPropEntry* const begin, moho::CWldPropEntry* const end) noexcept
  {
    if (begin == nullptr || end == nullptr || end < begin) {
      return;
    }

    DestroyPropsEntriesRange(begin, end);
  }

  void ClearOwnedWldPropsEntriesStorageCommon(moho::CWldProps* const props) noexcept
  {
    moho::CWldPropEntry* const begin = props->mEntriesBegin;
    if (begin != nullptr) {
      DestroyPropsEntriesRange(begin, props->mEntriesEnd);
      operator delete(begin);
    }

    props->mEntriesBegin = nullptr;
    props->mEntriesEnd = nullptr;
    props->mEntriesCapacityEnd = nullptr;
  }

  /**
   * Address: 0x00890290 (FUN_00890290, sub_890290)
   *
   * What it does:
   * Destroys and frees one CWldProps entry-storage block and clears all three
   * entry pointer lanes.
   */
  void ClearOwnedWldPropsEntriesStorageLaneA(moho::CWldProps* const props) noexcept
  {
    ClearOwnedWldPropsEntriesStorageCommon(props);
  }

  /**
   * Address: 0x008914F0 (FUN_008914F0, sub_8914F0)
   *
   * What it does:
   * Duplicate cleanup lane that destroys/frees CWldProps entry storage and
   * nulls begin/end/capacity pointers.
   */
  [[maybe_unused]] void ClearOwnedWldPropsEntriesStorageLaneB(moho::CWldProps* const props) noexcept
  {
    ClearOwnedWldPropsEntriesStorageCommon(props);
  }

  /**
   * Address: 0x00891560 (FUN_00891560, sub_891560)
   *
   * What it does:
   * Duplicate cleanup lane that destroys/frees CWldProps entry storage and
   * nulls begin/end/capacity pointers.
   */
  [[maybe_unused]] void ClearOwnedWldPropsEntriesStorageLaneC(moho::CWldProps* const props) noexcept
  {
    ClearOwnedWldPropsEntriesStorageCommon(props);
  }

  /**
   * Address: 0x008916A0 (FUN_008916A0, sub_8916A0)
   *
   * What it does:
   * Destroys one CWldProps object and its entry storage lanes, then frees the
   * owning CWldProps allocation.
   */
  void DestroyWldPropsOwned(moho::CWldProps* const props) noexcept
  {
    ClearOwnedWldPropsEntriesStorageLaneA(props);
    operator delete(props);
  }

  void DestroyWldProps(moho::CWldProps* const props) noexcept
  {
    if (props == nullptr) {
      return;
    }
    DestroyWldPropsOwned(props);
  }

  /**
   * Address: 0x008914C0 (FUN_008914C0)
   *
   * What it does:
   * Replaces one owned `CWldProps*` slot and destroys the previous object when
   * non-null.
   */
  [[maybe_unused]] moho::CWldProps** ReplaceOwnedWldPropsSlot(
    moho::CWldProps** const slot,
    moho::CWldProps* const replacement
  ) noexcept
  {
    moho::CWldProps* const previous = *slot;
    *slot = replacement;
    if (previous != nullptr) {
      DestroyWldPropsOwned(previous);
    }
    return slot;
  }

  /**
   * Address: 0x00891650 (FUN_00891650)
   *
   * What it does:
   * Destroys one `CWldProps` owner lane when present and returns the original
   * pointer value.
   */
  [[maybe_unused]] moho::CWldProps* DestroyWldPropsIfPresent(moho::CWldProps* const props) noexcept
  {
    if (props != nullptr) {
      DestroyWldPropsOwned(props);
    }
    return props;
  }

  /**
   * Address: 0x008915C0 (FUN_008915C0)
   *
   * What it does:
   * Jump-only adapter lane that forwards directly to global `operator delete`.
   */
  [[maybe_unused]] void DeleteRawPointerLaneA(void* const pointer) noexcept
  {
    ::operator delete(pointer);
  }

  /**
   * Address: 0x008915D0 (FUN_008915D0)
   *
   * What it does:
   * Reads one little-endian signed 16-bit lane from a binary stream.
   */
  [[maybe_unused]] std::int16_t ReadSigned16Lane(gpg::BinaryReader* const reader)
  {
    std::int16_t value = 0;
    reader->Read(reinterpret_cast<char*>(&value), sizeof(value));
    return value;
  }

  /**
   * Address: 0x00891770 (FUN_00891770)
   *
   * What it does:
   * Clears one legacy string lane to empty state and returns zero.
   */
  [[maybe_unused]] int ClearLegacyStringAndReturnZero(msvc8::string* const value) noexcept
  {
    value->tidy(true, 0U);
    return 0;
  }

  /**
   * Address: 0x008917A0 (FUN_008917A0)
   *
   * What it does:
   * Clears one legacy string lane to empty state and returns the same pointer.
   */
  [[maybe_unused]] msvc8::string* ClearLegacyStringAndReturnSelf(msvc8::string* const value) noexcept
  {
    value->tidy(true, 0U);
    return value;
  }

  /**
   * Address: 0x00891D10 (FUN_00891D10)
   *
   * What it does:
   * Copy-assigns one world-prop entry lane (path string + packed transform).
   */
  [[maybe_unused]] moho::CWldPropEntry* CopyWldPropEntryLane(
    moho::CWldPropEntry* const destination,
    const moho::CWldPropEntry* const source
  )
  {
    destination->mBlueprintPath.assign(source->mBlueprintPath, 0u, msvc8::string::npos);
    for (std::size_t lane = 0; lane < 7u; ++lane) {
      destination->mTransformData[lane] = source->mTransformData[lane];
    }
    return destination;
  }

  /**
   * Address: 0x008513A0 (FUN_008513A0)
   *
   * What it does:
   * Runs `CWldMap` non-deleting destructor logic, then frees the heap storage
   * block that owns that map instance.
   */
  [[maybe_unused]] moho::CWldMap* DestroyAndDeleteWldMap(moho::CWldMap* const map) noexcept
  {
    if (map != nullptr) {
      map->~CWldMap();
      ::operator delete(static_cast<void*>(map));
    }
    return map;
  }

  /**
   * Address: 0x00886610 (FUN_00886610, sub_886610)
   *
   * What it does:
   * Transfers one CWldMap ownership lane from source auto_ptr slot into target
   * slot, deleting the previous target object when ownership changes.
   */
  [[maybe_unused]] moho::CWldMap** TransferAutoPtrCWldMapOwnership(
    moho::CWldMap** const sourceSlot,
    moho::CWldMap** const targetSlot
  ) noexcept
  {
    moho::CWldMap* const transferred = *sourceSlot;
    *sourceSlot = nullptr;

    moho::CWldMap* const targetValue = *targetSlot;
    if (transferred != targetValue && targetValue != nullptr) {
      (void)DestroyAndDeleteWldMap(targetValue);
    }

    *targetSlot = transferred;
    return targetSlot;
  }

  /**
   * Address: 0x0088E720 (FUN_0088E720, sub_88E720)
   *
   * What it does:
   * Transfers one STIMap ownership lane from source auto_ptr slot into target
   * slot, deleting the previous target map when ownership changes.
   */
  [[maybe_unused]] moho::STIMap** TransferAutoPtrSTIMapOwnership(
    moho::STIMap** const sourceSlot,
    moho::STIMap** const targetSlot
  ) noexcept
  {
    moho::STIMap* const transferred = *sourceSlot;
    *sourceSlot = nullptr;

    moho::STIMap* const targetValue = *targetSlot;
    if (transferred != targetValue && targetValue != nullptr) {
      targetValue->~STIMap();
      operator delete(targetValue);
    }

    *targetSlot = transferred;
    return targetSlot;
  }

  /**
   * Address: 0x00886500 (FUN_00886500, sub_886500)
   *
   * What it does:
   * Transfers one LuaState ownership lane from source auto_ptr slot into
   * target slot, deleting the previous target state when ownership changes.
   */
  [[maybe_unused]] LuaPlus::LuaState** TransferAutoPtrLuaStateOwnership(
    LuaPlus::LuaState** const sourceSlot,
    LuaPlus::LuaState** const targetSlot
  ) noexcept
  {
    LuaPlus::LuaState* const transferred = *sourceSlot;
    *sourceSlot = nullptr;

    LuaPlus::LuaState* const targetValue = *targetSlot;
    if (transferred != targetValue && targetValue != nullptr) {
      targetValue->~LuaState();
      operator delete(targetValue);
    }

    *targetSlot = transferred;
    return targetSlot;
  }

  [[nodiscard]] std::size_t GetWldPropEntryCount(const moho::CWldProps& props) noexcept
  {
    if (props.mEntriesBegin == nullptr || props.mEntriesEnd == nullptr) {
      return 0u;
    }
    return static_cast<std::size_t>(props.mEntriesEnd - props.mEntriesBegin);
  }

  [[nodiscard]] std::size_t GetWldPropEntryCapacity(const moho::CWldProps& props) noexcept
  {
    if (props.mEntriesBegin == nullptr || props.mEntriesCapacityEnd == nullptr) {
      return 0u;
    }
    return static_cast<std::size_t>(props.mEntriesCapacityEnd - props.mEntriesBegin);
  }

  void ReserveWldPropsEntries(moho::CWldProps& props, const std::size_t requiredCount)
  {
    const std::size_t currentCapacity = GetWldPropEntryCapacity(props);
    if (requiredCount <= currentCapacity) {
      return;
    }

    const std::size_t currentCount = GetWldPropEntryCount(props);
    std::size_t newCapacity = currentCapacity + (currentCapacity >> 1u);
    if (newCapacity < requiredCount) {
      newCapacity = requiredCount;
    }

    auto* const storage = static_cast<moho::CWldPropEntry*>(::operator new(sizeof(moho::CWldPropEntry) * newCapacity));
    moho::CWldPropEntry* it = storage;
    try {
      for (auto* src = props.mEntriesBegin; src != props.mEntriesEnd; ++src, ++it) {
        new (it) moho::CWldPropEntry(*src);
      }
    } catch (...) {
      while (it != storage) {
        --it;
        DestroyPropsEntry(*it);
      }
      ::operator delete(storage);
      throw;
    }

    DestroyPropsEntries(props.mEntriesBegin, props.mEntriesEnd);
    ::operator delete(props.mEntriesBegin);
    props.mEntriesBegin = storage;
    props.mEntriesEnd = storage + currentCount;
    props.mEntriesCapacityEnd = storage + newCapacity;
  }

  [[nodiscard]] moho::CWldPropEntry MakeDefaultWldPropEntry()
  {
    moho::CWldPropEntry defaultEntry{};
    defaultEntry.mBlueprintPath.tidy(false, 0U);
    defaultEntry.mTransformData[0] = 1.0f;
    for (std::size_t lane = 1; lane < 7; ++lane) {
      defaultEntry.mTransformData[lane] = 0.0f;
    }
    return defaultEntry;
  }

  /**
   * Address: 0x008922F0 (FUN_008922F0, sub_8922F0)
   *
   * What it does:
   * Resizes one `CWldProps` entry vector to a caller-requested count while
   * preserving existing entries and using one caller-provided default record
   * for appended lanes.
   */
  void ResizeWldPropsEntries(
    moho::CWldProps& props,
    const std::uint32_t entryCount,
    const moho::CWldPropEntry& fillEntry
  )
  {
    constexpr std::size_t kMaxEntryCount = 0x04924924u;
    if (entryCount > kMaxEntryCount) {
      throw std::length_error("CWldProps entry count exceeds legacy limit");
    }

    const std::size_t currentCount = GetWldPropEntryCount(props);
    const std::size_t targetCount = static_cast<std::size_t>(entryCount);
    if (currentCount < targetCount) {
      ReserveWldPropsEntries(props, targetCount);

      moho::CWldPropEntry* appendedEnd = props.mEntriesEnd;
      try {
        for (std::size_t index = currentCount; index < targetCount; ++index, ++appendedEnd) {
          new (appendedEnd) moho::CWldPropEntry(fillEntry);
        }
      } catch (...) {
        DestroyPropsEntriesRange(props.mEntriesEnd, appendedEnd);
        throw;
      }
      props.mEntriesEnd = appendedEnd;
      return;
    }

    if (props.mEntriesBegin != nullptr && targetCount < currentCount) {
      moho::CWldPropEntry* const newEnd = props.mEntriesBegin + targetCount;
      DestroyPropsEntriesRange(newEnd, props.mEntriesEnd);
      props.mEntriesEnd = newEnd;
    }
  }

  /**
   * Address: 0x00891840 (FUN_00891840, sub_891840)
   *
   * What it does:
   * Packs one blueprint path plus seven transform lanes into a prop-entry
   * storage record.
   */
  moho::CWldPropEntry*
  PackWldPropEntry(moho::CWldPropEntry& outEntry, const float packedTransformLanes[7], const msvc8::string& path)
  {
    outEntry.mBlueprintPath.assign_owned(path.c_str());
    for (std::size_t i = 0; i < 7; ++i) {
      outEntry.mTransformData[i] = packedTransformLanes[i];
    }
    return &outEntry;
  }

  void TickLoadingProgress(moho::CBackgroundTaskControl& loadControl)
  {
    if (loadControl.mHandle != nullptr) {
      loadControl.mHandle->UpdateLoadingProgress();
    }
  }
} // namespace

namespace moho
{
  extern float ren_SyncTerrainLOD;

  /**
   * Address: 0x00892210 (FUN_00892210, ?WLD_CreateProps@Moho@@YAPAVCWldProps@1@XZ)
   *
   * What it does:
   * Allocates one `CWldProps` object and initializes entry-storage pointer lanes
   * to null.
   */
  CWldProps* WLD_CreateProps()
  {
    auto* const rawStorage = static_cast<CWldProps*>(::operator new(sizeof(CWldProps), std::nothrow));
    if (rawStorage == nullptr) {
      return nullptr;
    }

    rawStorage->mEntriesBegin = nullptr;
    rawStorage->mEntriesEnd = nullptr;
    rawStorage->mEntriesCapacityEnd = nullptr;
    return rawStorage;
  }

  /**
   * Address: 0x008918E0 (FUN_008918E0,
   * ?Load@CWldProps@Moho@@QAE_NAAVBinaryReader@gpg@@AAVCBackgroundTaskControl@2@@Z)
   *
   * What it does:
   * Reads world-prop entries from stream, converts matrix orientation to a
   * normalized quaternion lane, and stores packed 7-float transform data for
   * each entry.
   */
  bool CWldProps::Load(gpg::BinaryReader& reader, CBackgroundTaskControl& loadControl)
  {
    (void)loadControl;

    std::uint32_t entryCount = 0;
    reader.ReadExact(entryCount);

    const CWldPropEntry defaultEntry = MakeDefaultWldPropEntry();
    ResizeWldPropsEntries(*this, entryCount, defaultEntry);

    for (std::uint32_t index = 0; index < entryCount; ++index) {
      msvc8::string blueprintPath;
      blueprintPath.tidy(false, 0U);
      reader.ReadString(&blueprintPath);

      float packedTransformLanes[7]{};
      reader.ReadExact(packedTransformLanes[4]);
      reader.ReadExact(packedTransformLanes[5]);
      reader.ReadExact(packedTransformLanes[6]);

      float matrix[3][3]{};
      matrix[0][0] = 1.0f;
      matrix[1][1] = 1.0f;
      matrix[2][2] = 1.0f;

      reader.ReadExact(matrix[0][0]);
      reader.ReadExact(matrix[0][1]);
      reader.ReadExact(matrix[0][2]);
      reader.ReadExact(matrix[1][0]);
      reader.ReadExact(matrix[1][1]);
      reader.ReadExact(matrix[1][2]);
      reader.ReadExact(matrix[2][0]);
      reader.ReadExact(matrix[2][1]);
      reader.ReadExact(matrix[2][2]);

      float ignoredLane0 = 0.0f;
      float ignoredLane1 = 0.0f;
      float ignoredLane2 = 0.0f;
      reader.ReadExact(ignoredLane0);
      reader.ReadExact(ignoredLane1);
      reader.ReadExact(ignoredLane2);

      QuaternionLanes orientation = QuaternionFromMatrixRows(matrix);
      NormalizeQuaternionLanes(orientation);

      packedTransformLanes[0] = orientation.w;
      packedTransformLanes[1] = orientation.x;
      packedTransformLanes[2] = orientation.y;
      packedTransformLanes[3] = orientation.z;

      PackWldPropEntry(mEntriesBegin[index], packedTransformLanes, blueprintPath);
    }

    return true;
  }

  /**
   * Address: 0x00891D50 (FUN_00891D50, ?Save@CWldProps@Moho@@QAE_NAAVBinaryWriter@gpg@@@Z)
   *
   * What it does:
   * Saves all prop entries as blueprint path + position + rotation matrix
   * lanes in the world-map binary format.
   */
  bool CWldProps::Save(gpg::BinaryWriter& writer) const
  {
    const std::int32_t propCount =
      mEntriesBegin != nullptr ? static_cast<std::int32_t>(mEntriesEnd - mEntriesBegin) : 0;
    writer.Write(propCount);

    for (std::int32_t index = 0; index < propCount; ++index) {
      const CWldPropEntry& entry = mEntriesBegin[index];
      writer.Write(entry.mBlueprintPath.c_str(), entry.mBlueprintPath.size() + 1u);

      const float* const transform = entry.mTransformData;
      writer.Write(transform[4]);
      writer.Write(transform[5]);
      writer.Write(transform[6]);

      const QuaternionLanes orientation{transform[0], transform[1], transform[2], transform[3]};
      float matrix[3][3]{};
      QuaternionToRotationRows(orientation, matrix);

      writer.Write(matrix[0][0]);
      writer.Write(matrix[0][1]);
      writer.Write(matrix[0][2]);
      writer.Write(matrix[1][0]);
      writer.Write(matrix[1][1]);
      writer.Write(matrix[1][2]);
      writer.Write(matrix[2][0]);
      writer.Write(matrix[2][1]);
      writer.Write(matrix[2][2]);

      constexpr float kScaleIdentity = 1.0f;
      writer.Write(kScaleIdentity);
      writer.Write(kScaleIdentity);
      writer.Write(kScaleIdentity);
    }

    return true;
  }

  /**
   * Address: 0x008902E0 (FUN_008902E0, ??0RWldMapPreviewChunk@Moho@@QAE@XZ)
   *
   * What it does:
   * Initializes preview texture ownership, preview size metadata, and preview name to
   * an empty state.
   */
  RWldMapPreviewChunk::RWldMapPreviewChunk()
    : mPreviewTexture()
    , mPreviewSize(0.0f, 0.0f)
    , mPreviewName()
  {
    mPreviewName.tidy(false, 0U);
  }

  /**
   * Address: 0x00890350 (FUN_00890350)
   * Mangled: ??0RWldMapPreviewChunk@Moho@@QAE@V?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@ABV?$Vector2@M@Wm3@@PBD@Z
   *
   * What it does:
   * Captures the provided texture-sheet handle, preview size, and preview
   * display name into this chunk.
   */
  RWldMapPreviewChunk::RWldMapPreviewChunk(
    boost::shared_ptr<ID3DTextureSheet> textureSheet, const Wm3::Vector2f& previewSize, const char* const previewName
  )
    : mPreviewTexture(textureSheet)
    , mPreviewSize(previewSize)
    , mPreviewName()
  {
    mPreviewName.tidy(false, 0U);
    mPreviewName.assign_owned(previewName);
  }

  /**
   * Address: 0x00890420 (FUN_00890420, ??1RWldMapPreviewChunk@Moho@@QAE@XZ)
   *
   * What it does:
   * Releases owned preview-name storage and drops preview texture ownership.
   */
  RWldMapPreviewChunk::~RWldMapPreviewChunk()
  {
    mPreviewName.tidy(true, 0U);
  }

  /**
   * Address: 0x00890480 (FUN_00890480, ?GetTextureSheet@RWldMapPreviewChunk@Moho@@QAE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
   *
   * What it does:
   * Returns one retained shared texture-sheet handle for this preview chunk.
   */
  boost::shared_ptr<ID3DTextureSheet> RWldMapPreviewChunk::GetTextureSheet()
  {
    return mPreviewTexture;
  }

  /**
   * Address: 0x008904A0 (FUN_008904A0, ?GetTerrainDim@RWldMapPreviewChunk@Moho@@QBE?AV?$Vector2@M@Wm3@@XZ)
   *
   * What it does:
   * Returns stored preview terrain dimensions.
   */
  Wm3::Vector2f RWldMapPreviewChunk::GetTerrainDim() const
  {
    return mPreviewSize;
  }

  /**
   * Address: 0x008904B0 (FUN_008904B0, ?GetDescription@RWldMapPreviewChunk@Moho@@QBEPBDXZ)
   *
   * What it does:
   * Returns preview description text buffer pointer.
   */
  const char* RWldMapPreviewChunk::GetDescription() const
  {
    return mPreviewName.c_str();
  }

  /**
   * Address: 0x008904C0 (FUN_008904C0,
   * ?Load@RWldMapPreviewChunk@Moho@@QAE_NAAVBinaryReader@gpg@@AAVCBackgroundTaskControl@2@@Z)
   *
   * What it does:
   * Loads optional preview metadata header (version/size/name), then loads the
   * remaining preview texture payload and resolves runtime texture ownership.
   */
  bool RWldMapPreviewChunk::Load(gpg::BinaryReader& reader, CBackgroundTaskControl& loadControl)
  {
    constexpr std::uint32_t kPreviewHeaderMagic = 0xBEEFFEEDU;
    constexpr const char* kPreviewSheetLocation = "_mappreview.dds";
    constexpr const char* kFallbackPreviewTexture = "/textures/engine/b_fails_to_load.dds";

    gpg::Stream* const stream = reader.stream();
    std::uint32_t previewChunkVersion = 0U;

    std::uint32_t maybeMagic = 0U;
    reader.ReadExact(maybeMagic);

    if (maybeMagic == kPreviewHeaderMagic) {
      reader.ReadExact(previewChunkVersion);

      if (previewChunkVersion >= 1U) {
        reader.ReadExact(mPreviewSize.x);
        reader.ReadExact(mPreviewSize.y);

        std::wstring previewNameWide;
        while (true) {
          std::uint16_t wideChar = 0U;
          reader.ReadExact(wideChar);
          if (wideChar == 0U) {
            break;
          }
          previewNameWide.push_back(static_cast<wchar_t>(wideChar));
        }

        const msvc8::string previewNameUtf8 = gpg::STR_WideToUtf8(previewNameWide.c_str());
        mPreviewName.assign_owned(previewNameUtf8.c_str());

        std::uint32_t metadataEntryCount = 0U;
        reader.ReadExact(metadataEntryCount);
        for (std::uint32_t i = 0; i < metadataEntryCount; ++i) {
          std::uint32_t metadataTag = 0U;
          std::uint32_t metadataValue = 0U;
          reader.ReadExact(metadataTag);
          reader.ReadExact(metadataValue);
        }
      }
    } else {
      stream->VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginCurr, -4);
    }

    TickLoadingProgress(loadControl);

    const std::uint64_t payloadStart = stream->VirtTell(gpg::Stream::ModeReceive);
    const std::uint64_t payloadEnd = stream->VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginEnd, 0);
    stream->VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginBegin, static_cast<std::int64_t>(payloadStart));

    const std::size_t remainingBytes =
      payloadEnd >= payloadStart ? static_cast<std::size_t>(payloadEnd - payloadStart) : 0U;

    std::size_t payloadSize = remainingBytes;
    if (previewChunkVersion >= 2U) {
      std::uint32_t explicitPayloadSize = 0U;
      reader.ReadExact(explicitPayloadSize);
      payloadSize = static_cast<std::size_t>(explicitPayloadSize);
      if (payloadSize > remainingBytes) {
        return false;
      }
    }

    ID3DDeviceResources::TextureResourceHandle previewTexture{};
    if (payloadSize != 0U) {
      std::vector<char> payloadBytes(payloadSize);
      reader.Read(payloadBytes.data(), payloadBytes.size());

      TickLoadingProgress(loadControl);

      CD3DDevice* const device = D3D_GetDevice();
      ID3DDeviceResources* const resources = device->GetResources();
      resources->GetTextureSheet(
        previewTexture,
        kPreviewSheetLocation,
        static_cast<void*>(payloadBytes.data()),
        payloadBytes.size()
      );
    } else {
      CD3DDevice* const device = D3D_GetDevice();
      ID3DDeviceResources* const resources = device->GetResources();
      resources->GetTexture(previewTexture, kFallbackPreviewTexture, 0, true);
    }

    mPreviewTexture = boost::static_pointer_cast<ID3DTextureSheet>(previewTexture);
    return mPreviewTexture.get() != nullptr;
  }

  /**
   * Address: 0x0089E710 (FUN_0089E710, ?GetPlayableMapRect@IWldTerrainRes@Moho@@UBE?AV?$Rect2@H@gpg@@XZ)
   *
   * What it does:
   * Copies playable map bounds from terrain-res internal storage into `outRect`
   * and returns `&outRect`.
   */
  const VisibilityRect* IWldTerrainRes::GetPlayableMapRect(VisibilityRect& outRect) const
  {
    const TerrainPlayableRectSource* const source = mPlayableRectSource;
    outRect = source->mPlayableRect;
    return &outRect;
  }

  /**
   * Address: 0x008A6DA0 (FUN_008A6DA0, ?SetPlayableMapRect@CWldTerrainRes@Moho@@EAEXABV?$Rect2@H@gpg@@@Z)
   *
   * What it does:
   * Writes one playable-map rectangle through the owned terrain map and emits
   * warning text when bounds are invalid.
   */
  bool IWldTerrainRes::SetPlayableMapRect(const VisibilityRect& rect)
  {
    STIMap* const map = reinterpret_cast<STIMap*>(mPlayableRectSource);
    if (map == nullptr) {
      return false;
    }

    const bool setOk = map->SetPlayableMapRect(rect.AsRect2i());
    if (!setOk) {
      gpg::Warnf("Attempting to set an invalid playable rect");
      return false;
    }

    return true;
  }

  /**
   * Address: 0x008A6DD0 (FUN_008A6DD0, ?IsInPlayableRect@CWldTerrainRes@Moho@@EAE_NABV?$Vector3@M@Wm3@@@Z)
   *
   * What it does:
   * Returns true when `worldPos` lies within the terrain playable rectangle.
   */
  bool IWldTerrainRes::IsInPlayableRect(const Wm3::Vec3f& worldPos)
  {
    const STIMap* const map = AsTerrainRuntimeView(this)->mMap;
    const gpg::Rect2i& playableRect = map->mPlayableRect;

    return static_cast<float>(playableRect.x0) <= worldPos.x
      && static_cast<float>(playableRect.z0) <= worldPos.z
      && worldPos.x <= static_cast<float>(playableRect.x1)
      && worldPos.z <= static_cast<float>(playableRect.z1);
  }

  /**
   * Address: 0x008A1080 (FUN_008A1080, ?SetBackground@CWldTerrainRes@Moho@@UAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
   *
   * What it does:
   * Stores terrain background texture path and resolves the corresponding D3D
   * texture resource handle.
   */
  void IWldTerrainRes::SetBackground(const msvc8::string& texturePath)
  {
    auto* const view = AsTerrainVisualResourceRuntimeView(this);
    view->mBackgroundFile = texturePath;

    ID3DDeviceResources::TextureResourceHandle texture{};
    if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
      if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
        resources->GetTexture(texture, texturePath.c_str(), 0, true);
      }
    }

    view->mBackgroundTexture = texture;
  }

  /**
   * Address: 0x008A11C0 (FUN_008A11C0, ?SetSkycube@CWldTerrainRes@Moho@@UAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
   *
   * What it does:
   * Stores terrain skycube texture path and resolves the corresponding D3D
   * texture resource handle.
   */
  void IWldTerrainRes::SetSkycube(const msvc8::string& texturePath)
  {
    auto* const view = AsTerrainVisualResourceRuntimeView(this);
    view->mSkycubeFile = texturePath;

    ID3DDeviceResources::TextureResourceHandle texture{};
    if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
      if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
        resources->GetTexture(texture, texturePath.c_str(), 0, true);
      }
    }

    view->mSkycubeTexture = texture;
  }

  /**
   * Address: 0x008A1190 (FUN_008A1190, ?GetBackground@CWldTerrainRes@Moho@@UBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
   *
   * What it does:
   * Returns one retained shared texture handle for terrain background.
   */
  boost::shared_ptr<ID3DTextureSheet> IWldTerrainRes::GetBackground() const
  {
    return boost::static_pointer_cast<ID3DTextureSheet>(AsTerrainRuntimeView(this)->mBackgroundTexture);
  }

  /**
   * Address: 0x008A12D0 (FUN_008A12D0, ?GetSkycube@CWldTerrainRes@Moho@@UBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
   *
   * What it does:
   * Returns one retained shared texture handle for terrain skycube.
   */
  boost::shared_ptr<ID3DTextureSheet> IWldTerrainRes::GetSkycube() const
  {
    return boost::static_pointer_cast<ID3DTextureSheet>(AsTerrainRuntimeView(this)->mSkycubeTexture);
  }

  /**
   * Address: 0x008A1300
   * (FUN_008A1300, ?AddEnvLookup@CWldTerrainRes@Moho@@UAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@0@Z)
   *
   * What it does:
   * Resolves one environment texture path and upserts it into terrain
   * environment lookup storage under the provided environment key.
   */
  void IWldTerrainRes::AddEnvLookup(const msvc8::string& environmentKey, const msvc8::string& texturePath)
  {
    ID3DDeviceResources::TextureResourceHandle texture;
    if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
      if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
        resources->GetTexture(texture, texturePath.c_str(), 0, true);
      }
    }

    const TerrainEnvironmentLookupEntry lookup(texturePath, texture);

    TerrainEnvironmentLookupMapRuntimeView& map = AsTerrainRuntimeView(this)->mEnvLookup;
    TerrainEnvironmentLookupNodeRuntimeView* const node = InsertTerrainEnvironmentNode(map, environmentKey);
    if (node == nullptr) {
      return;
    }

    node->mValue.mEnvironmentName.assign_owned(lookup.mEnvironmentName.view());
    node->mValue.mTexture = lookup.mTexture;
  }

  /**
   * Address: 0x008A13F0
   * (FUN_008A13F0, ?RemoveEnvLookup@CWldTerrainRes@Moho@@UAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
   *
   * What it does:
   * Removes one environment-lookup entry by key when the key exists.
   */
  void IWldTerrainRes::RemoveEnvLookup(const msvc8::string& environmentKey)
  {
    TerrainEnvironmentLookupMapRuntimeView& map = AsTerrainRuntimeView(this)->mEnvLookup;
    TerrainEnvironmentLookupNodeRuntimeView* const node = FindTerrainEnvironmentNodeOrHeadForErase(map, environmentKey);
    if (node == map.mHead) {
      return;
    }

    (void)EraseTerrainEnvironmentNode(map, node);
  }

  /**
   * Address: 0x008A1430
   * (FUN_008A1430, ?GetEnvLookup@CWldTerrainRes@Moho@@UBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
   *
   * What it does:
   * Returns one environment texture by key, with `<default>` fallback.
   */
  boost::shared_ptr<ID3DTextureSheet> IWldTerrainRes::GetEnvLookup(const msvc8::string& environmentKey) const
  {
    TerrainEnvironmentLookupMapRuntimeView& map =
      const_cast<TerrainEnvironmentLookupMapRuntimeView&>(AsTerrainRuntimeView(this)->mEnvLookup);

    TerrainEnvironmentLookupNodeRuntimeView* node = FindTerrainEnvironmentNodeOrHead(map, environmentKey);
    if (node == map.mHead) {
      const msvc8::string defaultKey("<default>");
      node = FindTerrainEnvironmentNodeOrHead(map, defaultKey);
    }

    if (node == nullptr || node == map.mHead) {
      return {};
    }
    return boost::static_pointer_cast<ID3DTextureSheet>(node->mValue.mTexture);
  }

  /**
   * Address: 0x008A8310 (FUN_008A8310)
   *
   * What it does:
   * Appends one `{key,name}` environment-lookup pair into the destination
   * vector and returns the inserted slot.
   */
  [[nodiscard]] moho::TerrainEnvironmentLookupPair* AppendEnvironmentLookupPair(
    moho::TerrainEnvironmentLookupPairs& outPairs,
    const moho::TerrainEnvironmentLookupPair& pair
  )
  {
    outPairs.push_back(pair);
    return outPairs.empty() ? nullptr : &outPairs.back();
  }

  /**
   * Address: 0x008A1500
   * (FUN_008A1500, ?EnumerateEnvLookup@CWldTerrainRes@Moho@@UBEXAAV?$vector@U?$pair@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V12@@std@@V?$allocator@U?$pair@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V12@@std@@@2@@std@@@Z)
   *
   * What it does:
   * Clears and rebuilds one destination list with all environment map
   * key/name pairs in RB-tree iteration order.
   */
  void IWldTerrainRes::EnumerateEnvLookup(TerrainEnvironmentLookupPairs& outPairs) const
  {
    auto& outPairsRuntime = msvc8::AsVectorRuntimeView(outPairs);
    moho::TerrainEnvironmentLookupPair* eraseResult = nullptr;
    (void)EraseTerrainEnvironmentLookupPairRange(
      outPairs,
      &eraseResult,
      outPairsRuntime.begin,
      outPairsRuntime.end
    );

    TerrainEnvironmentLookupMapRuntimeView& map =
      const_cast<TerrainEnvironmentLookupMapRuntimeView&>(AsTerrainRuntimeView(this)->mEnvLookup);
    TerrainEnvironmentLookupNodeRuntimeView* node = map.mHead != nullptr ? map.mHead->left : nullptr;
    while (node != nullptr && node != map.mHead) {
      (void)AppendEnvironmentLookupPair(
        outPairs,
        moho::TerrainEnvironmentLookupPair{node->mKey, node->mValue.mEnvironmentName}
      );
      node = IncrementTerrainEnvironmentNode(node, map.mHead);
    }
  }

  /**
   * Address: 0x008A1640
   * (FUN_008A1640, ?ClearEnvLookup@CWldTerrainRes@Moho@@UAEXXZ)
   *
   * What it does:
   * Clears all nodes rooted at the environment-lookup tree root and resets
   * head links/size to the empty-map sentinel state.
   */
  void IWldTerrainRes::ClearEnvLookup()
  {
    TerrainEnvironmentLookupMapRuntimeView& map = AsTerrainRuntimeView(this)->mEnvLookup;
    TerrainEnvironmentLookupNodeRuntimeView* const head = map.mHead;

    DeleteTerrainEnvironmentSubtreePostOrder(head->parent);

    head->parent = head;
    head->left = head;
    head->right = head;
    map.mSize = 0;
  }

  /**
   * Address: 0x008A1030 (FUN_008A1030, Moho::CWldTerrainRes::GetBool)
   *
   * What it does:
   * Returns the terrain runtime boolean lane at `+0x08`.
   */
  bool IWldTerrainRes::GetBool() const
  {
    return AsTerrainRuntimeView(this)->mBool != 0;
  }

  /**
   * Address: 0x008A1040 (FUN_008A1040, ?GetCartographic@CWldTerrainRes@Moho@@UAEAAVCartographic@2@XZ)
   *
   * What it does:
   * Returns mutable access to terrain cartographic runtime state.
   */
  Cartographic& IWldTerrainRes::GetCartographic()
  {
    return AsTerrainRuntimeView(this)->mCartographic;
  }

  /**
   * Address: 0x008A1050 (FUN_008A1050, ?GetCartographic@CWldTerrainRes@Moho@@UBEABVCartographic@2@XZ)
   *
   * What it does:
   * Returns read-only access to terrain cartographic runtime state.
   */
  const Cartographic& IWldTerrainRes::GetCartographic() const
  {
    return AsTerrainRuntimeView(this)->mCartographic;
  }

  /**
   * Address: 0x008A1060 (FUN_008A1060, ?GetSkyDome@CWldTerrainRes@Moho@@UAEAAVSkyDome@2@XZ)
   *
   * What it does:
   * Returns mutable access to terrain skydome runtime state.
   */
  SkyDome& IWldTerrainRes::GetSkyDome()
  {
    return AsTerrainRuntimeView(this)->mSkyDome;
  }

  /**
   * Address: 0x008A1070 (FUN_008A1070, ?GetSkyDome@CWldTerrainRes@Moho@@UBEABVSkyDome@2@XZ)
   *
   * What it does:
   * Returns read-only access to terrain skydome runtime state.
   */
  const SkyDome& IWldTerrainRes::GetSkyDome() const
  {
    return AsTerrainRuntimeView(this)->mSkyDome;
  }

  /**
   * Address: 0x008A1680 (FUN_008A1680, ?SetTopographicSamples@CWldTerrainRes@Moho@@UAEXH@Z)
   *
   * What it does:
   * Sets the active topographic sample-count lane.
   */
  void IWldTerrainRes::SetTopographicSamples(const std::int32_t sampleCount)
  {
    AsTerrainRuntimeView(this)->mTopographicSamples = sampleCount;
  }

  /**
   * Address: 0x008A1690 (FUN_008A1690, ?GetTopographicSamples@CWldTerrainRes@Moho@@UBEHXZ)
   *
   * What it does:
   * Returns the active topographic sample-count lane.
   */
  std::int32_t IWldTerrainRes::GetTopographicSamples() const
  {
    return AsTerrainRuntimeView(this)->mTopographicSamples;
  }

  /**
   * Address: 0x008A16A0
   * (FUN_008A16A0, ?SetHypsometricColor@CWldTerrainRes@Moho@@UAEXW4HYPSOMETRIC_COLOR@IWldTerrainRes@2@I@Z)
   *
   * What it does:
   * Writes one indexed hypsometric color lane.
   */
  void IWldTerrainRes::SetHypsometricColor(const std::int32_t colorIndex, const std::uint32_t colorValue)
  {
    AsTerrainRuntimeView(this)->mHypsometricColor[static_cast<std::size_t>(colorIndex)] = colorValue;
  }

  /**
   * Address: 0x008A16C0
   * (FUN_008A16C0, ?GetHypsometricColor@CWldTerrainRes@Moho@@UBEIW4HYPSOMETRIC_COLOR@IWldTerrainRes@2@@Z)
   *
   * What it does:
   * Returns one indexed hypsometric color lane.
   */
  std::uint32_t IWldTerrainRes::GetHypsometricColor(const std::int32_t colorIndex) const
  {
    return AsTerrainRuntimeView(this)->mHypsometricColor[static_cast<std::size_t>(colorIndex)];
  }

  /**
   * Address: 0x008A16D0 (FUN_008A16D0, ?SetImagerElevationOffset@CWldTerrainRes@Moho@@UAEXM@Z)
   *
   * What it does:
   * Sets the terrain imager elevation offset lane.
   */
  void IWldTerrainRes::SetImagerElevationOffset(const float elevationOffset)
  {
    AsTerrainRuntimeView(this)->mImagerElevationOffset = elevationOffset;
  }

  /**
   * Address: 0x008A16F0 (FUN_008A16F0, ?GetImagerElevationOffset@CWldTerrainRes@Moho@@UBEMXZ)
   *
   * What it does:
   * Returns the terrain imager elevation offset lane.
   */
  float IWldTerrainRes::GetImagerElevationOffset() const
  {
    return AsTerrainRuntimeView(this)->mImagerElevationOffset;
  }

  /**
   * Address: 0x008A5010 (FUN_008A5010, ?GetWaveSystem@CWldTerrainRes@Moho@@EAEPAVWaveSystem@2@XZ)
   *
   * What it does:
   * Returns the owned terrain wave-system object.
   */
  WaveSystem* IWldTerrainRes::GetWaveSystem()
  {
    return &AsTerrainRuntimeView(this)->mWaveSystem;
  }

  /**
   * Address: 0x008A5040 (FUN_008A5040, ?GetWaterMap@CWldTerrainRes@Moho@@UBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
   *
   * What it does:
   * Returns one retained shared texture handle for the terrain water map.
   */
  boost::shared_ptr<ID3DTextureSheet> IWldTerrainRes::GetWaterMap() const
  {
    return boost::static_pointer_cast<ID3DTextureSheet>(AsTerrainRuntimeView(this)->mWaterMapTexture);
  }

  /**
   * Address: 0x008A5070 (FUN_008A5070, ?GetWaterMapSize@CWldTerrainRes@Moho@@UBE?AV?$Vector2@M@Wm3@@XZ)
   *
   * What it does:
   * Returns half-resolution terrain water-map dimensions derived from current
   * heightfield extents.
   */
  Wm3::Vector2f IWldTerrainRes::GetWaterMapSize() const
  {
    const auto* const view = AsTerrainRuntimeView(this);
    const CHeightField* const field = view->mMap->mHeightField.get();
    const std::int32_t waterMapWidth = (field->width - 1) >> 1;
    const std::int32_t waterMapHeight = (field->height - 1) >> 1;
    return {static_cast<float>(waterMapWidth), static_cast<float>(waterMapHeight)};
  }

  /**
   * Address: 0x008A5020 (FUN_008A5020, ?UpdateWaveSystem@CWldTerrainRes@Moho@@UAEXABVGeomCamera3@2@MH@Z)
   *
   * What it does:
   * Forwards one camera/timestep update into terrain wave simulation.
   */
  void IWldTerrainRes::UpdateWaveSystem(const GeomCamera3& camera, const float elapsedSeconds, const std::int32_t tick)
  {
    (void)camera;
    (void)elapsedSeconds;
    (void)tick;
  }

  /**
   * Address: 0x008A54B0 (FUN_008A54B0, ?GetDebugDirtyTerrain@CWldTerrainRes@Moho@@EAEPAVBitArray2D@gpg@@XZ)
   *
   * What it does:
   * Returns debug dirty-region bitmask storage.
   */
  gpg::BitArray2D* IWldTerrainRes::GetDebugDirtyTerrain()
  {
    return AsTerrainRuntimeView(this)->mDebugDirtyTerrain;
  }

  /**
   * Address: 0x008A54C0 (FUN_008A54C0, ?GetDebugDirtyRects@CWldTerrainRes@Moho@@UBEABV?$list@V?$Rect2@H@gpg@@V?$allocator@V?$Rect2@H@gpg@@@std@@@std@@XZ)
   *
   * What it does:
   * Returns the debug dirty-rectangle list lane.
   */
  const msvc8::list<gpg::Rect2i>& IWldTerrainRes::GetDebugDirtyRects() const
  {
    const TerrainDirtyRectListRuntimeView* const dirtyList = &AsTerrainRuntimeView(this)->mDebugDirtyRects;
    return *reinterpret_cast<const msvc8::list<gpg::Rect2i>*>(dirtyList);
  }

  /**
   * Address: 0x008A5FB0 (FUN_008A5FB0, ?GetNormalMapCount@CWldTerrainRes@Moho@@EAEHXZ)
   *
   * What it does:
   * Returns number of active normal-map tile handles.
   */
  std::int32_t IWldTerrainRes::GetNormalMapCount()
  {
    const auto* const view = AsTerrainRuntimeView(this);
    if (view->mNormalMap.mBegin == nullptr) {
      return 0;
    }
    return static_cast<std::int32_t>(view->mNormalMap.mEnd - view->mNormalMap.mBegin);
  }

  /**
   * Address: 0x00811210 (FUN_00811210, Moho::CWldTerrainRes::GetHeightAt)
   *
   * What it does:
   * Returns one clamped terrain height sample converted into world-space
   * height units (`heightWord * 1/128`).
   */
  float IWldTerrainRes::GetHeightAt(const std::int32_t x, const std::int32_t z) const
  {
    const auto* const view = AsTerrainRuntimeView(this);
    const CHeightField* const field = view->mMap->mHeightField.get();
    return static_cast<float>(field->GetHeightAt(x, z)) * 0.0078125f;
  }

  /**
   * Address: 0x008A6A60 (FUN_008A6A60, ?GetWorldBounds@CWldTerrainRes@Moho@@EBE?AV?$AxisAlignedBox3@M@Wm3@@XZ)
   *
   * What it does:
   * Returns world bounds computed from the terrain heightfield hierarchy.
   */
  Wm3::AxisAlignedBox3f IWldTerrainRes::GetWorldBounds() const
  {
    const auto* const view = AsTerrainRuntimeView(this);
    const CHeightField* const field = view->mMap->mHeightField.get();
    if (field == nullptr) {
      return Wm3::AxisAlignedBox3f{};
    }

    const CHeightFieldTier* const firstTier = field->mGrids.begin();
    const std::int32_t tierCount = firstTier != nullptr
                                     ? static_cast<std::int32_t>(field->mGrids.end() - firstTier)
                                     : 0;
    return BuildTerrainTierBoundsFromHeightfield(*field, tierCount, 0, 0);
  }

  /**
   * Address: 0x008A6AB0 (FUN_008A6AB0, ?GetLightingMultiplier@CWldTerrainRes@Moho@@UBEMXZ)
   *
   * What it does:
   * Returns terrain lighting multiplier.
   */
  float IWldTerrainRes::GetLightingMultiplier() const
  {
    return AsTerrainRuntimeView(this)->mLightingMultiplier;
  }

  /**
   * Address: 0x008A6AC0 (FUN_008A6AC0, ?SetLightingMultiplier@CWldTerrainRes@Moho@@EAEXABM@Z)
   *
   * What it does:
   * Sets terrain lighting multiplier.
   */
  void IWldTerrainRes::SetLightingMultiplier(const float& multiplier)
  {
    AsTerrainRuntimeView(this)->mLightingMultiplier = multiplier;
  }

  /**
   * Address: 0x008A6AD0 (FUN_008A6AD0, ?GetSunDirection@CWldTerrainRes@Moho@@EBE?AV?$Vector3@M@Wm3@@XZ)
   *
   * What it does:
   * Returns sun direction vector.
   */
  Wm3::Vector3f IWldTerrainRes::GetSunDirection() const
  {
    return AsTerrainRuntimeView(this)->mSunDirection;
  }

  /**
   * Address: 0x008A6B00 (FUN_008A6B00, ?SetSunDirection@CWldTerrainRes@Moho@@EAEXABV?$Vector3@M@Wm3@@@Z)
   *
   * What it does:
   * Sets sun direction vector.
   */
  void IWldTerrainRes::SetSunDirection(const Wm3::Vector3f& direction)
  {
    AsTerrainRuntimeView(this)->mSunDirection = direction;
  }

  /**
   * Address: 0x008A6B30 (FUN_008A6B30, ?GetSunAmbience@CWldTerrainRes@Moho@@EBE?AV?$Vector3@M@Wm3@@XZ)
   *
   * What it does:
   * Returns sun ambience vector.
   */
  Wm3::Vector3f IWldTerrainRes::GetSunAmbience() const
  {
    return AsTerrainRuntimeView(this)->mSunAmbience;
  }

  /**
   * Address: 0x008A6B60 (FUN_008A6B60, ?SetSunAmbience@CWldTerrainRes@Moho@@EAEXABV?$Vector3@M@Wm3@@@Z)
   *
   * What it does:
   * Sets sun ambience vector.
   */
  void IWldTerrainRes::SetSunAmbience(const Wm3::Vector3f& ambience)
  {
    AsTerrainRuntimeView(this)->mSunAmbience = ambience;
  }

  /**
   * Address: 0x008A6B90 (FUN_008A6B90, ?GetSpecularColor@CWldTerrainRes@Moho@@EBE?AVVector4f@2@XZ)
   *
   * What it does:
   * Returns terrain specular color vector.
   */
  Vector4f IWldTerrainRes::GetSpecularColor() const
  {
    return AsTerrainRuntimeView(this)->mSpecularColor;
  }

  /**
   * Address: 0x008A6BC0 (FUN_008A6BC0, ?SetSpecularColor@CWldTerrainRes@Moho@@EAEXABVVector4f@2@@Z)
   *
   * What it does:
   * Sets terrain specular color vector.
   */
  void IWldTerrainRes::SetSpecularColor(const Vector4f& color)
  {
    AsTerrainRuntimeView(this)->mSpecularColor = color;
  }

  /**
   * Address: 0x008A6BF0 (FUN_008A6BF0, ?GetBloom@CWldTerrainRes@Moho@@UBEMXZ)
   *
   * What it does:
   * Returns terrain bloom strength lane.
   */
  float IWldTerrainRes::GetBloom() const
  {
    return AsTerrainRuntimeView(this)->mBloom;
  }

  /**
   * Address: 0x008A6C00 (FUN_008A6C00, ?SetBloom@CWldTerrainRes@Moho@@EAEXM@Z)
   *
   * What it does:
   * Sets terrain bloom strength lane.
   */
  void IWldTerrainRes::SetBloom(const float bloom)
  {
    AsTerrainRuntimeView(this)->mBloom = bloom;
  }

  /**
   * Address: 0x008A6C20 (FUN_008A6C20, ?GetFogInfo@CWldTerrainRes@Moho@@EBEABUSFogInfo@2@XZ)
   *
   * What it does:
   * Returns read-only terrain fog parameter block.
   */
  const SFogInfo& IWldTerrainRes::GetFogInfo() const
  {
    return AsTerrainRuntimeView(this)->mFogInfo;
  }

  /**
   * Address: 0x008A6C30 (FUN_008A6C30, ?SetFogInfo@CWldTerrainRes@Moho@@EAEXABUSFogInfo@2@@Z)
   *
   * What it does:
   * Updates primary terrain fog parameter lanes.
   */
  void IWldTerrainRes::SetFogInfo(const SFogInfo& fogInfo)
  {
    auto* const view = AsTerrainRuntimeView(this);
    view->mFogInfo.mStartDistance = fogInfo.mStartDistance;
    view->mFogInfo.mCutoffDistance = fogInfo.mCutoffDistance;
    view->mFogInfo.mMinClamp = fogInfo.mMinClamp;
    view->mFogInfo.mMaxClamp = fogInfo.mMaxClamp;
    view->mFogInfo.mCurveExponent = fogInfo.mCurveExponent;
  }

  /**
   * Address: 0x008A6C70 (FUN_008A6C70, ?GetSunColor@CWldTerrainRes@Moho@@EBE?AV?$Vector3@M@Wm3@@XZ)
   *
   * What it does:
   * Returns sun color vector.
   */
  Wm3::Vector3f IWldTerrainRes::GetSunColor() const
  {
    return AsTerrainRuntimeView(this)->mSunColor;
  }

  /**
   * Address: 0x008A6CA0 (FUN_008A6CA0, ?SetSunColor@CWldTerrainRes@Moho@@EAEXABV?$Vector3@M@Wm3@@@Z)
   *
   * What it does:
   * Sets sun color vector.
   */
  void IWldTerrainRes::SetSunColor(const Wm3::Vector3f& color)
  {
    AsTerrainRuntimeView(this)->mSunColor = color;
  }

  /**
   * Address: 0x008A6CD0 (FUN_008A6CD0, ?GetShadowFillColor@CWldTerrainRes@Moho@@EBE?AV?$Vector3@M@Wm3@@XZ)
   *
   * What it does:
   * Returns shadow-fill color vector.
   */
  Wm3::Vector3f IWldTerrainRes::GetShadowFillColor() const
  {
    return AsTerrainRuntimeView(this)->mShadowFillColor;
  }

  /**
   * Address: 0x008A6D00 (FUN_008A6D00, ?SetShadowFillColor@CWldTerrainRes@Moho@@EAEXABV?$Vector3@M@Wm3@@@Z)
   *
   * What it does:
   * Sets shadow-fill color vector.
   */
  void IWldTerrainRes::SetShadowFillColor(const Wm3::Vector3f& color)
  {
    AsTerrainRuntimeView(this)->mShadowFillColor = color;
  }

  /**
   * Address: 0x008A6D30 (FUN_008A6D30, ?WaterEnabled@CWldTerrainRes@Moho@@EAEX_N@Z)
   *
   * What it does:
   * Toggles world-map water rendering/logic enabled flag.
   */
  void IWldTerrainRes::WaterEnabled(const bool enabled)
  {
    AsTerrainRuntimeView(this)->mMap->mWaterEnabled = static_cast<std::uint8_t>(enabled ? 1u : 0u);
  }

  /**
   * Address: 0x008A6D40 (FUN_008A6D40, ?SetWaterElevation@CWldTerrainRes@Moho@@EAEXM@Z)
   *
   * What it does:
   * Sets world-map surface water elevation.
   */
  void IWldTerrainRes::SetWaterElevation(const float elevation)
  {
    AsTerrainRuntimeView(this)->mMap->mWaterElevation = elevation;
  }

  /**
   * Address: 0x008A6D60 (FUN_008A6D60, ?SetWaterElevationDeep@CWldTerrainRes@Moho@@EAEXM@Z)
   *
   * What it does:
   * Sets world-map deep-water threshold elevation.
   */
  void IWldTerrainRes::SetWaterElevationDeep(const float elevation)
  {
    AsTerrainRuntimeView(this)->mMap->mWaterElevationDeep = elevation;
  }

  /**
   * Address: 0x008A6D80 (FUN_008A6D80, ?SetWaterElevationAbyss@CWldTerrainRes@Moho@@EAEXM@Z)
   *
   * What it does:
   * Sets world-map abyss-water threshold elevation.
   */
  void IWldTerrainRes::SetWaterElevationAbyss(const float elevation)
  {
    AsTerrainRuntimeView(this)->mMap->mWaterElevationAbyss = elevation;
  }

  /**
   * Address: 0x008A6E20 (FUN_008A6E20, ?SetWaterShaderProperties@CWldTerrainRes@Moho@@EAEXABVCWaterShaderProperties@2@@Z)
   *
   * What it does:
   * Copies one water-shader property block into terrain state.
   */
  void IWldTerrainRes::SetWaterShaderProperties(const CWaterShaderProperties& properties)
  {
    auto* const view = AsTerrainRuntimeView(this);
    if (&properties != &view->mWaterShaderProperties) {
      view->mWaterShaderProperties.~CWaterShaderProperties();
      new (&view->mWaterShaderProperties) CWaterShaderProperties(properties);
    }
  }

  /**
   * Address: 0x008A6E40 (FUN_008A6E40, ?GetWaterShaderProperties@CWldTerrainRes@Moho@@EAEPAVCWaterShaderProperties@2@XZ)
   *
   * What it does:
   * Returns mutable pointer to the owned water-shader property block.
   */
  CWaterShaderProperties* IWldTerrainRes::GetWaterShaderProperties()
  {
    return &AsTerrainRuntimeView(this)->mWaterShaderProperties;
  }

  /**
   * Address: 0x008A6E50 (FUN_008A6E50, ?GetWaterFoam@CWldTerrainRes@Moho@@EAEPAEZX)
   *
   * What it does:
   * Returns terrain water-foam mask buffer.
   */
  std::uint8_t* IWldTerrainRes::GetWaterFoam()
  {
    return AsTerrainRuntimeView(this)->mWaterFoam;
  }

  /**
   * Address: 0x008A6E60 (FUN_008A6E60, ?GetWaterFlatness@CWldTerrainRes@Moho@@EAEPAEZX)
   *
   * What it does:
   * Returns terrain water-flatness mask buffer.
   */
  std::uint8_t* IWldTerrainRes::GetWaterFlatness()
  {
    return AsTerrainRuntimeView(this)->mWaterFlatness;
  }

  /**
   * Address: 0x008A6E80 (FUN_008A6E80, ?IsInEditMode@CWldTerrainRes@Moho@@EBE_NXZ)
   *
   * What it does:
   * Returns true when terrain-resource edit mode is enabled.
   */
  bool IWldTerrainRes::IsInEditMode() const
  {
    return AsTerrainRuntimeView(this)->mEditMode != 0;
  }

  /**
   * Address: 0x008A6E90 (FUN_008A6E90, ?EnterEditMode@CWldTerrainRes@Moho@@EAEXAAVCBackgroundTaskControl@2@@Z)
   *
   * What it does:
   * Enables terrain edit mode, prepares packed edit-word storage, clones
   * editable stratum/water textures, then rebuilds full water-map contents.
   */
  void IWldTerrainRes::EnterEditMode(CBackgroundTaskControl& loadControl)
  {
    (void)loadControl;

    auto* const runtimeView = AsTerrainRuntimeView(this);
    auto* const normalView = AsTerrainNormalMapRuntimeView(this);
    auto* const visualView = AsTerrainVisualResourceRuntimeView(this);

    runtimeView->mEditMode = 1;

    const CHeightField* const field = normalView->mMap->mHeightField.get();
    const std::int64_t cellCount = static_cast<std::int64_t>(field->width - 1) * static_cast<std::int64_t>(field->height - 1);
    const std::size_t wordCount = cellCount > 0 ? static_cast<std::size_t>(cellCount >> 2) : 0u;
    EnsureTerrainEditWordCount(visualView->mEditWordBuffer, wordCount, 0u);

    CloneTerrainDynamicTextureForEdit(normalView->mStratumMask0, false);
    CloneTerrainDynamicTextureForEdit(normalView->mStratumMask1, false);
    CloneTerrainDynamicTextureForEdit(visualView->mWaterMapTexture, false);

    gpg::Rect2i fullRect{
      static_cast<std::int32_t>(0x80000000u),
      static_cast<std::int32_t>(0x80000000u),
      0x7FFFFFFF,
      0x7FFFFFFF
    };
    UpdateWaterMap(fullRect);
  }

  /**
   * Address: 0x008A7130 (FUN_008A7130, ?ExitEditMode@CWldTerrainRes@Moho@@EAEXXZ)
   *
   * What it does:
   * Flushes packed edit-word pixels into water-map texture, clears edit-mode
   * flag, and restores runtime texture instances.
   */
  void IWldTerrainRes::ExitEditMode()
  {
    auto* const runtimeView = AsTerrainRuntimeView(this);
    auto* const normalView = AsTerrainNormalMapRuntimeView(this);
    auto* const visualView = AsTerrainVisualResourceRuntimeView(this);

    UpdateTexture(visualView->mWaterMapTexture, visualView->mEditWordBuffer.begin);

    runtimeView->mEditMode = 0;
    if (visualView->mEditWordBuffer.begin != visualView->mEditWordBuffer.end) {
      visualView->mEditWordBuffer.end = visualView->mEditWordBuffer.begin;
    }

    CloneTerrainDynamicTextureForEdit(normalView->mStratumMask0, true);
    CloneTerrainDynamicTextureForEdit(normalView->mStratumMask1, true);
    CloneTerrainDynamicTextureForEdit(visualView->mWaterMapTexture, true);
  }

  /**
   * Address: 0x008A74D0 (FUN_008A74D0, IWldTerrainRes ctor lane)
   *
   * What it does:
   * Initializes one terrain-resource interface base and clears playable-rect
   * source ownership to null.
   */
  IWldTerrainRes::IWldTerrainRes()
    : mPlayableRectSource(nullptr)
  {}

  /**
   * Address: 0x008A7400 (FUN_008A7400, ?GetDecalManager@CWldTerrainRes@Moho@@EAEPAVIDecalManager@2@XZ)
   *
   * What it does:
   * Returns terrain decal-manager lane.
   */
  IDecalManager* IWldTerrainRes::GetDecalManager()
  {
    return reinterpret_cast<IDecalManager*>(AsTerrainRuntimeView(this)->mDecalManager);
  }

  /**
   * Address: 0x008A7410 (FUN_008A7410, ?CreateWaterMasks@CWldTerrainRes@Moho@@AAEXHH@Z)
   *
   * What it does:
   * Reallocates water foam/flatness/depth-bias mask lanes and initializes each
   * lane to binary default fill values (0x00/0xFF/0x7F).
   */
  void IWldTerrainRes::CreateWaterMasks(const std::int32_t width, const std::int32_t height)
  {
    const std::uint32_t maskSizeBytes = static_cast<std::uint32_t>(width * height);
    auto* const view = AsTerrainVisualResourceRuntimeView(this);

    auto* const newWaterFoam = static_cast<std::uint8_t*>(::operator new(maskSizeBytes));
    std::uint8_t* const oldWaterFoam = view->mWaterFoam;
    view->mWaterFoam = newWaterFoam;
    ::operator delete[](oldWaterFoam);
    std::memset(view->mWaterFoam, 0, maskSizeBytes);

    auto* const newWaterFlatness = static_cast<std::uint8_t*>(::operator new(maskSizeBytes));
    std::uint8_t* const oldWaterFlatness = view->mWaterFlatness;
    view->mWaterFlatness = newWaterFlatness;
    ::operator delete[](oldWaterFlatness);
    std::memset(view->mWaterFlatness, 0xFF, maskSizeBytes);

    auto* const newWaterDepthBias = static_cast<std::uint8_t*>(::operator new(maskSizeBytes));
    std::uint8_t* const oldWaterDepthBias = view->mWaterDepthBias;
    view->mWaterDepthBias = newWaterDepthBias;
    ::operator delete[](oldWaterDepthBias);
    std::memset(view->mWaterDepthBias, 0x7F, maskSizeBytes);
  }

  /**
   * Address: 0x008A50C0 (FUN_008A50C0, ?UpdateWaterMap@CWldTerrainRes@Moho@@UAEXXZ)
   *
   * What it does:
   * Rebuilds the full water-map texture area by forwarding sentinel bounds to
   * the rectangle lane.
   */
  void IWldTerrainRes::UpdateWaterMap()
  {
    gpg::Rect2i fullRect{};
    fullRect.x0 = static_cast<std::int32_t>(0x80000000u);
    fullRect.z0 = static_cast<std::int32_t>(0x80000000u);
    fullRect.x1 = 0x7FFFFFFF;
    fullRect.z1 = 0x7FFFFFFF;
    UpdateWaterMap(fullRect);
  }

  /**
   * Address: 0x008A50F0 (FUN_008A50F0, ?UpdateWaterMap@CWldTerrainRes@Moho@@UAEXABV?$Rect2@H@gpg@@@Z)
   *
   * What it does:
   * Rebuilds one caller-provided rectangle of the water-map texture.
   */
  void IWldTerrainRes::UpdateWaterMap(const gpg::Rect2i& rect)
  {
    RebuildWaterMapRect(*this, rect);
  }

  /**
   * Address: 0x008A5130 (FUN_008A5130, ?UpdateWaterMap@CWldTerrainRes@Moho@@QAEXAAVCBackgroundTaskControl@2@ABV?$Rect2@H@gpg@@@Z)
   *
   * What it does:
   * Rebuilds one caller-provided rectangle of the water-map texture while
   * preserving the original (unused) background-task-control signature lane.
   */
  void IWldTerrainRes::UpdateWaterMap(CBackgroundTaskControl& loadControl, const gpg::Rect2i& rect)
  {
    (void)loadControl;
    RebuildWaterMapRect(*this, rect);
  }

  /**
   * Address: 0x008A54D0 (FUN_008A54D0, ?InitNormalMap@CWldTerrainRes@Moho@@AAEXAAVCBackgroundTaskControl@2@@Z)
   *
   * What it does:
   * Computes normal-map tile dimensions/count, allocates one dynamic texture
   * per tile, then rebuilds full normal-map coverage.
   */
  void IWldTerrainRes::InitNormalMap(CBackgroundTaskControl& loadControl)
  {
    auto* const normalView = AsTerrainNormalMapRuntimeView(this);
    CHeightField* const field = normalView->mMap->mHeightField.get();

    const std::int32_t widthMinusOne = field->width - 1;
    const std::int32_t heightMinusOne = field->height - 1;

    const std::int32_t tileWidth = (widthMinusOne <= 2048) ? widthMinusOne : 2048;
    const std::int32_t tileHeight = (heightMinusOne <= 2048) ? heightMinusOne : 2048;

    normalView->mNormalMapWidth = tileWidth;
    normalView->mNormalMapHeight = tileHeight;

    if (tileWidth <= 0 || tileHeight <= 0 || widthMinusOne <= 0 || heightMinusOne <= 0) {
      ResizeNormalMapHandleStorage(normalView->mNormalMap, 0u);
      return;
    }

    const std::size_t tileCountX = static_cast<std::size_t>((tileWidth + widthMinusOne - 1) / tileWidth);
    const std::size_t tileCountY = static_cast<std::size_t>((tileHeight + heightMinusOne - 1) / tileHeight);
    const std::size_t tileCount = tileCountX * tileCountY;

    ResizeNormalMapHandleStorage(normalView->mNormalMap, tileCount);

    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    moho::ID3DDeviceResources* const resources = device != nullptr ? device->GetResources() : nullptr;

    for (std::size_t i = 0; i < tileCount; ++i) {
      boost::shared_ptr<CD3DDynamicTextureSheet> texture{};
      if (resources != nullptr) {
        (void)resources->NewDynamicTextureSheet(texture, tileWidth, tileHeight, 12);
      }

      normalView->mNormalMap.mBegin[i] = texture;
      if (normalView->mNormalMap.mBegin[i].get() == nullptr) {
        // Original binary at 0x008A5715 constructs one default-shaped
        // gpg::gal::Error via the 0x00940560 ctor then `_CxxThrowException`s it.
        throw gpg::gal::Error{};
      }
    }

    gpg::Rect2i fullRect{};
    fullRect.x0 = 0;
    fullRect.z0 = 0;
    fullRect.x1 = widthMinusOne;
    fullRect.z1 = heightMinusOne;
    UpdateNormalMap(loadControl, fullRect);
  }

  /**
   * Address: 0x008A5890 (FUN_008A5890, ?SyncTerrain@CWldTerrainRes@Moho@@EAEXPBVCHeightField@2@@Z)
   *
   * What it does:
   * Syncs queued dirty terrain rectangles from a source heightfield into the
   * active map field for camera-visible regions and updates dirty/error lanes.
   */
  void IWldTerrainRes::SyncTerrain(const CHeightField* const source)
  {
    RCamManager* const cameraManager = CAM_GetManager();
    CameraImpl* const camera = cameraManager != nullptr ? cameraManager->GetCamera("WorldCamera") : nullptr;
    if (camera == nullptr || camera->CameraGetTargetZoom() > ren_SyncTerrainLOD) {
      return;
    }

    auto* const runtimeView = AsTerrainRuntimeView(this);
    CHeightField* const field = runtimeView->mMap->mHeightField.get();
    const Wm3::AxisAlignedBox3f cameraAabb = field->ConvexIntersection(camera->CameraGetView().solid2);

    gpg::Rect2i cameraRect{};
    cameraRect.x0 = static_cast<std::int32_t>(std::floor(cameraAabb.Min.x));
    cameraRect.z0 = static_cast<std::int32_t>(std::floor(cameraAabb.Min.z));
    cameraRect.x1 = static_cast<std::int32_t>(std::ceil(cameraAabb.Max.x));
    cameraRect.z1 = static_cast<std::int32_t>(std::ceil(cameraAabb.Max.z));

    UserArmy* const focusArmy = WLD_GetActiveSession()->GetFocusArmy();

    auto* const visualView = AsTerrainVisualResourceRuntimeView(this);
    TerrainDirtyRectListRuntimeView& dirtyList = visualView->mDebugDirtyRects;
    TerrainDirtyRectNodeRuntimeView* current = dirtyList.mHead->mNext;

    bool syncedAnyRect = false;
    gpg::Rect2i syncedBounds{};

    while (current != dirtyList.mHead) {
      TerrainDirtyRectNodeRuntimeView* const next = current->mNext;
      const gpg::Rect2i dirtyRect = current->mValue;

      if (
        ShouldSyncDirtyRectInCameraBounds(dirtyRect, cameraRect)
        && TerrainRectVisibleForFocusArmy(dirtyRect, focusArmy)
      ) {
        const std::int32_t sourceOffset = dirtyRect.x0 + dirtyRect.z0 * field->width;
        field->SetElevationRectRaw(dirtyRect, source->data + sourceOffset, field->width);

        visualView->mDebugDirtyTerrain->FillRect(
          dirtyRect.x0 / 2,
          dirtyRect.z0 / 2,
          (dirtyRect.x1 / 2) - (dirtyRect.x0 / 2),
          (dirtyRect.z1 / 2) - (dirtyRect.z0 / 2),
          false
        );

        field->UpdateBounds(dirtyRect);

        if (syncedAnyRect) {
          if (syncedBounds.x0 > dirtyRect.x0) {
            syncedBounds.x0 = dirtyRect.x0;
          }
          if (syncedBounds.x1 < dirtyRect.x1) {
            syncedBounds.x1 = dirtyRect.x1;
          }
          if (syncedBounds.z0 > dirtyRect.z0) {
            syncedBounds.z0 = dirtyRect.z0;
          }
          if (syncedBounds.z1 < dirtyRect.z1) {
            syncedBounds.z1 = dirtyRect.z1;
          }
        } else {
          syncedBounds = dirtyRect;
          syncedAnyRect = true;
        }

        EraseTerrainDirtyRectNode(dirtyList, current);
      }

      current = next;
    }

    if (syncedAnyRect) {
      field->UpdateError(syncedBounds);
    }
  }

  /**
   * Address: 0x008A5BC0 (FUN_008A5BC0, ?UpdateNormalMap@CWldTerrainRes@Moho@@EAEXABV?$Rect2@H@gpg@@@Z)
   *
   * What it does:
   * Rebuilds one caller-provided normal-map rectangle with a null progress lane.
   */
  void IWldTerrainRes::UpdateNormalMap(const gpg::Rect2i& rect)
  {
    CBackgroundTaskControl loadControl{};
    loadControl.mHandle = nullptr;
    UpdateNormalMap(loadControl, rect);
  }

  /**
   * Address: 0x008A5BE0 (FUN_008A5BE0, ?UpdateNormalMap@CWldTerrainRes@Moho@@AAEXAAVCBackgroundTaskControl@2@ABV?$Rect2@H@gpg@@@Z)
   *
   * What it does:
   * Rebuilds one clipped normal-map rectangle across all normal-map tiles and
   * encodes each 4x4 block to DXT payload lanes.
   */
  void IWldTerrainRes::UpdateNormalMap(CBackgroundTaskControl& loadControl, const gpg::Rect2i& rect)
  {
    auto* const normalView = AsTerrainNormalMapRuntimeView(this);
    const std::int32_t tileWidth = normalView->mNormalMapWidth;
    const std::int32_t tileHeight = normalView->mNormalMapHeight;
    if (tileWidth <= 0 || tileHeight <= 0) {
      return;
    }

    CHeightField* const field = normalView->mMap->mHeightField.get();
    if (field == nullptr || field->width <= 1 || field->height <= 1) {
      return;
    }

    const std::size_t tileCount = static_cast<std::size_t>(normalView->mNormalMap.mEnd - normalView->mNormalMap.mBegin);
    std::size_t tileIndex = 0u;

    for (std::int32_t tileZBase = 0; tileZBase < field->height - 1; tileZBase += tileHeight) {
      const std::int32_t tileZEnd = tileZBase + tileHeight;
      for (std::int32_t tileXBase = 0; tileXBase < field->width - 1; tileXBase += tileWidth, ++tileIndex) {
        if (tileIndex >= tileCount) {
          return;
        }

        const std::int32_t tileXEnd = tileXBase + tileWidth;

        std::int32_t clippedX0 = tileXBase;
        if (clippedX0 < rect.x0) {
          clippedX0 = rect.x0;
        }
        std::int32_t clippedX1 = tileXEnd;
        if (clippedX1 > rect.x1) {
          clippedX1 = rect.x1;
        }

        std::int32_t clippedZ0 = tileZBase;
        if (clippedZ0 < rect.z0) {
          clippedZ0 = rect.z0;
        }
        std::int32_t clippedZ1 = tileZEnd;
        if (clippedZ1 > rect.z1) {
          clippedZ1 = rect.z1;
        }

        if (clippedX0 >= clippedX1 || clippedZ0 >= clippedZ1) {
          continue;
        }

        boost::shared_ptr<CD3DDynamicTextureSheet> texture = normalView->mNormalMap.mBegin[tileIndex];
        CD3DDynamicTextureSheet* const sheet = texture.get();
        if (sheet == nullptr) {
          continue;
        }

        gpg::Rect2i lockRect{};
        lockRect.x0 = AlignDownTo4(clippedX0 - tileXBase);
        lockRect.z0 = AlignDownTo4(clippedZ0 - tileZBase);
        lockRect.x1 = AlignUpTo4(clippedX1 - tileXBase);
        lockRect.z1 = AlignUpTo4(clippedZ1 - tileZBase);

        std::uint32_t pitchBytes = 0;
        void* mappedBits = nullptr;
        if (!sheet->LockRect(reinterpret_cast<const RECT*>(&lockRect), &pitchBytes, &mappedBits)) {
          continue;
        }

        auto* blockRowBytes = static_cast<std::uint8_t*>(mappedBits);
        for (std::int32_t localZ = lockRect.z0; localZ < lockRect.z1; localZ += 4) {
          auto* blockOutput = reinterpret_cast<std::uint64_t*>(blockRowBytes);
          for (std::int32_t localX = lockRect.x0; localX < lockRect.x1; localX += 4) {
            TerrainNormalEncodeBlock block{};

            for (std::int32_t sampleRow = 0; sampleRow < 4; ++sampleRow) {
              const std::int32_t rowOffset = sampleRow * 4;
              for (std::int32_t sampleCol = 0; sampleCol < 4; ++sampleCol) {
                const float worldX = static_cast<float>(tileXBase + localX + sampleCol) + 0.5f;
                const float worldZ = static_cast<float>(tileZBase + localZ + sampleRow) + 0.5f;
                const Wm3::Vec3f normal = field->GetNormal(worldX, worldZ);
                const std::int32_t sampleIndex = rowOffset + sampleCol;
                block.mNormalX[sampleIndex] = EncodeNormalLaneByte(normal.x);
                block.mNormalZ[sampleIndex] = EncodeNormalLaneByte(normal.z);
              }
            }

            *blockOutput++ = moho::DXT_EncodeAlphaBlock(block.mNormalX, 1, 4);
            *blockOutput++ = moho::DXT_EncodeGreenBlock(block.mNormalZ);

            TickLoadingProgress(loadControl);
          }

          blockRowBytes += pitchBytes;
        }

        (void)sheet->Unlock();
      }
    }
  }

  /**
   * Address: 0x008A5730 (FUN_008A5730, ?NotifyMapChange@CWldTerrainRes@Moho@@EAEXABV?$Rect2@H@gpg@@@Z)
   *
   * What it does:
   * For one terrain map-change rectangle, updates normal-map content,
   * appends the rect into the debug dirty-rect list, and marks the
   * half-resolution dirty area in the debug terrain bit-array.
   */
  void IWldTerrainRes::NotifyMapChange(const gpg::Rect2i& rect)
  {
    if (!IsInEditMode() && Finalize()) {
      return;
    }

    UpdateNormalMap(rect);

    auto* const view = AsTerrainVisualResourceRuntimeView(this);
    AppendTerrainDirtyRect(view->mDebugDirtyRects, rect);

    const std::int32_t halfX0 = FloorHalfCoordinate(rect.x0);
    const std::int32_t halfX1 = CeilHalfCoordinate(rect.x1);
    const std::int32_t halfZ0 = FloorHalfCoordinate(rect.z0);
    const std::int32_t halfZ1 = CeilHalfCoordinate(rect.z1);

    view->mDebugDirtyTerrain->FillRect(halfX0, halfZ0, halfX1 - halfX0, halfZ1 - halfZ0, true);
  }

  /**
   * Address: 0x008A4CB0 (FUN_008A4CB0, ?UpdateTexture@CWldTerrainRes@Moho@@QAEXV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@PAI@Z)
   *
   * What it does:
   * Locks one dynamic texture sheet and copies packed RGBA source rows into
   * each destination pitch row before unlocking.
   */
  void IWldTerrainRes::UpdateTexture(
    boost::shared_ptr<CD3DDynamicTextureSheet> textureSheet, const std::uint32_t* const sourcePixels
  )
  {
    CD3DDynamicTextureSheet* const sheet = textureSheet.get();
    if (sheet == nullptr || sourcePixels == nullptr) {
      return;
    }

    Wm3::Vector3f dimensions{};
    (void)sheet->GetDimensions(&dimensions);

    const std::int32_t height = static_cast<std::int32_t>(dimensions.y);
    const std::size_t bytesPerRow = sizeof(std::uint32_t) * static_cast<std::size_t>(static_cast<std::int32_t>(dimensions.x));

    std::uint32_t pitchBytes = 0;
    void* mappedBits = nullptr;
    if (!sheet->Lock(&pitchBytes, &mappedBits)) {
      return;
    }

    auto* destinationRow = static_cast<std::uint8_t*>(mappedBits);
    const auto* sourceRow = reinterpret_cast<const std::uint8_t*>(sourcePixels);

    for (std::int32_t row = 0; row < height; ++row) {
      std::memcpy(destinationRow, sourceRow, bytesPerRow);
      destinationRow += pitchBytes;
      sourceRow += bytesPerRow;
    }

    (void)sheet->Unlock();
  }

  /**
   * Address: 0x008A4DA0 (FUN_008A4DA0, ?ClearTexture@CWldTerrainRes@Moho@@QAEXV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@@Z)
   *
   * What it does:
   * Clears one lockable texture-sheet payload to zero over every mapped row.
   */
  void IWldTerrainRes::ClearTexture(boost::shared_ptr<CD3DDynamicTextureSheet> textureSheet)
  {
    CD3DDynamicTextureSheet* const sheet = textureSheet.get();
    if (sheet == nullptr) {
      return;
    }

    std::uint32_t pitchBytes = 0;
    void* mappedBits = nullptr;
    if (!sheet->Lock(&pitchBytes, &mappedBits)) {
      return;
    }

    Wm3::Vector3f dimensions{};
    (void)sheet->GetDimensions(&dimensions);
    const std::int32_t height = static_cast<std::int32_t>(dimensions.y);

    auto* rowBytes = static_cast<std::uint8_t*>(mappedBits);
    for (std::int32_t row = 0; row < height; ++row) {
      std::memset(rowBytes, 0, pitchBytes);
      rowBytes += pitchBytes;
    }

    (void)sheet->Unlock();
  }

  /**
   * Address: 0x008A4B90 (FUN_008A4B90, ?UpdateTextureChannel@CWldTerrainRes@Moho@@QAEXV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@HHHHIIPBE@Z)
   *
   * What it does:
   * Updates one channel lane in a locked terrain RGBA texture from
   * caller-supplied byte-mask rows over `[rowStart,rowEnd) x [columnStart,columnEnd)`.
   */
  void IWldTerrainRes::UpdateTextureChannel(
    const std::int32_t rowStart,
    const std::int32_t columnEnd,
    boost::shared_ptr<CD3DDynamicTextureSheet> textureSheet,
    const std::int32_t columnStart,
    const std::int32_t rowEnd,
    const std::uint32_t channelMask,
    const std::uint32_t channelShift,
    const std::uint8_t* const sourceMask
  )
  {
    CD3DDynamicTextureSheet* const sheet = textureSheet.get();
    if (sheet == nullptr) {
      return;
    }

    Wm3::Vector3f dimensions{};
    (void)sheet->GetDimensions(&dimensions);
    const std::int32_t textureWidth = static_cast<std::int32_t>(dimensions.x);

    std::uint32_t pitchBytes = 0;
    void* mappedBits = nullptr;
    if (!sheet->Lock(&pitchBytes, &mappedBits)) {
      return;
    }

    const std::int32_t pitchTexels = static_cast<std::int32_t>(pitchBytes >> 2u);
    auto* const destinationPixels = static_cast<std::uint32_t*>(mappedBits);

    if (rowStart < rowEnd) {
      const std::uint8_t* sourceRow = sourceMask + (rowStart * textureWidth);
      for (std::int32_t row = rowStart; row < rowEnd; ++row) {
        if (columnStart < columnEnd) {
          for (std::int32_t column = columnStart; column < columnEnd; ++column) {
            std::uint32_t* const destinationPixel = &destinationPixels[column + (pitchTexels * row)];
            const std::uint32_t channelValue = static_cast<std::uint32_t>(sourceRow[column]) << channelShift;
            *destinationPixel = (*destinationPixel & channelMask) | channelValue;
          }
        }
        sourceRow += textureWidth;
      }
    }

    (void)sheet->Unlock();
  }

  /**
   * Address: 0x008A4A60 (FUN_008A4A60, ?GetTextureChannel@CWldTerrainRes@Moho@@QAEXV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@IIPAE@Z)
   *
   * What it does:
   * Locks one packed RGBA texture, extracts one caller-selected channel lane
   * from each texel, writes unpacked bytes row-by-row, then unlocks.
   */
  void IWldTerrainRes::GetTextureChannel(
    boost::shared_ptr<CD3DDynamicTextureSheet> textureSheet,
    const std::uint32_t channelMask,
    const std::uint32_t channelShift,
    std::uint8_t* const outChannelData
  )
  {
    CD3DDynamicTextureSheet* const sheet = textureSheet.get();

    Wm3::Vector3f dimensions{};
    (void)sheet->GetDimensions(&dimensions);
    const std::int32_t width = static_cast<std::int32_t>(dimensions.x);
    const std::int32_t height = static_cast<std::int32_t>(dimensions.y);

    std::uint32_t pitchBytes = 0;
    void* mappedBits = nullptr;
    if (sheet->Lock(&pitchBytes, &mappedBits)) {
      const std::int32_t pitchTexels = static_cast<std::int32_t>(pitchBytes >> 2u);
      const std::uint8_t* sourceRow = static_cast<const std::uint8_t*>(mappedBits);
      std::uint8_t* destinationRow = outChannelData;

      if (height > 0) {
        const std::uint32_t sourceRowBytes = static_cast<std::uint32_t>(pitchTexels) * sizeof(std::uint32_t);
        for (std::int32_t row = 0; row < height; ++row) {
          if (width > 0) {
            auto* sourcePixel = reinterpret_cast<const std::uint32_t*>(sourceRow);
            for (std::int32_t column = 0; column < width; ++column) {
              const std::uint32_t channelValue = (sourcePixel[column] & channelMask) >> channelShift;
              destinationRow[column] = static_cast<std::uint8_t>(channelValue);
            }
          }

          sourceRow += sourceRowBytes;
          destinationRow += width;
        }
      }

      (void)sheet->Unlock();
    }
  }

  /**
   * Address: 0x008A4ED0 (FUN_008A4ED0, ?UpdateStratumMask@CWldTerrainRes@Moho@@UAEXHPBEHHHH@Z)
   *
   * What it does:
   * Selects one packed channel lane from stratum texture 0/1 and forwards one
   * byte-mask rectangle update through `UpdateTextureChannel`.
   */
  void IWldTerrainRes::UpdateStratumMask(
    const std::int32_t stratumIndex,
    const std::uint8_t* const sourceMask,
    const std::int32_t columnStart,
    const std::int32_t rowStart,
    const std::int32_t columnEnd,
    const std::int32_t rowEnd
  )
  {
    static constexpr std::uint32_t kChannelMask[4] = {
      0xFF00FFFFu,
      0xFFFF00FFu,
      0xFFFFFF00u,
      0x00FFFFFFu,
    };
    static constexpr std::uint32_t kChannelShift[4] = {16u, 8u, 0u, 24u};

    const std::int32_t channel = static_cast<std::int32_t>(static_cast<std::uint32_t>(stratumIndex) & 3u);
    const auto* const view = AsTerrainNormalMapRuntimeView(this);

    const boost::shared_ptr<CD3DDynamicTextureSheet> targetTexture =
      ((stratumIndex / 4) != 0) ? view->mStratumMask1 : view->mStratumMask0;

    UpdateTextureChannel(
      rowStart,
      columnEnd,
      targetTexture,
      columnStart,
      rowEnd,
      kChannelMask[channel],
      kChannelShift[channel],
      sourceMask
    );
  }

  /**
   * Address: 0x008A4F90 (FUN_008A4F90, ?GetStratumMask@CWldTerrainRes@Moho@@UAEXHPAE@Z)
   *
   * What it does:
   * Selects one stratum-mask texture/channel lane and forwards unpacking to
   * `GetTextureChannel`.
   */
  void IWldTerrainRes::GetStratumMask(const std::int32_t stratumIndex, std::uint8_t* const outMask)
  {
    static constexpr std::uint32_t kChannelMask[4] = {
      0xFF00FFFFu,
      0xFFFF00FFu,
      0xFFFFFF00u,
      0x00FFFFFFu,
    };
    static constexpr std::uint32_t kChannelShift[4] = {16u, 8u, 0u, 24u};

    const std::int32_t channel = static_cast<std::int32_t>(static_cast<std::uint32_t>(stratumIndex) & 3u);
    const auto* const view = AsTerrainNormalMapRuntimeView(this);
    const boost::shared_ptr<CD3DDynamicTextureSheet> sourceTexture =
      ((stratumIndex / 4) != 0) ? view->mStratumMask1 : view->mStratumMask0;

    GetTextureChannel(sourceTexture, kChannelMask[channel], kChannelShift[channel], outMask);
  }

  /**
   * Address: 0x008A6020 (FUN_008A6020, ?GetNormalMapInfo@CWldTerrainRes@Moho@@EAE?AUSNormalMapInfo@2@H@Z)
   *
   * What it does:
   * Builds shader-ready UV scale/offset lanes and texture ownership for one
   * normal-map tile index.
   */
  SNormalMapInfo IWldTerrainRes::GetNormalMapInfo(const std::int32_t index) const
  {
    SNormalMapInfo outInfo{};

    const auto* const view = AsTerrainNormalMapRuntimeView(this);
    const std::int32_t mapWidthMinusOne = view->mMap->mHeightField->width - 1;
    const std::int32_t mapHeightMinusOne = view->mMap->mHeightField->height - 1;

    const std::int32_t normalMapTilesPerRow = static_cast<std::int32_t>(
      static_cast<std::uint32_t>(mapWidthMinusOne) / static_cast<std::uint32_t>(view->mNormalMapWidth)
    );

    const std::int32_t tileIndexX = index % normalMapTilesPerRow;
    const std::int32_t tileIndexY = index / normalMapTilesPerRow;

    outInfo.mTileOriginX = static_cast<float>(view->mNormalMapWidth) * static_cast<float>(tileIndexX);
    outInfo.mTileOriginY = static_cast<float>(view->mNormalMapHeight) * static_cast<float>(tileIndexY);
    outInfo.mTexture = view->mNormalMap.mBegin[index];

    outInfo.mXResolution =
      static_cast<float>(static_cast<double>(static_cast<std::uint32_t>(mapWidthMinusOne)) / view->mNormalMapWidth);
    outInfo.mYResolution =
      static_cast<float>(static_cast<double>(static_cast<std::uint32_t>(mapHeightMinusOne)) / view->mNormalMapHeight);

    outInfo.mScaleBiasX = 0.0f;
    outInfo.mScaleBiasY = 1.0f;
    outInfo.mOffsetScaleX = (-0.0f - outInfo.mTileOriginX) / static_cast<float>(view->mNormalMapWidth);
    outInfo.mOffsetScaleY = (-0.0f - outInfo.mTileOriginY) / static_cast<float>(view->mNormalMapHeight);
    outInfo.mOffsetScaleZ = 0.0f;
    outInfo.mOffsetScaleW = 0.0f;
    outInfo.mWidth = static_cast<float>(view->mNormalMapWidth);
    outInfo.mHeight = static_cast<float>(view->mNormalMapHeight);
    return outInfo;
  }

  /**
   * Address: 0x008A61B0 (FUN_008A61B0, ?SetWaterDefaults@CWldTerrainRes@Moho@@AAEXXZ)
   *
   * What it does:
   * Reinitializes terrain water-shader parameters to their default property
   * payload by constructing one default property block and replacing the
   * currently owned instance.
   */
  void IWldTerrainRes::SetWaterDefaults()
  {
    CWaterShaderProperties defaults{};
    SetWaterShaderProperties(defaults);
  }

  /**
   * Address: 0x008A49D0 (FUN_008A49D0, ?GetStratumMaterial@CWldTerrainRes@Moho@@UAEAAVStratumMaterial@2@XZ)
   *
   * What it does:
   * Returns mutable access to the owned terrain stratum-material set.
   */
  StratumMaterial& IWldTerrainRes::GetStratumMaterial()
  {
    return AsTerrainNormalMapRuntimeView(this)->mStrata;
  }

  /**
   * Address: 0x008A49E0 (FUN_008A49E0, ?SetStratumDefaults@CWldTerrainRes@Moho@@QAEXXZ)
   *
   * What it does:
   * Replaces current terrain strata with default descriptors, then reapplies
   * map-size scaling to each configured layer.
   */
  void IWldTerrainRes::SetStratumDefaults()
  {
    auto* const normalView = AsTerrainNormalMapRuntimeView(this);
    normalView->mStrata = StratumMaterial{};
    normalView->mStrata.SetSizeTo(reinterpret_cast<CWldTerrainRes*>(this));
  }

  /**
   * Address: 0x008A4600 (FUN_008A4600, ?SaveTexturing@CWldTerrainRes@Moho@@QAEXAAVBinaryWriter@gpg@@@Z)
   *
   * What it does:
   * Serializes stratum-layer texture path/size lanes in save-order, then
   * delegates decal-manager persistence.
   */
  void IWldTerrainRes::SaveTexturing(gpg::BinaryWriter& writer)
  {
    const StratumMaterial& strata = AsTerrainNormalMapRuntimeView(this)->mStrata;

    SaveStratumLayer(writer, strata.mLowerAlbedoTexture);
    SaveStratumLayer(writer, strata.mStratum0AlbedoTexture);
    SaveStratumLayer(writer, strata.mStratum1AlbedoTexture);
    SaveStratumLayer(writer, strata.mStratum2AlbedoTexture);
    SaveStratumLayer(writer, strata.mStratum3AlbedoTexture);
    SaveStratumLayer(writer, strata.mStratum4AlbedoTexture);
    SaveStratumLayer(writer, strata.mStratum5AlbedoTexture);
    SaveStratumLayer(writer, strata.mStratum6AlbedoTexture);
    SaveStratumLayer(writer, strata.mStratum7AlbedoTexture);
    SaveStratumLayer(writer, strata.mUpperAlbedoTexture);
    SaveStratumLayer(writer, strata.mLowerNormalTexture);
    SaveStratumLayer(writer, strata.mStratum0NormalTexture);
    SaveStratumLayer(writer, strata.mStratum1NormalTexture);
    SaveStratumLayer(writer, strata.mStratum2NormalTexture);
    SaveStratumLayer(writer, strata.mStratum3NormalTexture);
    SaveStratumLayer(writer, strata.mStratum4NormalTexture);
    SaveStratumLayer(writer, strata.mStratum5NormalTexture);
    SaveStratumLayer(writer, strata.mStratum6NormalTexture);
    SaveStratumLayer(writer, strata.mStratum7NormalTexture);

    AsTerrainVisualResourceRuntimeView(this)->mDecalManager->Save(writer);
  }

  /**
   * Address: 0x008A0A20 (FUN_008A0A20, ??0struct_Env@@QAE@@Z)
   *
   * What it does:
   * Captures one environment lookup key plus one terrain texture resource
   * handle in one terrain environment entry object.
   */
  TerrainEnvironmentLookupEntry::TerrainEnvironmentLookupEntry(
    const msvc8::string& environmentName,
    boost::shared_ptr<RD3DTextureResource> texture
  )
  {
    mEnvironmentName.assign(environmentName, 0u, 0xFFFFFFFFu);
    mTexture = texture;
  }

  /**
   * Address: 0x00890CF0 (?Reset@CWldMap@Moho@@AAEXXZ)
   *
   * What it does:
   * Releases preview chunk, terrain resource, and world props in-place and
   * nulls each owning pointer.
   */
  void CWldMap::Reset()
  {
    RWldMapPreviewChunk* const previewChunk = mMapPreviewChunk;
    mMapPreviewChunk = nullptr;
    DestroyPreviewChunk(previewChunk);

    IWldTerrainRes* const terrainRes = mTerrainRes;
    mTerrainRes = nullptr;
    DestroyTerrainRes(terrainRes);

    CWldProps* const props = mProps;
    mProps = nullptr;
    DestroyWldProps(props);
  }

  /**
   * Address: 0x00890C70 (??1CWldMap@Moho@@QAE@XZ)
   *
   * What it does:
   * Performs standard map reset, then repeats guarded teardown checks matching
   * destructor epilogue behavior from the binary.
   */
  CWldMap::~CWldMap()
  {
    Reset();

    DestroyWldProps(mProps);
    DestroyTerrainRes(mTerrainRes);
    DestroyPreviewChunk(mMapPreviewChunk);
  }

  /**
   * Address: 0x00890DA0 (FUN_00890DA0,
   * ?MapLoad@CWldMap@Moho@@QAE_NVStrArg@gpg@@PAVLuaState@LuaPlus@@_NAAVCBackgroundTaskControl@2@@Z)
   *
   * What it does:
   * Resets current world-map resources, opens map stream data, and loads
   * preview/terrain/props stages with background progress updates.
   */
  bool CWldMap::MapLoad(
    const gpg::StrArg mapName,
    LuaPlus::LuaState* const state,
    const bool previewOnly,
    CBackgroundTaskControl& loadControl
  )
  {
    Reset();

    msvc8::string resolvedPath;
    resolvedPath.tidy(false, 0U);
    const char* openPath = mapName != nullptr ? mapName : "";

    FWaitHandleSet* const waitHandleSet = FILE_GetWaitHandleSet();
    if (waitHandleSet != nullptr && waitHandleSet->mHandle != nullptr) {
      (void)waitHandleSet->mHandle->FindFile(&resolvedPath, openPath, nullptr);
      openPath = resolvedPath.c_str();
    }

    msvc8::auto_ptr<gpg::Stream> stream = DISK_OpenFileRead(openPath);
    if (!stream.get()) {
      return false;
    }

    gpg::BinaryReader reader(stream.get());
    TickLoadingProgress(loadControl);

    std::uint32_t fileMagic = 0;
    std::uint32_t fileVersion = 0;
    reader.ReadExact(fileMagic);
    reader.ReadExact(fileVersion);
    if (fileMagic != 0x1A70614Du || fileVersion != 2u) {
      return false;
    }

    auto* const newPreviewChunk = new (std::nothrow) RWldMapPreviewChunk();
    ReplaceOwnedPreviewChunk(&mMapPreviewChunk, newPreviewChunk);
    if (mMapPreviewChunk == nullptr || !mMapPreviewChunk->Load(reader, loadControl)) {
      return false;
    }

    if (previewOnly) {
      return true;
    }

    TickLoadingProgress(loadControl);
    IWldTerrainRes* const newTerrainRes = WLD_CreateTerrainRes();
    IWldTerrainRes* const previousTerrainRes = mTerrainRes;
    mTerrainRes = newTerrainRes;
    DestroyTerrainRes(previousTerrainRes);
    if (mTerrainRes == nullptr || !mTerrainRes->Load(reader, state, loadControl)) {
      return false;
    }

    TickLoadingProgress(loadControl);
    CWldProps* const newProps = WLD_CreateProps();
    CWldProps* const previousProps = mProps;
    mProps = newProps;
    DestroyWldProps(previousProps);
    if (mProps == nullptr || !mProps->Load(reader, loadControl)) {
      return false;
    }

    return true;
  }

  /**
   * Address: 0x00891250 (FUN_00891250, ?MapSetPreview@CWldMap@Moho@@QAEXV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@ABV?$Vector2@M@Wm3@@PBD@Z)
   *
   * What it does:
   * Replaces the owned preview chunk with one built from the provided
   * texture/size/name lane and destroys any previous chunk.
   */
  void CWldMap::MapSetPreview(
    boost::shared_ptr<ID3DTextureSheet> textureSheet,
    const Wm3::Vector2f& previewSize,
    const char* const previewName
  )
  {
    auto* const newChunk = new (std::nothrow) RWldMapPreviewChunk(textureSheet, previewSize, previewName);
    ReplaceOwnedPreviewChunk(&mMapPreviewChunk, newChunk);
  }
} // namespace moho
