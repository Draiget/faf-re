#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "legacy/containers/Vector.h"
#include "moho/math/MathReflection.h"
#include "moho/mesh/Mesh.h"

namespace gpg
{
  class BinaryReader;
  class BinaryWriter;
}

namespace LuaPlus
{
  class LuaObject;
}

namespace moho
{
  class CParticleTexture;

  /**
   * Address: 0x00886EE0 (FUN_00886EE0, ??0WaveParameters@Moho@@QAE@AAVLuaObject@LuaPlus@@@Z)
   * Address: 0x00886DA0 (FUN_00886DA0, ??0WaveParameters@Moho@@... explicit-parameter overload)
   * Address: 0x00886FB0 (FUN_00886FB0, WaveParameters complete-object destructor)
   * Address: 0x00886D80 (FUN_00886D80, vtable-slot-0 scalar deleting destructor)
   * Address: 0x0088AB00 (FUN_0088AB00, compiler-generated copy constructor)
   *
   * What it does:
   * One water-wave particle-strip preset: a texture/ramp pair plus the
   * position, timing, scale, velocity-delta and frame-strip parameters that
   * drive one entry of a `WavePattern`'s `parameters` array. Polymorphic
   * (a single virtual-destructor vtable slot) so `msvc8::vector<WaveParameters>`
   * tears its elements down through the class's own vtable rather than a
   * statically-bound call -- see `WavePattern::~WavePattern` below.
   */
  class WaveParameters
  {
  public:
    /**
     * Address: 0x00886EE0 (FUN_00886EE0)
     *
     * What it does:
     * Default-initializes every scalar lane (position/period/speed/lifetime/
     * scale/velocityDelta zeroed, frameCount/frameRate/stripCount defaulted to
     * 1.0, frameRateVariance to 0.0) via the member initializers below, then
     * reads the matching fields out of `source` -- delegated to
     * `PopulateFromLua`, the recovered body of `FUN_00887000` -- overwriting
     * every lane the Lua table actually provides.
     */
    explicit WaveParameters(LuaPlus::LuaObject& source);

    /**
     * Address: 0x00886DA0 (FUN_00886DA0)
     *
     * What it does:
     * Builds one preset directly from typed engine values (no Lua table
     * involved). Confirms the field layout independently of the Lua-table
     * constructor: every offset this overload writes matches
     * `PopulateFromLua`'s reads exactly.
     */
    WaveParameters(
      const msvc8::string& texturePath,
      const msvc8::string& rampPath,
      const Wm3::Vec3f& position,
      float period,
      float periodVariance,
      float speed,
      float speedVariance,
      float lifetime,
      float lifetimeVariance,
      const Wm3::Vector2f& scale,
      float scaleVariance,
      const Wm3::Vec3f& velocityDelta,
      float frameCount,
      float frameRate,
      float frameRateVariance,
      float stripCount
    );

    WaveParameters(const WaveParameters&) = default;
    WaveParameters& operator=(const WaveParameters&) = default;

    /**
     * Address: 0x00886FB0 (FUN_00886FB0, complete-object destructor)
     * Address: 0x00886D80 (FUN_00886D80, vtable-slot-0 scalar deleting
     * destructor: tail-calls the body below then conditionally frees the
     * object -- ordinary C++ `delete` semantics, not modeled as a separate
     * function here)
     *
     * What it does:
     * Releases `mRampPath`'s and `mTexturePath`'s heap buffers (in that
     * reverse-declaration order, matching the binary) when either grew past
     * the inline SSO capacity. `msvc8::string` has no destructor of its own
     * by design (see `legacy/containers/String.h`), so owning classes tidy
     * their string members explicitly.
     */
    virtual ~WaveParameters();

  private:
    /**
     * Address: 0x00887000 (FUN_00887000)
     *
     * What it does:
     * Reads `texture`/`ramp` (strings), `position`/`velocityDelta` (1-based
     * 3-element Lua arrays), `period`/`periodVariance`/`speed`/
     * `speedVariance`/`lifetime`/`lifetimeVariance`/`scaleVariance`
     * (unconditional numbers), `scale[1]`/`scale[2]`, and
     * `frameCount`/`frameRate`/`frameRateVariance`/`stripCount` (each
     * defaulted when the Lua field is nil, matching the binary's per-field
     * `IsNil` guards) out of `source`.
     */
    void PopulateFromLua(LuaPlus::LuaObject& source);

    msvc8::string mTexturePath;                    // +0x04 ("texture")
    msvc8::string mRampPath;                        // +0x20 ("ramp")
    Wm3::Vec3f mPosition{0.0f, 0.0f, 0.0f};          // +0x3C ("position", 1-based array)
    float mPeriod = 0.0f;                            // +0x48
    float mPeriodVariance = 0.0f;                    // +0x4C
    float mSpeed = 0.0f;                              // +0x50
    float mSpeedVariance = 0.0f;                      // +0x54
    float mLifetime = 0.0f;                           // +0x58
    float mLifetimeVariance = 0.0f;                   // +0x5C
    Wm3::Vector2f mScale{0.0f, 0.0f};                 // +0x60 ("scale[1]"/"scale[2]")
    float mScaleVariance = 0.0f;                      // +0x68
    Wm3::Vec3f mVelocityDelta{0.0f, 0.0f, 0.0f};      // +0x6C ("velocityDelta", 1-based array)
    float mFrameCount = 1.0f;                         // +0x78 (default 1.0 when nil)
    float mFrameRate = 1.0f;                          // +0x7C (default 1.0 when nil)
    float mFrameRateVariance = 0.0f;                  // +0x80 (default 0.0 when nil)
    float mStripCount = 1.0f;                         // +0x84 (default 1.0 when nil)
  };

  static_assert(sizeof(WaveParameters) == 0x88, "WaveParameters size must be 0x88");

  /**
   * Address: 0x008876F0 (FUN_008876F0, default constructor -- zero-initializes
   * mName/mPreview/mWaves; equivalent to this class's in-class member
   * initializers, so no hand-written body is needed)
   * Address: 0x00887770 (FUN_00887770, ??0WavePattern@Moho@@QAE@AAVLuaObject@LuaPlus@@@Z)
   * Address: 0x008877E0 (FUN_008877E0, complete-object destructor)
   * Address: 0x00887750 (FUN_00887750, vtable-slot-0 scalar deleting destructor)
   *
   * What it does:
   * A named, shareable collection of `WaveParameters` presets loaded from one
   * Lua table: `name`/`preview` identify the pattern, `parameters` is the
   * array of per-wave preset tables that populate `mWaves`. Polymorphic
   * (single virtual-destructor vtable slot) so `msvc8::vector<WaveParameters>`
   * -- `mWaves` -- destroys its polymorphic elements through their own
   * vtable slot 0 rather than a statically-bound call; see
   * `legacy/containers/Vector.h`'s `destroy_range`.
   *
   * Caller evidence: the Lua-table constructor (0x00887770) and its
   * `LoadParametersFromLua` helper (0x00887870) are fully wired to each
   * other and to `WaveParameters`'s own Lua constructor/populate helper by
   * real `call` instructions in the binary (confirmed both via
   * `_callgraph_index.sqlite` and direct disassembly reading), and the class
   * itself is proven shipped/live: its vtable (`??_7WavePattern@Moho@@6B@`)
   * is real `.rdata` and its destructor chain (0x00887750 -> 0x008877E0 ->
   * the `mWaves` vector destructor) is reachable from that vtable root.
   * What has *not* been found, despite an exhaustive search (full
   * `call_edges`/`data_refs` scan of the 67k-function/140k-edge namespace
   * index, plus a raw absolute-address scan of both shipped
   * `ForgedAlliance.exe` binaries), is a caller of the Lua-table constructor
   * itself -- the whole construction-side API (both `WavePattern`
   * constructors, `WaveParameters`'s both constructors, and the
   * `msvc8::vector<WaveParameters>::push_back` growth path below) is
   * evidenced, real, internally self-consistent engine code with no
   * currently-discoverable external invocation. The most likely explanation
   * is whole-TU linkage: this file's `WaveGenerator`/`WaveSystem` code is
   * definitely live, and if the original compilation unit was built without
   * per-function COMDAT folding (`/Gy`), one live reference anywhere in the
   * translation unit keeps the whole object file, including this
   * currently-unreached Lua-pattern-library feature.
   */
  class WavePattern
  {
  public:
    WavePattern() = default;

    explicit WavePattern(LuaPlus::LuaObject& source);

    WavePattern(const WavePattern&) = delete;
    WavePattern& operator=(const WavePattern&) = delete;

    /**
     * What it does:
     * Tidies `mPreview` then `mName` (reverse declaration order, matching
     * the binary); `mWaves` tears down automatically via
     * `msvc8::vector<WaveParameters>::~vector()` since it is the
     * last-declared member.
     */
    virtual ~WavePattern();

  private:
    /**
     * Address: 0x00887870 (FUN_00887870)
     *
     * What it does:
     * Reads `name`/`preview` (strings) then iterates the `parameters` array
     * table, constructing one `WaveParameters` per entry from the Lua
     * sub-table and appending it to `mWaves`. The binary enumerates
     * `parameters` with a `LuaTableIterator` (pairs-style traversal);
     * `parameters` is authored as a 1-based array, so the recovered form
     * below (an equivalent indexed `LuaTableIterator` for-loop, matching
     * `lua/LuaTableIterator.h`'s already-recovered API) visits the same
     * entries in the same order.
     */
    void LoadParametersFromLua(LuaPlus::LuaObject& source);

    msvc8::string mName;                       // +0x04 ("name")
    msvc8::string mPreview;                     // +0x20 ("preview")
    msvc8::vector<WaveParameters> mWaves;       // +0x3C ("parameters")
  };

  static_assert(sizeof(WavePattern) == 0x4C, "WavePattern size must be 0x4C");

  class WaveGenerator
  {
  public:
    /**
     * Address: 0x00887BF0 (FUN_00887BF0, ??0WaveGenerator@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes one wave generator, loads serialized lanes from reader, and
     * rebuilds texture/schedule/bounds runtime state.
     */
    WaveGenerator(SpatialDB_MeshInstance* spatialStorage, std::int32_t formatVersion, gpg::BinaryReader& reader);

    /**
     * Address: 0x00887D40 (FUN_00887D40, sub_887D40)
     *
     * What it does:
     * Initializes one wave generator directly from runtime parameter lanes,
     * then rebuilds texture handles, schedule timing, and spatial bounds.
     */
    WaveGenerator(
      SpatialDB_MeshInstance* spatialStorage,
      const msvc8::string& primaryTexturePath,
      const msvc8::string& rampTexturePath,
      const Wm3::Vec3f& position,
      float angle,
      const Wm3::Vec3f& direction,
      const Wm3::Vector2f& lifetimeRange,
      const Wm3::Vector2f& updateIntervalRange,
      const Wm3::Vector2f& sizeRange,
      float rampValueScale,
      const Wm3::Vector2f& framerateRange,
      float textureSelectionRange
    );

    /**
     * Address: 0x00887EC0 (FUN_00887EC0, sub_887EC0)
     *
     * What it does:
     * Releases texture references, resets texture paths, and clears spatial-db
     * registration state for this generator.
     */
    virtual ~WaveGenerator();

    /**
     * Address: 0x00888250 (FUN_00888250, ?Save@WaveGenerator@Moho@@QBEXAAVBinaryWriter@gpg@@@Z)
     *
     * What it does:
     * Stores texture paths and wave-emission scalar lanes in binary stream
     * order used by terrain save/load.
     */
    void Save(gpg::BinaryWriter& writer) const;

    void Save(gpg::BinaryWriter* writer) const
    {
      if (writer != nullptr) {
        Save(*writer);
      }
    }

    /**
     * Address: 0x00888560 (FUN_00888560, ?Update@WaveGenerator@Moho@@QAEXN@Z)
     *
     * What it does:
     * Emits one world particle when the generator's randomized update interval
     * has elapsed: seeds a `SWorldParticle` from the generator's texture/scalar
     * lanes, picks a random texture selection under the global random mutex,
     * appends it to `sWorldParticles`, then reschedules the next emission.
     */
    void Update(double time);

  private:
    friend struct WaveGeneratorLayoutVerifier;

    /**
     * Address: 0x00887FC0 (FUN_00887FC0, sub_887FC0)
     *
     * What it does:
     * Reads texture paths and wave-emission scalar payload from one binary
     * reader lane, then refreshes runtime-dependent state.
     */
    void LoadSerializedState(gpg::BinaryReader& reader, std::int32_t formatVersion);

    /**
     * Address: 0x00888B30 (FUN_00888B30, sub_888B30)
     *
     * What it does:
     * Rebuilds texture handles from stored path lanes, randomizes initial
     * emission schedule, and refreshes spatial bounds.
     */
    void RefreshTextureHandlesAndSchedule();

    /**
     * Address: 0x00888830 (FUN_00888830, sub_888830)
     *
     * What it does:
     * Recomputes spatial AABB/basis payload from wave-generator scalar lanes
     * and updates the attached spatial-db entry bounds.
     */
    void RebuildSpatialBounds();

  private:
    std::uint32_t mReserved04;             // +0x04
    SpatialDB_MeshInstance mSpatialEntry;  // +0x08
    Wm3::AxisAlignedBox3f mBounds;         // +0x10
    Wm3::Vec3f mBoundsCenter;              // +0x28
    VAxes3 mBoundsAxes;                    // +0x34
    Wm3::Vec3f mBoundsHalfExtents;         // +0x58
    std::uint32_t mReserved64;             // +0x64
    double mCurrentTime;                   // +0x68
    double mUpdateInterval;                // +0x70
    msvc8::string mPrimaryTexturePath;     // +0x78
    CParticleTexture* mPrimaryTexture;     // +0x94
    msvc8::string mRampTexturePath;        // +0x98
    CParticleTexture* mRampTexture;        // +0xB4
    Wm3::Vec3f mPosition;                  // +0xB8
    float mAngle;                          // +0xC4
    Wm3::Vec3f mDirection;                 // +0xC8
    float mMinLifetime;                    // +0xD4
    float mMaxLifetime;                    // +0xD8
    float mMinUpdateInterval;              // +0xDC
    float mMaxUpdateInterval;              // +0xE0
    float mBeginSize;                      // +0xE4
    float mEndSize;                        // +0xE8
    float mRampValueScale;                 // +0xEC
    float mMinFramerate;                   // +0xF0
    float mMaxFramerate;                   // +0xF4
    float mTextureSelectionRange;          // +0xF8
    std::uint8_t mTailPaddingFC[0x04];     // +0xFC
  };

  class WaveSystem
  {
  public:
    /**
     * Address: 0x00888CB0 (FUN_00888CB0, ??0WaveSystem@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes wave runtime lanes, spatial registration entry, and the
     * inline generator-cache storage window.
     */
    WaveSystem();

    /**
     * Address: 0x00888D50 (FUN_00888D50, ??1WaveSystem@Moho@@UAE@XZ)
     *
     * What it does:
     * Releases owned wave generators and restores generator cache storage to
     * inline state before member teardown.
     */
    virtual ~WaveSystem();

    /**
     * Address: 0x00889BA0 (FUN_00889BA0, sub_889BA0)
     *
     * What it does:
     * Deletes all owned wave-generator objects and resets both generator
     * storage lanes to empty runtime state.
     */
    void ClearWaveGeneratorState();

    /**
     * Address: 0x008899E0 (FUN_008899E0, ?Load@WaveSystem@Moho@@QAEXHHHAAVBinaryReader@gpg@@@Z)
     *
     * What it does:
     * Clears existing generators, resizes embedded spatial storage for current
     * map dimensions, then loads and appends serialized wave generators.
     */
    void Load(std::int32_t formatVersion, std::int32_t mapHeight, std::int32_t mapWidth, gpg::BinaryReader& reader);

    /**
     * Address: 0x00889AD0 (FUN_00889AD0, ?Save@WaveSystem@Moho@@QBEXAAVBinaryWriter@gpg@@@Z)
     *
     * What it does:
     * Writes generator count and each wave-generator payload in save order.
     */
    void Save(gpg::BinaryWriter& writer) const;

    /**
     * Address: 0x00888E10 (FUN_00888E10, sub_888E10)
     *
     * What it does:
     * Allocates and appends one runtime wave generator from explicit parameter
     * lanes and returns the stored generator pointer.
     */
    WaveGenerator* CreateWaveGenerator(
      const msvc8::string& primaryTexturePath,
      const msvc8::string& rampTexturePath,
      const Wm3::Vec3f& position,
      float angle,
      const Wm3::Vec3f& direction,
      const Wm3::Vector2f& lifetimeRange,
      const Wm3::Vector2f& updateIntervalRange,
      const Wm3::Vector2f& sizeRange,
      float rampValueScale,
      const Wm3::Vector2f& framerateRange,
      float textureSelectionRange
    );

    /**
     * Address: 0x00888F20 (FUN_00888F20, sub_888F20)
     *
     * What it does:
     * Removes all cached references to `generator` from active wave-generator
     * storage and runs one deleting-destructor lane for that generator.
     */
    WaveGenerator* RemoveAndDeleteGenerator(WaveGenerator* generator);

    /**
     * Address: 0x00889900 (FUN_00889900, ?Update@WaveSystem@Moho@@QAEXABVGeomCamera3@2@MH@Z)
     *
     * What it does:
     * Advances the wave simulation for one frame. No-ops when no generators are
     * registered or the frame-delta guard (`elapsedSeconds <= 200`) fails. Every
     * 5th tick it refreshes the in-view generator cache from the spatial DB, then
     * emits from each cached generator via `WaveGenerator::Update` at the current
     * system time.
     */
    void Update(const GeomCamera3& camera, float elapsedSeconds, std::int32_t tick);

  public:
    std::uint32_t mReserved04;                            // +0x04
    SpatialDB_MeshInstance mSpatialMeshInstance;          // +0x08
    std::uint8_t mRuntimeBlock10[0x8C];                   // +0x10
    // 12-byte gpg-style vector (no proxy lane); matches the binary triplet
    // initialized in WaveSystem ctor at 0x00888CB0 (mVec._Myfirst/_Mylast/_Myend).
    gpg::core::FastVector<WaveGenerator*> mWaveGenerators; // +0x9C
    gpg::fastvector_n<WaveGenerator*, 100> mGeneratorCache; // +0xA8
  };

  static_assert(offsetof(WaveSystem, mReserved04) == 0x04, "WaveSystem::mReserved04 offset must be 0x04");
  static_assert(
    offsetof(WaveSystem, mSpatialMeshInstance) == 0x08,
    "WaveSystem::mSpatialMeshInstance offset must be 0x08"
  );
  static_assert(
    offsetof(WaveSystem, mWaveGenerators) == 0x9C,
    "WaveSystem::mWaveGenerators offset must be 0x9C"
  );
  static_assert(
    offsetof(WaveSystem, mGeneratorCache) == 0xA8,
    "WaveSystem::mGeneratorCache offset must be 0xA8"
  );
  static_assert(sizeof(WaveSystem) == 0x248, "WaveSystem size must be 0x248");

  struct WaveGeneratorLayoutVerifier
  {
    // Pending layout reconciliation: keep field-level annotations in class body.
  };
} // namespace moho
