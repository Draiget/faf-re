#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/scoped_array.hpp"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace boost
{
  template <typename T>
  class shared_ptr;
}

namespace gpg
{
  struct MD5Context;
  class SerConstructResult;
  struct SerHelperBase;
  class SerSaveConstructArgsResult;
}

namespace moho
{
  class CIntelGrid;
}

namespace gpg
{
  /**
   * Address: 0x00509200 (FUN_00509200, gpg::RRef_CIntelGrid)
   *
   * What it does:
   * Builds one typed reflection reference for a `CIntelGrid*` pointer.
   */
  gpg::RRef* RRef_CIntelGrid(gpg::RRef* outRef, moho::CIntelGrid* value);
}

namespace moho
{
  class STIMap;

  struct SDelayedSubVizInfo
  {
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00508840 (FUN_00508840 -- the compiler-generated copy of this
     * 20-byte aggregate (three field copies), emitted out of line for
     * `msvc8::vector<SDelayedSubVizInfo>`'s element-wise copy and fill steps;
     * no source line, it is the implicit `operator=`. Formerly transcribed as
     * `CopyDelayedSubVizInfoVariant1` in SDelayedSubVizInfoReflection.cpp,
     * removed 2026-09-10.)
     * Address: 0x00508B10 (FUN_00508B10 -- forwarding copy of the same body; formerly `CopyDelayedSubVizInfoVariant2`.)
     * Address: 0x00509880 (FUN_00509880 -- the same implicit copy, formerly `CopyDelayedSubVizInfoUnchecked`; zero callers, unreachable.)
     * Address: 0x005098A0 (FUN_005098A0 -- the same implicit copy behind a null guard, formerly `CopyDelayedSubVizInfoIfNotNullVariant1`; zero callers, unreachable.)
     * Address: 0x00509A40 (FUN_00509A40 -- forwarding copy of 0x005098A0, formerly `CopyDelayedSubVizInfoIfNotNullVariant2`; zero callers, unreachable.)
     */
    Wm3::Vec3f mLastPos;          // +0x00
    float mRadius;                // +0x0C
    std::int32_t mTicksTilUpdate; // +0x10

    /**
     * Address: 0x005088F0 (FUN_005088F0, Moho::SDelayedSubVizInfo::MemberDeserialize)
     *
     * What it does:
     * Loads `mLastPos`, `mRadius`, and `mTicksTilUpdate` from archive lanes.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00508950 (FUN_00508950, Moho::SDelayedSubVizInfo::MemberSerialize)
     *
     * What it does:
     * Writes `mLastPos`, `mRadius`, and `mTicksTilUpdate` into archive lanes.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  static_assert(sizeof(SDelayedSubVizInfo) == 0x14, "SDelayedSubVizInfo size must be 0x14");
  static_assert(sizeof(msvc8::vector<SDelayedSubVizInfo>) == 0x10, "msvc8::vector<SDelayedSubVizInfo> size must be 0x10");

  class CIntelGrid
  {
  public:
    /**
     * What it does:
     * Nothing: the construct hook rebuilds the grid from its map and size; the cells are not archived. `gpg::SerSaveLoadHelper<CIntelGrid>::Deserialize`
     * 0x00507490 and `Serialize` 0x005074A0 are a bare `ret`.
     */
    void MemberDeserialize(gpg::ReadArchive*) {}
    void MemberSerialize(gpg::WriteArchive*) const {}

    inline static gpg::RType* sType = nullptr;

    /**
     * Address: 0x00507720 (FUN_00507720, ??0CIntelGrid@Moho@@QAE@PBVSTIMap@1@H@Z)
     *
     * What it does:
     * Binds map source, allocates byte coverage grid, and sets delayed-update
     * storage to empty.
     */
    CIntelGrid(const STIMap* map, std::uint32_t size);

    /**
     * Address: 0x00508D80 (FUN_00508D80)
     * Address: 0x00508D40 (FUN_00508D40 -- the scalar deleting destructor; no callers.)
     *
     * What it does:
     * Implicit in effect: `mUpdateList` frees its storage, then `mGrid` its
     * cells (members in reverse order), which is the order 0x00508D80 frees
     * them in.
     */
    ~CIntelGrid();

    /**
     * What it does:
     * Reads the map and the cell size and builds a grid on them for an archive
     * load. Inlined into `SerConstructHelper<CIntelGrid>::Construct` 0x005073C0.
     */
    static void MemberConstruct(
      gpg::ReadArchive& archive, int version, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
    );

    /**
     * Address: 0x005BE150 (FUN_005BE150, ?IsVisible@CIntelGrid@Moho@@QBE_NHH@Z)
     *
     * What it does:
     * Returns true when `(x,z)` is inside the intel grid bounds and the cell
     * visibility byte is non-zero.
     */
    [[nodiscard]] bool IsVisible(std::int32_t x, std::int32_t z) const;

    /**
     * Address: 0x005BE180 (FUN_005BE180, ?IsVisible@CIntelGrid@Moho@@QBE_NABV?$Vector2@H@Wm3@@@Z)
     *
     * What it does:
     * Returns true when integer grid coordinates are inside bounds and the
     * addressed visibility byte is non-zero.
     */
    [[nodiscard]] bool IsVisible(const Wm3::Vector2i& gridCell) const;

    /**
     * Address: 0x005BE1C0 (FUN_005BE1C0, ?IsVisible@CIntelGrid@Moho@@QBE_NABV?$Vector3@M@Wm3@@@Z)
     *
     * Wm3::Vector3<float> const &
     *
     * IDA signature:
     * bool __usercall Moho::CIntelGrid::IsVisible@<al>(
     *   Moho::CIntelGrid *this@<edi>,
     *   Wm3::Vector3f *position@<esi>)
     *
     * What it does:
     * Converts world-space position to grid coordinates and returns true when
     * the mapped cell is inside bounds and has non-zero visibility.
     */
    [[nodiscard]] bool IsVisible(const Wm3::Vec3f& position) const;

    /**
     * Address: 0x005BE210 (FUN_005BE210, ?IsVisible@CIntelGrid@Moho@@QBE_NABV?$Rect2@H@gpg@@_N@Z)
     *
     * What it does:
     * Converts world-space rectangle bounds into grid-cell bounds and returns
     * true when any covered grid cell is visible.
     */
    [[nodiscard]] bool IsVisible(const gpg::Rect2<int>& rect, bool unused = false) const;

    /**
     * Address: 0x00507670 (FUN_00507670, ?AddCircle@CIntelGrid@Moho@@QAEXABV?$Vector3@M@Wm3@@I@Z)
     *
     * What it does:
     * Converts world radius to cell radius and adds +1 coverage over the
     * rasterized circle.
     */
    void AddCircle(const Wm3::Vec3f& position, std::uint32_t radius);

    /**
     * Address: 0x00507690 (FUN_00507690, ?SubtractCircle@CIntelGrid@Moho@@QAEXABV?$Vector3@M@Wm3@@I@Z)
     *
     * What it does:
     * Converts world radius to cell radius and subtracts 1 coverage over the
     * rasterized circle.
     */
    void SubtractCircle(const Wm3::Vec3f& position, std::uint32_t radius);

    /**
     * Address: 0x005076B0 (FUN_005076B0, ?DelayedSubtractCircle@CIntelGrid@Moho@@QAEXABV?$Vector3@M@Wm3@@I@Z)
     *
     * What it does:
     * Queues delayed subtraction update (30 ticks) for later processing.
     */
    void DelayedSubtractCircle(const Wm3::Vec3f& position, std::uint32_t radius);

    /**
     * Address: 0x005077B0 (FUN_005077B0, ?Tick@CIntelGrid@Moho@@QAEXH@Z)
     *
     * What it does:
     * Advances delayed subtraction timers and applies expired raster removals.
     */
    void Tick(std::int32_t dTicks);

    /**
     * Address: 0x00507880 (FUN_00507880, ?UpdateChecksum@CIntelGrid@Moho@@QAEXAAVMD5Context@gpg@@@Z)
     *
     * What it does:
     * Explicit no-op checksum lane (`retn` in binary).
     */
    void UpdateChecksum(gpg::MD5Context& context);

    /**
     * Address: 0x005072D0 (FUN_005072D0,
     * ?MemberSaveConstructArgs@CIntelGrid@Moho@@AAEXAAVWriteArchive@gpg@@HABVRRef@4@AAVSerSaveConstructArgsResult@4@@Z)
     *
     * What it does:
     * Saves construct args (`STIMap*`, `mGridSize`) as unowned tracked pointer
     * payload for serializer construct callback.
     */
    void MemberSaveConstructArgs(
      gpg::WriteArchive& archive, int version, const gpg::RRef& ownerRef, gpg::SerSaveConstructArgsResult& result
    );

  private:
    /**
     * Address: 0x00507540 (FUN_00507540, ?Raster@CIntelGrid@Moho@@AAEXABV?$Vector3@M@Wm3@@I_N@Z)
     *
     * What it does:
     * Applies +/-1 over the filled cell-space circle.
     */
    void Raster(const Wm3::Vec3f& position, std::uint32_t radiusInCells, bool doAdd);


  public:
    STIMap* mMapData;                            // +0x00
    boost::scoped_array<std::int8_t> mGrid;      // +0x04
    std::uint32_t mWidth;                        // +0x08
    std::uint32_t mHeight;                       // +0x0C
    msvc8::vector<SDelayedSubVizInfo> mUpdateList;   // +0x10
    std::uint32_t mGridSize;                     // +0x20
  };

  /**
   * VFTABLE: 0x00E0D784
   * COL: 0x00E670A8
   */
  class CIntelGridTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005070D0 (FUN_005070D0, Moho::CIntelGridTypeInfo::CIntelGridTypeInfo)
     *
     * What it does:
     * Constructs `CIntelGrid` type-info storage and preregisters RTTI mapping.
     */
    CIntelGridTypeInfo();

    /**
     * Address: 0x00507160 (FUN_00507160, gpg::RType::~RType thunk)
     * Slot: 2
     */
    ~CIntelGridTypeInfo() override;

    /**
     * Address: 0x00507150 (FUN_00507150, Moho::CIntelGridTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00507130 (FUN_00507130, Moho::CIntelGridTypeInfo::Init)
     * Slot: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CIntelGrid) == 0x24, "CIntelGrid size must be 0x24");
  static_assert(offsetof(CIntelGrid, mMapData) == 0x00, "CIntelGrid::mMapData offset must be 0x00");
  static_assert(offsetof(CIntelGrid, mGrid) == 0x04, "CIntelGrid::mGrid offset must be 0x04");
  static_assert(offsetof(CIntelGrid, mWidth) == 0x08, "CIntelGrid::mWidth offset must be 0x08");
  static_assert(offsetof(CIntelGrid, mHeight) == 0x0C, "CIntelGrid::mHeight offset must be 0x0C");
  static_assert(offsetof(CIntelGrid, mUpdateList) == 0x10, "CIntelGrid::mUpdateList offset must be 0x10");
  static_assert(offsetof(CIntelGrid, mGridSize) == 0x20, "CIntelGrid::mGridSize offset must be 0x20");

  static_assert(sizeof(CIntelGridTypeInfo) == 0x64, "CIntelGridTypeInfo size must be 0x64");

  /**
   * Address: 0x00BC7920 (FUN_00BC7920, register_CIntelGridTypeInfo)
   *
   * What it does:
   * Forces startup construction for `CIntelGridTypeInfo`.
   */
  void register_CIntelGridTypeInfo();
} // namespace moho
